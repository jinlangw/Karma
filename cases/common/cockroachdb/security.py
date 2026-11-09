"""Explicit TLS workload transformations used by CockroachDB case preparation."""

from __future__ import annotations

import copy
import hashlib
import json
import re
import shlex
from typing import Callable, Type

from .startup import database_container
from .types import UnsupportedLayoutError


_SECURITY_FLAGS = frozenset(
    {"--insecure", "--accept-sql-without-tls", "--unencrypted-localhost-http"}
)
_CERT_FILES = ("ca.crt", "node.crt", "node.key", "client.root.crt", "client.root.key")


def _fail(error_type: Type[Exception], message: str) -> None:
    raise error_type(message)


def mounted_secret_signatures(
    template: dict,
    get_secret: Callable[[str], dict | None],
    *,
    error_type: Type[Exception],
) -> dict[str, dict[str, str]]:
    """Fingerprint the mounted Secrets referenced by a Pod template.

    Secret lookup remains with the caller. References are deduplicated and
    looked up in sorted-name order; the result preserves the case helper's
    UID and sorted-JSON SHA-256 projection.
    """
    names = set()
    for volume in template['spec'].get('volumes', []):
        if 'secret' in volume:
            names.add(volume['secret']['secretName'])
        names |= {s['secret']['name'] for s in volume.get('projected', {}).get('sources', []) if 'secret' in s}
    result = {}
    for name in sorted(names):
        secret = get_secret(name)
        if secret is None:
            raise error_type('mounted Secret is missing')
        result[name] = {
            'uid': secret['metadata']['uid'],
            'sha256': hashlib.sha256(json.dumps(secret.get('data', {}), sort_keys=True).encode()).hexdigest(),
        }
    return result


def _generate_cert_database_container(template: dict, *, error_type: Type[Exception]) -> dict:
    """Keep generate-cert's original server selection and local error text."""
    containers = [c for c in template["spec"]["containers"]
                  if "cockroach" in (c.get("image", "") + " ".join(c.get("command", []) + c.get("args", [])))
                  and re.search(r"\bstart(?:-single-node)?\b", " ".join(c.get("command", []) + c.get("args", [])))]
    if len(containers) != 1:
        _fail(error_type, "cannot identify exactly one CockroachDB server container")
    return containers[0]


def _generate_cert_server_arguments(container: dict, *, error_type: Type[Exception]) -> list[str]:
    """Retain generate-cert's accepted shell form while sharing its parser."""
    command = container.get("command", [])
    if len(command) == 3 and command[0] in ("/bin/bash", "/bin/sh", "bash", "sh") and command[1] in ("-c", "-ec"):
        tokens = shlex.split(command[2])
        syntax = shlex.shlex(command[2], posix=True, punctuation_chars=";&|<>")
        syntax.whitespace_split = True
        if any(re.fullmatch(r"[;&|<>]+", token) for token in syntax):
            _fail(error_type, "compound server startup requires explicit security-mode configuration")
        return tokens + container.get("args", [])
    return command + container.get("args", [])


def _generate_cert_certificate_directory(container: dict, *, error_type: Type[Exception]) -> str:
    tokens = _generate_cert_server_arguments(container, error_type=error_type)
    for index, token in enumerate(tokens):
        if token.startswith("--certs-dir="):
            return token.split("=", 1)[1]
        if token == "--certs-dir" and index + 1 < len(tokens):
            return tokens[index + 1]
    return "/cockroach/cockroach-certs"


def insecure_template(
    template: dict,
    secret_names,
    *,
    error_type: Type[Exception] = UnsupportedLayoutError,
) -> dict:
    """Return a copy using generate-cert's original insecure conversion.

    This deliberately preserves that case's selector, parser, default
    certificate path, and security-flag/probe/mount rules. It is separate
    from :func:`secure_template`, whose stricter contracts serve a different
    workflow.
    """
    updated = copy.deepcopy(template)
    container = _generate_cert_database_container(updated, error_type=error_type)
    directory = _generate_cert_certificate_directory(container, error_type=error_type)

    def strip(tokens):
        result = []
        index = 0
        while index < len(tokens):
            token = tokens[index]
            if token in ("--certs-dir", "--accept-sql-without-tls"):
                index += 2 if token == "--certs-dir" else 1
                continue
            if token == "--insecure" or token.startswith(("--certs-dir=", "--insecure=", "--accept-sql-without-tls=")):
                index += 1
                continue
            result.append(token)
            index += 1
        return result

    command = container.get("command", [])
    arguments = _generate_cert_server_arguments(container, error_type=error_type)
    change_flags = not any(t in ("--insecure", "--insecure=true") for t in arguments) or any(
        t == "--certs-dir" or t.startswith(("--certs-dir=", "--accept-sql-without-tls")) for t in arguments)
    if not change_flags:
        pass
    elif len(command) == 3 and command[0] in ("/bin/bash", "/bin/sh", "bash", "sh") and command[1] in ("-c", "-ec"):
        body = command[2]
        # Preserve quoting and expansion of every unrelated startup argument.
        body = re.sub(r"(?<!\S)--certs-dir(?:=\S+|\s+\S+)(?=\s|$)", "", body)
        body = re.sub(r"(?<!\S)--(?:insecure|accept-sql-without-tls)(?:=\S+)?(?=\s|$)", "", body)
        wanted = strip(shlex.split(command[2]))
        if shlex.split(body) != wanted:
            _fail(error_type, "cannot safely edit quoted security arguments")
        container["command"][2] = body.rstrip() + " --insecure"
        if "args" in container:
            container["args"] = strip(container["args"])
    else:
        if "command" in container:
            container["command"] = strip(container["command"])
        if "args" in container:
            container["args"] = strip(container["args"]) + ["--insecure"]
        else:
            container["command"] = strip(container.get("command", [])) + ["--insecure"]

    def refs(volume):
        return {volume["secret"]["secretName"]} if "secret" in volume else {
            source["secret"]["name"] for source in volume.get("projected", {}).get("sources", []) if "secret" in source}

    removed = {volume["name"] for volume in updated["spec"].get("volumes", []) if refs(volume) & secret_names}
    removed |= {mount["name"] for mount in container.get("volumeMounts", []) if mount["mountPath"] in (directory, "/cockroach/cockroach-certs")}
    for volume in updated["spec"].get("volumes", []):
        if volume["name"] in removed and (not refs(volume) or refs(volume) - secret_names or any(
            "secret" not in source for source in volume.get("projected", {}).get("sources", []))):
            _fail(error_type, "certificate volume includes unrelated sources or non-Secret storage")
    # A shared volume used at an unrelated path cannot be removed implicitly.
    for other in updated["spec"].get("containers", []) + updated["spec"].get("initContainers", []):
        if other is not container and any(m["name"] in removed for m in other.get("volumeMounts", [])):
            _fail(error_type, "another container uses the database certificate volume")
    if "volumeMounts" in container:
        container["volumeMounts"] = [m for m in container["volumeMounts"] if m["name"] not in removed]
    if "volumes" in updated["spec"]:
        updated["spec"]["volumes"] = [v for v in updated["spec"]["volumes"] if v["name"] not in removed]
    for key in ("livenessProbe", "readinessProbe", "startupProbe"):
        probe = container.get(key, {})
        if "httpGet" in probe and probe["httpGet"].get("scheme") == "HTTPS":
            probe["httpGet"]["scheme"] = "HTTP"
        if "exec" in probe and any("--certs-dir" in arg for arg in probe["exec"]["command"]):
            _fail(error_type, "certificate-based exec health probe requires explicit mode conversion")
    return updated


def _parse_startup(container: dict, error_type: Type[Exception]) -> tuple[str, list[str], str | None]:
    command = container.get("command", [])
    args = container.get("args", [])
    if not isinstance(command, list) or not command or not isinstance(args, list):
        _fail(error_type, "CockroachDB startup command has an unsupported shape")
    if any(not isinstance(item, str) for item in command + args):
        _fail(error_type, "CockroachDB startup command contains a non-string argument")

    executable = command[0].rsplit("/", 1)[-1]
    shell_script = None
    if executable in {"sh", "bash"}:
        if len(command) != 3 or command[1] not in {"-c", "-ec"} or args:
            _fail(error_type, "Shell startup must be a direct, single-script CockroachDB command")
        shell_script = command[2]
        if "\n" in shell_script or "\r" in shell_script:
            _fail(error_type, "CockroachDB startup script uses unsupported command separators")
        try:
            lexer = shlex.shlex(shell_script, posix=True, punctuation_chars=";&|<>")
            lexer.whitespace_split = True
            tokens = list(lexer)
            plain_tokens = shlex.split(shell_script)
        except ValueError as error:
            raise error_type("CockroachDB startup script cannot be parsed safely") from error
        if any(re.fullmatch(r"[;&|<>]+", token) for token in tokens):
            _fail(error_type, "CockroachDB startup script contains unsupported shell control flow")
        tokens = plain_tokens
    else:
        if executable != "cockroach":
            _fail(error_type, "Startup must directly execute CockroachDB")
        tokens = command + args

    offset = 1 if tokens and tokens[0] == "exec" else 0
    if len(tokens) < offset + 2 or tokens[offset].rsplit("/", 1)[-1] != "cockroach":
        _fail(error_type, "Startup must directly execute CockroachDB")
    if tokens[offset + 1] not in {"start", "start-single-node"}:
        _fail(error_type, "Startup must directly execute CockroachDB start")
    for token in tokens:
        if "`" in token or (
            "$" in token
            and not token.startswith(
                ("--advertise-host=", "--advertise-addr=", "--advertise-sql-addr=", "--join=")
            )
        ):
            _fail(error_type, "CockroachDB startup contains unsupported shell expansion")
    return ("shell" if shell_script is not None else "argv", tokens, shell_script)


def _rewrite_flags(tokens: list[str], error_type: Type[Exception]) -> list[tuple[int, str]]:
    offset = 1 if tokens and tokens[0] == "exec" else 0
    result = [(index, token) for index, token in enumerate(tokens[: offset + 2])]
    seen_certs_dir = False
    index = offset + 2
    while index < len(tokens):
        token = tokens[index]
        name, separator, value = token.partition("=")
        if name in _SECURITY_FLAGS:
            # Cockroach's boolean CLI flags use --flag or --flag=true. A
            # positional token after a bare flag cannot be safely attributed
            # to another option, so reject rather than leave an orphan value.
            if not separator and index + 1 < len(tokens) and not tokens[index + 1].startswith("--"):
                _fail(error_type, f"CockroachDB {name} uses an unsupported separate value")
            if separator and value.lower() not in {"true", "false"}:
                _fail(error_type, f"CockroachDB {name} has an invalid boolean value")
            index += 1
            continue
        if name == "--certs-dir":
            if seen_certs_dir:
                _fail(error_type, "CockroachDB startup repeats --certs-dir")
            seen_certs_dir = True
            if not separator:
                if index + 1 >= len(tokens) or tokens[index + 1].startswith("--"):
                    _fail(error_type, "CockroachDB --certs-dir has no value")
                index += 2
            else:
                if not value:
                    _fail(error_type, "CockroachDB --certs-dir has no value")
                index += 1
            continue
        result.append((index, token))
        index += 1
    result.append((len(tokens), "__COCKROACH_CERTS_DIR__"))
    return result


def _http_listener_port(container: dict, error_type: Type[Exception]) -> int:
    command = container.get("command", [])
    args = container.get("args", [])
    if command and command[0].rsplit("/", 1)[-1] in {"sh", "bash"}:
        _, tokens, _ = _parse_startup(container, error_type)
    else:
        tokens = command + args
    values: list[str] = []
    index = 2 if tokens and tokens[0] == "exec" else 1
    while index < len(tokens):
        token = tokens[index]
        if token == "--http-port" or token.startswith("--http-port="):
            _fail(error_type, "CockroachDB startup uses unsupported --http-port listener configuration")
        if token.startswith("--http-addr="):
            values.append(token.split("=", 1)[1])
        elif token == "--http-addr":
            if index + 1 >= len(tokens):
                _fail(error_type, "CockroachDB --http-addr has no value")
            index += 1
            values.append(tokens[index])
        index += 1
    if len(set(values)) > 1:
        _fail(error_type, "CockroachDB startup has conflicting --http-addr values")
    if not values:
        return 8080
    value = values[0]
    if "$" in value or "`" in value:
        _fail(error_type, "CockroachDB --http-addr uses unsupported shell expansion")
    match = re.fullmatch(r"(?:(?:\[[^\]]+\]|[^:]*):)?([0-9]+)", value)
    if not match:
        _fail(error_type, "CockroachDB --http-addr has an unsupported address")
    port = int(match.group(1))
    if not 1 <= port <= 65535:
        _fail(error_type, "CockroachDB --http-addr has an invalid port")
    return port


def _probe_targets_http_listener(probe: dict, container: dict, port: int, error_type: Type[Exception]) -> bool:
    handler = probe.get("httpGet")
    if not isinstance(handler, dict) or handler.get("host") not in (None, ""):
        return False
    selected_port = handler.get("port")
    if type(selected_port) is int:
        return selected_port == port
    if not isinstance(selected_port, str):
        return False
    ports = container.get("ports", [])
    if not isinstance(ports, list):
        _fail(error_type, "CockroachDB HTTP listener port layout is unsupported")
    matches = [
        item
        for item in ports
        if isinstance(item, dict) and item.get("name") == selected_port
    ]
    if len(matches) > 1:
        _fail(error_type, "CockroachDB HTTP probe port name is ambiguous")
    return len(matches) == 1 and matches[0].get("containerPort") == port and matches[0].get("protocol", "TCP") == "TCP"


def _secure_probe_handlers(container: dict, error_type: Type[Exception]) -> None:
    http_port = _http_listener_port(container, error_type)
    for probe_name in ("livenessProbe", "readinessProbe", "startupProbe"):
        probe = container.get(probe_name)
        if not isinstance(probe, dict):
            continue
        if "exec" in probe:
            exec_probe = probe.get("exec")
            command = exec_probe.get("command", []) if isinstance(exec_probe, dict) else []
            joined = " ".join(str(item) for item in command).lower()
            if any(marker in joined for marker in ("cockroach", "--insecure", "--certs-dir", "sql ", "health")):
                _fail(error_type, f"CockroachDB {probe_name} exec probe requires explicit TLS conversion")
        http_get = probe.get("httpGet")
        if not isinstance(http_get, dict) or not _probe_targets_http_listener(
            probe, container, http_port, error_type
        ):
            continue
        scheme = http_get.get("scheme", "HTTP")
        if scheme not in {"HTTP", "HTTPS"}:
            _fail(error_type, f"CockroachDB {probe_name} HTTP probe has an unsupported scheme")
        http_get["scheme"] = "HTTPS"


def _attach_secret_mount(
    template: dict,
    container: dict,
    secret_name: str,
    cert_dir: str,
    error_type: Type[Exception],
) -> None:
    pod_spec = template.get("spec")
    if not isinstance(pod_spec, dict):
        _fail(error_type, "CockroachDB Pod template has no spec")
    mounts = container.get("volumeMounts", [])
    volumes = pod_spec.get("volumes", [])
    if not isinstance(mounts, list) or not isinstance(volumes, list):
        _fail(error_type, "CockroachDB certificate mount layout is unsupported")
    container["volumeMounts"] = mounts
    pod_spec["volumes"] = volumes
    existing = [mount for mount in mounts if isinstance(mount, dict) and mount.get("mountPath") == cert_dir]
    if len(existing) > 1:
        _fail(error_type, "CockroachDB certificate directory has multiple mounts")

    if existing:
        mount = existing[0]
        if mount.get("subPath") not in (None, "") or mount.get("subPathExpr") not in (None, ""):
            _fail(error_type, "CockroachDB certificate mount uses an unsupported subPath")
        mount["readOnly"] = True
        name = mount.get("name")
        selected = [volume for volume in volumes if isinstance(volume, dict) and volume.get("name") == name]
        if len(selected) != 1:
            _fail(error_type, "CockroachDB certificate mount volume is missing or ambiguous")
        volume = selected[0]
        if set(volume) - {"name", "secret"} or not isinstance(volume.get("secret"), dict):
            _fail(error_type, "CockroachDB certificate directory is not backed by a dedicated Secret volume")
        secret = volume["secret"]
        if set(secret) - {"secretName", "defaultMode", "items", "optional"}:
            _fail(error_type, "CockroachDB certificate Secret volume has unsupported fields")
        containers = pod_spec.get("containers", [])
        init_containers = pod_spec.get("initContainers", [])
        if not isinstance(containers, list) or not isinstance(init_containers, list):
            _fail(error_type, "CockroachDB certificate volume ownership is unsupported")
        for other in containers + init_containers:
            if other is container:
                continue
            if any(item.get("name") == name for item in other.get("volumeMounts", []) if isinstance(item, dict)):
                _fail(error_type, "Another container shares the CockroachDB certificate volume")
        secret["secretName"] = secret_name
        secret.setdefault("defaultMode", 256)
        secret["items"] = [{"key": key, "path": key} for key in _CERT_FILES]
        secret["optional"] = False
        return

    for mount in mounts:
        mount_path = mount.get("mountPath") if isinstance(mount, dict) else None
        if isinstance(mount_path, str) and mount_path.startswith(cert_dir.rstrip("/") + "/"):
            _fail(error_type, "CockroachDB certificate directory overlaps another mount")
    name = "cockroach-certs"
    used = {volume.get("name") for volume in volumes if isinstance(volume, dict)}
    suffix = 0
    while name in used:
        suffix += 1
        name = f"cockroach-certs-{suffix}"
    mounts.append({"name": name, "mountPath": cert_dir, "readOnly": True})
    volumes.append(
        {
            "name": name,
            "secret": {
                "secretName": secret_name,
                "defaultMode": 256,
                "items": [{"key": key, "path": key} for key in _CERT_FILES],
                "optional": False,
            },
        }
    )


def secure_template(
    template: dict,
    *,
    secret_name: str,
    cert_dir: str,
    error_type: Type[Exception] = UnsupportedLayoutError,
) -> dict:
    """Return a copy configured for the certificate-rotation secure-SQL/HTTPS stage.

    The operation changes only CockroachDB security flags, its dedicated
    certificate Secret mount, and modeled HTTP health probes. It does not infer
    HTTP transport from SQL TLS and does not alter unrelated probes or fields.
    """
    if (
        not isinstance(template, dict)
        or not isinstance(secret_name, str)
        or not secret_name
        or secret_name.strip() != secret_name
        or not isinstance(cert_dir, str)
        or not cert_dir.startswith("/")
        or cert_dir == "/"
        or ".." in cert_dir.split("/")
    ):
        _fail(error_type, "A Pod template, certificate Secret name, and absolute certificate directory are required")
    updated = copy.deepcopy(template)
    pod_spec = updated.get("spec")
    containers = pod_spec.get("containers") if isinstance(pod_spec, dict) else None
    if not isinstance(containers, list) or any(not isinstance(item, dict) for item in containers):
        _fail(error_type, "CockroachDB Pod template has no supported container list")
    for candidate in containers:
        for field in ("command", "args"):
            value = candidate.get(field, [])
            if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
                _fail(error_type, "CockroachDB startup command has an unsupported shape")
    container = database_container(updated, error_type=error_type)
    mode, tokens, script = _parse_startup(container, error_type)
    rewritten_tokens = _rewrite_flags(tokens, error_type)
    _secure_probe_handlers(container, error_type)
    _attach_secret_mount(updated, container, secret_name, cert_dir, error_type)

    if mode == "shell":
        assert script is not None
        new_cert_flag = f"--certs-dir={cert_dir}"
        expected_tokens = [
            new_cert_flag if token == "__COCKROACH_CERTS_DIR__" else token
            for _, token in rewritten_tokens
        ]
        if expected_tokens != tokens:
            # Keep all unmodified shell text, substitutions and quoting. The
            # parse-equivalence check below rejects any rewrite it cannot prove.
            pattern = re.compile(
                r"(?<!\S)(?:--insecure|--accept-sql-without-tls|--unencrypted-localhost-http)"
                r"(?:=[^\s]+)?(?=\s|$)|(?<!\S)--certs-dir(?:=[^\s]+|\s+[^\s]+)?(?=\s|$)"
            )
            rewritten_script = pattern.sub("", script).rstrip() + f" {new_cert_flag}"
            try:
                if shlex.split(rewritten_script) != expected_tokens:
                    _fail(error_type, "CockroachDB shell startup flags cannot be rewritten without changing other arguments")
            except ValueError as error:
                raise error_type("CockroachDB startup script cannot be rewritten safely") from error
            container["command"][2] = rewritten_script
    else:
        # Retain the Kubernetes command/args boundary for every unrelated
        # token; removed flags simply disappear from their original field.
        command_count = len(container["command"])
        new_cert_flag = f"--certs-dir={cert_dir}"
        rewritten = [
            (index, new_cert_flag if token == "__COCKROACH_CERTS_DIR__" else token)
            for index, token in rewritten_tokens
        ]
        container["command"] = [token for index, token in rewritten if index < command_count]
        container["args"] = [token for index, token in rewritten if index >= command_count]
    return updated

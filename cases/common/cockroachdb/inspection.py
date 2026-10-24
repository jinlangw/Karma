"""Read-only inspection and conservative layout parsing."""

from __future__ import annotations

import copy
import hashlib
import json
import re
import shlex
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .adapter import ClusterAdapter
from .startup import certificate_directory as _resolve_certificate_directory
from .types import (
    EnvReference,
    HTTPTransport,
    InvalidRequirementError,
    MissingResourceError,
    MountObservation,
    Observation,
    PodObservation,
    PortObservation,
    ProbeObservation,
    PvcObservation,
    RolloutInProgressError,
    SecretFingerprint,
    SQLConnectionObservation,
    ServiceObservation,
    ServicePortObservation,
    TLSMode,
    UnsupportedLayoutError,
    WorkloadRef,
)


_CERT_FILES = frozenset({"ca.crt", "node.crt", "node.key"})
_ROOT_CLIENT_FILES = frozenset({"client.root.crt", "client.root.key"})


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _list(value: Any) -> Sequence[Any]:
    return value if isinstance(value, (list, tuple)) else ()


def _metadata(resource: Mapping[str, Any]) -> Mapping[str, Any]:
    return _mapping(resource.get("metadata"))


def _container_ports(container: Mapping[str, Any]) -> tuple[PortObservation, ...]:
    found = []
    for item in _list(container.get("ports")):
        port = _mapping(item)
        value = port.get("containerPort")
        if isinstance(value, int):
            found.append(PortObservation(port.get("name"), value, str(port.get("protocol", "TCP"))))
    return tuple(found)


def _shell_start_tokens(container: Mapping[str, Any]) -> list[str]:
    command = [str(item) for item in _list(container.get("command"))]
    args = [str(item) for item in _list(container.get("args"))]
    if not command:
        image = str(container.get("image", ""))
        image_ref = image.split("@", 1)[0]
        image_path = image_ref
        last_component = image_ref.rsplit("/", 1)[-1]
        if ":" in last_component:
            image_path = image_ref[: -len(last_component)] + last_component.rsplit(":", 1)[0]
        env_names = {str(_mapping(item).get("name", "")) for item in _list(container.get("env"))}
        uses_known_entrypoint = image_path in {
            "cockroachdb/cockroach",
            "docker.io/cockroachdb/cockroach",
            "index.docker.io/cockroachdb/cockroach",
        }
        if (
            not uses_known_entrypoint
            or not args
            or args[0] != "start"
            or container.get("envFrom")
            or env_names.intersection({"COCKROACH", "COCKROACH_ARGS"})
        ):
            raise UnsupportedLayoutError("Database container has no explicit startup command")
        # The official image entrypoint dispatches its first argument as a
        # CockroachDB subcommand; `start` execs /cockroach/cockroach directly.
        command = ["/cockroach/cockroach"]
    executable = command[0].rsplit("/", 1)[-1]
    if executable in {"sh", "bash", "dash", "zsh"} and (len(command) >= 2 or args):
        command_parts = command[1:] + args
        script_index: int | None = None
        if command_parts and command_parts[0] == "-e" and len(command_parts) >= 2 and command_parts[1] == "-c":
            script_index = 2
        elif command_parts and command_parts[0].startswith("-") and "c" in command_parts[0][1:]:
            options = command_parts[0][1:]
            if any(option not in "cexu" for option in options):
                raise UnsupportedLayoutError("Shell startup uses unsupported shell options")
            script_index = 1
        if script_index is None:
            raise UnsupportedLayoutError("Shell startup must use a direct -c command")
        if len(command_parts) > script_index:
            script = command_parts[script_index]
            if len(command_parts) > script_index + 1:
                raise UnsupportedLayoutError("Shell startup command uses unsupported positional arguments")
        else:
            raise UnsupportedLayoutError("Shell startup command has no script")
        try:
            if "\n" in script or "\r" in script:
                raise UnsupportedLayoutError("Database startup script uses unsupported shell command separators")
            lexer = shlex.shlex(script, posix=True, punctuation_chars=";&|<>")
            lexer.whitespace_split = True
            tokens = list(lexer)
        except ValueError as error:
            raise UnsupportedLayoutError("Database startup script cannot be parsed safely") from error
        if any(re.fullmatch(r"[;&|<>]+", token) for token in tokens):
            raise UnsupportedLayoutError("Database startup script contains unsupported shell control flow")
        if tokens and tokens[0] == "exec":
            tokens = tokens[1:]
        if len(tokens) < 2 or tokens[1] != "start" or tokens[0].rsplit("/", 1)[-1] != "cockroach":
            raise UnsupportedLayoutError("Shell startup script must directly exec CockroachDB start")
        for token in tokens:
            if "`" in token:
                raise UnsupportedLayoutError("Database startup script uses command substitution")
            substitutions = re.findall(r"\$\(([^)]+)\)", token)
            for substitution in substitutions:
                if substitution not in {"POD_NAME", "POD_NAMESPACE"} or not token.startswith(
                    (
                        "--advertise-host=",
                        "--advertise-addr=",
                        "--advertise-sql-addr=",
                        "--join=",
                    )
                ):
                    raise UnsupportedLayoutError("Database startup uses unsupported environment substitution")
            remainder = re.sub(r"\$\((?:POD_NAME|POD_NAMESPACE)\)", "", token)
            if "$" in remainder:
                raise UnsupportedLayoutError("Database startup uses unsupported environment expansion")
        return tokens

    tokens = command + args
    if len(tokens) < 2 or tokens[1] != "start" or tokens[0].rsplit("/", 1)[-1] != "cockroach":
        raise UnsupportedLayoutError("Database command must directly run CockroachDB start")
    return tokens


def _advertised_host_template(
    flags: Mapping[str, str | None],
    candidates: tuple[str, ...],
) -> tuple[str | None, str | None, str | None, str | None]:
    """Resolve one advertised listener address without inferring DNS."""
    value = None
    flag_name = None
    for candidate in candidates:
        if candidate in flags:
            value = flags[candidate]
            flag_name = candidate
            break
    if value is None or flag_name is None:
        return None, None, None, None
    label = r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?"
    domain = rf"{label}(?:\.{label})*"
    suffix = r"(?::[0-9]{1,5})?" if flag_name != "advertise-host" else ""
    match = re.fullmatch(
        rf"\$\(POD_NAME\)\.({label})\.\$\(POD_NAMESPACE\)\.svc\.({domain}){suffix}",
        value,
    )
    if match and len(value) <= 253:
        service_name, cluster_domain = match.groups()[:2]
        template = f"$(POD_NAME).{service_name}.$(POD_NAMESPACE).svc.{cluster_domain}"
        return template, service_name, cluster_domain, None

    # A fixed advertised address is safe to resolve only for a singleton:
    # reusing it across replicas could silently probe one node repeatedly.
    if "$" not in value and "`" not in value:
        host = value
        if flag_name != "advertise-host":
            host, _ = _address_parts(value, flag_name)
        if host and re.fullmatch(rf"{domain}", host) and len(host) <= 253:
            return host, None, None, host
    return None, None, None, None


def _advertised_sql_host_template(
    flags: Mapping[str, str | None],
) -> tuple[str | None, str | None, str | None, str | None]:
    """Resolve the SQL advertise address, preferring its SQL-specific flag."""
    return _advertised_host_template(flags, ("advertise-sql-addr", "advertise-addr", "advertise-host"))


def _advertised_rpc_host_template(
    flags: Mapping[str, str | None],
) -> tuple[str | None, str | None, str | None, str | None]:
    """Resolve the RPC advertise address independently from SQL advertisement."""
    try:
        return _advertised_host_template(flags, ("advertise-addr", "advertise-host"))
    except UnsupportedLayoutError:
        # RPC is optional to SQL-only observers. An unparseable RPC advertise
        # address must not prevent them from using a valid SQL advertise address.
        return None, None, None, None


def _rpc_advertise_port_matches_listener(flags: Mapping[str, str | None], rpc_port: int) -> bool:
    if "advertise-addr" not in flags:
        return True
    value = flags["advertise-addr"]
    if value is None:
        return False
    match = re.search(r":([0-9]+)$", value)
    if match is None:
        return False
    port = int(match.group(1))
    return 1 <= port <= 65535 and port == rpc_port


def _pod_sql_host(
    pod_name: str,
    namespace: str,
    service_name: str | None,
    cluster_domain: str | None,
    literal_host: str | None,
    desired_replicas: int,
) -> str | None:
    if literal_host:
        return literal_host if desired_replicas == 1 else None
    if not service_name or not cluster_domain:
        return None
    label = r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?"
    if not re.fullmatch(label, pod_name) or not re.fullmatch(label, namespace):
        raise UnsupportedLayoutError("Pod DNS identity cannot be used for a CockroachDB SQL connection")
    host = f"{pod_name}.{service_name}.{namespace}.svc.{cluster_domain}"
    if len(host) > 253:
        raise UnsupportedLayoutError("CockroachDB advertised SQL host exceeds the DNS name limit")
    return host


def _flags(tokens: Sequence[str]) -> dict[str, str | None]:
    values: dict[str, str | None] = {}
    for index, token in enumerate(tokens[2:], start=2):
        if not token.startswith("--"):
            continue
        name, separator, value = token[2:].partition("=")
        if not name:
            raise UnsupportedLayoutError("Database startup contains an invalid flag")
        if separator:
            current: str | None = value
        elif name == "insecure":
            current = "true"
        elif index + 1 < len(tokens) and not tokens[index + 1].startswith("--"):
            current = tokens[index + 1]
        else:
            current = None
        if name in values and values[name] != current:
            raise UnsupportedLayoutError(f"Database startup repeats --{name} with conflicting values")
        values[name] = current
    return values


def _address_parts(value: str, flag_name: str) -> tuple[str | None, int]:
    if "$" in value or "`" in value:
        raise UnsupportedLayoutError(f"Database flag --{flag_name} uses dynamic shell expansion")
    match = re.fullmatch(r"(?:(\[[^\]]+\]|[^:]*):)?(\d+)", value)
    if not match:
        raise UnsupportedLayoutError(f"Database flag --{flag_name} has an ambiguous address")
    host = match.group(1)
    if host and host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    candidate = match.group(2)
    try:
        port = int(candidate)
    except ValueError as error:
        raise UnsupportedLayoutError(f"Database flag --{flag_name} has an ambiguous port") from error
    if not 1 <= port <= 65535:
        raise UnsupportedLayoutError(f"Database flag --{flag_name} has an invalid port")
    return host or None, port


def _integer_port(value: str, flag_name: str) -> int:
    return _address_parts(value, flag_name)[1]


def _address_host(flags: Mapping[str, str | None], flag: str) -> str | None:
    value = flags.get(flag)
    return _address_parts(value, flag)[0] if value is not None else None


def _flag_port(flags: Mapping[str, str | None], flag: str) -> int | None:
    value = flags.get(flag)
    return _integer_port(value, flag) if value is not None else None


def _named_port(ports: Sequence[PortObservation], name: str) -> PortObservation | None:
    found = [port for port in ports if (port.name or "").lower() == name]
    if len(found) > 1:
        raise UnsupportedLayoutError(f"Container declares multiple {name!r} ports")
    return found[0] if found else None


def _port_name(ports: Sequence[PortObservation], number: int, preferred: Sequence[str]) -> str | None:
    matching = [port for port in ports if port.number == number]
    if len(matching) == 1:
        return matching[0].name
    for name in preferred:
        named = [port for port in matching if (port.name or "").lower() == name]
        if len(named) == 1:
            return named[0].name
    return None


def _hash_json(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _probe_preservation_hash(spec: Mapping[str, Any], container_index: int) -> str:
    """Hash StatefulSet spec except the two explicitly mutable probe handlers."""
    projection = copy.deepcopy(dict(spec))
    template = dict(_mapping(projection.get("template")))
    template_spec = dict(_mapping(template.get("spec")))
    containers = list(_list(template_spec.get("containers")))
    if container_index >= len(containers):
        raise UnsupportedLayoutError("Selected container index is outside the StatefulSet template")
    selected = dict(_mapping(containers[container_index]))
    for probe_name in ("livenessProbe", "readinessProbe"):
        probe_value = selected.get(probe_name)
        if isinstance(probe_value, dict):
            probe = dict(probe_value)
            for handler_name in ("httpGet", "tcpSocket", "exec", "grpc"):
                probe.pop(handler_name, None)
            selected[probe_name] = probe
    containers[container_index] = selected
    template_spec["containers"] = containers
    template["spec"] = template_spec
    projection["template"] = template
    return _hash_json(projection)


def _parse_probe(probe_value: Any) -> ProbeObservation | None:
    probe = _mapping(probe_value)
    if not probe:
        return None
    handler = next((name for name in ("httpGet", "tcpSocket", "exec", "grpc") if name in probe), "unknown")
    value = _mapping(probe.get(handler))
    port = value.get("port")
    if not isinstance(port, (str, int)):
        port = None
    headers = value.get("httpHeaders")
    return ProbeObservation(
        handler=handler,
        path=value.get("path") if isinstance(value.get("path"), str) else None,
        port=port,
        scheme=value.get("scheme") if isinstance(value.get("scheme"), str) else None,
        host=value.get("host") if isinstance(value.get("host"), str) else None,
        period_seconds=probe.get("periodSeconds") if isinstance(probe.get("periodSeconds"), int) else None,
        initial_delay_seconds=probe.get("initialDelaySeconds") if isinstance(probe.get("initialDelaySeconds"), int) else None,
        timeout_seconds=probe.get("timeoutSeconds") if isinstance(probe.get("timeoutSeconds"), int) else None,
        failure_threshold=probe.get("failureThreshold") if isinstance(probe.get("failureThreshold"), int) else None,
        success_threshold=probe.get("successThreshold") if isinstance(probe.get("successThreshold"), int) else None,
        has_custom_headers=bool(headers),
    )


def _secret_volume(volume: Mapping[str, Any]) -> tuple[str | None, str, dict[str, str]]:
    direct = _mapping(volume.get("secret"))
    if direct:
        name = direct.get("secretName")
        file_map: dict[str, str] = {}
        items = direct.get("items")
        if items:
            for item_value in _list(items):
                item = _mapping(item_value)
                key, path = item.get("key"), item.get("path")
                if not isinstance(key, str) or not isinstance(path, str) or "/" in path or path in {".", ".."}:
                    return (str(name) if name else None, "unsupported-secret-projection", {})
                file_map[key] = path
        source_kind = "secret-optional" if direct.get("optional") else "secret"
        return (str(name) if name else None, source_kind, file_map)

    projected = _mapping(volume.get("projected"))
    if projected:
        sources = _list(projected.get("sources"))
        if len(sources) == 1:
            secret_source = _mapping(sources[0]).get("secret")
            secret_source = _mapping(secret_source)
            if secret_source and not secret_source.get("optional") and not secret_source.get("items"):
                name = secret_source.get("name")
                return (str(name) if name else None, "projected-secret", {})
        return (None, "unsupported-projection", {})
    source = next((key for key in volume if key not in {"name"}), "unknown")
    return (None, str(source), {})


def _env_references(container: Mapping[str, Any]) -> tuple[EnvReference, ...]:
    references = []
    for entry_value in _list(container.get("env")):
        entry = _mapping(entry_value)
        name = str(entry.get("name", ""))
        value_from = _mapping(entry.get("valueFrom"))
        secret_key = _mapping(value_from.get("secretKeyRef"))
        if secret_key:
            references.append(
                EnvReference(
                    name=name,
                    source="secretKeyRef",
                    secret_name=str(secret_key.get("name")) if secret_key.get("name") else None,
                    secret_key=str(secret_key.get("key")) if secret_key.get("key") else None,
                )
            )
        elif entry.get("valueFrom"):
            references.append(EnvReference(name=name, source="fieldOrConfigReference"))
        elif "value" in entry:
            references.append(EnvReference(name=name, source="literal", has_literal_value=True))
    for entry_value in _list(container.get("envFrom")):
        entry = _mapping(entry_value)
        secret_ref = _mapping(entry.get("secretRef"))
        if secret_ref.get("name"):
            references.append(
                EnvReference(name="*", source="envFrom.secretRef", secret_name=str(secret_ref["name"]))
            )
    return tuple(sorted(references, key=lambda item: (item.name, item.source, item.secret_name or "")))


def _validate_known_environment_expansion(tokens: Sequence[str], container: Mapping[str, Any]) -> None:
    used = {
        variable
        for token in tokens
        for variable in re.findall(r"\$\(([^)]+)\)", token)
    }
    if not used:
        return
    allowed = {"POD_NAME": "metadata.name", "POD_NAMESPACE": "metadata.namespace"}
    if not used.issubset(allowed):
        raise UnsupportedLayoutError("Database startup references an unsupported environment variable")
    bindings = {}
    for entry_value in _list(container.get("env")):
        entry = _mapping(entry_value)
        value_from = _mapping(entry.get("valueFrom"))
        field_ref = _mapping(value_from.get("fieldRef"))
        if entry.get("name") and field_ref.get("fieldPath"):
            bindings[str(entry["name"])] = str(field_ref["fieldPath"])
    for variable in used:
        if bindings.get(variable) != allowed[variable]:
            raise UnsupportedLayoutError(
                f"Database startup variable {variable} is not bound to its Kubernetes pod identity field"
            )


def _selected_container(template: Mapping[str, Any], requested_name: str | None) -> tuple[int, Mapping[str, Any]]:
    spec = _mapping(template.get("spec"))
    containers = [_mapping(item) for item in _list(spec.get("containers"))]
    if requested_name:
        matching = [(index, value) for index, value in enumerate(containers) if value.get("name") == requested_name]
    else:
        matching = [
            (index, value)
            for index, value in enumerate(containers)
            if "cockroach" in str(value.get("image", "")).lower()
            or any("cockroach" in str(token).lower() for token in _list(value.get("command")))
        ]
    if len(matching) != 1:
        raise UnsupportedLayoutError("Could not identify exactly one selected CockroachDB container")
    return matching[0]


def _is_standard_service_account_projection(volume: Mapping[str, Any]) -> bool:
    """Recognize only Kubernetes' default projected API credential volume."""
    if set(volume) != {"name", "projected"}:
        return False
    name = str(volume.get("name", ""))
    if not re.fullmatch(r"kube-api-access-[a-z0-9]{5}", name):
        return False
    projected = _mapping(volume.get("projected"))
    if set(projected) != {"defaultMode", "sources"} or projected.get("defaultMode") != 420:
        return False
    sources = [_mapping(item) for item in _list(projected.get("sources"))]
    if len(sources) != 3:
        return False
    token = [source["serviceAccountToken"] for source in sources if set(source) == {"serviceAccountToken"}]
    root_ca = [source["configMap"] for source in sources if set(source) == {"configMap"}]
    namespace = [source["downwardAPI"] for source in sources if set(source) == {"downwardAPI"}]
    if len(token) != 1 or len(root_ca) != 1 or len(namespace) != 1:
        return False
    token_value = _mapping(token[0])
    if (
        set(token_value) - {"path", "expirationSeconds", "audience"}
        or token_value.get("path") != "token"
        or type(token_value.get("expirationSeconds")) is not int
        or not 600 <= token_value["expirationSeconds"] <= 86400
        or ("audience" in token_value and not isinstance(token_value["audience"], str))
    ):
        return False
    root_ca_value = _mapping(root_ca[0])
    if set(root_ca_value) != {"name", "items"} or root_ca_value.get("name") != "kube-root-ca.crt":
        return False
    items = [_mapping(item) for item in _list(root_ca_value.get("items"))]
    if len(items) != 1 or items[0] != {"key": "ca.crt", "path": "ca.crt"}:
        return False
    namespace_value = _mapping(namespace[0])
    if set(namespace_value) != {"items"}:
        return False
    namespace_items = [_mapping(item) for item in _list(namespace_value.get("items"))]
    expected_item = {"path": "namespace", "fieldRef": {"apiVersion": "v1", "fieldPath": "metadata.namespace"}}
    return namespace_items == [expected_item]


def _standard_service_account_mount(
    template: Mapping[str, Any], pod: Mapping[str, Any], container_name: str
) -> bool:
    template_spec = _mapping(template.get("spec"))
    pod_spec = _mapping(pod.get("spec"))
    template_containers = [_mapping(item) for item in _list(template_spec.get("containers"))]
    pod_containers = [_mapping(item) for item in _list(pod_spec.get("containers"))]
    left = next((item for item in template_containers if item.get("name") == container_name), None)
    right = next((item for item in pod_containers if item.get("name") == container_name), None)
    if left is None or right is None:
        return False

    template_mounts = [_mapping(item) for item in _list(left.get("volumeMounts"))]
    live_mounts = [_mapping(item) for item in _list(right.get("volumeMounts"))]
    unmatched = list(live_mounts)
    for expected in template_mounts:
        try:
            unmatched.remove(expected)
        except ValueError:
            return False
    if not unmatched:
        return True
    if len(unmatched) != 1:
        return False
    mount = unmatched[0]
    if (
        set(mount) - {"name", "mountPath", "readOnly", "mountPropagation"}
        or mount.get("mountPath") != "/var/run/secrets/kubernetes.io/serviceaccount"
        or mount.get("readOnly") is not True
        or mount.get("mountPropagation") not in (None, "None")
        or any(item.get("mountPath") == mount.get("mountPath") for item in template_mounts)
    ):
        return False

    name = str(mount.get("name", ""))
    if any(_mapping(item).get("name") == name for item in _list(template_spec.get("volumes"))):
        return False
    live_volume = next(
        (_mapping(item) for item in _list(pod_spec.get("volumes")) if _mapping(item).get("name") == name),
        None,
    )
    return live_volume is not None and _is_standard_service_account_projection(live_volume)


def _startup_mismatches(
    template: Mapping[str, Any],
    pod: Mapping[str, Any],
    container_name: str,
    *,
    allow_image_mismatch: bool = False,
) -> tuple[str, ...]:
    template_containers = [_mapping(item) for item in _list(_mapping(template.get("spec")).get("containers"))]
    pod_containers = [_mapping(item) for item in _list(_mapping(pod.get("spec")).get("containers"))]
    left = next((item for item in template_containers if item.get("name") == container_name), None)
    right = next((item for item in pod_containers if item.get("name") == container_name), None)
    if left is None or right is None:
        return ("container",)
    important = (
        "image",
        "command",
        "args",
        "workingDir",
        "ports",
        "volumeMounts",
        "env",
        "envFrom",
        "resources",
        "securityContext",
        "lifecycle",
        "startupProbe",
        "livenessProbe",
        "readinessProbe",
    )
    mismatches = [
        key for key in important
        if key != "volumeMounts"
        and not (allow_image_mismatch and key == "image")
        and left.get(key) != right.get(key)
    ]
    if allow_image_mismatch and left.get("image") != right.get("image"):
        mismatches.append("image")
    if not _standard_service_account_mount(template, pod, container_name):
        template_mounts = [_mapping(item) for item in _list(left.get("volumeMounts"))]
        live_mounts = [_mapping(item) for item in _list(right.get("volumeMounts"))]
        if template_mounts != live_mounts:
            mismatches.append("volumeMounts")
    return tuple(mismatches)


def _startup_equivalent(template: Mapping[str, Any], pod: Mapping[str, Any], container_name: str) -> bool:
    return not _startup_mismatches(template, pod, container_name)


@dataclass(frozen=True, slots=True)
class _StartupLayout:
    container_index: int
    container: Mapping[str, Any]
    container_name: str
    tokens: tuple[str, ...]
    env_references: tuple[EnvReference, ...]
    tls_mode: TLSMode
    certs_dir: str | None
    sql_port: int
    rpc_port: int
    http_port: int | None
    sql_bind_host: str | None
    rpc_bind_host: str | None
    http_bind_host: str | None
    sql_port_name: str | None
    rpc_port_name: str | None
    http_port_name: str | None
    mounts: tuple[MountObservation, ...]
    secrets: tuple[SecretFingerprint, ...]
    advertised_sql_host_template: str | None
    advertised_service: str | None
    cluster_domain: str | None
    literal_advertised_host: str | None
    advertised_rpc_host_template: str | None
    rpc_advertised_service: str | None
    rpc_cluster_domain: str | None
    literal_rpc_host: str | None
    rpc_advertise_port_matches_listener: bool
    http_transport: HTTPTransport


def _startup_layout(
    adapter: ClusterAdapter,
    ref: WorkloadRef,
    source: Mapping[str, Any],
    *,
    mode: str,
) -> _StartupLayout:
    """Parse startup fields for strict inspection or a selected SQL connection."""
    if mode not in {"full", "sql_connection"}:
        raise ValueError("unknown private startup inspection mode")
    inspect_http = mode == "full"
    inspect_secret_material = mode == "full"
    source_spec = _mapping(source.get("spec"))
    container_index, container = _selected_container(source, ref.container_name)
    container_name = str(container.get("name", ""))
    tokens = _shell_start_tokens(container)
    flags = _flags(tokens)
    validation_tokens = tokens
    if mode == "sql_connection":
        # HTTP-only listener flags do not affect the gateway SQL connection.
        # Exclude their values from this narrow observer's env-expansion gate.
        validation_tokens = []
        skip_flag_value = False
        for token in tokens:
            if skip_flag_value:
                skip_flag_value = False
                continue
            if token.startswith("--"):
                flag, separator, _value = token[2:].partition("=")
                if flag in {"http-addr", "http-host", "http-port"}:
                    skip_flag_value = not separator
                    continue
            validation_tokens.append(token)
    _validate_known_environment_expansion(validation_tokens, container)
    if inspect_http and "http-port" in flags:
        raise UnsupportedLayoutError(
            "Startup uses unsupported --http-port; HTTP listener port must be resolved from --http-addr"
        )
    unencrypted_localhost_http = (
        "unencrypted-localhost-http" in flags
        and flags.get("unencrypted-localhost-http") not in {"false", "0"}
    )
    if inspect_http and unencrypted_localhost_http:
        has_http_addr = "http-addr" in flags
        has_http_host_alias = "http-host" in flags
        if has_http_addr and has_http_host_alias:
            raise UnsupportedLayoutError(
                "Startup sets both --http-addr and its --http-host alias; the HTTP bind is ambiguous"
            )
        if has_http_addr or has_http_host_alias:
            if has_http_addr:
                http_addr = flags["http-addr"]
                if http_addr is None:
                    raise UnsupportedLayoutError("--http-addr has no value")
                http_host = _address_host(flags, "http-addr")
            else:
                http_host = flags["http-host"]
                if http_host is None:
                    raise UnsupportedLayoutError("--http-host has no value")

            if http_host not in {None, ""}:
                if http_host != "localhost":
                    raise UnsupportedLayoutError(
                        "--unencrypted-localhost-http conflicts with an explicit non-local HTTP bind host"
                    )
            else:
                # Cockroach fills an explicitly empty HTTP host from its RPC/listen
                # host before validating the localhost-only flag.
                has_listen_addr = "listen-addr" in flags
                has_host_alias = "host" in flags
                if has_listen_addr == has_host_alias:
                    raise UnsupportedLayoutError(
                        "An explicitly empty HTTP host has an ambiguous inherited listen address"
                    )
                inherited_host = (
                    _address_host(flags, "listen-addr")
                    if has_listen_addr
                    else flags["host"]
                )
                if inherited_host != "localhost":
                    raise UnsupportedLayoutError(
                        "An explicitly empty HTTP host inherits a non-local listen address"
                    )

    for flag_name, flag_value in flags.items():
        if not flag_value or "$" not in flag_value:
            continue
        if not inspect_http and flag_name in {"http-addr", "http-host", "http-port"}:
            continue
        substitutions = re.findall(r"\$\(([^)]+)\)", flag_value)
        remainder = re.sub(r"\$\((?:POD_NAME|POD_NAMESPACE)\)", "", flag_value)
        if (
            flag_name not in {"advertise-host", "advertise-addr", "advertise-sql-addr", "join"}
            or "$" in remainder
            or any(item not in {"POD_NAME", "POD_NAMESPACE"} for item in substitutions)
        ):
            raise UnsupportedLayoutError(f"Database flag --{flag_name} uses unsupported environment expansion")

    ports = _container_ports(container)
    if "rpc-addr" in flags:
        raise UnsupportedLayoutError("--rpc-addr is not a supported CockroachDB startup flag in this library")
    sql_addr_port = _flag_port(flags, "sql-addr")
    listen_port = _flag_port(flags, "listen-addr")
    flag_port = _flag_port(flags, "port")
    sql_port = (
        sql_addr_port
        if sql_addr_port is not None
        else listen_port
        if listen_port is not None
        else flag_port
        if flag_port is not None
        else 26257
    )
    rpc_port = listen_port if listen_port is not None else flag_port if flag_port is not None else 26257
    http_port = _flag_port(flags, "http-addr") if inspect_http else None
    if inspect_http and http_port is None:
        http_port = 8080
    sql_bind_host = _address_host(flags, "sql-addr")
    rpc_bind_host = _address_host(flags, "listen-addr")
    http_bind_host = _address_host(flags, "http-addr") if inspect_http else None
    sql_port_name = _port_name(ports, sql_port, ("sql",))
    rpc_port_name = _port_name(ports, rpc_port, ("rpc", "grpc"))
    http_port_name = _port_name(ports, http_port, ("http",)) if http_port is not None else None

    tls_flag = flags.get("insecure")
    configured_certs_dir = flags.get("certs-dir")
    if "certs-dir" in flags and configured_certs_dir is None:
        raise UnsupportedLayoutError("--certs-dir has no value")
    if configured_certs_dir is not None and ("$" in configured_certs_dir or "`" in configured_certs_dir):
        raise UnsupportedLayoutError("--certs-dir uses dynamic shell expansion")
    if tls_flag not in (None, "false", "0") and configured_certs_dir:
        raise UnsupportedLayoutError("Startup specifies both --insecure and --certs-dir")

    certs_dir = None
    if tls_flag not in (None, "false", "0"):
        tls_mode = TLSMode.INSECURE
    else:
        certs_dir = _resolve_certificate_directory(
            container,
            configured_certs_dir,
            pod_security_context=lambda: _mapping(source_spec.get("securityContext")),
            error_type=UnsupportedLayoutError,
        )
        tls_mode = TLSMode.TLS

    volumes = [_mapping(item) for item in _list(source_spec.get("volumes"))]
    volume_by_name = {str(item.get("name")): item for item in volumes if item.get("name")}
    mounts = []
    if inspect_secret_material:
        for mount_value in _list(container.get("volumeMounts")):
            mount = _mapping(mount_value)
            mount_name = str(mount.get("name", ""))
            volume = volume_by_name.get(mount_name, {})
            secret_name, source_kind, file_map = _secret_volume(volume)
            mounts.append(
                MountObservation(
                    name=mount_name,
                    path=str(mount.get("mountPath", "")),
                    read_only=bool(mount.get("readOnly", False)),
                    source_kind=source_kind,
                    source_name=secret_name,
                    sub_path=str(mount.get("subPath") or mount.get("subPathExpr") or "") or None,
                    mounted_files=tuple(sorted(file_map.items())),
                )
            )
    env_refs = _env_references(container)
    secrets: tuple[SecretFingerprint, ...] = ()
    if tls_mode is TLSMode.TLS:
        if inspect_secret_material:
            cert_mounts = [mount for mount in mounts if mount.path == certs_dir]
            if len(cert_mounts) != 1:
                raise UnsupportedLayoutError("Configured --certs-dir is not backed by exactly one mounted Secret")
            cert_mount = cert_mounts[0]
            if cert_mount.sub_path or cert_mount.source_kind not in {"secret", "projected-secret"}:
                raise UnsupportedLayoutError("Certificate mount layout is unsupported")
            if not cert_mount.read_only:
                raise UnsupportedLayoutError("Certificate Secret mount must be read-only")
            if not cert_mount.source_name:
                raise UnsupportedLayoutError("Certificate Secret identity is unavailable")
            fingerprint = adapter.secret_fingerprint(ref.namespace, cert_mount.source_name)
            secrets = (fingerprint,)
            mounted = dict(cert_mount.mounted_files) if cert_mount.mounted_files else {
                key: key for key in fingerprint.keys
            }
            mounted_names = set(mounted.values())
            if not _CERT_FILES.issubset(mounted_names):
                raise UnsupportedLayoutError("Certificate Secret does not mount the required node certificates")
            if not _ROOT_CLIENT_FILES.issubset(mounted_names):
                raise UnsupportedLayoutError("Secure SQL inspection requires mounted client.root.crt and client.root.key")
            for required in _ROOT_CLIENT_FILES | {"ca.crt"}:
                key = next((source for source, filename in mounted.items() if filename == required), None)
                if key is None or key not in dict(fingerprint.sha256_by_key):
                    raise UnsupportedLayoutError("Root SQL credential files are not present in the mounted Secret")

    advertised_host_template, advertised_service, cluster_domain, literal_advertised_host = (
        _advertised_sql_host_template(flags)
    )
    advertised_rpc_host_template, rpc_advertised_service, rpc_cluster_domain, literal_rpc_host = (
        _advertised_rpc_host_template(flags)
    )
    rpc_advertise_port_matches_listener = _rpc_advertise_port_matches_listener(flags, rpc_port)
    if inspect_http and unencrypted_localhost_http:
        http_bind_host = "localhost"
    http_transport = (
        HTTPTransport.HTTP
        if unencrypted_localhost_http or tls_mode is TLSMode.INSECURE
        else HTTPTransport.HTTPS
        if tls_mode is TLSMode.TLS
        else HTTPTransport.UNKNOWN
    ) if inspect_http else HTTPTransport.UNKNOWN

    return _StartupLayout(
        container_index=container_index,
        container=container,
        container_name=container_name,
        tokens=tuple(tokens),
        env_references=env_refs,
        tls_mode=tls_mode,
        certs_dir=certs_dir,
        sql_port=sql_port,
        rpc_port=rpc_port,
        http_port=http_port,
        sql_bind_host=sql_bind_host,
        rpc_bind_host=rpc_bind_host,
        http_bind_host=http_bind_host,
        sql_port_name=sql_port_name,
        rpc_port_name=rpc_port_name,
        http_port_name=http_port_name,
        mounts=tuple(mounts),
        secrets=secrets,
        advertised_sql_host_template=advertised_host_template,
        advertised_service=advertised_service,
        cluster_domain=cluster_domain,
        literal_advertised_host=literal_advertised_host,
        advertised_rpc_host_template=advertised_rpc_host_template,
        rpc_advertised_service=rpc_advertised_service,
        rpc_cluster_domain=rpc_cluster_domain,
        literal_rpc_host=literal_rpc_host,
        rpc_advertise_port_matches_listener=rpc_advertise_port_matches_listener,
        http_transport=http_transport,
    )


class WorkloadInspector:
    def __init__(self, adapter: ClusterAdapter):
        self.adapter = adapter

    def inspect(self, ref: WorkloadRef) -> Observation:
        return self._inspect(ref, allow_image_rollout=False)

    def inspect_for_health(self, ref: WorkloadRef) -> Observation:
        """Observe health during an image-only StatefulSet rollout.

        Every selected Pod is still checked against the desired template for
        all startup fields except the container image. Probe preparation and
        public inspection use the strict path above.
        """
        return self._inspect(ref, allow_image_rollout=True)

    def inspect_sql_connection(
        self,
        ref: WorkloadRef,
        ordinal: int = 0,
    ) -> SQLConnectionObservation:
        """Observe the SQL connection from one live Pod without requiring its peers.

        This deliberately ignores the desired template, revision convergence,
        Services, PVCs, Secret contents, certificate fingerprints, and other
        ordinals. The selected Pod's own SQL startup flags define the connection;
        the caller's SQL query validates that mounted client credentials work.
        """
        if type(ordinal) is not int or ordinal < 0:
            raise InvalidRequirementError("Selected Pod ordinal must be a non-negative integer")
        statefulset = self.adapter.get_resource("statefulset", ref.namespace, ref.name)
        if statefulset is None:
            raise MissingResourceError(f"StatefulSet {ref.namespace}/{ref.name} is missing")
        sts_meta = _metadata(statefulset)
        uid = sts_meta.get("uid")
        if (
            sts_meta.get("name") != ref.name
            or sts_meta.get("namespace") != ref.namespace
            or not isinstance(uid, str)
            or not uid
        ):
            raise UnsupportedLayoutError("Selected StatefulSet lacks the requested Kubernetes identity")
        if sts_meta.get("deletionTimestamp"):
            raise RolloutInProgressError("Selected StatefulSet is terminating")
        spec = _mapping(statefulset.get("spec"))
        replicas = spec.get("replicas", 1)
        if type(replicas) is not int or replicas < 1 or ordinal >= replicas:
            raise RolloutInProgressError("Selected database Pod ordinal is outside the desired StatefulSet size")
        selector = _mapping(_mapping(spec.get("selector")).get("matchLabels"))
        if not selector:
            raise UnsupportedLayoutError("StatefulSet has no selector for its selected Pod")

        pod_name = f"{ref.name}-{ordinal}"
        pod = self.adapter.get_resource("pod", ref.namespace, pod_name)
        if pod is None:
            raise RolloutInProgressError(f"Selected database Pod {pod_name} is not present")
        pod_meta = _metadata(pod)
        pod_uid = pod_meta.get("uid")
        if pod_meta.get("name") != pod_name or pod_meta.get("namespace") != ref.namespace:
            raise UnsupportedLayoutError("Kubernetes returned a different selected Pod identity than requested")
        if not isinstance(pod_uid, str) or not pod_uid:
            raise UnsupportedLayoutError("Selected database Pod lacks Kubernetes identity metadata")
        if pod_meta.get("deletionTimestamp"):
            raise RolloutInProgressError("Selected database Pod is terminating")
        labels = _mapping(pod_meta.get("labels"))
        if any(labels.get(key) != value for key, value in selector.items()):
            raise UnsupportedLayoutError("Selected database Pod does not match its StatefulSet selector")
        owner = next(
            (
                _mapping(value)
                for value in _list(pod_meta.get("ownerReferences"))
                if _mapping(value).get("uid") == uid and _mapping(value).get("controller") is True
            ),
            None,
        )
        if owner is None or owner.get("kind") not in (None, "StatefulSet") or owner.get("name") not in (None, ref.name):
            raise UnsupportedLayoutError("Selected database Pod is not owned by the selected StatefulSet")

        layout = _startup_layout(self.adapter, ref, pod, mode="sql_connection")
        host = _pod_sql_host(
            pod_name,
            ref.namespace,
            layout.advertised_service,
            layout.cluster_domain,
            layout.literal_advertised_host,
            replicas,
        )
        if host is None:
            raise UnsupportedLayoutError("Selected Pod has no resolvable advertised SQL host")
        rpc_host = _pod_sql_host(
            pod_name,
            ref.namespace,
            layout.rpc_advertised_service,
            layout.rpc_cluster_domain,
            layout.literal_rpc_host,
            replicas,
        )
        if not layout.rpc_advertise_port_matches_listener:
            rpc_host = None

        current_sts = self.adapter.get_resource("statefulset", ref.namespace, ref.name)
        current_pod = self.adapter.get_resource("pod", ref.namespace, pod_name)
        if current_sts is None or _metadata(current_sts).get("uid") != uid:
            raise RolloutInProgressError("Selected StatefulSet identity changed during SQL connection inspection")
        if current_pod is None or _metadata(current_pod).get("uid") != pod_uid:
            raise RolloutInProgressError("Selected Pod identity changed during SQL connection inspection")
        return SQLConnectionObservation(
            namespace=ref.namespace,
            workload_name=ref.name,
            workload_uid=uid,
            pod_name=pod_name,
            pod_uid=pod_uid,
            container_name=layout.container_name,
            image=str(layout.container.get("image", "")),
            sql_binary=layout.tokens[0],
            sql_host=host,
            sql_port=layout.sql_port,
            rpc_port=layout.rpc_port,
            tls_mode=layout.tls_mode,
            certs_dir=layout.certs_dir,
            rpc_host=rpc_host,
        )

    def _inspect(self, ref: WorkloadRef, *, allow_image_rollout: bool) -> Observation:
        statefulset = self.adapter.get_resource("statefulset", ref.namespace, ref.name)
        if statefulset is None:
            raise MissingResourceError(f"StatefulSet {ref.namespace}/{ref.name} is missing")
        metadata = _metadata(statefulset)
        spec = _mapping(statefulset.get("spec"))
        status = _mapping(statefulset.get("status"))
        uid = str(metadata.get("uid", ""))
        resource_version = str(metadata.get("resourceVersion", ""))
        if not uid or not resource_version:
            raise UnsupportedLayoutError("Selected StatefulSet lacks Kubernetes identity metadata")
        if metadata.get("name") != ref.name or metadata.get("namespace") != ref.namespace:
            raise UnsupportedLayoutError("Kubernetes returned a different StatefulSet identity than requested")
        if metadata.get("deletionTimestamp"):
            raise RolloutInProgressError("Selected StatefulSet is terminating")
        controller_owned = any(
            _mapping(owner).get("controller") is True
            for owner in _list(metadata.get("ownerReferences"))
        )
        generation = int(metadata.get("generation", 0))
        observed_generation = int(status.get("observedGeneration", 0))
        if observed_generation < generation:
            raise RolloutInProgressError("StatefulSet controller has not observed the current template")

        template = _mapping(spec.get("template"))
        pod_template_metadata = _metadata(template)
        pod_template_spec = _mapping(template.get("spec"))
        desired_replicas = int(spec.get("replicas", 1))
        if desired_replicas < 1:
            raise UnsupportedLayoutError("Selected StatefulSet has zero database replicas")
        layout = _startup_layout(self.adapter, ref, template, mode="full")
        container_index = layout.container_index
        container = layout.container
        container_name = layout.container_name
        tokens = layout.tokens
        env_refs = layout.env_references
        observed_tls = layout.tls_mode
        certs_dir = layout.certs_dir
        sql_port = layout.sql_port
        rpc_port = layout.rpc_port
        http_port = layout.http_port
        sql_bind_host = layout.sql_bind_host
        rpc_bind_host = layout.rpc_bind_host
        http_bind_host = layout.http_bind_host
        sql_port_name = layout.sql_port_name
        rpc_port_name = layout.rpc_port_name
        http_port_name = layout.http_port_name
        mounts = layout.mounts
        secret_fingerprints = layout.secrets
        advertised_sql_host_template = layout.advertised_sql_host_template
        advertised_service = layout.advertised_service
        cluster_domain = layout.cluster_domain
        literal_advertised_host = layout.literal_advertised_host
        http_transport = layout.http_transport

        service_name = str(spec.get("serviceName", ""))
        if not service_name:
            raise UnsupportedLayoutError("StatefulSet does not declare its governing Service")
        selector = _mapping(_mapping(spec.get("selector")).get("matchLabels"))
        template_labels = _mapping(pod_template_metadata.get("labels"))
        if not selector or any(template_labels.get(key) != value for key, value in selector.items()):
            raise UnsupportedLayoutError("StatefulSet selector does not match its pod template")

        all_pods = tuple(self.adapter.list_resources("pod", ref.namespace))
        selected_pods = []
        for pod in all_pods:
            pod_metadata = _metadata(pod)
            labels = _mapping(pod_metadata.get("labels"))
            if not all(labels.get(key) == value for key, value in selector.items()):
                continue
            owner_refs = [_mapping(item) for item in _list(pod_metadata.get("ownerReferences"))]
            selected_owner = next((item for item in owner_refs if item.get("uid") == uid and item.get("controller") is True), None)
            if selected_owner is None:
                raise UnsupportedLayoutError("StatefulSet selector also matches a pod owned by another resource")
            selected_pods.append(pod)
        pod_by_ordinal = {}
        for pod in selected_pods:
            pod_name = str(_metadata(pod).get("name", ""))
            prefix = f"{ref.name}-"
            if not pod_name.startswith(prefix) or not pod_name[len(prefix):].isdigit():
                raise UnsupportedLayoutError("Selected pod name does not follow the StatefulSet ordinal layout")
            ordinal = int(pod_name[len(prefix):])
            if ordinal in pod_by_ordinal:
                raise UnsupportedLayoutError("StatefulSet has duplicate pod ordinals")
            pod_by_ordinal[ordinal] = pod
        if set(pod_by_ordinal) != set(range(desired_replicas)):
            raise RolloutInProgressError("StatefulSet pod set does not match its desired replicas")

        pod_observations = []
        pvc_names: set[str] = set()
        template_volumes = {
            str(_mapping(item).get("name")): _mapping(item)
            for item in _list(pod_template_spec.get("volumes"))
        }
        template_claim_names = {
            str(_metadata(_mapping(item)).get("name", ""))
            for item in _list(spec.get("volumeClaimTemplates"))
            if _metadata(_mapping(item)).get("name")
        }
        expected_revision = status.get("updateRevision") or status.get("currentRevision")
        current_revision = status.get("currentRevision")
        update_revision = status.get("updateRevision")
        revisions_diverged = bool(current_revision and update_revision and current_revision != update_revision)
        if revisions_diverged and not allow_image_rollout:
            raise RolloutInProgressError("StatefulSet is rolling between controller revisions")
        image_rollout_observed = False
        all_pods_on_update_revision = bool(update_revision)
        all_pods_match_template = True
        for ordinal in range(desired_replicas):
            pod = pod_by_ordinal[ordinal]
            pod_meta = _metadata(pod)
            if pod_meta.get("namespace") != ref.namespace:
                raise UnsupportedLayoutError("Selected pod is reported in a different namespace")
            if not pod_meta.get("uid"):
                raise UnsupportedLayoutError("Selected pod lacks Kubernetes identity metadata")
            pod_spec = _mapping(pod.get("spec"))
            pod_status = _mapping(pod.get("status"))
            if pod_meta.get("deletionTimestamp"):
                raise RolloutInProgressError("A selected database pod is terminating")
            revision = _mapping(pod_meta.get("labels")).get("controller-revision-hash")
            known_revisions = {value for value in (current_revision, update_revision) if value}
            startup_mismatches = _startup_mismatches(
                template,
                pod,
                container_name,
                allow_image_mismatch=allow_image_rollout,
            )
            if revision != update_revision:
                all_pods_on_update_revision = False
            if startup_mismatches:
                all_pods_match_template = False
            image_only_mismatch = (
                allow_image_rollout
                and startup_mismatches == ("image",)
                and bool(revision)
                and revision in known_revisions
            )
            if image_only_mismatch:
                image_rollout_observed = True
            if startup_mismatches and not image_only_mismatch:
                fields = ", ".join(startup_mismatches)
                raise RolloutInProgressError(
                    f"A live pod differs from its selected StatefulSet startup fields: {fields}"
                )
            if pod_spec.get("securityContext") != pod_template_spec.get("securityContext"):
                raise RolloutInProgressError("A live pod has a different pod security context than its template")
            live_volumes = {
                str(_mapping(item).get("name")): _mapping(item)
                for item in _list(pod_spec.get("volumes"))
            }
            for mount_value in _list(container.get("volumeMounts")):
                mount_name = str(_mapping(mount_value).get("name", ""))
                expected_volume = template_volumes.get(mount_name)
                actual_volume = live_volumes.get(mount_name)
                if expected_volume is not None:
                    matches = expected_volume == actual_volume
                elif mount_name in template_claim_names:
                    claim = _mapping(_mapping(actual_volume).get("persistentVolumeClaim"))
                    matches = claim.get("claimName") == f"{mount_name}-{ref.name}-{ordinal}"
                else:
                    matches = False
                if not matches:
                    raise RolloutInProgressError("A live pod volume source differs from the inspected template")
            if allow_image_rollout and revisions_diverged:
                if not revision or revision not in {current_revision, update_revision}:
                    raise RolloutInProgressError("A live pod is outside the selected image rollout revisions")
            elif expected_revision and (not revision or revision != expected_revision):
                raise RolloutInProgressError("A live pod is on a different controller revision")
            container_status = next(
                (
                    _mapping(item)
                    for item in _list(pod_status.get("containerStatuses"))
                    if _mapping(item).get("name") == container_name
                ),
                {},
            )
            state = _mapping(container_status.get("state"))
            state_name = next(iter(state), "unknown")
            owner_uid = next(
                (
                    str(_mapping(item).get("uid"))
                    for item in _list(pod_meta.get("ownerReferences"))
                    if _mapping(item).get("uid") == uid
                ),
                None,
            )
            conditions = [_mapping(item) for item in _list(pod_status.get("conditions"))]
            pod_ready = any(item.get("type") == "Ready" and item.get("status") == "True" for item in conditions)
            pod_observations.append(
                PodObservation(
                    name=str(pod_meta.get("name", "")),
                    sql_host=_pod_sql_host(
                        str(pod_meta.get("name", "")),
                        ref.namespace,
                        advertised_service,
                        cluster_domain,
                        literal_advertised_host,
                        desired_replicas,
                    ),
                    uid=str(pod_meta.get("uid", "")),
                    owner_uid=owner_uid,
                    phase=str(pod_status.get("phase", "Unknown")),
                    container_state=str(state_name),
                    container_ready=bool(container_status.get("ready", False)),
                    pod_ready=pod_ready,
                    revision=str(revision) if revision else None,
                    image=str(
                        next(
                            (
                                _mapping(item).get("image", "")
                                for item in _list(pod_spec.get("containers"))
                                if _mapping(item).get("name") == container_name
                            ),
                            "",
                        )
                    ),
                    startup_matches_template=not image_only_mismatch,
                )
            )
            for volume in _list(pod_spec.get("volumes")):
                pvc = _mapping(_mapping(volume).get("persistentVolumeClaim"))
                if pvc.get("claimName"):
                    pvc_names.add(str(pvc["claimName"]))

        completed_revision_rollout = (
            allow_image_rollout
            and revisions_diverged
            and int(status.get("updatedReplicas", 0)) == desired_replicas
            and all_pods_on_update_revision
            and all_pods_match_template
        )
        if revisions_diverged and not image_rollout_observed and not completed_revision_rollout:
            raise RolloutInProgressError(
                "StatefulSet revision rollout is not explained by a selected container image change"
            )

        service_resources = tuple(self.adapter.list_resources("service", ref.namespace))
        governing = next(
            (
                resource
                for resource in service_resources
                if _metadata(resource).get("name") == service_name
            ),
            None,
        )
        if governing is None:
            raise MissingResourceError(f"Governing Service {ref.namespace}/{service_name} is missing")
        service_observations = []
        selected_labels = _mapping(pod_template_metadata.get("labels"))
        for service in service_resources:
            service_meta = _metadata(service)
            if service_meta.get("namespace") != ref.namespace:
                raise UnsupportedLayoutError("Selected Service is reported in a different namespace")
            if not service_meta.get("uid") or not service_meta.get("resourceVersion"):
                raise UnsupportedLayoutError("Selected Service lacks Kubernetes identity metadata")
            service_spec = _mapping(service.get("spec"))
            service_selector = _mapping(service_spec.get("selector"))
            is_governing = service_meta.get("name") == service_name
            matches_template = bool(service_selector) and all(
                selected_labels.get(key) == value for key, value in service_selector.items()
            )
            if not is_governing and not matches_template:
                continue
            if not service_selector or not matches_template:
                raise UnsupportedLayoutError("A selected CockroachDB Service has an empty or mismatched selector")
            for other_pod in all_pods:
                other_labels = _mapping(_metadata(other_pod).get("labels"))
                if all(other_labels.get(key) == value for key, value in service_selector.items()):
                    other_owner_uids = {
                        _mapping(owner).get("uid") for owner in _list(_metadata(other_pod).get("ownerReferences"))
                    }
                    if uid not in other_owner_uids:
                        raise UnsupportedLayoutError("CockroachDB Service selects a pod outside the selected StatefulSet")
            service_ports = []
            for port_value in _list(service_spec.get("ports")):
                port = _mapping(port_value)
                if isinstance(port.get("port"), int):
                    target = port.get("targetPort", port.get("port"))
                    service_ports.append(
                        ServicePortObservation(
                            name=port.get("name") if isinstance(port.get("name"), str) else None,
                            port=int(port["port"]),
                            target_port=target if isinstance(target, (str, int)) else None,
                            protocol=str(port.get("protocol", "TCP")),
                        )
                    )
            service_observations.append(
                ServiceObservation(
                    name=str(service_meta.get("name", "")),
                    uid=str(service_meta.get("uid", "")),
                    resource_version=str(service_meta.get("resourceVersion", "")),
                    cluster_ip=service_spec.get("clusterIP") if isinstance(service_spec.get("clusterIP"), str) else None,
                    selector=tuple(sorted((str(key), str(value)) for key, value in service_selector.items())),
                    ports=tuple(service_ports),
                    routing_hash=_hash_json(service_spec),
                )
            )
        governing_observation = next(item for item in service_observations if item.name == service_name)
        if governing_observation.cluster_ip != "None":
            raise UnsupportedLayoutError("StatefulSet governing Service must be headless")
        if advertised_service is not None:
            advertised_observation = next(
                (item for item in service_observations if item.name == advertised_service),
                None,
            )
            if advertised_observation is None or advertised_observation.cluster_ip != "None":
                raise UnsupportedLayoutError(
                    "Per-pod CockroachDB advertised host requires an observed headless Service selecting this workload"
                )

        all_pvcs = tuple(self.adapter.list_resources("pvc", ref.namespace))
        pvc_map = {_metadata(item).get("name"): item for item in all_pvcs}
        pvc_observations = []
        for pvc_name in sorted(pvc_names):
            pvc = pvc_map.get(pvc_name)
            if pvc is None:
                raise MissingResourceError(f"Pod volume claim {pvc_name!r} is missing")
            pvc_meta = _metadata(pvc)
            if pvc_meta.get("namespace") != ref.namespace:
                raise UnsupportedLayoutError("Selected PVC is reported in a different namespace")
            if not pvc_meta.get("uid") or not pvc_meta.get("resourceVersion"):
                raise UnsupportedLayoutError("Selected PVC lacks Kubernetes identity metadata")
            pvc_spec = _mapping(pvc.get("spec"))
            pvc_status = _mapping(pvc.get("status"))
            pvc_observations.append(
                PvcObservation(
                    name=str(pvc_meta.get("name", "")),
                    uid=str(pvc_meta.get("uid", "")),
                    resource_version=str(pvc_meta.get("resourceVersion", "")),
                    volume_name=str(pvc_spec.get("volumeName")) if pvc_spec.get("volumeName") else None,
                    phase=str(pvc_status.get("phase")) if pvc_status.get("phase") else None,
                    spec_hash=_hash_json(pvc_spec),
                )
            )

        claims = tuple(
            str(_metadata(_mapping(item)).get("name", ""))
            for item in _list(spec.get("volumeClaimTemplates"))
        )
        return Observation(
            namespace=ref.namespace,
            name=ref.name,
            workload_uid=uid,
            controller_owned=controller_owned,
            resource_version=resource_version,
            generation=generation,
            observed_generation=observed_generation,
            desired_replicas=desired_replicas,
            ready_replicas=int(status.get("readyReplicas", 0)),
            updated_replicas=int(status.get("updatedReplicas", 0)),
            service_name=service_name,
            advertised_sql_host_template=advertised_sql_host_template,
            container_name=container_name,
            container_index=container_index,
            image=str(container.get("image", "")),
            sql_binary=tokens[0],
            workload_spec_hash=_hash_json(spec),
            probe_preservation_hash=_probe_preservation_hash(spec, container_index),
            env_references=env_refs,
            tls_mode=observed_tls,
            http_transport=http_transport,
            certs_dir=certs_dir,
            sql_port=sql_port,
            rpc_port=rpc_port,
            http_port=http_port,
            sql_bind_host=sql_bind_host,
            rpc_bind_host=rpc_bind_host,
            http_bind_host=http_bind_host,
            sql_port_name=sql_port_name,
            rpc_port_name=rpc_port_name,
            http_port_name=http_port_name,
            mounts=tuple(mounts),
            secrets=secret_fingerprints,
            liveness_probe=_parse_probe(container.get("livenessProbe")),
            readiness_probe=_parse_probe(container.get("readinessProbe")),
            pods=tuple(pod_observations),
            services=tuple(sorted(service_observations, key=lambda item: item.name)),
            pvcs=tuple(pvc_observations),
            volume_claim_templates=claims,
            controller_revision=str(status.get("currentRevision")) if status.get("currentRevision") else None,
            update_revision=str(status.get("updateRevision")) if status.get("updateRevision") else None,
        )

"""Read-only inspection and conservative layout parsing."""

from __future__ import annotations

import copy
import hashlib
import json
import re
import shlex
from collections.abc import Mapping, Sequence
from typing import Any

from .adapter import ClusterAdapter
from .types import (
    EnvReference,
    MissingResourceError,
    MountObservation,
    Observation,
    PodObservation,
    PortObservation,
    ProbeObservation,
    PvcObservation,
    RolloutInProgressError,
    SecretFingerprint,
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
        raise UnsupportedLayoutError("Database container has no explicit startup command")
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


def _advertised_sql_host_template(
    flags: Mapping[str, str | None],
) -> tuple[str | None, str | None, str | None, str | None]:
    """Resolve explicit advertised SQL or per-node address forms without DNS guesses."""
    # The SQL-specific address is authoritative when present; otherwise honor
    # Cockroach's node advertise address and then its compatible host flag.
    value = None
    flag_name = None
    for candidate in ("advertise-sql-addr", "advertise-addr", "advertise-host"):
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


def _startup_mismatches(template: Mapping[str, Any], pod: Mapping[str, Any], container_name: str) -> tuple[str, ...]:
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
        "securityContext",
        "livenessProbe",
        "readinessProbe",
    )
    mismatches = [
        key for key in important
        if key != "volumeMounts" and left.get(key) != right.get(key)
    ]
    if not _standard_service_account_mount(template, pod, container_name):
        template_mounts = [_mapping(item) for item in _list(left.get("volumeMounts"))]
        live_mounts = [_mapping(item) for item in _list(right.get("volumeMounts"))]
        if template_mounts != live_mounts:
            mismatches.append("volumeMounts")
    return tuple(mismatches)


def _startup_equivalent(template: Mapping[str, Any], pod: Mapping[str, Any], container_name: str) -> bool:
    return not _startup_mismatches(template, pod, container_name)


class WorkloadInspector:
    def __init__(self, adapter: ClusterAdapter):
        self.adapter = adapter

    def inspect(self, ref: WorkloadRef) -> Observation:
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
        container_index, container = _selected_container(template, ref.container_name)
        container_name = str(container.get("name", ""))
        tokens = _shell_start_tokens(container)
        _validate_known_environment_expansion(tokens, container)
        flags = _flags(tokens)
        for flag_name, flag_value in flags.items():
            if not flag_value or "$" not in flag_value:
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
        if sql_addr_port is not None:
            sql_port = sql_addr_port
        elif flag_port is not None:
            sql_port = flag_port
        else:
            sql_port = 26257
        if listen_port is not None:
            rpc_port = listen_port
        elif flag_port is not None:
            rpc_port = flag_port
        else:
            rpc_port = 26257
        http_port = _flag_port(flags, "http-addr")
        if http_port is None:
            http_port = 8080
        sql_bind_host = _address_host(flags, "sql-addr")
        rpc_bind_host = _address_host(flags, "listen-addr")
        http_bind_host = _address_host(flags, "http-addr")
        http_port_name = _port_name(ports, http_port, ("http",))
        sql_port_name = _port_name(ports, sql_port, ("sql",))
        rpc_port_name = _port_name(ports, rpc_port, ("rpc", "grpc"))

        tls_flag = flags.get("insecure")
        certs_dir = flags.get("certs-dir")
        if certs_dir is not None and ("$" in certs_dir or "`" in certs_dir):
            raise UnsupportedLayoutError("--certs-dir uses dynamic shell expansion")
        if tls_flag not in (None, "false", "0") and certs_dir:
            raise UnsupportedLayoutError("Startup specifies both --insecure and --certs-dir")

        volumes = [_mapping(item) for item in _list(pod_template_spec.get("volumes"))]
        volume_by_name = {str(item.get("name")): item for item in volumes if item.get("name")}
        mounts = []
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
        secret_fingerprints: tuple[SecretFingerprint, ...] = ()
        observed_tls = TLSMode.UNKNOWN
        if tls_flag not in (None, "false", "0"):
            observed_tls = TLSMode.INSECURE
        elif certs_dir is not None:
            if not certs_dir.startswith("/"):
                raise UnsupportedLayoutError("--certs-dir must be an absolute path")
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
            fingerprint = self.adapter.secret_fingerprint(ref.namespace, cert_mount.source_name)
            secret_fingerprints = (fingerprint,)
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
            observed_tls = TLSMode.TLS

        service_name = str(spec.get("serviceName", ""))
        if not service_name:
            raise UnsupportedLayoutError("StatefulSet does not declare its governing Service")
        advertised_sql_host_template, advertised_service, cluster_domain, literal_advertised_host = (
            _advertised_sql_host_template(flags)
        )
        desired_replicas = int(spec.get("replicas", 1))
        if desired_replicas < 1:
            raise UnsupportedLayoutError("Selected StatefulSet has zero database replicas")
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
        if current_revision and status.get("updateRevision") and current_revision != status.get("updateRevision"):
            raise RolloutInProgressError("StatefulSet is rolling between controller revisions")
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
            startup_mismatches = _startup_mismatches(template, pod, container_name)
            if startup_mismatches:
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
            revision = _mapping(pod_meta.get("labels")).get("controller-revision-hash")
            if expected_revision and (not revision or revision != expected_revision):
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
                    startup_matches_template=True,
                )
            )
            for volume in _list(pod_spec.get("volumes")):
                pvc = _mapping(_mapping(volume).get("persistentVolumeClaim"))
                if pvc.get("claimName"):
                    pvc_names.add(str(pvc["claimName"]))

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

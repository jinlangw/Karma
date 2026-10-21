#!/usr/bin/env python3
"""Apply the certificate-rotation TLS template to an existing target safely."""

from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
import re
import sys
from collections.abc import Mapping, Sequence
from typing import Any
from string import Template

import yaml

from karma.crdb import KubectlAdapter, secure_template
from karma.crdb.security import _parse_startup
from karma.crdb.startup import database_container
from karma.crdb.types import CrdbError, StaleIdentityError, UnsupportedLayoutError


_REQUIRED_SERVICE_PORTS = {26257: "sql", 8080: "http"}


def build_plan(
    statefulset: Mapping[str, Any],
    *,
    secret_name: str,
    cert_dir: str,
    case_replicas: int,
) -> dict[str, Any]:
    metadata = statefulset.get("metadata", {})
    spec = statefulset.get("spec")
    uid = metadata.get("uid") if isinstance(metadata, Mapping) else None
    if not isinstance(uid, str) or not uid or not isinstance(spec, Mapping):
        raise UnsupportedLayoutError("Selected StatefulSet has incomplete identity or spec")
    # Kubernetes defaults an omitted StatefulSet replica count to one.
    replicas = spec.get("replicas", 1)
    if type(replicas) is not int or replicas < 0:
        raise UnsupportedLayoutError("Selected StatefulSet has an unsupported replica count")
    if type(case_replicas) is not int or case_replicas < 1:
        raise UnsupportedLayoutError("Certificate-rotation replica count is invalid")
    template = spec.get("template")
    if not isinstance(template, Mapping):
        raise UnsupportedLayoutError("Selected StatefulSet has no supported Pod template")
    transformed = secure_template(
        dict(template), secret_name=secret_name, cert_dir=cert_dir
    )
    service_requirements = _service_requirements(transformed)
    return {
        "uid": uid,
        "original_spec": copy.deepcopy(dict(spec)),
        "original_replicas": replicas,
        # The case has always restored its declared three-node target after an
        # empty deployment; preserve nonzero inherited topology otherwise.
        "target_replicas": replicas if replicas > 0 else case_replicas,
        "secure_template": transformed,
        "service_requirements": service_requirements,
    }


def _listener_port(container: Mapping[str, Any], flags: Sequence[str], default: int) -> int:
    _, parsed_tokens, _ = _parse_startup(dict(container), UnsupportedLayoutError)
    tokens = list(parsed_tokens)
    for flag in flags:
        values: list[str | None] = []
        index = 0
        while index < len(tokens):
            token = tokens[index]
            if token == flag:
                if index + 1 < len(tokens) and not tokens[index + 1].startswith("--"):
                    values.append(tokens[index + 1])
                    index += 1
                else:
                    values.append(None)
            elif token.startswith(flag + "="):
                values.append(token.split("=", 1)[1])
            index += 1
        if not values:
            continue
        if len(values) != 1 or not isinstance(values[0], str) or not values[0]:
            raise UnsupportedLayoutError("CockroachDB listener address is ambiguous")
        value = values[0]
        match = re.fullmatch(r"(?:(?:\[[^\]]+\]|[^:]*):)?([0-9]+)", value)
        if not match:
            raise UnsupportedLayoutError("CockroachDB listener address has an unsupported port")
        port = int(match.group(1))
        if not 1 <= port <= 65535:
            raise UnsupportedLayoutError("CockroachDB listener address has an invalid port")
        return port
    return default


def _service_requirements(template: Mapping[str, Any]) -> dict[str, Any]:
    container = database_container(template, error_type=UnsupportedLayoutError)
    sql_port = _listener_port(container, ("--sql-addr", "--listen-addr", "--port"), 26257)
    http_port = _listener_port(container, ("--http-addr",), 8080)
    metadata = template.get("metadata", {})
    labels = metadata.get("labels", {}) if isinstance(metadata, Mapping) else {}
    if not isinstance(labels, Mapping):
        labels = {}
    return {
        "template_labels": {str(key): str(value) for key, value in labels.items()},
        "container_ports": copy.deepcopy(container.get("ports", [])),
        "sql_port": sql_port,
        "http_port": http_port,
    }


def _service_target_port(service_port: Mapping[str, Any], container_ports: Sequence[Any]) -> int | None:
    service_number = service_port.get("port")
    target = service_port.get("targetPort", service_number)
    if type(target) is int:
        return target
    if not isinstance(target, str) or not target:
        return None
    matches = [
        item for item in container_ports
        if isinstance(item, Mapping) and item.get("name") == target
    ]
    if len(matches) != 1:
        return None
    candidate = matches[0].get("containerPort")
    protocol = matches[0].get("protocol", "TCP")
    if type(candidate) is not int or protocol != "TCP":
        return None
    return candidate


def _service_is_valid(
    adapter: KubectlAdapter,
    namespace: str,
    statefulset_name: str,
    service_name: str,
    service: Mapping[str, Any],
    plan: Mapping[str, Any],
) -> bool:
    requirements = plan.get("service_requirements")
    if not isinstance(requirements, Mapping):
        raise UnsupportedLayoutError("TLS preparation plan lacks Service routing requirements")
    metadata = service.get("metadata")
    spec = service.get("spec")
    if not isinstance(metadata, Mapping) or not isinstance(spec, Mapping):
        return False
    if metadata.get("name") != service_name or metadata.get("namespace") != namespace:
        return False

    template_labels = requirements.get("template_labels")
    selector = spec.get("selector")
    if not isinstance(template_labels, Mapping) or not template_labels:
        return False
    if not isinstance(selector, Mapping) or not selector:
        return False
    if any(template_labels.get(key) != value for key, value in selector.items()):
        return False

    service_type = spec.get("type", "ClusterIP")
    if service_name == statefulset_name:
        if service_type != "ClusterIP" or spec.get("clusterIP") != "None":
            return False
        if spec.get("publishNotReadyAddresses") is not True:
            return False
    elif service_name == f"{statefulset_name}-public":
        if service_type not in {"ClusterIP", "NodePort", "LoadBalancer"}:
            return False
        if spec.get("clusterIP") == "None":
            return False
    else:
        raise UnsupportedLayoutError("Unsupported certificate-rotation Service name")

    ports = spec.get("ports")
    if not isinstance(ports, list):
        return False
    container_ports = requirements.get("container_ports", [])
    if not isinstance(container_ports, list):
        return False
    for front_port, listener in _REQUIRED_SERVICE_PORTS.items():
        matches = [
            item for item in ports
            if (
                isinstance(item, Mapping)
                and item.get("port") == front_port
                and item.get("protocol", "TCP") == "TCP"
            )
        ]
        if len(matches) != 1:
            return False
        item = matches[0]
        backend_port = _service_target_port(item, container_ports)
        expected_port = requirements.get(f"{listener}_port")
        if type(expected_port) is not int or backend_port != expected_port:
            return False

    # A selected Service may have additional selectors only when the planned
    # template has those labels. Preserve it only when every matching Pod is
    # controlled by this StatefulSet; zero Pods is valid during the TLS scale.
    statefulset_uid = plan.get("uid")
    for pod in adapter.list_resources("pod", namespace):
        pod_metadata = pod.get("metadata", {})
        pod_labels = pod_metadata.get("labels", {}) if isinstance(pod_metadata, Mapping) else {}
        if not isinstance(pod_labels, Mapping) or any(
            pod_labels.get(key) != value for key, value in selector.items()
        ):
            continue
        owners = pod_metadata.get("ownerReferences", []) if isinstance(pod_metadata, Mapping) else []
        if not isinstance(owners, Sequence) or isinstance(owners, (str, bytes)):
            return False
        if not any(
            isinstance(owner, Mapping)
            and owner.get("uid") == statefulset_uid
            and owner.get("kind") == "StatefulSet"
            for owner in owners
        ):
            return False
    return True


def service_needs_repair(
    adapter: KubectlAdapter,
    namespace: str,
    statefulset_name: str,
    service_name: str,
    plan: Mapping[str, Any],
) -> bool:
    statefulset = adapter.get_resource("statefulset", namespace, statefulset_name)
    if statefulset is None:
        raise StaleIdentityError("Selected StatefulSet disappeared before the Service check")
    uid, _ = _metadata_identity(statefulset)
    if uid != plan.get("uid") or _spec(statefulset) != _expected_scaled_spec(plan):
        raise StaleIdentityError("Selected StatefulSet changed before the Service check")
    service = adapter.get_resource("service", namespace, service_name)
    if service is None:
        return True
    return not _service_is_valid(adapter, namespace, statefulset_name, service_name, service, plan)


def render_service(manifest: Path, service_name: str, cluster_name: str) -> str:
    try:
        source = Template(manifest.read_text(encoding="utf-8")).substitute(
            BENCH_PARAM_CLUSTER_NAME=cluster_name
        )
        documents = list(yaml.safe_load_all(source))
    except (OSError, KeyError, ValueError, yaml.YAMLError) as error:
        raise UnsupportedLayoutError("Certificate-rotation Service manifest cannot be rendered") from error
    matches = [
        document for document in documents
        if isinstance(document, Mapping)
        and document.get("kind") == "Service"
        and isinstance(document.get("metadata"), Mapping)
        and document["metadata"].get("name") == service_name
    ]
    if len(matches) != 1:
        raise UnsupportedLayoutError("Certificate-rotation manifest must contain the selected Service")
    return yaml.safe_dump(dict(matches[0]), sort_keys=False)


def _metadata_identity(statefulset: Mapping[str, Any]) -> tuple[str, str]:
    metadata = statefulset.get("metadata", {})
    uid = metadata.get("uid") if isinstance(metadata, Mapping) else None
    resource_version = metadata.get("resourceVersion") if isinstance(metadata, Mapping) else None
    if not isinstance(uid, str) or not uid or not isinstance(resource_version, str) or not resource_version:
        raise StaleIdentityError("Selected StatefulSet identity is incomplete")
    return uid, resource_version


def _spec(statefulset: Mapping[str, Any]) -> Mapping[str, Any]:
    value = statefulset.get("spec")
    if not isinstance(value, Mapping):
        raise StaleIdentityError("Selected StatefulSet spec is unavailable")
    return value


def _expected_scaled_spec(plan: Mapping[str, Any]) -> dict[str, Any]:
    original = plan.get("original_spec")
    if not isinstance(original, Mapping):
        raise UnsupportedLayoutError("TLS preparation plan is invalid")
    expected = copy.deepcopy(dict(original))
    expected["replicas"] = 0
    return expected


def _patch_replicas(
    adapter: KubectlAdapter,
    namespace: str,
    name: str,
    statefulset: Mapping[str, Any],
    replicas: int,
    *,
    add: bool = False,
) -> None:
    uid, resource_version = _metadata_identity(statefulset)
    adapter.patch_statefulset_json(
        namespace=namespace,
        name=name,
        uid=uid,
        resource_version=resource_version,
        operations=[
            {"op": "test", "path": "/metadata/uid", "value": uid},
            {"op": "test", "path": "/metadata/resourceVersion", "value": resource_version},
            {"op": "add" if add else "replace", "path": "/spec/replicas", "value": replicas},
        ],
        timeout=30,
    )


def prepare_existing(
    adapter: KubectlAdapter,
    namespace: str,
    name: str,
    *,
    secret_name: str,
    cert_dir: str,
    case_replicas: int,
) -> dict[str, Any] | None:
    statefulset = adapter.get_resource("statefulset", namespace, name)
    if statefulset is None:
        return None
    return build_plan(
        statefulset,
        secret_name=secret_name,
        cert_dir=cert_dir,
        case_replicas=case_replicas,
    )


def scale_existing(
    adapter: KubectlAdapter,
    namespace: str,
    name: str,
    plan: Mapping[str, Any],
) -> None:
    statefulset = adapter.get_resource("statefulset", namespace, name)
    if statefulset is None:
        raise StaleIdentityError("Selected StatefulSet disappeared before the guarded scale")
    uid, _ = _metadata_identity(statefulset)
    if uid != plan.get("uid") or _spec(statefulset) != plan.get("original_spec"):
        raise StaleIdentityError("Selected StatefulSet changed before the guarded scale")
    spec = _spec(statefulset)
    _patch_replicas(
        adapter,
        namespace,
        name,
        statefulset,
        0,
        add="replicas" not in spec,
    )


def finish_existing(
    adapter: KubectlAdapter,
    namespace: str,
    name: str,
    plan: Mapping[str, Any],
) -> None:
    statefulset = adapter.get_resource("statefulset", namespace, name)
    if statefulset is None:
        raise StaleIdentityError("Selected StatefulSet disappeared before the guarded TLS update")
    uid, resource_version = _metadata_identity(statefulset)
    if uid != plan.get("uid") or _spec(statefulset) != _expected_scaled_spec(plan):
        raise StaleIdentityError("Selected StatefulSet changed before the guarded TLS update")
    transformed = plan.get("secure_template")
    replicas = plan.get("target_replicas")
    if not isinstance(transformed, Mapping) or type(replicas) is not int or replicas < 1:
        raise UnsupportedLayoutError("TLS preparation plan is invalid")
    adapter.patch_statefulset_json(
        namespace=namespace,
        name=name,
        uid=uid,
        resource_version=resource_version,
        operations=[
            {"op": "test", "path": "/metadata/uid", "value": uid},
            {"op": "test", "path": "/metadata/resourceVersion", "value": resource_version},
            {"op": "replace", "path": "/spec/template", "value": transformed},
            {"op": "replace", "path": "/spec/replicas", "value": replicas},
        ],
        timeout=30,
    )


def _write_plan(path: Path, plan: Mapping[str, Any]) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(plan, stream, separators=(",", ":"))


def _read_plan(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise UnsupportedLayoutError("TLS preparation plan is unavailable") from error
    if not isinstance(value, dict):
        raise UnsupportedLayoutError("TLS preparation plan is invalid")
    return value


def _case_replicas_from_manifest(manifest: Path) -> int:
    try:
        documents = list(yaml.safe_load_all(manifest.read_text(encoding="utf-8")))
    except (OSError, yaml.YAMLError) as error:
        raise UnsupportedLayoutError("Certificate-rotation StatefulSet manifest cannot be read") from error
    statefulsets = [document for document in documents if isinstance(document, Mapping) and document.get("kind") == "StatefulSet"]
    if len(statefulsets) != 1:
        raise UnsupportedLayoutError("Certificate-rotation StatefulSet manifest must contain one StatefulSet")
    spec = statefulsets[0].get("spec")
    replicas = spec.get("replicas") if isinstance(spec, Mapping) else None
    if type(replicas) is not int or replicas < 1:
        raise UnsupportedLayoutError("Certificate-rotation StatefulSet manifest has no valid replica count")
    return replicas
def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("prepare", "scale", "finish", "service-check", "render-service"))
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--statefulset", required=True)
    parser.add_argument("--service", default=None)
    parser.add_argument("--services-manifest", type=Path, default=None)
    parser.add_argument("--cluster-name", default=None)
    parser.add_argument("--secret", default=None)
    parser.add_argument("--cert-dir", default=None)
    parser.add_argument("--case-manifest", type=Path, default=None)
    parser.add_argument("--plan", type=Path, default=None)
    parser.add_argument("--kubectl", default="kubectl")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.mode == "render-service":
        if args.services_manifest is None or args.service is None or args.cluster_name is None:
            raise SystemExit("render-service requires --services-manifest, --service, and --cluster-name")
        sys.stdout.write(render_service(args.services_manifest, args.service, args.cluster_name))
        return 0
    adapter = KubectlAdapter(kubectl=args.kubectl)
    if args.mode == "prepare":
        if args.plan is None or args.secret is None or args.cert_dir is None or args.case_manifest is None:
            raise SystemExit("prepare requires --plan, --secret, --cert-dir, and --case-manifest")
        plan = prepare_existing(
            adapter,
            args.namespace,
            args.statefulset,
            secret_name=args.secret,
            cert_dir=args.cert_dir,
            case_replicas=_case_replicas_from_manifest(args.case_manifest),
        )
        if plan is None:
            return 3
        _write_plan(args.plan, plan)
        return 0
    if args.plan is None:
        raise SystemExit(f"{args.mode} requires --plan")
    plan = _read_plan(args.plan)
    if args.mode == "service-check":
        if args.service is None:
            raise SystemExit("service-check requires --service")
        return 4 if service_needs_repair(
            adapter, args.namespace, args.statefulset, args.service, plan
        ) else 0
    if args.mode == "scale":
        scale_existing(adapter, args.namespace, args.statefulset, plan)
    else:
        finish_existing(adapter, args.namespace, args.statefulset, plan)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except CrdbError as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)

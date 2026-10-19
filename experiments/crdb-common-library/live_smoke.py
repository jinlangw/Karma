#!/usr/bin/env python3
"""One-node, owned live proof for the standalone karma.crdb library.

This harness refuses to pull or build images. It creates a fresh namespace,
uses one cached CockroachDB image and one 1Gi PVC, proves insecure then TLS
behavior sequentially, and removes only resources carrying its run label after
checking their UIDs. It writes safe summaries only; certificate files are held
in a temporary directory and are never copied to the evidence directory.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict
from decimal import Decimal
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable, Sequence


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from karma.crdb import (  # noqa: E402
    CrdbError,
    CrdbLibrary,
    KubectlAdapter,
    Lifecycle,
    ProbeStatus,
    Requirement,
    TLSMode,
    WorkloadRef,
)


class SmokeFailure(RuntimeError):
    def __init__(self, message: str, *, command_event: dict[str, Any] | None = None):
        super().__init__(message)
        self.command_event = command_event


_SENSITIVE_ASSIGNMENT = re.compile(
    r"(?i)([\"']?(?:password|passwd|token|secret|api[-_ ]?key|authorization|bearer|credential|private[-_ ]?key)"
    r"[\"']?\s*[:=]\s*)(\"(?:\\.|[^\"])*\"|'(?:\\.|[^'])*'|[^\s,;]+)"
)
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_STARTUP_LOG = re.compile(
    r"(?i)(cockroach\s+start|--(?:certs-dir|advertise(?:-sql)?-addr|join|store|sql-addr|listen-addr|http-addr))"
)


def _safe_diagnostic_text(value: Any, *, limit: int = 1200) -> str:
    """Redact sensitive/startup material before diagnostics reach evidence files."""
    text = str(value or "")
    text = re.sub(
        r"-----BEGIN [^-]+-----.*?-----END [^-]+-----",
        "<REDACTED PEM BLOCK>",
        text,
        flags=re.DOTALL,
    )
    safe_lines: list[str] = []
    in_pem = False
    for line in text.splitlines():
        if "-----BEGIN " in line:
            in_pem = True
            safe_lines.append("<REDACTED PEM BLOCK>")
            continue
        if in_pem:
            if "-----END " in line:
                in_pem = False
            continue
        if _STARTUP_LOG.search(line):
            safe_lines.append("<REDACTED startup-related log line>")
            continue
        line = _SENSITIVE_ASSIGNMENT.sub(r"\1<REDACTED>", line)
        line = re.sub(r"(?i)\bbearer\s+\S+", "Bearer <REDACTED>", line)
        line = re.sub(r"(?i)(postgres(?:ql)?://[^:/\s]+:)[^@\s]+@", r"\1<REDACTED>@", line)
        line = _JWT.sub("<REDACTED JWT>", line)
        safe_lines.append(line[:limit])
    return "\n".join(safe_lines)[-limit * 80 :]


def _safe_probe_config(probe: Any) -> dict[str, Any] | None:
    if not isinstance(probe, dict):
        return None
    handler_keys = ("httpGet", "tcpSocket", "exec", "grpc")
    handler = next((key for key in handler_keys if key in probe), None)
    summary: dict[str, Any] = {"handler": handler}
    if handler == "httpGet":
        value = probe.get(handler, {})
        summary[handler] = {
            key: value.get(key)
            for key in ("path", "port", "scheme")
            if key in value
        }
    elif handler == "tcpSocket":
        value = probe.get(handler, {})
        summary[handler] = {key: value.get(key) for key in ("port", "host") if key in value}
    elif handler == "grpc":
        value = probe.get(handler, {})
        summary[handler] = {key: value.get(key) for key in ("port", "service") if key in value}
    # Exec-probe commands can contain arbitrary data and are deliberately omitted.
    for key in (
        "initialDelaySeconds", "periodSeconds", "timeoutSeconds", "successThreshold",
        "failureThreshold", "terminationGracePeriodSeconds",
    ):
        if key in probe:
            summary[key] = probe[key]
    return summary


def _safe_probe_observation(probe: Any) -> dict[str, Any] | None:
    if probe is None:
        return None
    allowed = (
        "handler", "path", "port", "scheme", "period_seconds", "initial_delay_seconds",
        "timeout_seconds", "failure_threshold", "success_threshold", "has_custom_headers",
    )
    return {key: getattr(probe, key) for key in allowed if hasattr(probe, key)}


def _safe_pod_summary(pod: dict[str, Any]) -> dict[str, Any]:
    metadata = pod.get("metadata", {})
    spec = pod.get("spec", {})
    status = pod.get("status", {})

    def state_summary(state: Any) -> dict[str, Any] | None:
        if not isinstance(state, dict) or not state:
            return None
        name, value = next(iter(state.items()))
        if not isinstance(value, dict):
            return {"state": name}
        allowed = ("reason", "exitCode", "signal", "startedAt", "finishedAt", "message")
        summary = {"state": name}
        for key in allowed:
            if key in value:
                summary[key] = _safe_diagnostic_text(value[key]) if key == "message" else value[key]
        return summary

    containers = []
    for container in (*spec.get("initContainers", []), *spec.get("containers", [])):
        containers.append(
            {
                "name": container.get("name"),
                "image": container.get("image"),
                "imagePullPolicy": container.get("imagePullPolicy"),
                "ports": [
                    {key: port.get(key) for key in ("name", "containerPort", "protocol") if key in port}
                    for port in container.get("ports", [])
                ],
                "resources": container.get("resources", {}),
                "livenessProbe": _safe_probe_config(container.get("livenessProbe")),
                "readinessProbe": _safe_probe_config(container.get("readinessProbe")),
                "startupProbe": _safe_probe_config(container.get("startupProbe")),
            }
        )
    statuses = []
    for container in (*status.get("initContainerStatuses", []), *status.get("containerStatuses", [])):
        statuses.append(
            {
                "name": container.get("name"),
                "image": container.get("image"),
                "imageID": container.get("imageID"),
                "ready": container.get("ready"),
                "restartCount": container.get("restartCount"),
                "state": state_summary(container.get("state")),
                "lastState": state_summary(container.get("lastState")),
            }
        )
    conditions = []
    for condition in status.get("conditions", []):
        conditions.append(
            {
                key: (_safe_diagnostic_text(condition[key]) if key == "message" else condition[key])
                for key in ("type", "status", "reason", "message", "lastTransitionTime")
                if key in condition
            }
        )
    return {
        "metadata": {
            key: metadata.get(key)
            for key in ("name", "namespace", "uid", "creationTimestamp", "deletionTimestamp")
            if key in metadata
        },
        "spec": {"nodeName": spec.get("nodeName"), "containers": containers},
        "status": {
            key: (_safe_diagnostic_text(status[key]) if key == "message" else status[key])
            for key in ("phase", "reason", "message", "startTime", "hostIP", "podIP")
            if key in status
        },
        "conditions": conditions,
        "containerStatuses": statuses,
    }


def write_json_atomic(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".partial")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def run(
    argv: Sequence[str],
    *,
    timeout: float = 30,
    input_text: str | None = None,
    operation: str | None = None,
    observer: Callable[[dict[str, Any]], None] | None = None,
) -> str:
    """Run a bounded command without including output or arguments in errors."""
    operation = operation or Path(argv[0]).name
    started = time.monotonic()
    try:
        result = subprocess.run(
            list(argv),
            input=input_text,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        event = {
            "operation": operation,
            "outcome": "timeout",
            "returncode": None,
            "elapsed_ms": round((time.monotonic() - started) * 1000),
        }
        if observer:
            observer(event)
        raise SmokeFailure(f"{operation} timed out", command_event=event) from error
    except OSError as error:
        event = {
            "operation": operation,
            "outcome": "os_error",
            "returncode": None,
            "elapsed_ms": round((time.monotonic() - started) * 1000),
        }
        if observer:
            observer(event)
        raise SmokeFailure(f"{operation} could not be started", command_event=event) from error
    event = {
        "operation": operation,
        "outcome": "ok" if result.returncode == 0 else "exit_error",
        "returncode": result.returncode,
        "elapsed_ms": round((time.monotonic() - started) * 1000),
    }
    if observer:
        observer(event)
    if result.returncode:
        raise SmokeFailure(f"{operation} returned an error", command_event=event)
    return result.stdout


class Fixture:
    def __init__(self, args: argparse.Namespace, phase: str, run_id: str):
        self.args = args
        self.phase = phase
        self.run_id = run_id
        self.namespace = f"karma-crdb-library-{run_id}-{phase}"
        self.labels = {"app.kubernetes.io/name": "crdb-common-library-smoke", "crdb-library-run": run_id}
        self.created: dict[tuple[str, str], str] = {}
        self.namespace_uid: str | None = None
        self.namespace_baseline: set[tuple[str, str, str]] = set()
        self.checkpoint_callback = None
        self.command_trace: list[dict[str, Any]] = []
        self.current_stage = "fixture-created"
        self.started_at = time.monotonic()
        self.stage_started = self.started_at
        self.stage_history: list[dict[str, Any]] = []
        self.kubectl_base = [args.kubectl]
        if args.context:
            self.kubectl_base += ["--context", args.context]

    @staticmethod
    def _kubectl_operation(argv: Sequence[str]) -> str:
        if not argv:
            return "kubectl"
        verb = argv[0]
        if verb in {"get", "wait", "logs", "describe"}:
            target = next((item for item in argv[1:] if not item.startswith("-")), "")
            if verb == "wait" and target:
                return f"kubectl wait {target} Ready"
            if verb == "logs" and target:
                previous = " previous" if "--previous" in argv else ""
                return f"kubectl logs {target}{previous}"
            if target:
                return f"kubectl {verb} {target}"
        if verb == "exec":
            target = next((item for item in argv[1:] if not item.startswith("-")), "")
            container = next((item.split("=", 1)[1] for item in argv if item.startswith("--container=")), None)
            return f"kubectl exec {target}" + (f" container/{container}" if container else "")
        return f"kubectl {verb}"

    def _record_command(self, event: dict[str, Any]) -> None:
        self.command_trace.append(dict(event))
        if len(self.command_trace) > 80:
            del self.command_trace[:-80]

    def set_stage(self, name: str) -> None:
        now = time.monotonic()
        if name == self.current_stage:
            return
        self.stage_history.append(
            {"stage": self.current_stage, "elapsed_ms": round((now - self.stage_started) * 1000)}
        )
        self.current_stage = name
        self.stage_started = now

    def stage_snapshot(self) -> dict[str, Any]:
        now = time.monotonic()
        return {
            "current_stage": self.current_stage,
            "current_stage_elapsed_ms": round((now - self.stage_started) * 1000),
            "total_elapsed_ms": round((now - self.started_at) * 1000),
            "completed_stages": list(self.stage_history),
        }

    def kubectl(self, *argv: str, namespace: str | None = None, timeout: float = 30, input_text: str | None = None) -> str:
        command = list(self.kubectl_base)
        if namespace:
            command += ["--namespace", namespace]
        command.extend(argv)
        return run(
            command,
            timeout=timeout,
            input_text=input_text,
            operation=self._kubectl_operation(argv),
            observer=self._record_command,
        )

    def get(
        self,
        resource: str,
        name: str | None = None,
        *,
        all_namespaces: bool = False,
        timeout: float = 30,
    ) -> dict[str, Any]:
        command = ["get", resource]
        if name:
            command.append(name)
        cluster_scoped = {
            "namespace", "namespaces", "node", "nodes", "persistentvolume", "persistentvolumes",
            "storageclass", "storageclasses",
        }
        if all_namespaces and resource.lower() not in cluster_scoped:
            command.append("--all-namespaces")
        command += ["--output=json", "--ignore-not-found=true"]
        output = self.kubectl(*command, namespace=None if all_namespaces else self.namespace, timeout=timeout)
        if not output.strip():
            return {}
        try:
            parsed = json.loads(output)
        except json.JSONDecodeError as error:
            raise SmokeFailure("Kubernetes returned invalid JSON during live smoke") from error
        return parsed if isinstance(parsed, dict) else {}

    def wait_pod_running(self, timeout: float) -> bool:
        """Observe Running without treating Kubernetes Ready as a prerequisite."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            pod = self.get("pods", "db-0", timeout=min(5, max(1, deadline - time.monotonic())))
            if pod.get("status", {}).get("phase") == "Running":
                return True
            time.sleep(min(1, max(0, deadline - time.monotonic())))
        return False

    def _diagnostic_events(self, pod_uid: str | None) -> list[dict[str, Any]]:
        selector = f"involvedObject.uid={pod_uid}" if pod_uid else "involvedObject.name=db-0"
        output = self.kubectl(
            "get", "events", "--field-selector", selector, "--sort-by=.lastTimestamp", "--output=json",
            namespace=self.namespace, timeout=5,
        )
        document = json.loads(output)
        events = []
        for item in document.get("items", [])[-30:]:
            metadata = item.get("metadata", {})
            events.append(
                {
                    key: metadata.get(key)
                    for key in ("creationTimestamp",)
                    if key in metadata
                }
                | {
                    key: item.get(key)
                    for key in ("eventTime", "firstTimestamp", "lastTimestamp", "count", "type", "reason")
                    if key in item
                }
                | {"message": _safe_diagnostic_text(item.get("message", ""))}
            )
        return events

    def _diagnostic_logs(self, *, previous: bool) -> dict[str, Any]:
        command = ["logs", "pod/db-0", "--container=db", "--tail=80", "--timestamps"]
        if previous:
            command.append("--previous")
        try:
            output = self.kubectl(*command, namespace=self.namespace, timeout=5)
        except SmokeFailure as error:
            return {"available": False, "failure": str(error)}
        return {"available": True, "lines": _safe_diagnostic_text(output).splitlines()[-80:]}

    def capture_diagnostics(self, phase_data: dict[str, Any], *, label: str) -> dict[str, Any]:
        """Capture a small safe runtime snapshot before normal fixture cleanup."""
        started = time.monotonic()
        diagnostic: dict[str, Any] = {
            "label": label,
            "captured_at_utc": datetime.now(timezone.utc).isoformat(),
            "stage": self.stage_snapshot(),
        }
        pod: dict[str, Any] = {}
        try:
            pod = self.get("pods", "db-0", timeout=5)
            diagnostic["pod"] = _safe_pod_summary(pod) if pod else None
        except Exception as error:
            diagnostic["pod_observation_error"] = {"type": type(error).__name__, "detail": _safe_diagnostic_text(error)}
        pod_uid = str(pod.get("metadata", {}).get("uid", "")) or None
        try:
            diagnostic["events"] = self._diagnostic_events(pod_uid)
        except Exception as error:
            diagnostic["events_error"] = {"type": type(error).__name__, "detail": _safe_diagnostic_text(error)}
        diagnostic["current_logs"] = self._diagnostic_logs(previous=False)
        diagnostic["previous_logs"] = self._diagnostic_logs(previous=True)
        diagnostic["operations"] = list(self.command_trace[-50:])
        diagnostic["capture_elapsed_ms"] = round((time.monotonic() - started) * 1000)
        phase_data.setdefault("runtime_diagnostics", {})[label] = diagnostic
        self._checkpoint(f"diagnostics-{label}")
        return diagnostic

    def create(self, resource: dict[str, Any]) -> dict[str, Any]:
        output = self.kubectl("create", "--filename=-", "--output=json", namespace=self.namespace,
                              input_text=json.dumps(resource, separators=(",", ":")))
        try:
            created = json.loads(output)
        except json.JSONDecodeError as error:
            raise SmokeFailure("Kubernetes did not return created-resource identity") from error
        metadata = created.get("metadata", {})
        kind = str(created.get("kind", "")).lower()
        name = str(metadata.get("name", ""))
        uid = str(metadata.get("uid", ""))
        if not kind or not name or not uid:
            raise SmokeFailure("Created resource is missing its Kubernetes identity")
        self.created[(kind, name)] = uid
        self._checkpoint("resource-created")
        return created

    def _checkpoint(self, status: str) -> None:
        if self.checkpoint_callback:
            self.checkpoint_callback(status)

    def label_selector(self) -> str:
        return f"app.kubernetes.io/name={self.labels['app.kubernetes.io/name']},crdb-library-run={self.run_id}"

    def prepare_namespace(self) -> None:
        if self.get("namespace", self.namespace, all_namespaces=True):
            raise SmokeFailure("Generated namespace already exists; refusing to reuse it")
        namespace_manifest = {
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {"name": self.namespace, "labels": self.labels},
        }
        namespace = self.kubectl(
            "create", "--filename=-", "--output=json",
            input_text=json.dumps(namespace_manifest, separators=(",", ":")),
        )
        try:
            resource = json.loads(namespace)
            self.namespace_uid = str(resource["metadata"]["uid"])
        except (json.JSONDecodeError, KeyError, TypeError) as error:
            raise SmokeFailure("Created namespace did not return a valid UID") from error
        self.created[("namespace", self.namespace)] = self.namespace_uid
        self._checkpoint("namespace-created")
        for _ in range(30):
            if self.get("serviceaccounts", "default") and self.get("configmaps", "kube-root-ca.crt"):
                break
            time.sleep(1)
        self.namespace_baseline = self._namespace_resource_identities()
        self._checkpoint("namespace-baseline-captured")

    def _namespace_resource_identities(self) -> set[tuple[str, str, str]]:
        result: set[tuple[str, str, str]] = set()
        for kind in (
            "pods", "services", "statefulsets", "persistentvolumeclaims", "secrets", "configmaps",
            "serviceaccounts", "endpoints", "endpointslices", "deployments", "replicasets", "jobs", "cronjobs", "daemonsets",
        ):
            for item in self.get(kind).get("items", []):
                metadata = item.get("metadata", {})
                result.add((kind, str(metadata.get("name", "")), str(metadata.get("uid", ""))))
        return result

    def make_secret(self, cert_dir: Path) -> None:
        secret_document = self.kubectl(
            "create", "secret", "generic", "db-certs",
            "--from-file=ca.crt=" + str(cert_dir / "ca.crt"),
            "--from-file=node.crt=" + str(cert_dir / "node.crt"),
            "--from-file=node.key=" + str(cert_dir / "node.key"),
            "--from-file=client.root.crt=" + str(cert_dir / "client.root.crt"),
            "--from-file=client.root.key=" + str(cert_dir / "client.root.key"),
            "--dry-run=client", "--output=json",
            namespace=self.namespace,
        )
        try:
            resource = json.loads(secret_document)
            resource.setdefault("metadata", {})["labels"] = self.labels
            resource["metadata"]["namespace"] = self.namespace
        except (json.JSONDecodeError, KeyError, TypeError) as error:
            raise SmokeFailure("Client could not prepare a TLS Secret manifest") from error
        secret_uid = self.kubectl(
            "create", "--filename=-", "--output=jsonpath={.metadata.uid}",
            namespace=self.namespace,
            input_text=json.dumps(resource, separators=(",", ":")),
        )
        name, uid = "db-certs", secret_uid.strip()
        if not uid:
            raise SmokeFailure("Kubernetes did not return the TLS Secret identity")
        self.created[("secret", name)] = uid
        self._checkpoint("resource-created")

    def service_manifest(self) -> dict[str, Any]:
        return {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "db", "namespace": self.namespace, "labels": self.labels},
            "spec": {
                "clusterIP": "None",
                "publishNotReadyAddresses": True,
                "selector": self.labels,
                "ports": [
                    {"name": "sql", "port": 26257, "targetPort": "sql", "protocol": "TCP"},
                    {"name": "rpc", "port": 26258, "targetPort": "rpc", "protocol": "TCP"},
                    {"name": "http", "port": 8080, "targetPort": "http", "protocol": "TCP"},
                ],
            },
        }

    def statefulset_manifest(self, tls: bool) -> dict[str, Any]:
        cert_arg = "--certs-dir=/cockroach/certs" if tls else "--insecure"
        script = " ".join(
            [
                "exec /cockroach/cockroach start",
                "--sql-addr=0.0.0.0:26257",
                "--listen-addr=0.0.0.0:26258",
                "--http-addr=0.0.0.0:8080",
                "--advertise-addr=$(POD_NAME).db.$(POD_NAMESPACE).svc.cluster.local:26258",
                "--advertise-sql-addr=$(POD_NAME).db.$(POD_NAMESPACE).svc.cluster.local:26257",
                "--join=db-0.db.$(POD_NAMESPACE).svc.cluster.local:26258",
                "--store=/cockroach/cockroach-data",
                "--cache=128MiB",
                "--max-sql-memory=128MiB",
                cert_arg,
            ]
        )
        mounts: list[dict[str, Any]] = [{"name": "data", "mountPath": "/cockroach/cockroach-data"}]
        volumes: list[dict[str, Any]] = []
        if tls:
            mounts.append({"name": "certs", "mountPath": "/cockroach/certs", "readOnly": True})
            volumes.append({"name": "certs", "secret": {"secretName": "db-certs", "defaultMode": 256}})
        container = {
            "name": "db",
            "image": self.args.image,
            "imagePullPolicy": "Never",
            "command": ["/bin/bash", "-ec", script],
            "env": [
                {"name": "POD_NAME", "valueFrom": {"fieldRef": {"fieldPath": "metadata.name"}}},
                {"name": "POD_NAMESPACE", "valueFrom": {"fieldRef": {"fieldPath": "metadata.namespace"}}},
            ],
            "ports": [
                {"name": "sql", "containerPort": 26257, "protocol": "TCP"},
                {"name": "rpc", "containerPort": 26258, "protocol": "TCP"},
                {"name": "http", "containerPort": 8080, "protocol": "TCP"},
            ],
            "volumeMounts": mounts,
            "resources": {
                "requests": {"cpu": "100m", "memory": "256Mi"},
                "limits": {"cpu": "1", "memory": "1Gi"},
            },
            "livenessProbe": {
                "tcpSocket": {"port": "rpc"},
                "initialDelaySeconds": 10,
                "periodSeconds": 5,
                "timeoutSeconds": 3,
                "failureThreshold": 6,
            },
            "readinessProbe": {
                "tcpSocket": {"port": "rpc"},
                "initialDelaySeconds": 5,
                "periodSeconds": 3,
                "timeoutSeconds": 3,
                "failureThreshold": 5,
            },
        }
        return {
            "apiVersion": "apps/v1",
            "kind": "StatefulSet",
            "metadata": {"name": "db", "namespace": self.namespace, "labels": self.labels},
            "spec": {
                "serviceName": "db",
                "replicas": 1,
                "podManagementPolicy": "Parallel",
                "selector": {"matchLabels": self.labels},
                "updateStrategy": {"type": "RollingUpdate", "rollingUpdate": {"partition": 0}},
                "template": {
                    "metadata": {"labels": self.labels},
                    "spec": {
                        "nodeSelector": {"kubernetes.io/hostname": self.args.node},
                        "terminationGracePeriodSeconds": 30,
                        "containers": [container],
                        "volumes": volumes,
                    },
                },
                "volumeClaimTemplates": [
                    {
                        "metadata": {"name": "data", "labels": self.labels},
                        "spec": {
                            "accessModes": ["ReadWriteOnce"],
                            "storageClassName": getattr(self, "storage_class", None),
                            "resources": {"requests": {"storage": "1Gi"}},
                        },
                    }
                ],
            },
        }

    def wait_ready(self, timeout: float = 240) -> None:
        self.set_stage("pod-ready-wait")
        self.kubectl(
            "wait", "--for=condition=Ready", "pod/db-0", f"--timeout={int(timeout)}s",
            namespace=self.namespace, timeout=timeout + 10,
        )
        self._checkpoint("pod-ready-condition-met")
        self.set_stage("pvc-identity-discovery")
        claims = self.get("persistentvolumeclaims").get("items", [])
        if len(claims) != 1:
            raise SmokeFailure("Fixture did not create exactly one expected PVC")
        pvc = claims[0]
        pvcmeta = pvc.get("metadata", {})
        if pvcmeta.get("labels", {}).get("crdb-library-run") != self.run_id:
            raise SmokeFailure("Fixture PVC is missing its ownership label")
        pvc_name, pvc_uid = str(pvcmeta.get("name", "")), str(pvcmeta.get("uid", ""))
        self.created[("persistentvolumeclaim", pvc_name)] = pvc_uid
        volume_name = str(pvc.get("spec", {}).get("volumeName", ""))
        if volume_name:
            pv = self.get("persistentvolume", volume_name, all_namespaces=True)
            claim_ref = pv.get("spec", {}).get("claimRef", {})
            if claim_ref.get("uid") != pvc_uid or claim_ref.get("namespace") != self.namespace or claim_ref.get("name") != pvc_name:
                raise SmokeFailure("Fixture PV does not reference its owned PVC identity")
            self.created[("persistentvolume", volume_name)] = str(pv.get("metadata", {}).get("uid", ""))
        self._checkpoint("storage-identities-recorded")

    def init(self, tls: bool) -> None:
        self.set_stage("explicit-init")
        # cockroach init uses the node's RPC listen address; SQL queries use
        # the separate SQL listener. This matches the native fixture helpers.
        address = f"db-0.db.{self.namespace}.svc.cluster.local:26258"
        command = [
            *self.kubectl_base,
            "--namespace", self.namespace,
            "exec", "db-0", "--container=db", "--",
            "/cockroach/cockroach", "init",
        ]
        command.append("--certs-dir=/cockroach/certs" if tls else "--insecure")
        command.append("--host=" + address)
        run(command, timeout=45, operation="cockroach init", observer=self._record_command)

    def raw_delete_uid(
        self,
        kind: str,
        name: str,
        uid: str,
        *,
        propagation: str | None = None,
    ) -> None:
        """Delete using Kubernetes DeleteOptions.preconditions.uid."""
        endpoints = {
            "statefulset": f"/apis/apps/v1/namespaces/{self.namespace}/statefulsets/{name}",
            "service": f"/api/v1/namespaces/{self.namespace}/services/{name}",
            "secret": f"/api/v1/namespaces/{self.namespace}/secrets/{name}",
            "persistentvolumeclaim": f"/api/v1/namespaces/{self.namespace}/persistentvolumeclaims/{name}",
            "persistentvolume": f"/api/v1/persistentvolumes/{name}",
            "namespace": f"/api/v1/namespaces/{name}",
        }
        endpoint = endpoints.get(kind)
        if endpoint is None:
            raise SmokeFailure("Cleanup does not support this resource type")
        options: dict[str, Any] = {
            "apiVersion": "v1",
            "kind": "DeleteOptions",
            "preconditions": {"uid": uid},
        }
        if propagation:
            options["propagationPolicy"] = propagation
        command = [*self.kubectl_base, "delete", "--raw=" + endpoint, "--filename=-"]
        run(command, timeout=30, input_text=json.dumps(options, separators=(",", ":")))

    def wait_absent(self, kind: str, name: str, *, timeout: float = 180) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not self.get(kind, name, all_namespaces=kind in {"namespace", "persistentvolume"}):
                return
            time.sleep(1)
        raise SmokeFailure(f"Owned {kind}/{name} did not disappear within cleanup bound")

    def cleanup(self) -> None:
        """Delete in dependency order using exact UID preconditions."""
        if not self.namespace_uid:
            return
        self.set_stage("uid-guarded-cleanup")
        sts_uid = self.created.get(("statefulset", "db"))
        if sts_uid:
            sts = self.get("statefulset", "db")
            if sts:
                metadata = sts.get("metadata", {})
                if metadata.get("uid") != sts_uid or metadata.get("labels", {}).get("crdb-library-run") != self.run_id:
                    raise SmokeFailure("Cleanup stopped because StatefulSet identity or ownership changed")
                self.raw_delete_uid("statefulset", "db", sts_uid, propagation="Foreground")
                self._checkpoint("statefulset-delete-requested")
                self.wait_absent("statefulset", "db")
            for _ in range(180):
                pods = self.get("pods").get("items", [])
                if not pods:
                    break
                if any(pod.get("metadata", {}).get("labels", {}).get("crdb-library-run") != self.run_id for pod in pods):
                    raise SmokeFailure("Cleanup stopped because an unowned pod appeared in the fixture namespace")
                time.sleep(1)
            else:
                raise SmokeFailure("StatefulSet pods did not terminate within cleanup bound")
            self._checkpoint("statefulset-and-pods-absent")

        # StatefulSet claims survive by default. Delete the exact run-labeled
        # claim only after its database pod has terminated.
        pvc_list = self.get("persistentvolumeclaims")
        for pvc in pvc_list.get("items", []):
            metadata = pvc.get("metadata", {})
            name = str(metadata.get("name", ""))
            uid = str(metadata.get("uid", ""))
            if metadata.get("labels", {}).get("crdb-library-run") != self.run_id:
                raise SmokeFailure("Cleanup stopped because the namespace contains an unowned PVC")
            previous_uid = self.created.get(("persistentvolumeclaim", name))
            if previous_uid and previous_uid != uid:
                raise SmokeFailure("Cleanup stopped because the fixture PVC UID changed")
            self.created[("persistentvolumeclaim", name)] = uid
            self._checkpoint("pvc-identity-recorded")
            volume_name = pvc.get("spec", {}).get("volumeName")
            self.raw_delete_uid("persistentvolumeclaim", name, uid)
            self._checkpoint("pvc-delete-requested")
            self.wait_absent("persistentvolumeclaim", name)
            if volume_name:
                for _ in range(90):
                    pv = self.get("persistentvolume", str(volume_name), all_namespaces=True)
                    if not pv:
                        break
                    claim = pv.get("spec", {}).get("claimRef", {})
                    if claim.get("uid") != uid or claim.get("namespace") != self.namespace or claim.get("name") != name:
                        raise SmokeFailure("Cleanup stopped because the PV no longer belongs to the fixture claim")
                    pvmeta = pv.get("metadata", {})
                    pv_uid = str(pvmeta.get("uid", ""))
                    previous_pv_uid = self.created.get(("persistentvolume", str(volume_name)))
                    if previous_pv_uid and previous_pv_uid != pv_uid:
                        raise SmokeFailure("Cleanup stopped because the fixture PV UID changed")
                    self.created[("persistentvolume", str(volume_name))] = pv_uid
                    self._checkpoint("pv-identity-recorded")
                    if pv.get("spec", {}).get("persistentVolumeReclaimPolicy") != "Delete":
                        self.raw_delete_uid("persistentvolume", str(volume_name), pv_uid)
                        self.wait_absent("persistentvolume", str(volume_name), timeout=180)
                        break
                    time.sleep(1)
                else:
                    raise SmokeFailure("Owned PV did not clear within the cleanup bound")
            self._checkpoint("pvc-and-pv-absent")

        # Service DNS and TLS material remain available until the database
        # pod and its claim are gone.
        for kind, name in (("service", "db"), ("secret", "db-certs")):
            uid = self.created.get((kind, name))
            if not uid:
                continue
            obj = self.get(kind, name)
            if not obj:
                continue
            metadata = obj.get("metadata", {})
            if metadata.get("uid") != uid or metadata.get("labels", {}).get("crdb-library-run") != self.run_id:
                raise SmokeFailure(f"Cleanup stopped because {kind}/{name} identity or ownership changed")
            self.raw_delete_uid(kind, name, uid)
            self.wait_absent(kind, name)
            self._checkpoint(f"{kind}-absent")
            if kind == "service":
                for _ in range(60):
                    endpoint_slices = self.get("endpointslices").get("items", [])
                    owned_slices = [
                        item
                        for item in endpoint_slices
                        if any(
                            reference.get("uid") == uid
                            for reference in item.get("metadata", {}).get("ownerReferences", [])
                        )
                    ]
                    if not owned_slices:
                        break
                    time.sleep(1)
                else:
                    raise SmokeFailure("Service-owned EndpointSlices did not clear within cleanup bound")

        current = self._namespace_resource_identities()
        unexpected = current - self.namespace_baseline
        if unexpected:
            raise SmokeFailure("Cleanup found resources outside its namespace baseline; refusing namespace deletion")
        namespace = self.get("namespace", self.namespace, all_namespaces=True)
        if namespace:
            if namespace.get("metadata", {}).get("uid") != self.namespace_uid:
                raise SmokeFailure("Cleanup stopped because namespace UID changed")
            self.raw_delete_uid("namespace", self.namespace, self.namespace_uid)
            self._checkpoint("namespace-delete-requested")
            self.wait_absent("namespace", self.namespace)
        self._checkpoint("cleanup-complete")


def _resource_quantity(value: str, *, cpu: bool) -> Decimal:
    if cpu:
        if value.endswith("m"):
            return Decimal(value[:-1]) / Decimal(1000)
        return Decimal(value)
    units = {
        "Ki": 1024, "Mi": 1024**2, "Gi": 1024**3, "Ti": 1024**4,
        "K": 1000, "M": 1000**2, "G": 1000**3, "T": 1000**4,
    }
    for suffix, factor in units.items():
        if value.endswith(suffix):
            return Decimal(value[:-len(suffix)]) * factor
    return Decimal(value)


def _find_default_storage_class(items: Sequence[dict[str, Any]]) -> str:
    candidates = [
        str(item.get("metadata", {}).get("name", ""))
        for item in items
        if item.get("metadata", {}).get("annotations", {}).get("storageclass.kubernetes.io/is-default-class") == "true"
    ]
    if len(candidates) != 1:
        raise SmokeFailure("A single default StorageClass is required for the 1Gi PVC")
    return candidates[0]


def _openssl_version() -> str:
    version = run(["openssl", "version"], timeout=10).strip()
    match = re.match(r"^OpenSSL (\d+)\.(\d+)\.(\d+)(?:\D|$)", version)
    if not match or tuple(int(part) for part in match.groups()) < (1, 1, 1):
        raise SmokeFailure("TLS phase requires OpenSSL 1.1.1 or newer")
    return version


def preflight(args: argparse.Namespace, fixture: Fixture) -> dict[str, Any]:
    """Fresh per-phase capacity, image-cache, and competing-DB check."""
    namespaces = fixture.get("namespaces", all_namespaces=True).get("items", [])
    if any(item.get("metadata", {}).get("name") == fixture.namespace for item in namespaces):
        raise SmokeFailure("Generated namespace already exists; refusing to reuse it")
    pods = fixture.get("pods", all_namespaces=True).get("items", [])
    db_pods = []
    for pod in pods:
        status = pod.get("status", {})
        if status.get("phase") in {"Succeeded", "Failed"}:
            continue
        containers = pod.get("spec", {}).get("containers", []) + pod.get("spec", {}).get("initContainers", [])
        descriptor = " ".join(
            str(value).lower()
            for container in containers
            for value in (
                container.get("name", ""), container.get("image", ""),
                *(container.get("command") or ()), *(container.get("args") or ()),
            )
        )
        if "cockroach" in descriptor:
            db_pods.append(pod.get("metadata", {}).get("name", "unknown"))
    if db_pods:
        raise SmokeFailure("A CockroachDB pod is active or pending; live smoke requires an empty DB slot")

    active_db_workloads = []
    for kind in ("statefulsets", "deployments"):
        for workload in fixture.get(kind, all_namespaces=True).get("items", []):
            spec = workload.get("spec", {})
            replicas = int(spec.get("replicas", 1))
            template = spec.get("template", {}).get("spec", {})
            containers = template.get("containers", []) + template.get("initContainers", [])
            descriptor = " ".join(
                str(value).lower()
                for container in containers
                for value in (
                    container.get("name", ""), container.get("image", ""),
                    *(container.get("command") or ()), *(container.get("args") or ()),
                )
            )
            if replicas > 0 and "cockroach" in descriptor:
                active_db_workloads.append(workload.get("metadata", {}).get("name", "unknown"))
    if active_db_workloads:
        raise SmokeFailure("Another CockroachDB workload has desired replicas; live smoke requires an empty DB slot")
    docker_images = run([args.docker, "ps", "--format={{.Image}}"], timeout=15).splitlines()
    if any("cockroach" in image.lower() for image in docker_images):
        raise SmokeFailure("A CockroachDB Docker container is active outside Kubernetes")

    pvs = fixture.get("persistentvolumes", all_namespaces=True).get("items", [])
    pvcs = fixture.get("persistentvolumeclaims", all_namespaces=True).get("items", [])
    nodes = fixture.get("nodes", all_namespaces=True).get("items", [])
    target = [node for node in nodes if node.get("metadata", {}).get("name") == args.node]
    if len(target) != 1:
        raise SmokeFailure("Pinned Kind node is missing")
    node = target[0]
    allocatable = node.get("status", {}).get("allocatable", {})
    cpu_free = _resource_quantity(str(allocatable.get("cpu", "0")), cpu=True)
    mem_free = _resource_quantity(str(allocatable.get("memory", "0")), cpu=False)
    scheduled_cpu = Decimal(0)
    scheduled_mem = Decimal(0)
    for pod in pods:
        if pod.get("spec", {}).get("nodeName") != args.node or pod.get("status", {}).get("phase") in {"Succeeded", "Failed"}:
            continue
        pod_spec = pod.get("spec", {})
        regular_cpu = Decimal(0)
        regular_mem = Decimal(0)
        for container in pod_spec.get("containers", []):
            requests = container.get("resources", {}).get("requests", {})
            if requests.get("cpu"):
                regular_cpu += _resource_quantity(str(requests["cpu"]), cpu=True)
            if requests.get("memory"):
                regular_mem += _resource_quantity(str(requests["memory"]), cpu=False)
        init_cpu = Decimal(0)
        init_mem = Decimal(0)
        for container in pod_spec.get("initContainers", []):
            requests = container.get("resources", {}).get("requests", {})
            init_cpu = max(init_cpu, _resource_quantity(str(requests.get("cpu", "0")), cpu=True))
            init_mem = max(init_mem, _resource_quantity(str(requests.get("memory", "0")), cpu=False))
        overhead = pod_spec.get("overhead", {})
        scheduled_cpu += max(regular_cpu, init_cpu) + _resource_quantity(str(overhead.get("cpu", "0")), cpu=True)
        scheduled_mem += max(regular_mem, init_mem) + _resource_quantity(str(overhead.get("memory", "0")), cpu=False)
    free_cpu = cpu_free - scheduled_cpu
    free_mem = mem_free - scheduled_mem
    if free_cpu < Decimal("0.15") or free_mem < Decimal(384 * 1024**2):
        raise SmokeFailure("Kind node lacks the bounded smoke fixture's requested CPU or memory headroom")

    host_free = shutil.disk_usage("/").free
    if host_free < 4 * 1024**3:
        raise SmokeFailure("Host has less than 4GiB free; refusing a database live phase")
    docker_df = run([args.docker, "exec", args.node, "df", "-Pk", "/var/lib/containerd"], timeout=15)
    df_lines = [line for line in docker_df.splitlines() if line.strip()]
    try:
        worker_free = int(df_lines[-1].split()[3]) * 1024
    except (IndexError, ValueError) as error:
        raise SmokeFailure("Kind node disk capacity could not be parsed") from error
    if worker_free < 2 * 1024**3:
        raise SmokeFailure("Kind node has less than 2GiB free; refusing a database live phase")

    image_json = run([args.docker, "exec", args.node, "crictl", "images", "-o", "json"], timeout=20)
    try:
        image_data = json.loads(image_json)
        references = [
            str(reference)
            for image in image_data.get("images", [])
            for reference in image.get("repoTags", [])
        ]
    except (json.JSONDecodeError, AttributeError) as error:
        raise SmokeFailure("Cached Kind image inventory could not be verified") from error
    if not any(reference == args.image or reference.endswith("/" + args.image) for reference in references):
        raise SmokeFailure("The requested CockroachDB image is not cached on the pinned Kind node")

    openssl = _openssl_version() if fixture.phase == "tls" else None

    storage_classes = fixture.get("storageclasses", all_namespaces=True).get("items", [])
    default_storage = _find_default_storage_class(storage_classes)
    return {
        "phase": fixture.phase,
        "namespace": fixture.namespace,
        "host_free_bytes": host_free,
        "kind_node": args.node,
        "kind_node_free_bytes": worker_free,
        "kind_node_free_cpu_cores": str(free_cpu),
        "kind_node_free_memory_bytes": int(free_mem),
        "running_cockroach_pods": len(db_pods),
        "cluster_namespaces": len(namespaces),
        "active_pods_all_namespaces": len([pod for pod in pods if pod.get("status", {}).get("phase") not in {"Succeeded", "Failed"}]),
        "existing_pvcs": len(pvcs),
        "existing_pvs": len(pvs),
        "cached_image": args.image,
        "image_pull_policy": "Never",
        "storage_class": default_storage,
        "openssl_version": openssl,
        "fixture_pods": 1,
        "fixture_pvc": "1Gi",
        "pod_requests": {"cpu": "100m", "memory": "256Mi"},
    }


def make_certificates(cert_dir: Path, namespace: str) -> None:
    """Create short-lived local certificates without writing them to evidence."""
    cert_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    ca_key, ca_crt = cert_dir / "ca.key", cert_dir / "ca.crt"
    node_key, node_csr, node_crt = cert_dir / "node.key", cert_dir / "node.csr", cert_dir / "node.crt"
    root_key, root_csr, root_crt = cert_dir / "client.root.key", cert_dir / "client.root.csr", cert_dir / "client.root.crt"
    extfile = cert_dir / "extensions.cnf"
    extfile.write_text(
        "[node]\n"
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth,clientAuth\n"
        f"subjectAltName=DNS:db-0.db.{namespace}.svc.cluster.local,DNS:localhost,DNS:db,IP:127.0.0.1\n"
        "[root]\n"
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=clientAuth\n",
        encoding="utf-8",
    )
    run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(ca_key), "-out", str(ca_crt),
         "-days", "2", "-subj", "/CN=crdb-common-library-smoke-ca",
         "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"], timeout=30)
    run(["openssl", "genrsa", "-out", str(node_key), "2048"], timeout=30)
    run(["openssl", "req", "-new", "-key", str(node_key), "-out", str(node_csr), "-subj", "/CN=node"], timeout=30)
    run(["openssl", "x509", "-req", "-in", str(node_csr), "-CA", str(ca_crt), "-CAkey", str(ca_key),
         "-CAcreateserial", "-out", str(node_crt), "-days", "2", "-extfile", str(extfile), "-extensions", "node"], timeout=30)
    run(["openssl", "genrsa", "-out", str(root_key), "2048"], timeout=30)
    run(["openssl", "req", "-new", "-key", str(root_key), "-out", str(root_csr), "-subj", "/CN=root/O=admin"], timeout=30)
    run(["openssl", "x509", "-req", "-in", str(root_csr), "-CA", str(ca_crt), "-CAkey", str(ca_key),
         "-CAcreateserial", "-out", str(root_crt), "-days", "2", "-extfile", str(extfile), "-extensions", "root"], timeout=30)


def phase(args: argparse.Namespace, name: str, run_id: str, evidence_dir: Path) -> dict[str, Any]:
    fixture = Fixture(args, name, run_id)
    phase_data: dict[str, Any] = {"phase": name, "tls_mode": "tls" if name == "tls" else "insecure"}
    failure: Exception | None = None
    cleanup_failure: Exception | None = None

    def checkpoint(status: str) -> None:
        write_json_atomic(
            evidence_dir / f"{name}-journal.json",
            {
                "phase": name,
                "run_id": run_id,
                "namespace": fixture.namespace,
                "status": status,
                "namespace_uid": fixture.namespace_uid,
                "namespace_baseline": sorted(fixture.namespace_baseline),
                "owned_resource_uids": [
                    {"kind": kind, "name": object_name, "uid": uid}
                    for (kind, object_name), uid in sorted(fixture.created.items())
                ],
                "safe_observations": phase_data,
            },
        )

    fixture.checkpoint_callback = checkpoint
    checkpoint("preflight-started")
    try:
        fixture.set_stage("capacity-preflight")
        phase_data["capacity_preflight"] = preflight(args, fixture)
        fixture.storage_class = phase_data["capacity_preflight"]["storage_class"]
        checkpoint("preflight-passed")
        fixture.set_stage("namespace-prepare")
        fixture.prepare_namespace()
        fixture.set_stage("service-create")
        phase_data["service_uid"] = fixture.create(fixture.service_manifest())["metadata"]["uid"]
        if name == "tls":
            with tempfile.TemporaryDirectory(prefix="crdb-library-certs-") as temp:
                cert_dir = Path(temp)
                make_certificates(cert_dir, fixture.namespace)
                fixture.make_secret(cert_dir)
                fixture.set_stage("statefulset-create")
                fixture.create(fixture.statefulset_manifest(tls=True))
                if args.diagnostic_only:
                    raise SmokeFailure("Diagnostic-only mode supports only the insecure phase")
                phase_data.update(_exercise_phase(args, fixture, tls=True))
        else:
            fixture.set_stage("statefulset-create")
            fixture.create(fixture.statefulset_manifest(tls=False))
            if args.diagnostic_only:
                phase_data.update(_diagnostic_readiness_phase(args, fixture, phase_data))
            else:
                phase_data.update(_exercise_phase(args, fixture, tls=False))
        checkpoint("work-complete")
    except Exception as error:
        failure = error
        phase_data["failure_stage"] = fixture.stage_snapshot()
        if isinstance(error, SmokeFailure) and error.command_event:
            phase_data["failure_command"] = dict(error.command_event)
        detail = _safe_diagnostic_text(error) if isinstance(error, (SmokeFailure, CrdbError)) else "details withheld"
        phase_data["execution_failure"] = {"type": type(error).__name__, "detail": detail}
        try:
            fixture.capture_diagnostics(phase_data, label="before-cleanup")
        except Exception as diagnostic_error:
            phase_data["diagnostic_capture_failure"] = {
                "type": type(diagnostic_error).__name__,
                "detail": _safe_diagnostic_text(diagnostic_error),
            }
    try:
        fixture.cleanup()
        phase_data["cleanup_verdict"] = "completed with UID preconditions and normal deletion"
    except Exception as error:
        cleanup_failure = error
        if isinstance(error, (SmokeFailure, CrdbError)):
            detail = str(error)
        else:
            detail = "details withheld"
        phase_data["cleanup_failure"] = {"type": type(error).__name__, "detail": detail}
        phase_data["cleanup_verdict"] = "incomplete; ownership journal retained"
    phase_data["namespace"] = fixture.namespace
    phase_data["result"] = "passed" if failure is None and cleanup_failure is None else "failed"
    phase_data["stage_timing"] = fixture.stage_snapshot()
    phase_data["command_trace"] = list(fixture.command_trace[-80:])
    evidence_dir.mkdir(parents=True, exist_ok=True)
    write_json_atomic(evidence_dir / f"{name}-phase.json", phase_data)
    checkpoint("phase-finished")
    if failure or cleanup_failure:
        raise SmokeFailure(
            f"{name} phase failed; inspect {evidence_dir / f'{name}-phase.json'} and its ownership journal"
        ) from (failure or cleanup_failure)
    return phase_data


def _exercise_phase(args: argparse.Namespace, fixture: Fixture, *, tls: bool) -> dict[str, Any]:
    fixture.wait_ready(timeout=args.ready_timeout)
    ref = WorkloadRef(fixture.namespace, "db", "db")
    library = CrdbLibrary(KubectlAdapter(kubectl=args.kubectl, context=args.context))
    mode = TLSMode.TLS if tls else TLSMode.INSECURE

    # The deployed-only requirement is expected to pass before explicit init.
    fixture.set_stage("pre-init-deployed-probe")
    before_init = library.probe(ref, Requirement(Lifecycle.DEPLOYED, minimum_nodes=1, tls_mode=mode), per_node_timeout=4)
    if before_init.status is not ProbeStatus.SATISFIED or before_init.health.lifecycle is not Lifecycle.DEPLOYED:
        raise SmokeFailure("Pre-initialization deployed readiness did not match the explicit requirement")

    fixture.init(tls)
    fixture.set_stage("initialized-semantic-reconcile")
    initialized = library.reconcile(
        ref,
        Requirement(Lifecycle.INITIALIZED, minimum_nodes=1, tls_mode=mode),
        timeout=120,
        poll_interval=1,
        per_node_timeout=5,
    )
    if initialized.assessment.status is not ProbeStatus.SATISFIED:
        raise SmokeFailure("Initialized semantic readiness did not converge")
    fixture.set_stage("witness-data-write")
    _fixture_sql(fixture, tls, "CREATE DATABASE crdb_common_library_smoke")
    _fixture_sql(
        fixture,
        tls,
        "CREATE TABLE crdb_common_library_smoke.public.witness (id INT PRIMARY KEY, payload STRING NOT NULL)",
    )
    _fixture_sql(
        fixture,
        tls,
        "INSERT INTO crdb_common_library_smoke.public.witness VALUES "
        "(1, 'preserve-through-probe-rollout'), (2, 'fixture-row-two')",
    )
    witness_before = _fixture_sql(
        fixture,
        tls,
        "SELECT id, payload FROM crdb_common_library_smoke.public.witness ORDER BY id",
    )
    witness_before_hash = hashlib.sha256(witness_before.encode("utf-8")).hexdigest()
    fixture.set_stage("http-health-preflight")
    health = library.probe_health_endpoint(ref, path="/health", per_node_timeout=4)
    ready = library.probe_health_endpoint(ref, path="/health?ready=1", per_node_timeout=4)
    if not all(row[2] for row in (*health, *ready)):
        raise SmokeFailure("CockroachDB HTTP health endpoints failed before probe repair")

    accepted = library.capture_accepted_state(ref, per_node_timeout=5)
    noop = library.reconcile(
        ref,
        Requirement(Lifecycle.INITIALIZED, minimum_nodes=1, tls_mode=mode),
        timeout=15,
        poll_interval=1,
        per_node_timeout=5,
        accepted_state=accepted,
    )
    if noop.changed_by_library or noop.assessment.status is not ProbeStatus.SATISFIED:
        raise SmokeFailure("Accepted-state no-op reconciliation changed or failed the fixture")

    fixture.set_stage("http-probe-preparation")
    repaired = library.prepare_health_recovery_probes(ref, timeout=180, poll_interval=1, per_node_timeout=5)
    if not repaired.changed or repaired.verified.status is not ProbeStatus.SATISFIED:
        raise SmokeFailure("Explicit health-probe preparation did not perform and verify the supported mutation")
    if repaired.after.tls_mode is not mode:
        raise SmokeFailure("Probe preparation changed the observed TLS mode")
    if repaired.after.liveness_probe.handler != "httpGet" or repaired.after.readiness_probe.handler != "httpGet":
        raise SmokeFailure("Probe preparation did not install HTTP handlers")
    expected_scheme = "HTTPS" if tls else "HTTP"
    if repaired.after.liveness_probe.scheme != expected_scheme or repaired.after.readiness_probe.scheme != expected_scheme:
        raise SmokeFailure("Probe preparation did not preserve the observed HTTP scheme")
    verified = library.verify_accepted_state(ref, repaired.accepted_after, per_node_timeout=5)
    if verified.status is not ProbeStatus.SATISFIED:
        raise SmokeFailure("Post-mutation accepted state did not verify")
    witness_after = _fixture_sql(
        fixture,
        tls,
        "SELECT id, payload FROM crdb_common_library_smoke.public.witness ORDER BY id",
    )
    witness_after_hash = hashlib.sha256(witness_after.encode("utf-8")).hexdigest()
    if witness_before_hash != witness_after_hash:
        raise SmokeFailure("Fixture witness rows changed across probe preparation")

    # Public observation contains IDs, versions, hashes, and redacted metadata;
    # it contains no certificate bytes or startup command contents.
    return {
        "preinit_lifecycle": before_init.health.lifecycle.value,
        "preinit_ready_nodes": len(before_init.health.deployed_pods),
        "initialized_lifecycle": initialized.assessment.health.lifecycle.value,
        "cluster_id": accepted.cluster_id,
        "node_ids": accepted.node_ids,
        "sql_versions": accepted.sql_versions,
        "tls_mode_before_after": [accepted.tls_mode.value, repaired.accepted_after.tls_mode.value],
        "image": accepted.image,
        "desired_replicas": accepted.desired_replicas,
        "pvc_identities": accepted.pvc_identities,
        "certificate_fingerprints": accepted.certificate_fingerprints,
        "service_routing": accepted.service_routing,
        "accepted_spec_hash_before": accepted.workload_spec_hash,
        "accepted_spec_hash_after": repaired.accepted_after.workload_spec_hash,
        "probe_preservation_hash_before": repaired.before.probe_preservation_hash,
        "probe_preservation_hash_after": repaired.after.probe_preservation_hash,
        "noop_reconcile_changed": noop.changed_by_library,
        "mutation_changed": repaired.changed,
        "liveness_probe": asdict(repaired.after.liveness_probe),
        "readiness_probe": asdict(repaired.after.readiness_probe),
        "health_endpoint_statuses": {"health": health, "ready": ready},
        "post_mutation_accepted_state_verified": True,
        "witness_row_count": 2,
        "witness_sha256_before_after": [witness_before_hash, witness_after_hash],
    }


def _diagnostic_readiness_phase(
    args: argparse.Namespace,
    fixture: Fixture,
    phase_data: dict[str, Any],
) -> dict[str, Any]:
    """Run a read-only pre-Ready observation, then preserve Ready wait as the verdict."""
    fixture.set_stage("pre-ready-running-observation")
    running = False
    try:
        running = fixture.wait_pod_running(args.running_observation_timeout)
    except Exception as error:
        phase_data["pre_ready_running_observation_error"] = {
            "type": type(error).__name__,
            "detail": _safe_diagnostic_text(error),
        }
    phase_data["pre_ready_pod_running"] = running

    ref = WorkloadRef(fixture.namespace, "db", "db")
    library = CrdbLibrary(KubectlAdapter(kubectl=args.kubectl, context=args.context))
    if running:
        fixture.set_stage("pre-ready-library-inspect-and-probe")
        try:
            observation = library.inspect(ref)
            phase_data["pre_ready_inspection"] = {
                "tls_mode": observation.tls_mode.value,
                "sql_port": observation.sql_port,
                "rpc_port": observation.rpc_port,
                "http_port": observation.http_port,
                "pods": [
                    {
                        "name": pod.name,
                        "phase": pod.phase,
                        "container_state": pod.container_state,
                        "container_ready": pod.container_ready,
                        "pod_ready": pod.pod_ready,
                    }
                    for pod in observation.pods
                ],
                "liveness_probe": _safe_probe_observation(observation.liveness_probe),
                "readiness_probe": _safe_probe_observation(observation.readiness_probe),
            }
        except Exception as error:
            phase_data["pre_ready_inspection_error"] = {
                "type": type(error).__name__,
                "detail": _safe_diagnostic_text(error),
            }
        try:
            assessment = library.probe(
                ref,
                Requirement(Lifecycle.DEPLOYED, minimum_nodes=1, tls_mode=TLSMode.INSECURE),
                per_node_timeout=2,
            )
            phase_data["pre_ready_library_probe"] = {
                "status": assessment.status.value,
                "lifecycle": assessment.health.lifecycle.value,
                "deployed_pods": assessment.health.deployed_pods,
                "uninitialized_pods": assessment.health.uninitialized_pods,
                "reasons": assessment.reasons,
            }
        except Exception as error:
            phase_data["pre_ready_library_probe_error"] = {
                "type": type(error).__name__,
                "detail": _safe_diagnostic_text(error),
            }
    fixture._checkpoint("pre-ready-observation-recorded")

    # The original Kubernetes Ready gate remains the diagnostic pass/fail
    # signal. Pre-Ready observation errors are recorded but never short-circuit it.
    fixture.wait_ready(timeout=args.ready_timeout)
    fixture.set_stage("post-ready-deployed-probe")
    try:
        assessment = library.probe(
            ref,
            Requirement(Lifecycle.DEPLOYED, minimum_nodes=1, tls_mode=TLSMode.INSECURE),
            per_node_timeout=2,
        )
        phase_data["post_ready_library_probe"] = {
            "status": assessment.status.value,
            "lifecycle": assessment.health.lifecycle.value,
            "deployed_pods": assessment.health.deployed_pods,
            "uninitialized_pods": assessment.health.uninitialized_pods,
            "reasons": assessment.reasons,
        }
        if assessment.status is not ProbeStatus.SATISFIED:
            raise SmokeFailure("Post-Ready deployed semantic readiness was unsatisfied")
    except Exception as error:
        phase_data["post_ready_library_probe_error"] = {
            "type": type(error).__name__,
            "detail": _safe_diagnostic_text(error),
        }
        raise SmokeFailure("Post-Ready deployed semantic probe failed") from error
    fixture.capture_diagnostics(phase_data, label="diagnostic-only-complete")
    return {
        "diagnostic_only": True,
        "pre_ready_pod_running": running,
        "pre_ready_library_probe": phase_data.get("pre_ready_library_probe"),
        "post_ready_library_probe": phase_data.get("post_ready_library_probe"),
    }


def _fixture_sql(fixture: Fixture, tls: bool, sql: str) -> str:
    command = [
        *fixture.kubectl_base,
        "--namespace", fixture.namespace,
        "exec", "db-0", "--container=db", "--",
        "/cockroach/cockroach", "sql",
        "--host=localhost", "--port=26257", "--format=csv",
    ]
    command.append("--certs-dir=/cockroach/certs" if tls else "--insecure")
    command.extend(["-e", sql])
    return run(command, timeout=35)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", help="kubectl context; omit to use the current context")
    parser.add_argument("--kubectl", default="kubectl")
    parser.add_argument("--docker", default="docker")
    parser.add_argument("--node", default="kind-worker")
    parser.add_argument("--image", default="cockroachdb/cockroach:v24.1.0")
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument(
        "--diagnostic-only",
        action="store_true",
        help="run one insecure pre-Ready/Ready semantic diagnostic; do not initialize or mutate CockroachDB",
    )
    parser.add_argument("--ready-timeout", type=float, default=240.0)
    parser.add_argument("--running-observation-timeout", type=float, default=8.0)
    args = parser.parse_args(argv)
    if not math.isfinite(args.ready_timeout) or args.ready_timeout <= 0:
        raise SmokeFailure("Ready timeout must be finite and positive")
    if not math.isfinite(args.running_observation_timeout) or args.running_observation_timeout < 0:
        raise SmokeFailure("Running observation timeout must be finite and non-negative")
    if args.diagnostic_only and (args.ready_timeout > 30 or args.running_observation_timeout > 12):
        raise SmokeFailure("Diagnostic-only timeouts exceed the 30-second Ready / 12-second Running bounds")
    run_id = f"{time.strftime('%y%m%d')}-{os.getpid():x}"
    evidence_dir = args.evidence_dir.expanduser().resolve()
    if not re.fullmatch(r"[a-z0-9-]{1,16}", run_id):
        raise SmokeFailure("Generated run identity is not a valid DNS label")
    if evidence_dir.exists():
        raise SmokeFailure("Evidence directory must be new; refusing to overwrite existing experiment records")
    evidence_dir.mkdir(parents=True, exist_ok=False)
    purpose = "live diagnostic" if args.diagnostic_only else "live proof"
    print(f"Starting bounded CockroachDB {purpose}; run id {run_id}", flush=True)
    insecure = phase(args, "insecure", run_id, evidence_dir)
    if args.diagnostic_only:
        print(f"Insecure diagnostic complete and cleaned: {insecure['namespace']}", flush=True)
        return 0
    print(f"Insecure phase complete and cleaned: {insecure['namespace']}", flush=True)
    secure = phase(args, "tls", run_id, evidence_dir)
    print(f"TLS phase complete and cleaned: {secure['namespace']}", flush=True)
    (evidence_dir / "live-summary.json").write_text(
        json.dumps({"run_id": run_id, "phases": [insecure, secure]}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"Live proof passed; safe evidence at {evidence_dir}", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SmokeFailure as error:
        print(f"LIVE SMOKE STOPPED: {error}", file=sys.stderr, flush=True)
        raise SystemExit(2)

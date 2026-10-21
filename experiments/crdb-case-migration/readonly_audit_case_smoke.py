#!/usr/bin/env python3
"""Bounded live proof for the readonly-audit case migration.

Runs one native-shaped three-node HTTPS fixture followed, after full cleanup,
by one fresh three-node bootstrap through the case's manifest-directory seam.
Only cached CockroachDB v24.1.0 is used. No solver or workflow is started.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import importlib
import importlib.util
import json
import math
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
from typing import Any, Iterator, Mapping

import yaml


ROOT = Path(__file__).resolve().parents[2]
BASE_PATH = ROOT / "experiments" / "crdb-common-library" / "live_smoke.py"
HEALTH_HARNESS_PATH = ROOT / "experiments" / "crdb-case-migration" / "health_recovery_case_smoke.py"
AUDIT_ROOT = ROOT / "cases" / "cockroachdb" / "readonly-audit"
AUDIT_SCRIPTS = AUDIT_ROOT / "scripts"
AUDIT_PREPARE = AUDIT_SCRIPTS / "prepare.py"
AUDIT_ORACLE = AUDIT_ROOT / "oracle" / "oracle.py"
SETTINGS_TARGET = ROOT / "cases" / "cockroachdb" / "cluster-settings" / "resource" / "ensure-target-cluster.py"
_BASE_SPEC = importlib.util.spec_from_file_location("crdb_library_live_smoke", BASE_PATH)
_HEALTH_SPEC = importlib.util.spec_from_file_location("health_recovery_case_smoke", HEALTH_HARNESS_PATH)
if _BASE_SPEC is None or _BASE_SPEC.loader is None or _HEALTH_SPEC is None or _HEALTH_SPEC.loader is None:
    raise RuntimeError("Could not load the reviewed CRDB live-fixture helpers")
_BASE = importlib.util.module_from_spec(_BASE_SPEC)
_BASE_SPEC.loader.exec_module(_BASE)
_HEALTH = importlib.util.module_from_spec(_HEALTH_SPEC)
_HEALTH_SPEC.loader.exec_module(_HEALTH)

from cryptography.fernet import Fernet  # noqa: E402
from karma.crdb import (  # noqa: E402
    CrdbLibrary,
    KubectlAdapter,
    Lifecycle,
    ProbeStatus,
    Requirement,
    TLSMode,
    WorkloadRef,
)


_NODE_COUNT = 3
_WITNESS_DB = "crdb_readonly_audit_smoke"
_WITNESS_TABLE = f"{_WITNESS_DB}.public.witness"
_WITNESS_ROWS = [
    ["id", "payload"],
    ["1", "observed before audit preparation"],
    ["2", "retained across audit preparation"],
]
_CASE_LABELS = {"app.kubernetes.io/name": "cockroachdb", "app.kubernetes.io/instance": "db"}
@contextmanager
def case_environment(
    fixture: "AuditFixture",
    *,
    setting_name: str | None = None,
    setting_value: str | None = None,
) -> Iterator[None]:
    updates = {
        "BENCH_NAMESPACE": fixture.namespace,
        "BENCH_PARAM_CLUSTER_NAME": "db",
        "BENCH_PARAM_REPLICA_COUNT": str(_NODE_COUNT),
        "BENCH_RUN_ID": fixture.run_id,
        "BENCH_STAGE_ID": fixture.stage_id,
    }
    if setting_name is not None:
        updates["BENCH_PARAM_SETTING_NAME"] = setting_name
    if setting_value is not None:
        updates["BENCH_PARAM_SETTING_VALUE"] = setting_value
    resolved = shutil.which(fixture.args.kubectl)
    if resolved and Path(fixture.args.kubectl).name == "kubectl":
        updates["PATH"] = str(Path(resolved).parent) + os.pathsep + os.environ.get("PATH", "")
    previous = {key: os.environ.get(key) for key in updates}
    os.environ.update(updates)
    try:
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def audit_artifact_names(namespace: str, run_id: str, stage_id: str) -> dict[str, Any]:
    context = {
        "namespace": namespace,
        "cluster_name": "db",
        "run_id": run_id,
        "stage_id": stage_id,
    }
    digest = hashlib.sha256(
        "/".join(context[key] for key in ("namespace", "cluster_name", "run_id", "stage_id")).encode()
    ).hexdigest()[:20]
    report_name = "crdb-audit-" + digest
    return {
        "context": context,
        "audit_id": digest,
        "report_name": report_name,
        "baseline_name": report_name + "-baseline",
        "labels": {
            **_CASE_LABELS,
            "karma.dev/fixture": "readonly-audit",
            "karma.dev/audit-id": digest,
        },
    }


class AuditFixture(_HEALTH.HealthCaseFixture):
    """Three-node fixture with the audit case's observed HTTPS readiness contract."""

    def __init__(self, args: argparse.Namespace, phase: str, run_id: str):
        super().__init__(args, phase, run_id)
        self.stage_id = "readonly-audit-smoke"
        self.audit_context = audit_artifact_names(self.namespace, run_id, self.stage_id)
        self.artifact_create_intents: set[str] = set()
        self.phase_data: dict[str, Any] = {}

    def statefulset_manifest(self, tls: bool) -> dict[str, Any]:
        manifest = super().statefulset_manifest(tls)
        container = manifest["spec"]["template"]["spec"]["containers"][0]
        scheme = "HTTPS" if tls else "HTTP"
        container["livenessProbe"] = {
            "httpGet": {"path": "/health", "port": "http", "scheme": scheme},
            "initialDelaySeconds": 20,
            "periodSeconds": 5,
            "timeoutSeconds": 3,
            "failureThreshold": 6,
        }
        container["readinessProbe"] = {
            "httpGet": {"path": "/health?ready=1", "port": "http", "scheme": scheme},
            "initialDelaySeconds": 10,
            "periodSeconds": 3,
            "timeoutSeconds": 3,
            "failureThreshold": 10,
        }
        return manifest

    def capture_diagnostics(self, phase_data: dict[str, Any], *, label: str) -> dict[str, Any]:
        diagnostic = super().capture_diagnostics(phase_data, label=label)
        pod = diagnostic.get("pod")
        if not isinstance(pod, Mapping) or not pod.get("metadata", {}).get("name"):
            return diagnostic
        mode = "--certs-dir=/cockroach/cockroach-certs" if phase_data.get("tls_mode") == "TLS" else "--insecure"
        command = [
            *self.kubectl_base,
            "--namespace", self.namespace,
            "exec", "db-0", "--container=db", "--",
            "/cockroach/cockroach", "node", "status", "--all", mode,
            f"--host=db-0.db.{self.namespace}.svc.cluster.local",
            "--port=26257", "--format=csv",
        ]
        started = time.monotonic()
        try:
            output = _BASE.run(
                command,
                timeout=10,
                operation="readonly-audit diagnostic node status",
                observer=self._record_command,
            )
            rows = [row for row in __import__("csv").reader(output.splitlines()) if row]
            diagnostic["node_status_csv"] = {
                "available": bool(rows),
                "headers": rows[0] if rows else [],
                "row_count": max(0, len(rows) - 1),
            }
        except Exception as error:
            diagnostic["node_status_csv"] = {
                "available": False,
                "error_type": type(error).__name__,
                "detail": _BASE._safe_diagnostic_text(error),
            }
        diagnostic["node_status_diagnostic_elapsed_ms"] = round((time.monotonic() - started) * 1000)
        phase_data.setdefault("runtime_diagnostics", {}).setdefault(label, diagnostic)
        self._checkpoint("diagnostic-node-status-captured")
        return diagnostic

    def record_artifact_intent(self, name: str) -> None:
        if name not in (self.audit_context["report_name"], self.audit_context["baseline_name"]):
            raise _BASE.SmokeFailure("Refusing to journal an unexpected audit ConfigMap name")
        if name in {item[1] for item in self.namespace_baseline if item[0] == "configmaps"}:
            raise _BASE.SmokeFailure("Audit artifact existed in the fresh namespace baseline")
        self.artifact_create_intents.add(name)
        self.phase_data.setdefault("audit_artifact_create_intents", []).append(name)
        self._checkpoint("audit-artifact-create-intent-" + name)

    def record_created_artifact(self, obj: Mapping[str, Any]) -> dict[str, Any]:
        metadata = obj.get("metadata", {})
        name = metadata.get("name") if isinstance(metadata, Mapping) else None
        if name not in self.artifact_create_intents:
            raise _BASE.SmokeFailure("Audit ConfigMap was not preceded by a recorded create intent")
        expected = self.audit_context
        labels = metadata.get("labels", {})
        if any(labels.get(key) != value for key, value in expected["labels"].items()):
            raise _BASE.SmokeFailure("Audit ConfigMap labels do not match this run and stage")
        uid = metadata.get("uid")
        if not isinstance(uid, str) or not uid:
            raise _BASE.SmokeFailure("Audit ConfigMap has no Kubernetes UID")
        existing_uid = self.created.get(("configmap", name))
        if existing_uid and existing_uid != uid:
            raise _BASE.SmokeFailure("Audit ConfigMap UID changed during this run")
        self.created[("configmap", name)] = uid
        encrypted = obj.get("data", {}).get("snapshot.enc") if name == expected["baseline_name"] else None
        summary = {
            "name": name,
            "uid": uid,
            "audit_id": expected["audit_id"],
            "encrypted_baseline_sha256": hashlib.sha256(encrypted.encode()).hexdigest() if isinstance(encrypted, str) else None,
        }
        rows = self.phase_data.setdefault("audit_artifact_identities", [])
        previous = next((item for item in rows if item["name"] == name), None)
        if previous is not None and previous != summary:
            raise _BASE.SmokeFailure("Audit ConfigMap identity or encrypted baseline hash changed")
        if previous is None:
            rows.append(summary)
        self._checkpoint("audit-artifact-identity-recorded-" + name)
        return summary

    def capture_artifact_if_owned(self, name: str) -> dict[str, Any] | None:
        obj = self.get("configmaps", name)
        if not obj:
            return None
        return self.record_created_artifact(obj)

    def _namespace_resource_identities(self) -> set[tuple[str, str, str]]:
        identities = super()._namespace_resource_identities()
        for kind in ("roles", "rolebindings"):
            for item in self.get(kind).get("items", []):
                metadata = item.get("metadata", {})
                identities.add((kind, str(metadata.get("name", "")), str(metadata.get("uid", ""))))
        return identities

    def _delete_rbac_uid(self, kind: str, name: str, uid: str) -> None:
        plural = {"role": "roles", "rolebinding": "rolebindings"}.get(kind)
        if plural is None:
            raise _BASE.SmokeFailure("Cleanup does not support this RBAC resource")
        endpoint = f"/apis/rbac.authorization.k8s.io/v1/namespaces/{self.namespace}/{plural}/{name}"
        options = {"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": uid}}
        _BASE.run(
            [*self.kubectl_base, "delete", "--raw=" + endpoint, "--filename=-"],
            timeout=30,
            input_text=json.dumps(options, separators=(",", ":")),
            operation=f"kubectl delete {kind}/{name} with UID precondition",
            observer=self._record_command,
        )

    def _wait_service_slices_absent(self, uid: str, timeout: float = 60) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            slices = self.get("endpointslices").get("items", [])
            if not any(
                reference.get("uid") == uid
                for item in slices
                for reference in item.get("metadata", {}).get("ownerReferences", [])
            ):
                return
            time.sleep(1)
        raise _BASE.SmokeFailure("db-public EndpointSlices did not clear within the cleanup bound")

    def cleanup_additional_resources(self) -> None:
        expected = self.audit_context
        configmaps = (expected["report_name"], expected["baseline_name"])
        for name in configmaps:
            obj = self.get("configmaps", name)
            if not obj:
                continue
            if name not in self.artifact_create_intents:
                raise _BASE.SmokeFailure("Cleanup refused to adopt an audit ConfigMap without create intent")
            summary = self.record_created_artifact(obj)
            self.raw_delete_uid("configmap", name, summary["uid"])
            self.wait_absent("configmap", name)
            self._checkpoint("configmap-" + name + "-absent")

        for kind, name in (
            ("service", "db-public"),
            ("rolebinding", "db-rolebinding"),
            ("role", "db-role"),
            ("serviceaccount", "db-sa"),
        ):
            uid = self.created.get((kind, name))
            if not uid:
                continue
            obj = self.get(kind, name)
            if not obj:
                continue
            metadata = obj.get("metadata", {})
            if metadata.get("uid") != uid or metadata.get("labels", {}).get("crdb-library-run") != self.run_id:
                raise _BASE.SmokeFailure(f"Cleanup stopped because {kind}/{name} identity or ownership changed")
            if kind in {"role", "rolebinding"}:
                self._delete_rbac_uid(kind, name, uid)
            else:
                self.raw_delete_uid(kind, name, uid)
            self.wait_absent(kind, name)
            self._checkpoint(f"{kind}-{name}-absent")
            if kind == "service":
                self._wait_service_slices_absent(uid)


def _pod_uids(fixture: AuditFixture) -> dict[str, str]:
    pods = fixture.get("pods").get("items", [])
    selected = {
        pod.get("metadata", {}).get("name"): pod.get("metadata", {}).get("uid")
        for pod in pods
        if pod.get("metadata", {}).get("name") in {f"db-{ordinal}" for ordinal in range(_NODE_COUNT)}
    }
    expected = {f"db-{ordinal}" for ordinal in range(_NODE_COUNT)}
    if set(selected) != expected or any(not isinstance(uid, str) or not uid for uid in selected.values()):
        raise _BASE.SmokeFailure("Expected all three selected Pod UIDs")
    return dict(sorted((name, uid) for name, uid in selected.items()))


def _library(fixture: AuditFixture) -> tuple[CrdbLibrary, WorkloadRef]:
    library = CrdbLibrary(KubectlAdapter(kubectl=fixture.args.kubectl))
    return library, WorkloadRef(fixture.namespace, "db", container_name="db")


def _reconcile(fixture: AuditFixture, lifecycle: Lifecycle, tls: bool, timeout: float):
    library, ref = _library(fixture)
    result = library.reconcile(
        ref,
        Requirement(
            lifecycle,
            minimum_nodes=_NODE_COUNT,
            tls_mode=TLSMode.TLS if tls else TLSMode.INSECURE,
        ),
        timeout=timeout,
        poll_interval=2,
        per_node_timeout=5,
    )
    if result.assessment.status is not ProbeStatus.SATISFIED:
        raise _BASE.SmokeFailure(f"CockroachDB did not satisfy {lifecycle.value} readiness")
    return result


def _initialize_fixture(fixture: AuditFixture, *, tls: bool, timeout: float) -> dict[str, Any]:
    fixture.set_stage("wait-for-three-pods-running-before-kubernetes-ready")
    deadline = time.monotonic() + timeout
    expected = {f"db-{ordinal}" for ordinal in range(_NODE_COUNT)}
    while time.monotonic() < deadline:
        pods = fixture.get("pods").get("items", [])
        running = {
            item.get("metadata", {}).get("name")
            for item in pods
            if item.get("status", {}).get("phase") == "Running"
            and not item.get("metadata", {}).get("deletionTimestamp")
        }
        if expected <= running:
            break
        time.sleep(1)
    else:
        raise _BASE.SmokeFailure("All three audit Pods did not reach Running before the bounded wait")

    fixture._checkpoint("three-pods-running-before-ready")
    fixture.set_stage("positive-deployed-uninitialized-observation")
    deployed = _reconcile(fixture, Lifecycle.DEPLOYED, tls, timeout=180)
    health = deployed.assessment.health
    if health.lifecycle is not Lifecycle.DEPLOYED or set(health.uninitialized_pods) != expected:
        raise _BASE.SmokeFailure("Fixture was not positively observed as deployed and uninitialized")
    fixture._checkpoint("positive-deployed-uninitialized-observed")

    fixture.init(tls)
    fixture.set_stage("initialized-semantic-readiness")
    _reconcile(fixture, Lifecycle.INITIALIZED, tls, timeout=240)
    fixture.wait_ready(timeout=timeout)
    return {
        "preinit_pods_running_before_kubernetes_ready": True,
        "preinit_lifecycle": Lifecycle.DEPLOYED.value,
        "preinit_uninitialized_pods": sorted(expected),
        "explicit_init_listener": "RPC 26258",
        "postinit_lifecycle": Lifecycle.INITIALIZED.value,
    }


def _create_tracked(fixture: AuditFixture, resource: Mapping[str, Any]) -> dict[str, Any]:
    metadata = resource.get("metadata", {})
    kind, name = resource.get("kind"), metadata.get("name") if isinstance(metadata, Mapping) else None
    if not isinstance(kind, str) or not isinstance(name, str):
        raise _BASE.SmokeFailure("Fixture create request is missing its resource identity")
    fixture.phase_data.setdefault("resource_create_intents", []).append({"kind": kind, "name": name})
    fixture._checkpoint(f"create-intent-{kind.lower()}-{name}")
    created = fixture.create(dict(resource))
    identity = {
        "kind": str(created["kind"]).lower(),
        "name": str(created["metadata"]["name"]),
        "uid": str(created["metadata"]["uid"]),
    }
    fixture.phase_data.setdefault("created_resource_identities", []).append(identity)
    fixture._checkpoint(f"resource-uid-recorded-{identity['kind']}-{identity['name']}")
    return created


def _render(value: Any, substitutions: Mapping[str, str]) -> Any:
    if isinstance(value, str):
        for key, replacement in substitutions.items():
            value = value.replace("${" + key + "}", replacement)
        return value
    if isinstance(value, list):
        return [_render(item, substitutions) for item in value]
    if isinstance(value, dict):
        return {key: _render(item, substitutions) for key, item in value.items()}
    return value


def _case_rbac_documents(fixture: AuditFixture) -> list[dict[str, Any]]:
    source = AUDIT_ROOT / "resource" / "rbac.yaml"
    substitutions = {"BENCH_NAMESPACE": fixture.namespace, "BENCH_PARAM_CLUSTER_NAME": "db"}
    documents = [
        _render(document, substitutions)
        for document in yaml.safe_load_all(source.read_text(encoding="utf-8"))
        if document is not None
    ]
    for document in documents:
        document["metadata"].setdefault("labels", {}).update(fixture.labels)
    return documents


def small_bootstrap_documents(fixture: AuditFixture) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    documents = _case_rbac_documents(fixture)
    headless, public = fixture.service_manifests()
    for service in (headless, public):
        service["metadata"].setdefault("labels", {}).update(fixture.labels)
        service["spec"]["selector"] = dict(fixture.labels)
    statefulset = fixture.statefulset_manifest(tls=False)
    statefulset["metadata"]["labels"] = dict(fixture.labels)
    spec = statefulset["spec"]
    spec["replicas"] = _NODE_COUNT
    spec["selector"]["matchLabels"] = dict(fixture.labels)
    template = spec["template"]
    template["metadata"]["labels"] = dict(fixture.labels)
    template["spec"]["nodeSelector"] = {"kubernetes.io/hostname": fixture.args.node}
    for claim in spec.get("volumeClaimTemplates", []):
        claim["metadata"].setdefault("labels", {}).update(fixture.labels)
        claim["spec"]["storageClassName"] = fixture.storage_class
        claim["spec"]["resources"]["requests"]["storage"] = "1Gi"
    container = template["spec"]["containers"][0]
    container["image"] = fixture.args.image
    container["imagePullPolicy"] = "Never"
    container["resources"] = {
        "requests": {"cpu": "100m", "memory": "256Mi"},
        "limits": {"cpu": "1", "memory": "1Gi"},
    }
    command = container.get("command", [])
    if len(command) != 3 or "--cache=128MiB" not in command[2] or "--max-sql-memory=128MiB" not in command[2]:
        raise _BASE.SmokeFailure("Temporary audit manifest must retain bounded CockroachDB memory flags")
    statefulset["spec"]["template"]["spec"]["terminationGracePeriodSeconds"] = max(
        30, int(statefulset["spec"]["template"]["spec"].get("terminationGracePeriodSeconds", 30))
    )
    documents.extend((headless, public, statefulset))
    return documents, statefulset


def write_small_manifest_dir(directory: Path, fixture: AuditFixture) -> None:
    documents, _ = small_bootstrap_documents(fixture)
    (directory / "rbac.yaml").write_text(yaml.safe_dump_all(documents[:3], sort_keys=False), encoding="utf-8")
    (directory / "services.yaml").write_text(yaml.safe_dump_all(documents[3:5], sort_keys=False), encoding="utf-8")
    (directory / "statefulset.yaml").write_text(yaml.safe_dump(documents[5], sort_keys=False), encoding="utf-8")


@contextmanager
def case_modules():
    saved_path = list(sys.path)
    names = ("cluster", "storage", "audit", "environment")
    saved_modules = {name: sys.modules.pop(name) for name in names if name in sys.modules}
    sys.path.insert(0, str(AUDIT_SCRIPTS))
    try:
        yield SimpleNamespace(
            cluster=importlib.import_module("cluster"),
            storage=importlib.import_module("storage"),
            audit=importlib.import_module("audit"),
            environment=importlib.import_module("environment"),
        )
    finally:
        for name in names:
            sys.modules.pop(name, None)
        sys.modules.update(saved_modules)
        sys.path[:] = saved_path


def _command_event(operation: str, returncode: int | None, started: float, outcome: str) -> dict[str, Any]:
    return {
        "operation": operation,
        "outcome": outcome,
        "returncode": returncode,
        "elapsed_ms": round((time.monotonic() - started) * 1000),
    }


def _safe_case_stderr(stderr: Any, trusted_input: Mapping[str, Any] | None) -> str:
    text = str(stderr or "")
    stage_key = trusted_input.get("key") if isinstance(trusted_input, Mapping) else None
    if isinstance(stage_key, str) and stage_key:
        text = text.replace(stage_key, "<REDACTED stage key>")
    return _BASE._safe_diagnostic_text(text, limit=300)[-1200:]


def run_case_command(
    fixture: AuditFixture,
    script: Path,
    arguments: tuple[str, ...],
    *,
    timeout: float,
    trusted_input: Mapping[str, Any] | None = None,
    expect_success: bool = True,
    expected_failure_text: str | None = None,
    setting_name: str | None = None,
    setting_value: str | None = None,
    create_intent_name: str | None = None,
) -> dict[str, Any]:
    operation = f"{script.name} {' '.join(arguments)}"
    fixture.set_stage(operation)
    if create_intent_name:
        fixture.record_artifact_intent(create_intent_name)
    input_text = json.dumps(dict(trusted_input), separators=(",", ":")) if trusted_input is not None else None
    started = time.monotonic()
    try:
        with case_environment(fixture, setting_name=setting_name, setting_value=setting_value):
            result = subprocess.run(
                [sys.executable, str(script), *arguments],
                input=input_text,
                text=True,
                capture_output=True,
                timeout=timeout,
                check=False,
                env=os.environ.copy(),
            )
    except subprocess.TimeoutExpired as error:
        event = _command_event(operation, None, started, "timeout")
        stderr_excerpt = _safe_case_stderr(error.stderr, trusted_input)
        if stderr_excerpt:
            event["safe_stderr"] = stderr_excerpt
        fixture._record_command(event)
        fixture.phase_data.setdefault("case_command_failures", []).append(dict(event))
        raise _BASE.SmokeFailure(f"{operation} timed out", command_event=event) from error

    expected_code = 0 if expect_success else 1
    matched_failure = expected_failure_text is None or expected_failure_text in (result.stderr or "")
    passed = result.returncode == expected_code and matched_failure
    outcome = "passed" if passed else "exit_error"
    event = _command_event(operation, result.returncode, started, outcome)
    if not passed:
        stderr_excerpt = _safe_case_stderr(result.stderr, trusted_input)
        if stderr_excerpt:
            event["safe_stderr"] = stderr_excerpt
    fixture._record_command(event)
    if not passed:
        fixture.phase_data.setdefault("case_command_failures", []).append(dict(event))

    artifact_capture_error: Exception | None = None
    if create_intent_name:
        # Recover a ConfigMap UID even if the CLI created it and then failed
        # during its own post-create verification.
        try:
            fixture.capture_artifact_if_owned(create_intent_name)
        except Exception as error:
            artifact_capture_error = error
            fixture.phase_data.setdefault("artifact_capture_failures", []).append(
                {
                    "name": create_intent_name,
                    "type": type(error).__name__,
                    "detail": _BASE._safe_diagnostic_text(error),
                }
            )
    if not passed:
        detail = f"; stderr: {event['safe_stderr']}" if event.get("safe_stderr") else ""
        raise _BASE.SmokeFailure(
            f"{operation} did not meet its expected command result{detail}",
            command_event=event,
        )
    if artifact_capture_error:
        raise _BASE.SmokeFailure(
            f"{operation} succeeded but its created ConfigMap identity could not be safely recorded",
            command_event=event,
        ) from artifact_capture_error
    return event


def _audit_private(key: str, *, frozen: bool) -> dict[str, Any]:
    return {"key": key, "frozen": frozen}


def _run_oracle(fixture: AuditFixture, key: str, *, should_accept: bool) -> dict[str, Any]:
    event = run_case_command(
        fixture,
        AUDIT_ORACLE,
        (),
        timeout=180,
        trusted_input=_audit_private(key, frozen=True),
        expect_success=should_accept,
        expected_failure_text=None if should_accept else "current-stage audit report is missing",
    )
    return {"outcome": event["outcome"], "returncode": event["returncode"]}


def _run_audit_units(fixture: AuditFixture, unit: str, *, trusted: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
    events = []
    for mode in ("probe", "apply", "verify"):
        create_intent = None
        if unit == "baseline" and mode == "apply" and trusted is not None and trusted.get("frozen") is False:
            create_intent = fixture.audit_context["baseline_name"]
            if fixture.get("configmaps", create_intent):
                raise _BASE.SmokeFailure("A supposedly fresh audit baseline already exists")
        event = run_case_command(
            fixture,
            AUDIT_PREPARE,
            (unit, mode),
            timeout={"environment": 180, "report": 30, "baseline": 60}[unit],
            trusted_input=trusted if unit == "baseline" else None,
            create_intent_name=create_intent,
        )
        events.append(event)
    return events


def _artifact_summary(fixture: AuditFixture, name: str) -> dict[str, Any]:
    obj = fixture.get("configmaps", name)
    if not obj:
        raise _BASE.SmokeFailure("Expected audit ConfigMap is missing")
    return fixture.record_created_artifact(obj)


def _audit_report_from_live_observations(fixture: AuditFixture) -> tuple[dict[str, Any], dict[str, Any]]:
    with case_environment(fixture):
        with case_modules() as modules:
            cluster = modules.cluster.Cluster(fixture.namespace, "db")
            audit = modules.audit.Audit(cluster)
            observed = audit.snapshot()
            if observed["report"]["identity"] != {
                **fixture.audit_context["context"],
                "cluster_id": observed["report"]["identity"].get("cluster_id"),
            }:
                raise _BASE.SmokeFailure("Observed report identity does not match the live audit context")
            if observed["report"].get("replicas") != _NODE_COUNT or len(observed["report"].get("nodes", [])) != _NODE_COUNT:
                raise _BASE.SmokeFailure("Observed audit report did not cover all three live database nodes")
            state_hash = hashlib.sha256(
                json.dumps(observed["state"], sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            return dict(observed["report"]), {
                "report_name": audit.report_name,
                "baseline_name": audit.baseline_name,
                "labels": dict(audit.labels),
                "state_sha256": state_hash,
                "report_sha256": hashlib.sha256(
                    json.dumps(observed["report"], sort_keys=True, separators=(",", ":")).encode()
                ).hexdigest(),
            }


def _create_observed_report(fixture: AuditFixture, report: Mapping[str, Any]) -> dict[str, Any]:
    name = fixture.audit_context["report_name"]
    if fixture.get("configmaps", name):
        raise _BASE.SmokeFailure("Current-stage report unexpectedly exists before live observation")
    fixture.record_artifact_intent(name)
    resource = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": name,
            "namespace": fixture.namespace,
            "labels": dict(fixture.audit_context["labels"]),
        },
        "data": {
            "findings.json": json.dumps(dict(report), sort_keys=True, separators=(",", ":")),
        },
    }
    created = _create_tracked(fixture, resource)
    return fixture.record_created_artifact(created)


def _sql(fixture: AuditFixture, query: str, *, tls: bool) -> str:
    command = [
        *fixture.kubectl_base,
        "--namespace", fixture.namespace,
        "exec", "db-0", "--container=db", "--",
        "/cockroach/cockroach", "sql",
        "--host=localhost", "--port=26257", "--format=csv",
        "--certs-dir=/cockroach/cockroach-certs" if tls else "--insecure",
        "-e", query,
    ]
    return _BASE.run(command, timeout=35, operation="readonly-audit fixture SQL", observer=fixture._record_command)


def _witness_hash(fixture: AuditFixture, *, tls: bool) -> tuple[int, str]:
    output = _sql(fixture, f"SELECT id, payload FROM {_WITNESS_TABLE} ORDER BY id", tls=tls)
    import csv

    rows = [row for row in csv.reader(output.splitlines()) if row]
    if rows != _WITNESS_ROWS:
        raise _BASE.SmokeFailure("Audit preservation witness did not return the exact two expected rows")
    canonical = json.dumps(rows, ensure_ascii=False, separators=(",", ":"))
    return len(rows) - 1, hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _create_witness(fixture: AuditFixture, *, tls: bool) -> tuple[int, str]:
    _sql(fixture, f"CREATE DATABASE {_WITNESS_DB}", tls=tls)
    _sql(
        fixture,
        f"CREATE TABLE {_WITNESS_TABLE} (id INT PRIMARY KEY, payload STRING NOT NULL)",
        tls=tls,
    )
    _sql(
        fixture,
        f"INSERT INTO {_WITNESS_TABLE} VALUES "
        "(1, 'observed before audit preparation'), (2, 'retained across audit preparation')",
        tls=tls,
    )
    return _witness_hash(fixture, tls=tls)


def _accepted_summary(state: Any) -> dict[str, Any]:
    return {
        "cluster_id": state.cluster_id,
        "node_ids": state.node_ids,
        "sql_versions": state.sql_versions,
        "tls_mode": state.tls_mode.value,
        "image": state.image,
        "desired_replicas": state.desired_replicas,
        "workload_spec_hash": state.workload_spec_hash,
        "pvc_identities": state.pvc_identities,
        "certificate_fingerprints": state.certificate_fingerprints,
        "service_routing": state.service_routing,
    }


def _snapshot_inherited(fixture: AuditFixture, *, tls: bool) -> tuple[Any, dict[str, str], tuple[int, str]]:
    library, ref = _library(fixture)
    state = library.capture_accepted_state(ref, per_node_timeout=5)
    return state, _pod_uids(fixture), _witness_hash(fixture, tls=tls)


def _assert_preserved(
    fixture: AuditFixture,
    *,
    tls: bool,
    accepted: Any,
    pods: Mapping[str, str],
    witness: tuple[int, str],
) -> dict[str, Any]:
    library, ref = _library(fixture)
    current = library.capture_accepted_state(ref, per_node_timeout=5)
    current_pods = _pod_uids(fixture)
    current_witness = _witness_hash(fixture, tls=tls)
    if current != accepted:
        raise _BASE.SmokeFailure("Audit preparation changed the full accepted workload snapshot")
    if current_pods != pods:
        raise _BASE.SmokeFailure("Audit preparation rolled or replaced a selected database Pod")
    if current_witness != witness:
        raise _BASE.SmokeFailure("Audit preparation changed the persisted two-row SQL witness")
    verification = library.verify_accepted_state(ref, accepted, per_node_timeout=5)
    if verification.status is not ProbeStatus.SATISFIED:
        raise _BASE.SmokeFailure("Accepted state did not verify after audit preparation")
    return {
        "accepted_state": _accepted_summary(current),
        "pod_uids": current_pods,
        "witness_row_count": current_witness[0],
        "witness_sha256": current_witness[1],
        "accepted_state_verified": True,
    }


def _run_settings_preconditions(fixture: AuditFixture) -> list[dict[str, Any]]:
    events = []
    for mode in ("probe", "apply", "verify"):
        events.append(
            run_case_command(
                fixture,
                SETTINGS_TARGET,
                (mode,),
                timeout={"probe": 90, "apply": 150, "verify": 90}[mode],
                setting_name="kv.snapshot_rebalance.max_rate",
                setting_value="128MiB",
            )
        )
    return events


def _controlled_setting(fixture: AuditFixture, *, tls: bool) -> str:
    _sql(fixture, "SET CLUSTER SETTING kv.snapshot_rebalance.max_rate = '128MiB'", tls=tls)
    return _read_controlled_setting(fixture, tls=tls)


def _read_controlled_setting(fixture: AuditFixture, *, tls: bool) -> str:
    output = _sql(fixture, "SHOW CLUSTER SETTING kv.snapshot_rebalance.max_rate", tls=tls)
    values = [line.strip() for line in output.splitlines()[1:] if line.strip()]
    if len(values) != 1 or values[0].replace(" ", "").casefold() != "128mib":
        raise _BASE.SmokeFailure("Controlled cluster setting did not read back as 128MiB")
    return values[0]


def _create_existing_fixture(args: argparse.Namespace, fixture: AuditFixture, *, tls: bool, phase_data: dict[str, Any]) -> None:
    fixture.set_stage("create-native-audit-dependencies")
    for resource in _case_rbac_documents(fixture):
        _create_tracked(fixture, resource)
    headless, public = fixture.service_manifests()
    _create_tracked(fixture, headless)
    _create_tracked(fixture, public)
    if tls:
        with tempfile.TemporaryDirectory(prefix="crdb-readonly-audit-certs-") as temporary:
            _HEALTH.make_case_certificates(Path(temporary), fixture.namespace)
            fixture.make_secret(Path(temporary))
            fixture.set_stage("create-https-audit-statefulset")
            _create_tracked(fixture, fixture.statefulset_manifest(tls=True))
    else:
        fixture.set_stage("create-http-audit-statefulset")
        _create_tracked(fixture, fixture.statefulset_manifest(tls=False))
    phase_data["fixture_statefulset_uid"] = fixture.created[("statefulset", "db")]


def _run_tls_audit_phase(args: argparse.Namespace, fixture: AuditFixture, phase_data: dict[str, Any]) -> dict[str, Any]:
    phase_data["startup"] = _initialize_fixture(fixture, tls=True, timeout=args.ready_timeout)
    phase_data["settings_case_preconditions"] = _run_settings_preconditions(fixture)
    setting_value = _controlled_setting(fixture, tls=True)
    witness_before = _create_witness(fixture, tls=True)
    accepted_before, pod_uids_before, witness_before = _snapshot_inherited(fixture, tls=True)
    phase_data["controlled_setting"] = setting_value
    phase_data["preparation_snapshot"] = {
        "accepted_state": _accepted_summary(accepted_before),
        "pod_uids": pod_uids_before,
        "witness_row_count": witness_before[0],
        "witness_sha256": witness_before[1],
    }

    phase_data["audit_environment_units"] = _run_audit_units(fixture, "environment")
    phase_data["report_absence_units"] = _run_audit_units(fixture, "report")
    key = Fernet.generate_key().decode("ascii")
    phase_data["stage_key_used_only_in_memory_and_stdin"] = True
    apply_false = run_case_command(
        fixture,
        AUDIT_PREPARE,
        ("baseline", "apply"),
        timeout=240,
        trusted_input=_audit_private(key, frozen=False),
        create_intent_name=fixture.audit_context["baseline_name"],
    )
    phase_data["baseline_initial_apply"] = apply_false
    baseline_before = _artifact_summary(fixture, fixture.audit_context["baseline_name"])
    phase_data["baseline_initial_identity"] = baseline_before

    phase_data["baseline_frozen_verify_units"] = [
        run_case_command(
            fixture,
            AUDIT_PREPARE,
            ("baseline", mode),
            timeout=60,
            trusted_input=_audit_private(key, frozen=True),
        )
        for mode in ("probe", "verify", "apply", "verify")
    ]
    wrong_key = Fernet.generate_key().decode("ascii")
    phase_data["wrong_stage_key_rejected"] = run_case_command(
        fixture,
        AUDIT_PREPARE,
        ("baseline", "verify"),
        timeout=60,
        trusted_input=_audit_private(wrong_key, frozen=True),
        expect_success=False,
        expected_failure_text="baseline authentication failed",
    )
    baseline_after_retry = _artifact_summary(fixture, fixture.audit_context["baseline_name"])
    if baseline_after_retry != baseline_before:
        raise _BASE.SmokeFailure("Authenticated frozen retry rewrote the encrypted baseline")
    phase_data["baseline_frozen_retry_preserved"] = baseline_after_retry

    phase_data["oracle_missing_report_rejection"] = _run_oracle(fixture, key, should_accept=False)
    report, live_observation = _audit_report_from_live_observations(fixture)
    phase_data["live_report_snapshot"] = live_observation
    phase_data["report_observation_method"] = (
        "Actual Audit.snapshot over current SQL and Kubernetes observations; "
        "the same reader used by the oracle, not an independent parser."
    )
    phase_data["report_create_identity"] = _create_observed_report(fixture, report)
    phase_data["oracle_correct_report_acceptance"] = _run_oracle(fixture, key, should_accept=True)
    phase_data["preservation_after_audit"] = _assert_preserved(
        fixture,
        tls=True,
        accepted=accepted_before,
        pods=pod_uids_before,
        witness=witness_before,
    )
    baseline_final = _artifact_summary(fixture, fixture.audit_context["baseline_name"])
    if baseline_final != baseline_before:
        raise _BASE.SmokeFailure("Oracle verification changed the encrypted frozen baseline")
    phase_data["baseline_final_identity"] = baseline_final
    setting_after_audit = _read_controlled_setting(fixture, tls=True)
    if setting_after_audit.replace(" ", "").casefold() != setting_value.replace(" ", "").casefold():
        raise _BASE.SmokeFailure("Readonly-audit preparation changed the controlled cluster setting")
    phase_data["controlled_setting_after_audit"] = setting_after_audit
    phase_data["stage_key_values_written_to_evidence"] = False
    return phase_data


def _install_tracked_case_cluster(
    case_cluster: Any,
    fixture: AuditFixture,
    phase_data: dict[str, Any],
) -> None:
    def tracked_kubectl(*args: str, timeout: float = 20, input_text: str | None = None, namespace: str | None = None):
        document = None
        if args and args[0] == "create" and input_text:
            try:
                document = json.loads(input_text)
            except json.JSONDecodeError as error:
                raise _BASE.SmokeFailure("Case bootstrap issued an invalid create document") from error
            kind, name = document.get("kind"), document.get("metadata", {}).get("name")
            phase_data.setdefault("resource_create_intents", []).append({"kind": kind, "name": name})
            fixture._checkpoint(f"create-intent-{str(kind).lower()}-{name}")
        result_text = fixture.kubectl(
            *args,
            namespace=fixture.namespace if namespace is None else (namespace or None),
            timeout=timeout,
            input_text=input_text,
            diagnose_api_error=True,
        )
        if document is not None:
            try:
                created = json.loads(result_text)
                metadata = created["metadata"]
                kind, name, uid = str(created["kind"]).lower(), str(metadata["name"]), str(metadata["uid"])
            except (json.JSONDecodeError, KeyError, TypeError) as error:
                raise _BASE.SmokeFailure("Case bootstrap create did not return a safe resource UID") from error
            if not uid or kind != str(document.get("kind", "")).lower() or name != document.get("metadata", {}).get("name"):
                raise _BASE.SmokeFailure("Case bootstrap create returned a different resource identity")
            fixture.created[(kind, name)] = uid
            phase_data.setdefault("created_resource_identities", []).append({"kind": kind, "name": name, "uid": uid})
            fixture._checkpoint(f"resource-uid-recorded-{kind}-{name}")
        return subprocess.CompletedProcess(list(args), 0, result_text, "")

    def tracked_create(resource: Mapping[str, Any]) -> None:
        response = tracked_kubectl(
            "create", "-f", "-", "--output=json",
            input_text=json.dumps(dict(resource), separators=(",", ":")),
        )
        case_cluster.require(response)

    case_cluster.kubectl = tracked_kubectl
    case_cluster.create = tracked_create


def _bootstrap_fresh_through_environment(
    fixture: AuditFixture,
    manifest_dir: Path,
    phase_data: dict[str, Any],
) -> None:
    with case_environment(fixture):
        with case_modules() as modules:
            case_cluster = modules.cluster.Cluster(fixture.namespace, "db", manifest_dir=manifest_dir)
            _install_tracked_case_cluster(case_cluster, fixture, phase_data)
            environment = modules.environment.Environment(
                case_cluster,
                library=CrdbLibrary(KubectlAdapter(kubectl=fixture.args.kubectl)),
            )
            fixture.set_stage("fresh-bootstrap-through-audit-environment-apply")
            environment.apply()
    if fixture.created.get(("statefulset", "db")) is None:
        raise _BASE.SmokeFailure("Fresh audit bootstrap did not journal its StatefulSet UID")
    expected = {
        ("serviceaccount", "db-sa"),
        ("role", "db-role"),
        ("rolebinding", "db-rolebinding"),
        ("service", "db"),
        ("service", "db-public"),
        ("statefulset", "db"),
    }
    if not expected.issubset(fixture.created):
        raise _BASE.SmokeFailure("Fresh audit bootstrap did not journal all six declared resources")


def _run_fresh_phase(args: argparse.Namespace, fixture: AuditFixture, phase_data: dict[str, Any]) -> dict[str, Any]:
    fixture.set_stage("fresh-small-manifest-bootstrap")
    with tempfile.TemporaryDirectory(prefix="crdb-readonly-audit-manifests-") as temporary:
        manifest_dir = Path(temporary)
        write_small_manifest_dir(manifest_dir, fixture)
        _bootstrap_fresh_through_environment(fixture, manifest_dir, phase_data)
    fixture.wait_ready(timeout=args.ready_timeout)
    phase_data["created_resources"] = list(phase_data.get("created_resource_identities", []))
    library, ref = _library(fixture)
    accepted_before = library.capture_accepted_state(ref, per_node_timeout=5)
    pod_uids_before = _pod_uids(fixture)
    witness_before = _create_witness(fixture, tls=False)
    commands = [
        run_case_command(fixture, AUDIT_PREPARE, ("environment", mode), timeout=180)
        for mode in ("probe", "apply", "verify")
    ]
    preserved = _assert_preserved(
        fixture,
        tls=False,
        accepted=accepted_before,
        pods=pod_uids_before,
        witness=witness_before,
    )
    return {
        "bootstrap_path": "actual Environment.apply with Cluster(manifest_dir=temporary)",
        "created_resource_count": len(phase_data["created_resources"]),
        "resource_identities": phase_data["created_resources"],
        "cli_environment_probe_apply_verify": commands,
        "post_bootstrap_preservation": preserved,
        "temporary_manifest_limits": {
            "nodes": 3,
            "pvc_each": "1Gi",
            "cache": "128MiB",
            "requests_each": {"cpu": "100m", "memory": "256Mi"},
            "limits_each": {"cpu": "1", "memory": "1Gi"},
            "image_pull_policy": "Never",
        },
    }


def phase(args: argparse.Namespace, name: str, run_id: str, evidence_dir: Path) -> dict[str, Any]:
    fixture = AuditFixture(args, name, run_id)
    phase_data: dict[str, Any] = {
        "phase": name,
        "run_id": run_id,
        "namespace": fixture.namespace,
        "tls_mode": "TLS" if name == "tls" else "INSECURE",
    }
    fixture.phase_data = phase_data
    failure: BaseException | None = None
    cleanup_failure: BaseException | None = None

    def checkpoint(status: str) -> None:
        _BASE.write_json_atomic(
            evidence_dir / f"{name}-journal.json",
            {
                "phase": name,
                "run_id": run_id,
                "namespace": fixture.namespace,
                "status": status,
                "namespace_uid": fixture.namespace_uid,
                "namespace_baseline": sorted(fixture.namespace_baseline),
                "owned_resource_uids": [
                    {"kind": kind, "name": resource_name, "uid": uid}
                    for (kind, resource_name), uid in sorted(fixture.created.items())
                ],
                "safe_observations": phase_data,
            },
        )

    fixture.checkpoint_callback = checkpoint
    checkpoint("preflight-started")
    try:
        fixture.set_stage("three-node-capacity-preflight")
        preflight = _HEALTH.preflight(args, fixture)
        fixture.storage_class = preflight["storage_class"]
        phase_data["capacity_preflight"] = preflight
        checkpoint("preflight-passed")
        fixture.set_stage("create-isolated-namespace")
        fixture.prepare_namespace()
        if name == "tls":
            _create_existing_fixture(args, fixture, tls=True, phase_data=phase_data)
            phase_data.update(_run_tls_audit_phase(args, fixture, phase_data))
        elif name == "fresh":
            phase_data.update(_run_fresh_phase(args, fixture, phase_data))
        else:
            raise _BASE.SmokeFailure("Unknown readonly-audit smoke phase")
        checkpoint("work-complete")
    except BaseException as error:
        failure = error
        phase_data["failure_stage"] = fixture.stage_snapshot()
        if isinstance(error, _BASE.SmokeFailure) and error.command_event:
            phase_data["failure_command"] = dict(error.command_event)
        phase_data["execution_failure"] = {
            "type": type(error).__name__,
            "detail": _BASE._safe_diagnostic_text(error) if isinstance(error, _BASE.SmokeFailure) else "details withheld",
        }
        try:
            fixture.capture_diagnostics(phase_data, label="before-cleanup")
        except BaseException as diagnostic_error:
            phase_data["diagnostic_capture_failure"] = {
                "type": type(diagnostic_error).__name__,
                "detail": _BASE._safe_diagnostic_text(diagnostic_error),
            }
    try:
        fixture.cleanup()
        phase_data["cleanup_verdict"] = "completed with exact UID preconditions and normal deletion grace"
    except BaseException as error:
        cleanup_failure = error
        phase_data["cleanup_failure"] = {
            "type": type(error).__name__,
            "detail": _BASE._safe_diagnostic_text(error) if isinstance(error, _BASE.SmokeFailure) else "details withheld",
        }
        phase_data["cleanup_verdict"] = "incomplete; ownership journal retained"
    phase_data["stage_timing"] = fixture.stage_snapshot()
    phase_data["command_trace"] = list(fixture.command_trace[-80:])
    phase_data["result"] = "passed" if failure is None and cleanup_failure is None else "failed"
    _BASE.write_json_atomic(evidence_dir / f"{name}-phase.json", phase_data)
    checkpoint("phase-finished")
    if failure or cleanup_failure:
        raise _BASE.SmokeFailure(
            f"readonly-audit {name} phase failed; inspect {evidence_dir / f'{name}-phase.json'} and its ownership journal"
        ) from (failure or cleanup_failure)
    return phase_data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kubectl", default="kubectl")
    parser.add_argument("--docker", default="docker")
    parser.add_argument("--node", default="kind-worker")
    parser.add_argument("--image", default="cockroachdb/cockroach:v24.1.0")
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--ready-timeout", type=float, default=300.0)
    args = parser.parse_args(argv)
    args.context = None  # Native case scripts always use the current kubectl context.
    if not math.isfinite(args.ready_timeout) or not 0 < args.ready_timeout <= 300:
        raise _BASE.SmokeFailure("Ready timeout must be finite and within its bounded range")
    if not _BASE.re.fullmatch(r"cockroachdb/cockroach:v24\.1\.0", args.image):
        raise _BASE.SmokeFailure("Readonly-audit proof supports only cached CockroachDB v24.1.0")
    if args.kubectl != "kubectl" and Path(args.kubectl).name != "kubectl":
        raise _BASE.SmokeFailure("Native case scripts require a kubectl executable named 'kubectl'")
    evidence_dir = args.evidence_dir.expanduser().resolve()
    if evidence_dir.exists():
        raise _BASE.SmokeFailure("Evidence directory must be new; refusing to overwrite previous records")
    evidence_dir.mkdir(parents=True, exist_ok=False)
    run_id = f"{time.strftime('%y%m%d')}-{os.getpid():x}"
    if not _BASE.re.fullmatch(r"[a-z0-9-]{1,16}", run_id):
        raise _BASE.SmokeFailure("Generated run identity is not a valid Kubernetes label")
    print(f"Starting sequential readonly-audit case proof; run id {run_id}", flush=True)
    results = []
    for name in ("tls", "fresh"):
        result = phase(args, name, run_id, evidence_dir)
        results.append(result)
        print(f"{name} fixture completed and UID-cleaned: {result['namespace']}", flush=True)
    _BASE.write_json_atomic(evidence_dir / "live-summary.json", {"run_id": run_id, "phases": results})
    print(f"Readonly-audit case proof passed; safe evidence at {evidence_dir}", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except _BASE.SmokeFailure as error:
        print(f"READONLY-AUDIT CASE PROOF STOPPED: {error}", file=sys.stderr, flush=True)
        raise SystemExit(2)

#!/usr/bin/env python3
"""Bounded live proof for the migrated health-check-recovery preconditions.

This harness reuses the owned fixture, capacity inventory, redacted diagnostics,
and UID-guarded cleanup from ``experiments/crdb-common-library/live_smoke.py``.
It creates three one-GiB PVC-backed nodes on one cached Kind image at a time.
It does not invoke a solver or deploy a controller.
"""

from __future__ import annotations

import argparse
import csv
from contextlib import contextmanager
from dataclasses import asdict, replace
from decimal import Decimal
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[2]
BASE_PATH = ROOT / "experiments" / "crdb-common-library" / "live_smoke.py"
PREPARE_PATH = ROOT / "cases" / "cockroachdb" / "health-check-recovery" / "scripts" / "prepare.py"
ORACLE_PATH = ROOT / "cases" / "cockroachdb" / "health-check-recovery" / "oracle" / "oracle.py"
_BASE_SPEC = importlib.util.spec_from_file_location("crdb_library_live_smoke", BASE_PATH)
if _BASE_SPEC is None or _BASE_SPEC.loader is None:
    raise RuntimeError("Could not load the reviewed common live-fixture helper")
_BASE = importlib.util.module_from_spec(_BASE_SPEC)
_BASE_SPEC.loader.exec_module(_BASE)

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


_NODE_COUNT = 3
_MIN_FREE_CPU = Decimal("0.5")  # 300m fixture requests plus 200m scheduling headroom.
_MIN_FREE_MEMORY = 3584 * 1024**2  # 3Gi aggregate container limits plus 512Mi headroom.
_MIN_HOST_FREE_BYTES = 8 * 1024**3
_MIN_KIND_DISK_FREE_BYTES = 4 * 1024**3
_NAMESPACE_LABELS = {"app.kubernetes.io/name": "cockroachdb", "app.kubernetes.io/instance": "db"}
_BASELINE_NAME = "db-health-recovery-baseline"
_WITNESS_DB = "crdb_case_health_recovery"
_WITNESS_TABLE = f"{_WITNESS_DB}.public.witness"
_NO_FAULT_REASON = "selected workload does not have this case's health fault"


class HealthCaseFixture(_BASE.Fixture):
    """Native-shaped three-node workload with run-owned extra resources."""

    def __init__(self, args: argparse.Namespace, phase: str, run_id: str):
        super().__init__(args, phase, run_id)
        self.name = "db"
        self.labels = {**_NAMESPACE_LABELS, "crdb-library-run": run_id}
        self.baseline_create_intent = False
        self.proof_mode = getattr(args, "proof_mode", "fault")

    def service_manifests(self) -> tuple[dict[str, Any], dict[str, Any]]:
        ports = [
            {"name": "sql", "port": 26257, "targetPort": "sql", "protocol": "TCP"},
            {"name": "rpc", "port": 26258, "targetPort": "rpc", "protocol": "TCP"},
            {"name": "http", "port": 8080, "targetPort": "http", "protocol": "TCP"},
        ]
        headless = {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "db", "namespace": self.namespace, "labels": self.labels},
            "spec": {
                "clusterIP": "None",
                "publishNotReadyAddresses": True,
                "selector": self.labels,
                "ports": ports,
            },
        }
        public = {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "db-public", "namespace": self.namespace, "labels": self.labels},
            "spec": {"selector": self.labels, "ports": ports},
        }
        return headless, public

    def service_account_manifest(self) -> dict[str, Any]:
        return {
            "apiVersion": "v1",
            "kind": "ServiceAccount",
            "metadata": {"name": "db-sa", "namespace": self.namespace, "labels": self.labels},
        }

    def statefulset_manifest(self, tls: bool) -> dict[str, Any]:
        manifest = super().statefulset_manifest(tls)
        spec = manifest["spec"]
        spec["replicas"] = _NODE_COUNT
        spec["template"]["spec"]["serviceAccountName"] = "db-sa"
        container = spec["template"]["spec"]["containers"][0]
        if tls:
            container["command"][2] = container["command"][2].replace(
                "--certs-dir=/cockroach/certs", "--certs-dir=/cockroach/cockroach-certs"
            )
            for mount in container["volumeMounts"]:
                if mount["name"] == "certs":
                    mount["mountPath"] = "/cockroach/cockroach-certs"
        if self.proof_mode == "recovery":
            # Keep kubelet liveness from restarting the process before the
            # case's bounded apply path can observe and recover the fault.
            # Readiness remains prompt so the proof can establish unready.
            container["livenessProbe"]["failureThreshold"] = 120
            container["readinessProbe"]["failureThreshold"] = 1
            container["readinessProbe"]["periodSeconds"] = 3
        return manifest

    def init(self, tls: bool) -> None:
        self.set_stage("explicit-cockroach-init")
        command = [
            *self.kubectl_base,
            "--namespace", self.namespace,
            "exec", "db-0", "--container=db", "--",
            "/cockroach/cockroach", "init",
            "--certs-dir=/cockroach/cockroach-certs" if tls else "--insecure",
            f"--host=db-0.db.{self.namespace}.svc.cluster.local:26258",
        ]
        _BASE.run(command, timeout=45, operation="cockroach init", observer=self._record_command)

    def wait_ready(self, timeout: float = 240) -> None:
        self.set_stage("all-three-pods-ready")
        deadline = time.monotonic() + timeout
        by_name: dict[str, dict[str, Any]] = {}
        while time.monotonic() < deadline:
            items = self.get("pods").get("items", [])
            by_name = {str(pod.get("metadata", {}).get("name", "")): pod for pod in items}
            if all(_pod_ready(by_name.get(f"db-{ordinal}")) for ordinal in range(_NODE_COUNT)):
                break
            time.sleep(1)
        else:
            phases = {
                f"db-{ordinal}": (by_name.get(f"db-{ordinal}") or {}).get("status", {}).get("phase")
                for ordinal in range(_NODE_COUNT)
            }
            raise _BASE.SmokeFailure(f"Three-node fixture did not become Ready within its bound: {phases}")

        self._checkpoint("all-three-pods-ready")
        self.set_stage("three-pvc-pv-identity-discovery")
        claims = self.get("persistentvolumeclaims").get("items", [])
        expected_names = {f"data-db-{ordinal}" for ordinal in range(_NODE_COUNT)}
        if {str(item.get("metadata", {}).get("name", "")) for item in claims} != expected_names:
            raise _BASE.SmokeFailure("Fixture did not create exactly the three expected PVCs")
        for pvc in claims:
            metadata = pvc.get("metadata", {})
            name = str(metadata.get("name", ""))
            uid = str(metadata.get("uid", ""))
            if metadata.get("labels", {}).get("crdb-library-run") != self.run_id:
                raise _BASE.SmokeFailure("Fixture PVC is missing its run ownership label")
            if pvc.get("status", {}).get("phase") != "Bound":
                raise _BASE.SmokeFailure("Fixture PVC is not Bound")
            self.created[("persistentvolumeclaim", name)] = uid
            volume_name = str(pvc.get("spec", {}).get("volumeName", ""))
            if volume_name:
                pv = self.get("persistentvolume", volume_name, all_namespaces=True)
                claim_ref = pv.get("spec", {}).get("claimRef", {})
                if claim_ref.get("uid") != uid or claim_ref.get("namespace") != self.namespace or claim_ref.get("name") != name:
                    raise _BASE.SmokeFailure("Fixture PV does not reference its owned PVC identity")
                self.created[("persistentvolume", volume_name)] = str(pv.get("metadata", {}).get("uid", ""))
            self._checkpoint("storage-identity-recorded")
        self._checkpoint("three-storage-identities-recorded")

    def capture_diagnostics(self, phase_data: dict[str, Any], *, label: str) -> dict[str, Any]:
        diagnostic = super().capture_diagnostics(phase_data, label=label)
        pods: dict[str, Any] = {}
        for ordinal in range(1, _NODE_COUNT):
            name = f"db-{ordinal}"
            pod: dict[str, Any] = {}
            try:
                pod = self.get("pods", name, timeout=5)
                pods[name] = {"pod": _BASE._safe_pod_summary(pod) if pod else None}
            except Exception as error:
                pods[name] = {"pod_observation_error": _BASE._safe_diagnostic_text(error)}
            uid = str(pod.get("metadata", {}).get("uid", "")) or None
            try:
                pods[name]["events"] = self._diagnostic_events(uid)
            except Exception as error:
                pods[name]["events_error"] = _BASE._safe_diagnostic_text(error)
            pods[name]["current_logs"] = self._logs_for_pod(name, previous=False)
            pods[name]["previous_logs"] = self._logs_for_pod(name, previous=True)
        diagnostic["other_pods"] = pods
        return diagnostic

    def _logs_for_pod(self, name: str, *, previous: bool) -> dict[str, Any]:
        command = ["logs", f"pod/{name}", "--container=db", "--tail=80", "--timestamps"]
        if previous:
            command.append("--previous")
        try:
            output = self.kubectl(*command, namespace=self.namespace, timeout=5)
        except _BASE.SmokeFailure as error:
            return {"available": False, "failure": _BASE._safe_diagnostic_text(error)}
        return {"available": True, "lines": _BASE._safe_diagnostic_text(output).splitlines()[-80:]}

    def cleanup_additional_resources(self) -> None:
        expected = (
            ("service", "db-public"),
            ("configmap", _BASELINE_NAME),
            ("serviceaccount", "db-sa"),
        )
        for kind, name in expected:
            if kind == "configmap" and not self.baseline_create_intent:
                obj = self.get(kind, name)
                if obj:
                    raise _BASE.SmokeFailure("Unexpected health baseline appeared without a recorded creation intent")
                continue
            obj = self.get(kind, name)
            if not obj:
                continue
            metadata = obj.get("metadata", {})
            labels = metadata.get("labels", {})
            uid = str(metadata.get("uid", ""))
            previous_uid = self.created.get((kind, name))
            if kind == "configmap":
                expected_case_labels = {
                    **_NAMESPACE_LABELS,
                    "karma.dev/fixture": "health-recovery-baseline",
                }
                if any(labels.get(key) != value for key, value in expected_case_labels.items()):
                    raise _BASE.SmokeFailure("Cleanup stopped because the health baseline labels changed")
                expected_statefulset_uid = self.created.get(("statefulset", "db"))
                if not expected_statefulset_uid or obj.get("data", {}).get("statefulset_uid") != expected_statefulset_uid:
                    raise _BASE.SmokeFailure("Cleanup stopped because the health baseline does not identify this fixture StatefulSet")
            elif labels.get("crdb-library-run") != self.run_id:
                raise _BASE.SmokeFailure(f"Cleanup stopped because {kind}/{name} is not run-owned")
            if previous_uid and previous_uid != uid:
                raise _BASE.SmokeFailure(f"Cleanup stopped because {kind}/{name} UID changed")
            self.created[(kind, name)] = uid
            self._checkpoint("additional-resource-identity-recorded")
            self.raw_delete_uid(kind, name, uid)
            self.wait_absent(kind, name)
            self._checkpoint(f"{kind}-{name}-absent")
            if kind == "service":
                self._wait_service_endpoint_slices_absent(uid)

    def _wait_service_endpoint_slices_absent(self, service_uid: str) -> None:
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            slices = self.get("endpointslices").get("items", [])
            owned = [
                item for item in slices
                if any(reference.get("uid") == service_uid for reference in item.get("metadata", {}).get("ownerReferences", []))
            ]
            if not owned:
                return
            time.sleep(1)
        raise _BASE.SmokeFailure("db-public EndpointSlices did not clear within the cleanup bound")


def _pod_ready(pod: dict[str, Any] | None) -> bool:
    if not pod or pod.get("metadata", {}).get("deletionTimestamp") or pod.get("status", {}).get("phase") != "Running":
        return False
    return any(
        condition.get("type") == "Ready" and condition.get("status") == "True"
        for condition in pod.get("status", {}).get("conditions", [])
    )


def enforce_three_node_capacity(snapshot: dict[str, Any]) -> dict[str, Any]:
    free_cpu = Decimal(str(snapshot["kind_node_free_cpu_cores"]))
    free_memory = int(snapshot["kind_node_free_memory_bytes"])
    if free_cpu < _MIN_FREE_CPU or free_memory < _MIN_FREE_MEMORY:
        raise _BASE.SmokeFailure("Kind node lacks aggregate three-pod request capacity and safety headroom")
    if int(snapshot["host_free_bytes"]) < _MIN_HOST_FREE_BYTES:
        raise _BASE.SmokeFailure("Host has less than 8GiB free for the three-node fixture")
    if int(snapshot["kind_node_free_bytes"]) < _MIN_KIND_DISK_FREE_BYTES:
        raise _BASE.SmokeFailure("Kind node has less than 4GiB free for the three-node fixture")
    return {
        **snapshot,
        "fixture_pods": _NODE_COUNT,
        "fixture_pvc_count": _NODE_COUNT,
        "fixture_pvc_each": "1Gi",
        "fixture_total_pvc": "3Gi",
        "pod_requests_each": {"cpu": "100m", "memory": "256Mi"},
        "pod_limits_each": {"cpu": "1", "memory": "1Gi"},
        "aggregate_requested": {"cpu": "300m", "memory": "768Mi"},
        "minimum_free_capacity_including_headroom": {
            "cpu": "500m",
            "memory": "3584Mi",
            "host_disk": "8Gi",
            "kind_node_disk": "4Gi",
        },
    }


def preflight(args: argparse.Namespace, fixture: HealthCaseFixture) -> dict[str, Any]:
    snapshot = _BASE.preflight(args, fixture)
    return enforce_three_node_capacity(snapshot)


def make_case_certificates(cert_dir: Path, namespace: str) -> None:
    """Make ephemeral node/client certs with DNS SANs for all three pod names."""
    cert_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    ca_key, ca_crt = cert_dir / "ca.key", cert_dir / "ca.crt"
    node_key, node_csr, node_crt = cert_dir / "node.key", cert_dir / "node.csr", cert_dir / "node.crt"
    root_key, root_csr, root_crt = cert_dir / "client.root.key", cert_dir / "client.root.csr", cert_dir / "client.root.crt"
    extfile = cert_dir / "extensions.cnf"
    dns = [f"DNS:db-{ordinal}.db.{namespace}.svc.cluster.local" for ordinal in range(_NODE_COUNT)]
    dns.extend(("DNS:db", "DNS:localhost", "IP:127.0.0.1"))
    extfile.write_text(
        "[node]\n"
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth,clientAuth\n"
        "subjectAltName=" + ",".join(dns) + "\n"
        "[root]\n"
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=clientAuth\n",
        encoding="utf-8",
    )
    runner = _BASE.run
    runner(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(ca_key), "-out", str(ca_crt),
            "-days", "2", "-subj", "/CN=health-case-smoke-ca", "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign"], timeout=30)
    runner(["openssl", "genrsa", "-out", str(node_key), "2048"], timeout=30)
    runner(["openssl", "req", "-new", "-key", str(node_key), "-out", str(node_csr), "-subj", "/CN=node"], timeout=30)
    runner(["openssl", "x509", "-req", "-in", str(node_csr), "-CA", str(ca_crt), "-CAkey", str(ca_key),
            "-CAcreateserial", "-out", str(node_crt), "-days", "2", "-extfile", str(extfile), "-extensions", "node"], timeout=30)
    runner(["openssl", "genrsa", "-out", str(root_key), "2048"], timeout=30)
    runner(["openssl", "req", "-new", "-key", str(root_key), "-out", str(root_csr), "-subj", "/CN=root/O=admin"], timeout=30)
    runner(["openssl", "x509", "-req", "-in", str(root_csr), "-CA", str(ca_crt), "-CAkey", str(ca_key),
            "-CAcreateserial", "-out", str(root_crt), "-days", "2", "-extfile", str(extfile), "-extensions", "root"], timeout=30)


@contextmanager
def case_environment(namespace: str):
    keys = {"BENCH_NAMESPACE": namespace, "BENCH_PARAM_CLUSTER_NAME": "db"}
    previous = {key: os.environ.get(key) for key in keys}
    os.environ.update(keys)
    try:
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def run_case_command(
    fixture: HealthCaseFixture,
    unit: str,
    mode: str,
    *,
    timeout: float,
    expected_failure: str | None = None,
    expect_failure: bool = False,
) -> dict[str, Any]:
    operation = f"case {unit} {mode}"
    fixture.set_stage(operation)
    started = time.monotonic()
    command = [sys.executable, str(PREPARE_PATH), unit, mode]
    try:
        with case_environment(fixture.namespace):
            result = subprocess.run(command, text=True, capture_output=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as error:
        event = {"operation": operation, "outcome": "timeout", "returncode": None,
                 "elapsed_ms": round((time.monotonic() - started) * 1000)}
        fixture._record_command(event)
        raise _BASE.SmokeFailure(f"{operation} timed out", command_event=event) from error
    elapsed_ms = round((time.monotonic() - started) * 1000)
    event = {"operation": operation, "outcome": "ok" if result.returncode == 0 else "exit_error",
             "returncode": result.returncode, "elapsed_ms": elapsed_ms}
    fixture._record_command(event)
    safe_stderr = _BASE._safe_diagnostic_text(result.stderr)
    if expect_failure:
        if result.returncode == 0:
            raise _BASE.SmokeFailure(f"{operation} unexpectedly succeeded", command_event=event)
        return {"operation": operation, "outcome": "expected_failure", "reason": safe_stderr,
                "elapsed_ms": elapsed_ms}
    if expected_failure is not None:
        if result.returncode == 0 or expected_failure not in safe_stderr:
            raise _BASE.SmokeFailure(f"{operation} did not fail for the expected reason: {safe_stderr}", command_event=event)
        return {"operation": operation, "outcome": "expected_failure", "reason": expected_failure,
                "elapsed_ms": elapsed_ms}
    if result.returncode != 0:
        raise _BASE.SmokeFailure(f"{operation} failed: {safe_stderr}", command_event=event)
    return {"operation": operation, "outcome": "passed", "elapsed_ms": elapsed_ms}


def _timed(fixture: HealthCaseFixture, operation: str, callback: Callable[[], Any]) -> Any:
    fixture.set_stage(operation)
    started = time.monotonic()
    try:
        value = callback()
    except Exception as error:
        fixture._record_command({"operation": operation, "outcome": "error", "error_type": type(error).__name__,
                                 "elapsed_ms": round((time.monotonic() - started) * 1000)})
        raise
    fixture._record_command({"operation": operation, "outcome": "ok",
                             "elapsed_ms": round((time.monotonic() - started) * 1000)})
    return value


def _record_milestone(fixture: HealthCaseFixture, phase_data: dict[str, Any], name: str, value: Any = True) -> None:
    """Persist safe progress as soon as an experiment assertion completes."""
    phase_data.setdefault("milestones", {})[name] = value
    phase_data["last_progress"] = {"milestone": name, "stage": fixture.stage_snapshot()}
    fixture._checkpoint(f"milestone-{name}")


def _run_sql(fixture: HealthCaseFixture, tls: bool, sql: str) -> str:
    command = [
        *fixture.kubectl_base,
        "--namespace", fixture.namespace,
        "exec", "db-0", "--container=db", "--",
        "/cockroach/cockroach", "sql", "--host=localhost", "--port=26257", "--format=csv",
    ]
    command.append("--certs-dir=/cockroach/cockroach-certs" if tls else "--insecure")
    command.extend(["-e", sql])
    return _BASE.run(command, timeout=35, operation="fixture SQL witness", observer=fixture._record_command)


def _read_controlled_fixture_setting(fixture: HealthCaseFixture, *, tls: bool) -> str:
    output = _run_sql(fixture, tls, "SHOW CLUSTER SETTING kv.snapshot_rebalance.max_rate")
    rows = [row for row in csv.reader(output.splitlines()) if row]
    if len(rows) != 2 or len(rows[1]) != 1 or rows[1][0].replace(" ", "").casefold() != "128mib":
        raise _BASE.SmokeFailure("Controlled cluster setting did not read back as 128MiB")
    return rows[1][0]


def _set_controlled_fixture_setting(fixture: HealthCaseFixture, *, tls: bool) -> str:
    _timed(
        fixture,
        "set-controlled-128mib-cluster-setting",
        lambda: _run_sql(
            fixture,
            tls,
            "SET CLUSTER SETTING kv.snapshot_rebalance.max_rate = '128MiB'",
        ),
    )
    return _read_controlled_fixture_setting(fixture, tls=tls)


def _witness_hash(fixture: HealthCaseFixture, tls: bool) -> tuple[int, str]:
    output = _timed(
        fixture,
        "read-two-row-data-witness",
        lambda: _run_sql(fixture, tls, f"SELECT id, payload FROM {_WITNESS_TABLE} ORDER BY id"),
    )
    rows = [row for row in csv.reader(output.splitlines()) if row]
    expected = [
        ["id", "payload"],
        ["1", "before probe rollout"],
        ["2", "after fault recovery"],
    ]
    if rows != expected:
        raise _BASE.SmokeFailure("Persisted witness query did not return the two expected rows")
    canonical = json.dumps(rows, ensure_ascii=False, separators=(",", ":"))
    return len(rows) - 1, hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _phase_names(args: argparse.Namespace) -> tuple[str, ...]:
    return ("tls",) if getattr(args, "proof_mode", "fault") == "recovery" else ("insecure", "tls")


def _pod_uid_map(fixture: HealthCaseFixture) -> dict[str, str]:
    result = {}
    for ordinal in range(_NODE_COUNT):
        pod = fixture.get("pods", f"db-{ordinal}")
        uid = str(pod.get("metadata", {}).get("uid", "")) if pod else ""
        if not uid:
            raise _BASE.SmokeFailure(f"Database Pod db-{ordinal} has no observed UID")
        result[f"db-{ordinal}"] = uid
    return result


def _require_same_pod_uid(fixture: HealthCaseFixture, name: str, expected_uid: str) -> dict[str, Any]:
    pod = fixture.get("pods", name)
    if not pod or pod.get("metadata", {}).get("uid") != expected_uid:
        raise _BASE.SmokeFailure(f"Owned Pod {name} changed identity before the recovery test action")
    return pod


def _cockroach_pid1(fixture: HealthCaseFixture, expected_uid: str) -> None:
    _require_same_pod_uid(fixture, "db-1", expected_uid)
    output = fixture.kubectl(
        "exec", "db-1", "--container=db", "--", "/bin/sh", "-ec",
        'test "$(readlink /proc/1/exe)" = /cockroach/cockroach && printf cockroach-pid1',
        timeout=10,
    )
    if output.strip() != "cockroach-pid1":
        raise _BASE.SmokeFailure("Recovery test target does not have CockroachDB as PID 1")


def _signal_owned_cockroach(fixture: HealthCaseFixture, expected_uid: str, signal: str) -> None:
    if signal not in {"STOP", "CONT"}:
        raise _BASE.SmokeFailure("Unsupported recovery-test process signal")
    _cockroach_pid1(fixture, expected_uid)
    # The target UID is re-read immediately before the fixed signal command.
    _require_same_pod_uid(fixture, "db-1", expected_uid)
    fixture.kubectl(
        "exec", "db-1", "--container=db", "--", "/bin/sh", "-ec", f"kill -{signal} 1", timeout=10,
    )


def _wait_for_one_owned_pod_unready(
    fixture: HealthCaseFixture,
    pod_uids: dict[str, str],
    *,
    timeout: float = 60,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        pods = {name: fixture.get("pods", name) for name in pod_uids}
        if any(not pods[name] for name in pod_uids):
            time.sleep(1)
            continue
        for peer in ("db-0", "db-2"):
            if pods[peer]["metadata"].get("uid") != pod_uids[peer] or not _pod_ready(pods[peer]):
                raise _BASE.SmokeFailure(f"Healthy peer {peer} changed or became unready during the single-Pod test")
        target = pods["db-1"]
        if target["metadata"].get("uid") != pod_uids["db-1"]:
            raise _BASE.SmokeFailure("Kubelet or controller replaced db-1 before the case recovery path ran")
        last = _BASE._safe_pod_summary(target)
        if target.get("status", {}).get("phase") == "Running" and not _pod_ready(target):
            return last
        time.sleep(1)
    raise _BASE.SmokeFailure(f"Owned db-1 did not become Running and unready within the bound: {last}")


def _resume_paused_target_if_owned(fixture: HealthCaseFixture, phase_data: dict[str, Any]) -> dict[str, Any]:
    fault = phase_data.get("recovery_fault")
    if not isinstance(fault, dict) or not fault.get("stop_intent_recorded"):
        return {"action": "not-needed"}
    expected_uid = fault.get("pod_uid")
    if not isinstance(expected_uid, str) or not expected_uid:
        return {"action": "not-attempted", "reason": "missing-owned-pod-uid"}
    current = fixture.get("pods", "db-1")
    if not current or current.get("metadata", {}).get("uid") != expected_uid:
        return {"action": "not-needed", "reason": "target-pod-was-replaced"}
    _signal_owned_cockroach(fixture, expected_uid, "CONT")
    return {"action": "resumed-owned-cockroach-process"}


def _baseline_snapshot(fixture: HealthCaseFixture) -> dict[str, str]:
    baseline = fixture.get("configmap", _BASELINE_NAME)
    if not baseline:
        raise _BASE.SmokeFailure("Health case did not create its owned baseline ConfigMap")
    labels = baseline.get("metadata", {}).get("labels", {})
    expected = {**_NAMESPACE_LABELS, "karma.dev/fixture": "health-recovery-baseline"}
    if any(labels.get(key) != value for key, value in expected.items()):
        raise _BASE.SmokeFailure("Health case baseline ConfigMap has unexpected labels")
    metadata = baseline["metadata"]
    result = {
        "uid": str(metadata["uid"]),
        "resource_version": str(metadata["resourceVersion"]),
        "data_sha256": hashlib.sha256(json.dumps(baseline.get("data", {}), sort_keys=True).encode()).hexdigest(),
    }
    fixture.created[("configmap", _BASELINE_NAME)] = result["uid"]
    fixture._checkpoint("health-baseline-identity-recorded")
    return result


def _assert_baseline_snapshot_unchanged(fixture: HealthCaseFixture, expected: dict[str, str]) -> None:
    current = _baseline_snapshot(fixture)
    if current != expected:
        raise _BASE.SmokeFailure("Health precondition retries modified the case baseline ConfigMap")


def _patch_statefulset(fixture: HealthCaseFixture, *, uid: str, fields: dict[str, Any]) -> None:
    statefulset = fixture.get("statefulset", "db")
    if not statefulset or statefulset.get("metadata", {}).get("uid") != uid:
        raise _BASE.SmokeFailure("StatefulSet identity changed before deterministic test restoration")
    operations = [
        {"op": "test", "path": "/metadata/uid", "value": uid},
        {"op": "test", "path": "/metadata/resourceVersion", "value": statefulset["metadata"]["resourceVersion"]},
    ]
    for field, value in fields.items():
        operations.append({"op": "replace", "path": f"/spec/{field}", "value": value})
    fixture.kubectl(
        "patch", "statefulset", "db", "--type=json", "-p", json.dumps(operations),
        namespace=fixture.namespace,
        timeout=20,
        diagnose_api_error=True,
    )


def _restore_case_fault(
    fixture: HealthCaseFixture,
    *,
    tls: bool,
    library: CrdbLibrary,
    ref: WorkloadRef,
    accepted_before_fault: Any,
    witness_before: tuple[int, str],
    pod_uids_before_fault: dict[str, str],
) -> dict[str, Any]:
    fixture.set_stage("deterministic-fault-restore")
    baseline = fixture.get("configmap", _BASELINE_NAME)
    if not baseline:
        raise _BASE.SmokeFailure("Cannot restore the fault without its case-owned baseline")
    baseline_data = baseline.get("data", {})
    original_template = json.loads(baseline_data["original_template"])
    original_strategy = json.loads(baseline_data["original_update_strategy"])
    statefulset = fixture.get("statefulset", "db")
    if not statefulset:
        raise _BASE.SmokeFailure("StatefulSet disappeared before test restoration")
    statefulset_uid = str(statefulset["metadata"]["uid"])
    target_before = fixture.get("pods", "db-1")
    if not target_before:
        raise _BASE.SmokeFailure("Expected the fault target Pod before restoration")
    target_uid = str(target_before["metadata"]["uid"])
    if statefulset.get("spec", {}).get("updateStrategy", {}).get("type") != "OnDelete":
        raise _BASE.SmokeFailure("Fault fixture no longer has its owned OnDelete strategy")

    _timed(
        fixture,
        "restore-original-template-under-ondelete",
        lambda: _patch_statefulset(fixture, uid=statefulset_uid, fields={"template": original_template}),
    )
    current = fixture.get("statefulset", "db")
    if current.get("spec", {}).get("template") != original_template or current.get("spec", {}).get("updateStrategy", {}).get("type") != "OnDelete":
        raise _BASE.SmokeFailure("Template restoration changed more than the case fault template")
    _timed(
        fixture,
        "uid-guarded-delete-faulted-pod",
        lambda: fixture.raw_delete_uid("pod", "db-1", target_uid),
    )
    deadline = time.monotonic() + 180
    restored_pod: dict[str, Any] = {}
    while time.monotonic() < deadline:
        restored_pod = fixture.get("pods", "db-1")
        if restored_pod and restored_pod.get("metadata", {}).get("uid") != target_uid and _pod_ready(restored_pod):
            break
        time.sleep(1)
    else:
        raise _BASE.SmokeFailure("Restored db-1 Pod did not become Ready within the bounded rollout")

    _timed(
        fixture,
        "restore-original-update-strategy",
        lambda: _patch_statefulset(fixture, uid=statefulset_uid, fields={"updateStrategy": original_strategy}),
    )
    assessment = _timed(
        fixture,
        "verify-restored-semantic-readiness",
        lambda: library.probe(
            ref, Requirement(Lifecycle.INITIALIZED, minimum_nodes=3,
                            tls_mode=TLSMode.TLS if tls else TLSMode.INSECURE), per_node_timeout=5
        ),
    )
    if assessment.status is not ProbeStatus.SATISFIED:
        raise _BASE.SmokeFailure("Restored cluster did not satisfy initialized readiness")
    verified = _timed(
        fixture,
        "verify-accepted-state-after-restore",
        lambda: library.verify_accepted_state(ref, accepted_before_fault, per_node_timeout=5),
    )
    witness_after = _witness_hash(fixture, tls)
    if witness_before != witness_after:
        raise _BASE.SmokeFailure("Persisted data witness changed across deterministic fault recovery")
    restored_pod_uids = {
        f"db-{ordinal}": str(fixture.get("pods", f"db-{ordinal}").get("metadata", {}).get("uid", ""))
        for ordinal in range(_NODE_COUNT)
    }
    for peer in ("db-0", "db-2"):
        if restored_pod_uids[peer] != pod_uids_before_fault[peer]:
            raise _BASE.SmokeFailure(f"Healthy peer {peer} was restarted during the single-pod fault task")
    return {
        "restored_pod_uid_changed": restored_pod["metadata"]["uid"] != target_uid,
        "healthy_peer_pod_uids_unchanged": {peer: restored_pod_uids[peer] for peer in ("db-0", "db-2")},
        "restored_template_matches_baseline": True,
        "restored_update_strategy_matches_baseline": True,
        "accepted_state_verified": verified.status is ProbeStatus.SATISFIED,
        "post_restore_witness_rows": witness_after[0],
        "witness_sha256_before_after_restore": [witness_before[1], witness_after[1]],
        "cluster_id": verified.health.cluster_id,
        "node_ids": verified.health.node_ids,
        "sql_versions": verified.health.sql_versions,
    }


def _load_oracle_evaluate() -> Callable[[], list[str]]:
    namespace = runpy.run_path(str(ORACLE_PATH))
    return namespace["evaluate"]


def _evaluate_case_oracle(fixture: HealthCaseFixture) -> list[str]:
    with case_environment(fixture.namespace):
        return _load_oracle_evaluate()()


def _exercise_recovery_phase(
    fixture: HealthCaseFixture,
    *,
    tls: bool,
    library: CrdbLibrary,
    ref: WorkloadRef,
    accepted_before: Any,
    witness_before: tuple[int, str],
    phase_data: dict[str, Any],
) -> dict[str, Any]:
    """Prove the real case recovers one persistently unready, owned Pod."""
    if not tls:
        raise _BASE.SmokeFailure("The recovery-specific proof requires the reviewed TLS fixture")

    pod_uids_before_noop = _pod_uid_map(fixture)
    sts_before_noop = fixture.get("statefulset", "db")
    if not sts_before_noop:
        raise _BASE.SmokeFailure("StatefulSet disappeared before the healthy no-op proof")
    spec_before_noop = hashlib.sha256(
        json.dumps(sts_before_noop.get("spec", {}), sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    setting_before = _set_controlled_fixture_setting(fixture, tls=tls)
    phase_data["controlled_cluster_setting"] = {"name": "kv.snapshot_rebalance.max_rate", "before": setting_before}
    fixture._checkpoint("controlled-setting-baseline-recorded")
    fixture.set_stage("recovery-proof-healthy-noop")
    healthy_commands = [
        run_case_command(fixture, "cluster", "probe", timeout=120),
        run_case_command(fixture, "cluster", "apply", timeout=180),
        run_case_command(fixture, "cluster", "verify", timeout=120),
    ]
    accepted_after_noop = _timed(
        fixture, "verify-accepted-state-after-healthy-noop",
        lambda: library.verify_accepted_state(ref, accepted_before, per_node_timeout=5),
    )
    setting_after_noop = _read_controlled_fixture_setting(fixture, tls=tls)
    phase_data["controlled_cluster_setting"]["after_healthy_noop"] = setting_after_noop
    fixture._checkpoint("controlled-setting-after-healthy-noop-recorded")
    if setting_after_noop != setting_before:
        raise _BASE.SmokeFailure("Healthy cluster probe/apply/verify changed the controlled SQL setting")
    pod_uids_before_fault = _pod_uid_map(fixture)
    sts_before_fault = fixture.get("statefulset", "db")
    if not sts_before_fault:
        raise _BASE.SmokeFailure("StatefulSet disappeared before the recovery proof")
    spec_before_fault = hashlib.sha256(
        json.dumps(sts_before_fault.get("spec", {}), sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    if pod_uids_before_fault != pod_uids_before_noop or spec_before_fault != spec_before_noop:
        raise _BASE.SmokeFailure("Healthy cluster probe/apply/verify changed a Pod UID or StatefulSet specification")
    container = next(
        (item for item in sts_before_fault.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
         if item.get("name") == "db"),
        None,
    )
    startup = " ".join((container or {}).get("command", []) + (container or {}).get("args", []))
    if "--cache=128MiB" not in startup or "--max-sql-memory=128MiB" not in startup:
        raise _BASE.SmokeFailure("The recovery fixture no longer has its bounded 128MiB memory settings")
    if witness_before[0] != 2 or _witness_hash(fixture, tls) != witness_before:
        raise _BASE.SmokeFailure("The healthy no-op commands changed the two-row data witness")
    _record_milestone(
        fixture,
        phase_data,
        "healthy_noop_state_verified",
        {
            "commands": healthy_commands,
            "accepted_state_equal": accepted_after_noop.status is ProbeStatus.SATISFIED,
            "pod_uids_before_after": [pod_uids_before_noop, pod_uids_before_fault],
            "statefulset_spec_sha256_before_after": [spec_before_noop, spec_before_fault],
            "pod_uids": pod_uids_before_fault,
            "statefulset_spec_sha256": spec_before_fault,
            "witness_rows": witness_before[0],
            "witness_sha256": witness_before[1],
            "controlled_setting_before_after": [setting_before, setting_after_noop],
            "memory_settings": ["--cache=128MiB", "--max-sql-memory=128MiB"],
        },
    )

    target_uid = pod_uids_before_fault["db-1"]
    phase_data["recovery_fault"] = {
        "pod_uid": target_uid,
        "stop_intent_recorded": False,
        "sigstop_sent": False,
    }
    fixture._checkpoint("recovery-target-identity-recorded")
    _timed(fixture, "confirm-owned-cockroach-pid1", lambda: _cockroach_pid1(fixture, target_uid))
    phase_data["recovery_fault"]["stop_intent_recorded"] = True
    fixture._checkpoint("owned-cockroach-stop-intent-recorded")
    _timed(
        fixture,
        "sigstop-owned-cockroach-process",
        lambda: _signal_owned_cockroach(fixture, target_uid, "STOP"),
    )
    phase_data["recovery_fault"]["sigstop_sent"] = True
    fixture._checkpoint("owned-cockroach-process-stopped")
    unready = _timed(
        fixture,
        "wait-for-owned-pod-to-become-unready",
        lambda: _wait_for_one_owned_pod_unready(fixture, pod_uids_before_fault, timeout=60),
    )
    phase_data["recovery_fault"]["unready_pod_observation"] = unready
    _record_milestone(fixture, phase_data, "single_owned_pod_unready_verified", unready)

    unhealthy_probe = run_case_command(
        fixture, "cluster", "probe", timeout=120, expect_failure=True,
    )
    _record_milestone(
        fixture,
        phase_data,
        "case_probe_rejected_unready_pod",
        unhealthy_probe,
    )
    recovery_apply = run_case_command(fixture, "cluster", "apply", timeout=480)
    recovery_verify = run_case_command(fixture, "cluster", "verify", timeout=180)
    accepted_after_recovery = _timed(
        fixture, "verify-accepted-state-after-unready-pod-recovery",
        lambda: library.verify_accepted_state(ref, accepted_before, per_node_timeout=5),
    )
    pod_uids_after_recovery = _pod_uid_map(fixture)
    if pod_uids_after_recovery["db-1"] == target_uid:
        raise _BASE.SmokeFailure("Case apply did not replace the stopped db-1 Pod")
    for peer in ("db-0", "db-2"):
        if pod_uids_after_recovery[peer] != pod_uids_before_fault[peer]:
            raise _BASE.SmokeFailure(f"Healthy peer {peer} changed Pod identity during targeted recovery")
    witness_after = _witness_hash(fixture, tls)
    if witness_after != witness_before:
        raise _BASE.SmokeFailure("The persisted two-row witness changed during Pod recovery")
    setting_after_recovery = _read_controlled_fixture_setting(fixture, tls=tls)
    phase_data["controlled_cluster_setting"]["after_recovery"] = setting_after_recovery
    fixture._checkpoint("controlled-setting-after-recovery-recorded")
    if setting_after_recovery != setting_before:
        raise _BASE.SmokeFailure("Case recovery changed the controlled SQL setting")
    sts_after_recovery = fixture.get("statefulset", "db")
    spec_after_recovery = hashlib.sha256(
        json.dumps((sts_after_recovery or {}).get("spec", {}), sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    if spec_after_recovery != spec_before_fault:
        raise _BASE.SmokeFailure("Case recovery changed the StatefulSet specification")
    _record_milestone(
        fixture,
        phase_data,
        "one_pod_recovery_and_preservation_verified",
        {
            "recovery_apply": recovery_apply,
            "recovery_verify": recovery_verify,
            "pod_uids_before": pod_uids_before_fault,
            "pod_uids_after": pod_uids_after_recovery,
            "accepted_state_equal": accepted_after_recovery.status is ProbeStatus.SATISFIED,
            "statefulset_spec_sha256_before_after": [spec_before_fault, spec_after_recovery],
            "witness_rows_before_after": [witness_before[0], witness_after[0]],
            "witness_sha256_before_after": [witness_before[1], witness_after[1]],
            "controlled_setting_before_after": [setting_before, setting_after_recovery],
        },
    )
    phase_data["recovery_fault"]["sigstop_sent"] = False
    phase_data["recovery_fault"]["stop_intent_recorded"] = False
    fixture._checkpoint("recovery-process-no-longer-needs-resume")
    return {
        "proof_mode": "recovery",
        "healthy_noop_commands": healthy_commands,
        "unhealthy_probe": unhealthy_probe,
        "recovery_apply": recovery_apply,
        "recovery_verify": recovery_verify,
        "pod_uids_before": pod_uids_before_fault,
        "pod_uids_after": pod_uids_after_recovery,
        "accepted_state_preserved": accepted_after_recovery.status is ProbeStatus.SATISFIED,
        "controlled_setting_before_after": [setting_before, setting_after_recovery],
        "statefulset_spec_sha256_before_after": [spec_before_fault, spec_after_recovery],
        "persisted_witness_rows": witness_after[0],
        "persisted_witness_sha256_before_after": [witness_before[1], witness_after[1]],
        "pvc_identities": accepted_before.pvc_identities,
        "certificate_fingerprints": accepted_before.certificate_fingerprints,
        "cluster_id": accepted_before.cluster_id,
        "node_ids": accepted_before.node_ids,
        "sql_versions": accepted_before.sql_versions,
    }


def exercise_case_phase(
    args: argparse.Namespace,
    fixture: HealthCaseFixture,
    *,
    tls: bool,
    phase_data: dict[str, Any],
) -> dict[str, Any]:
    fixture.wait_ready(timeout=args.ready_timeout)
    library = CrdbLibrary(KubectlAdapter(kubectl=args.kubectl))
    ref = WorkloadRef(fixture.namespace, "db", "db")
    mode = TLSMode.TLS if tls else TLSMode.INSECURE

    deployed = _timed(
        fixture,
        "pre-init-deployed-readiness",
        lambda: library.probe(ref, Requirement(Lifecycle.DEPLOYED, minimum_nodes=3, tls_mode=mode), per_node_timeout=5),
    )
    preinit_initialized = _timed(
        fixture,
        "pre-init-initialized-requirement",
        lambda: library.probe(ref, Requirement(Lifecycle.INITIALIZED, minimum_nodes=3, tls_mode=mode), per_node_timeout=5),
    )
    if deployed.status is not ProbeStatus.SATISFIED or deployed.health.lifecycle is not Lifecycle.DEPLOYED:
        raise _BASE.SmokeFailure("Deployed-only readiness did not distinguish the uninitialized fixture")
    if preinit_initialized.status is not ProbeStatus.UNSATISFIED or preinit_initialized.health.cluster_id is not None:
        raise _BASE.SmokeFailure("The fresh fixture appeared initialized before explicit cockroach init")
    _record_milestone(
        fixture,
        phase_data,
        "preinit_lifecycle_distinguished",
        {"deployed": deployed.status.value, "initialized": preinit_initialized.status.value},
    )

    fixture.init(tls)
    initialized = _timed(
        fixture,
        "initialized-semantic-reconcile",
        lambda: library.reconcile(
            ref, Requirement(Lifecycle.INITIALIZED, minimum_nodes=3, tls_mode=mode),
            timeout=180, poll_interval=2, per_node_timeout=5,
        ),
    )
    if initialized.assessment.status is not ProbeStatus.SATISFIED:
        raise _BASE.SmokeFailure("Explicitly initialized three-node cluster did not become semantically ready")
    _record_milestone(fixture, phase_data, "explicit_init_and_semantic_readiness_verified")
    pre_probe_accepted = _timed(
        fixture, "capture-accepted-state-before-probe-preparation",
        lambda: library.capture_accepted_state(ref, per_node_timeout=5),
    )

    _timed(fixture, "create-case-witness-database", lambda: _run_sql(fixture, tls, f"CREATE DATABASE {_WITNESS_DB}"))
    _timed(
        fixture,
        "create-case-witness-table",
        lambda: _run_sql(fixture, tls, f"CREATE TABLE {_WITNESS_TABLE} (id INT PRIMARY KEY, payload STRING NOT NULL)"),
    )
    _timed(
        fixture,
        "insert-case-witness-rows",
        lambda: _run_sql(
            fixture, tls,
            f"INSERT INTO {_WITNESS_TABLE} VALUES (1, 'before probe rollout'), (2, 'after fault recovery')",
        ),
    )
    witness_before = _witness_hash(fixture, tls)
    health_before = _timed(fixture, "preflight-health-endpoints-before-case-mutation", lambda: (
        library.probe_health_endpoint(ref, path="/health", per_node_timeout=4),
        library.probe_health_endpoint(ref, path="/health?ready=1", per_node_timeout=4),
    ))
    if any(not passed for group in health_before for _, _, passed in group):
        raise _BASE.SmokeFailure("HTTP health endpoints were not healthy before case probe preparation")

    # Both case preconditions first report why mutation is required. These
    # expected failures are bounded, read-only, and do not change the fixture.
    cluster_probe = run_case_command(
        fixture, "cluster", "probe", timeout=180,
        expected_failure="health probes need explicit preparation",
    )
    cluster_apply = run_case_command(fixture, "cluster", "apply", timeout=240)
    cluster_verify = run_case_command(fixture, "cluster", "verify", timeout=120)
    prepared_workload = _timed(fixture, "inspect-case-probe-preparation", lambda: library.inspect(ref))
    if not CrdbLibrary.health_recovery_probes_prepared(prepared_workload):
        raise _BASE.SmokeFailure("Case apply did not prepare semantically correct health probes")
    if prepared_workload.probe_preservation_hash != initialized.assessment.workload.probe_preservation_hash:
        raise _BASE.SmokeFailure("Case probe preparation changed unrelated StatefulSet template state")
    health = _timed(fixture, "check-health-endpoints-after-case-preparation", lambda: (
        library.probe_health_endpoint(ref, path="/health", per_node_timeout=4),
        library.probe_health_endpoint(ref, path="/health?ready=1", per_node_timeout=4),
    ))
    if any(not passed for group in health for _, _, passed in group):
        raise _BASE.SmokeFailure("Case probe preparation did not leave both HTTP endpoints healthy")
    accepted = _timed(fixture, "capture-accepted-state-before-fault", lambda: library.capture_accepted_state(ref, per_node_timeout=5))
    if replace(accepted, workload_spec_hash=pre_probe_accepted.workload_spec_hash) != pre_probe_accepted:
        raise _BASE.SmokeFailure("Case probe preparation changed accepted fields beyond the two probe handlers")
    after_probe_rollout = _witness_hash(fixture, tls)
    if witness_before != after_probe_rollout:
        raise _BASE.SmokeFailure("Persisted rows changed during the case's probe-only rollout")
    _record_milestone(
        fixture,
        phase_data,
        "probe_preparation_and_preservation_verified",
        {"two_row_witness_count": after_probe_rollout[0], "witness_sha256": after_probe_rollout[1]},
    )

    if fixture.proof_mode == "recovery":
        return _exercise_recovery_phase(
            fixture,
            tls=tls,
            library=library,
            ref=ref,
            accepted_before=accepted,
            witness_before=after_probe_rollout,
            phase_data=phase_data,
        )

    fault_probe = run_case_command(
        fixture, "fault", "probe", timeout=45,
        expected_failure=_NO_FAULT_REASON,
    )
    _record_milestone(fixture, phase_data, "fault_inactive_precondition_checked")
    pod_uids_before_fault = {
        f"db-{ordinal}": str(fixture.get("pods", f"db-{ordinal}").get("metadata", {}).get("uid", ""))
        for ordinal in range(_NODE_COUNT)
    }
    if any(not pod_uids_before_fault[f"db-{ordinal}"] for ordinal in range(_NODE_COUNT)):
        raise _BASE.SmokeFailure("A database Pod identity was missing before fault injection")
    fixture.baseline_create_intent = True
    fixture._checkpoint("health-baseline-create-intent")
    _record_milestone(fixture, phase_data, "fault_baseline_creation_intent_recorded")
    fault_apply = run_case_command(fixture, "fault", "apply", timeout=300)
    baseline_snapshot = _baseline_snapshot(fixture)
    pod_uids_after_fault = {
        f"db-{ordinal}": str(fixture.get("pods", f"db-{ordinal}").get("metadata", {}).get("uid", ""))
        for ordinal in range(_NODE_COUNT)
    }
    if any(not pod_uids_after_fault[f"db-{ordinal}"] for ordinal in range(_NODE_COUNT)):
        raise _BASE.SmokeFailure("A database Pod identity was missing after fault injection")
    if any(pod_uids_after_fault[peer] != pod_uids_before_fault[peer] for peer in ("db-0", "db-2")):
        raise _BASE.SmokeFailure("A healthy peer Pod changed unexpectedly during fault injection")
    fault_verify = run_case_command(fixture, "fault", "verify", timeout=45)
    active_fault_cluster_probe = run_case_command(fixture, "cluster", "probe", timeout=45)
    active_fault_cluster_apply = run_case_command(fixture, "cluster", "apply", timeout=45)
    active_fault_cluster_verify = run_case_command(fixture, "cluster", "verify", timeout=45)
    repeated_fault_apply = run_case_command(fixture, "fault", "apply", timeout=45)
    repeated_fault_verify = run_case_command(fixture, "fault", "verify", timeout=45)
    _assert_baseline_snapshot_unchanged(fixture, baseline_snapshot)
    _record_milestone(fixture, phase_data, "fault_and_idempotent_retries_verified", baseline_snapshot)

    oracle_errors = _timed(
        fixture, "independent-oracle-rejects-planted-fault", lambda: _evaluate_case_oracle(fixture)
    )
    if not oracle_errors:
        raise _BASE.SmokeFailure("Independent health oracle accepted the intentionally faulted cluster")
    oracle_reason = _BASE._safe_diagnostic_text(oracle_errors[0])
    _record_milestone(fixture, phase_data, "oracle_rejected_planted_fault", oracle_reason)

    restore = _restore_case_fault(
        fixture, tls=tls, library=library, ref=ref, accepted_before_fault=accepted,
        witness_before=after_probe_rollout, pod_uids_before_fault=pod_uids_before_fault,
    )
    _record_milestone(fixture, phase_data, "deterministic_restore_verified", restore)
    final_cluster_verify = run_case_command(fixture, "cluster", "verify", timeout=120)
    oracle_restored = _timed(
        fixture, "independent-oracle-accepts-restored-state", lambda: _evaluate_case_oracle(fixture)
    )
    if oracle_restored:
        raise _BASE.SmokeFailure("Independent health oracle rejected the restored healthy fixture")
    _record_milestone(fixture, phase_data, "oracle_accepted_restored_state")
    _assert_baseline_snapshot_unchanged(fixture, baseline_snapshot)
    return {
        "preinit_deployed_status": deployed.status.value,
        "preinit_lifecycle": deployed.health.lifecycle.value,
        "preinit_initialized_status": preinit_initialized.status.value,
        "explicit_init_lifecycle": initialized.assessment.health.lifecycle.value,
        "cluster_unit": [cluster_probe, cluster_apply, cluster_verify, final_cluster_verify],
        "fault_unit": [fault_probe, fault_apply, fault_verify, active_fault_cluster_probe,
                       active_fault_cluster_apply, active_fault_cluster_verify,
                       repeated_fault_apply, repeated_fault_verify],
        "oracle_rejected_planted_fault": True,
        "oracle_rejection_reason": oracle_reason,
        "oracle_accepted_restored_state": True,
        "baseline_unchanged": baseline_snapshot,
        "accepted_state_after_probe_preparation": asdict(accepted),
        "probe_preparation_preserved_unrelated_state": True,
        "pre_mutation_health_endpoint_statuses": health_before,
        "restoration": restore,
        "health_endpoint_statuses": health,
        "probe_preservation_hash": initialized.assessment.workload.probe_preservation_hash,
        "persisted_witness_rows": after_probe_rollout[0],
        "persisted_witness_sha256_before_after_probe_rollout": [witness_before[1], after_probe_rollout[1]],
        "cluster_id": accepted.cluster_id,
        "node_ids": accepted.node_ids,
        "sql_versions": accepted.sql_versions,
        "tls_mode": accepted.tls_mode.value,
        "image": accepted.image,
        "desired_replicas": accepted.desired_replicas,
        "pvc_identities": accepted.pvc_identities,
        "certificate_fingerprints": accepted.certificate_fingerprints,
        "service_routing": accepted.service_routing,
    }


def phase(args: argparse.Namespace, name: str, run_id: str, evidence_dir: Path) -> dict[str, Any]:
    fixture = HealthCaseFixture(args, name, run_id)
    phase_data: dict[str, Any] = {
        "phase": name,
        "proof_mode": fixture.proof_mode,
        "tls_mode": "tls" if name == "tls" else "insecure",
    }
    failure: Exception | None = None
    cleanup_failure: Exception | None = None

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
                    {"kind": kind, "name": object_name, "uid": uid}
                    for (kind, object_name), uid in sorted(fixture.created.items())
                ],
                "safe_observations": phase_data,
            },
        )

    fixture.checkpoint_callback = checkpoint
    checkpoint("preflight-started")
    try:
        fixture.set_stage("three-node-capacity-preflight")
        phase_data["capacity_preflight"] = preflight(args, fixture)
        fixture.storage_class = phase_data["capacity_preflight"]["storage_class"]
        checkpoint("preflight-passed")
        fixture.set_stage("namespace-prepare")
        fixture.prepare_namespace()
        fixture.set_stage("case-service-account-create")
        fixture.create(fixture.service_account_manifest())
        fixture.set_stage("case-service-create")
        for service in fixture.service_manifests():
            fixture.create(service)
        if name == "tls":
            with tempfile.TemporaryDirectory(prefix="crdb-health-case-certs-") as temp:
                cert_dir = Path(temp)
                make_case_certificates(cert_dir, fixture.namespace)
                fixture.make_secret(cert_dir)
                fixture.set_stage("three-node-statefulset-create")
                fixture.create(fixture.statefulset_manifest(tls=True))
                phase_data.update(exercise_case_phase(args, fixture, tls=True, phase_data=phase_data))
        else:
            fixture.set_stage("three-node-statefulset-create")
            fixture.create(fixture.statefulset_manifest(tls=False))
            phase_data.update(exercise_case_phase(args, fixture, tls=False, phase_data=phase_data))
        checkpoint("work-complete")
    except BaseException as error:
        failure = error
        phase_data["failure_stage"] = fixture.stage_snapshot()
        if isinstance(error, _BASE.SmokeFailure) and error.command_event:
            phase_data["failure_command"] = dict(error.command_event)
        if isinstance(error, (_BASE.SmokeFailure, CrdbError)):
            detail = _BASE._safe_diagnostic_text(error)
        elif isinstance(error, (KeyboardInterrupt, SystemExit)):
            detail = "interrupted; normal UID-guarded cleanup will run"
        else:
            detail = "details withheld"
        phase_data["execution_failure"] = {"type": type(error).__name__, "detail": detail}
        try:
            fixture.capture_diagnostics(phase_data, label="before-cleanup")
        except Exception as diagnostic_error:
            phase_data["diagnostic_capture_failure"] = {
                "type": type(diagnostic_error).__name__,
                "detail": _BASE._safe_diagnostic_text(diagnostic_error),
            }
    if fixture.proof_mode == "recovery":
        try:
            phase_data["fault_process_cleanup"] = _resume_paused_target_if_owned(fixture, phase_data)
        except BaseException as error:
            phase_data["fault_process_cleanup_failure"] = {
                "type": type(error).__name__,
                "detail": _BASE._safe_diagnostic_text(error) if isinstance(error, _BASE.SmokeFailure) else "details withheld",
            }
            if failure is None:
                failure = error
    try:
        fixture.cleanup()
        phase_data["cleanup_verdict"] = "completed with UID preconditions and normal deletion"
    except BaseException as error:
        cleanup_failure = error
        detail = _BASE._safe_diagnostic_text(error) if isinstance(error, (_BASE.SmokeFailure, CrdbError)) else "details withheld"
        phase_data["cleanup_failure"] = {"type": type(error).__name__, "detail": detail}
        phase_data["cleanup_verdict"] = "incomplete; ownership journal retained"
    phase_data["namespace"] = fixture.namespace
    phase_data["result"] = "passed" if failure is None and cleanup_failure is None else "failed"
    phase_data["stage_timing"] = fixture.stage_snapshot()
    phase_data["command_trace"] = list(fixture.command_trace[-80:])
    _BASE.write_json_atomic(evidence_dir / f"{name}-phase.json", phase_data)
    checkpoint("phase-finished")
    if failure or cleanup_failure:
        raise _BASE.SmokeFailure(
            f"{name} phase failed; inspect {evidence_dir / f'{name}-phase.json'} and its ownership journal"
        ) from (failure or cleanup_failure)
    return phase_data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker", default="docker")
    parser.add_argument("--node", default="kind-worker")
    parser.add_argument("--image", default="cockroachdb/cockroach:v24.1.0")
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--ready-timeout", type=float, default=240.0)
    parser.add_argument(
        "--proof-mode", choices=("fault", "recovery"), default="fault",
        help="fault preserves the original proof; recovery exercises one owned unready-Pod repair",
    )
    parser.add_argument("--context", default=None, help="Optional kubectl context; defaults to the current context")
    args = parser.parse_args(argv)
    args.kubectl = "kubectl"
    # The case scripts use the current kubectl context too; the optional value
    # must therefore be absent for both the harness and native CLI invocations.
    if args.context:
        raise _BASE.SmokeFailure("Case CLI proof requires the current kubectl context; omit --context")
    if args.image != "cockroachdb/cockroach:v24.1.0":
        raise _BASE.SmokeFailure("This bounded proof supports only the cached v24.1.0 image")
    run_id = f"{time.strftime('%y%m%d')}-{os.getpid():x}"
    if not _BASE.re.fullmatch(r"[a-z0-9-]{1,16}", run_id):
        raise _BASE.SmokeFailure("Generated run identity is not a valid DNS label")
    evidence_dir = args.evidence_dir.expanduser().resolve()
    if evidence_dir.exists():
        raise _BASE.SmokeFailure("Evidence directory must be new; refusing to overwrite a prior result")
    evidence_dir.mkdir(parents=True, exist_ok=False)
    phase_names = _phase_names(args)
    if args.proof_mode == "recovery" and args.ready_timeout < 240:
        raise _BASE.SmokeFailure("Recovery proof requires the existing bounded fixture startup timeout")
    print(f"Starting isolated three-node health case proof ({args.proof_mode}); run id {run_id}", flush=True)
    results = []
    for name in phase_names:
        result = phase(args, name, run_id, evidence_dir)
        results.append(result)
        print(f"{name.title()} health case fixture completed and cleaned: {result['namespace']}", flush=True)
    _BASE.write_json_atomic(
        evidence_dir / "live-summary.json",
        {"run_id": run_id, "proof_mode": args.proof_mode, "phases": results},
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except _BASE.SmokeFailure as error:
        print(f"HEALTH CASE LIVE PROOF STOPPED: {error}", file=sys.stderr, flush=True)
        raise SystemExit(2)

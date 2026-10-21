"""Behavior-preserving version-check environment and shared-health tests."""

from __future__ import annotations

import copy
import importlib
import importlib.util
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from karma.crdb import CrdbLibrary, ProbeStatus
from karma.crdb.types import AuthenticationError, KubernetesAccessError


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "cases/cockroachdb/version-check/scripts"


@pytest.fixture
def case_modules(monkeypatch):
    for name in ("cluster", "versions", "environment", "storage"):
        monkeypatch.delitem(sys.modules, name, raising=False)
    monkeypatch.syspath_prepend(str(SCRIPTS))
    cluster_module = importlib.import_module("cluster")
    environment_module = importlib.import_module("environment")
    yield cluster_module, environment_module
    for name in ("cluster", "versions", "environment", "storage"):
        sys.modules.pop(name, None)


def _memory_adapter(*, tls: bool):
    """Use the library's real in-memory transport fixture for this bridge test."""
    support_path = ROOT / "tests/crdb/test_library.py"
    spec = importlib.util.spec_from_file_location("crdb_library_fixture_support", support_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.MemoryAdapter(tls=tls, replicas=2, custom_ports=True)


@pytest.mark.parametrize("tls", [False, True], ids=["insecure", "tls"])
def test_cluster_ready_preserves_case_readiness_then_uses_real_shared_health(case_modules, monkeypatch, tls):
    cluster_module, _ = case_modules
    adapter = _memory_adapter(tls=tls)
    monkeypatch.setenv("BENCH_NAMESPACE", adapter.namespace)
    monkeypatch.setenv("BENCH_PARAM_CLUSTER_NAME", adapter.name)
    cluster = cluster_module.Cluster(library=CrdbLibrary(adapter))
    calls = []
    cluster.deployment_ready = lambda: calls.append("deployment") or "initialized"
    cluster.statefulset = lambda: copy.deepcopy(adapter.sts)
    cluster.pods = lambda _sts: copy.deepcopy(adapter.pods)
    # These legacy case readers remain available for task/oracle callers, but
    # the common range/liveness measurement now comes from CrdbLibrary.
    cluster.node_rows = lambda *args, **kwargs: pytest.fail("duplicated node-status read")
    cluster.liveness_rows = lambda *args, **kwargs: pytest.fail("duplicated liveness read")

    assert cluster.ready() is True
    assert calls == ["deployment"]
    assert adapter.node_status_calls
    assert adapter.query_sql_calls
    assert adapter.native_identity_calls == []


def test_cluster_ready_uses_native_identity_for_26_1_pods(case_modules, monkeypatch):
    cluster_module, _ = case_modules
    adapter = _memory_adapter(tls=True)
    adapter.server_versions = ["CockroachDB CCL v24.1.4", "CockroachDB CCL v26.1.8"]
    adapter.node_status_output = (
        "id,membership,is_draining,is_available,ranges_unavailable,ranges_underreplicated,is_live\n"
        "1,active,false,true,0,0,true\n"
        "2,active,false,true,0,0,true\n"
    )
    monkeypatch.setenv("BENCH_NAMESPACE", adapter.namespace)
    monkeypatch.setenv("BENCH_PARAM_CLUSTER_NAME", adapter.name)
    cluster = cluster_module.Cluster(library=CrdbLibrary(adapter))
    cluster.deployment_ready = lambda: "initialized"
    cluster.statefulset = lambda: copy.deepcopy(adapter.sts)
    cluster.pods = lambda _sts: copy.deepcopy(adapter.pods)

    assert cluster.ready() is True
    assert [call["pod_name"] for call in adapter.native_identity_calls] == ["db-1"]
    assert [(call["pod_name"], call["sql"]) for call in adapter.query_sql_calls] == [
        ("db-0", "SELECT version() AS version;"),
        ("db-1", "SELECT version() AS version;"),
        (
            "db-0",
            "SELECT crdb_internal.cluster_id() AS cluster_id, "
            "crdb_internal.node_id() AS node_id, version() AS version;",
        ),
    ]


@pytest.mark.parametrize(
    "error",
    [AuthenticationError("credentials rejected"), KubernetesAccessError("Kubernetes read forbidden")],
)
def test_library_access_failures_remain_case_unsafe_state(case_modules, monkeypatch, error):
    cluster_module, _ = case_modules
    adapter = _memory_adapter(tls=False)
    monkeypatch.setenv("BENCH_NAMESPACE", adapter.namespace)
    monkeypatch.setenv("BENCH_PARAM_CLUSTER_NAME", adapter.name)

    class FailedLibrary:
        def probe_full_health(self, *_args, **_kwargs):
            raise error

    cluster = cluster_module.Cluster(library=FailedLibrary())
    cluster.deployment_ready = lambda: "initialized"
    cluster.statefulset = lambda: copy.deepcopy(adapter.sts)
    cluster.pods = lambda _sts: copy.deepcopy(adapter.pods)

    with pytest.raises(cluster_module.UnsafeState):
        cluster.ready()


@pytest.mark.parametrize(
    "error",
    [AuthenticationError("credentials rejected"), KubernetesAccessError("Kubernetes read forbidden")],
)
def test_library_access_failures_do_not_enter_original_reset_branch(case_modules, monkeypatch, error):
    cluster_module, environment_module = case_modules
    adapter = _memory_adapter(tls=False)
    monkeypatch.setenv("BENCH_NAMESPACE", adapter.namespace)
    monkeypatch.setenv("BENCH_PARAM_CLUSTER_NAME", adapter.name)

    class FailedLibrary:
        def probe_full_health(self, *_args, **_kwargs):
            raise error

    cluster = cluster_module.Cluster(library=FailedLibrary())
    cluster.get = lambda kind, name=None, namespace=None: (
        copy.deepcopy(adapter.sts) if kind == "statefulset" else None
    )
    cluster.deployment_ready = lambda: "initialized"
    cluster.statefulset = lambda: copy.deepcopy(adapter.sts)
    cluster.pods = lambda _sts: copy.deepcopy(adapter.pods)
    cluster.wait = lambda check, _seconds: check()
    environment = environment_module.Environment(cluster)
    environment.load = lambda: None
    environment.services = lambda: None
    resets = []
    environment.reset = lambda record=None: resets.append(record)

    with pytest.raises(cluster_module.UnsafeState):
        environment.apply()
    assert resets == []


def test_shared_health_cannot_accept_a_different_statefulset_incarnation(case_modules, monkeypatch):
    cluster_module, _ = case_modules
    adapter = _memory_adapter(tls=False)
    monkeypatch.setenv("BENCH_NAMESPACE", adapter.namespace)
    monkeypatch.setenv("BENCH_PARAM_CLUSTER_NAME", adapter.name)

    class StaleLibrary:
        def probe_full_health(self, *_args, **_kwargs):
            return SimpleNamespace(
                status=ProbeStatus.SATISFIED,
                reasons=(),
                assessment=SimpleNamespace(
                    workload=SimpleNamespace(workload_uid="replacement-sts"),
                ),
            )

    cluster = cluster_module.Cluster(library=StaleLibrary())
    cluster.deployment_ready = lambda: "initialized"
    cluster.statefulset = lambda: copy.deepcopy(adapter.sts)
    cluster.pods = lambda _sts: copy.deepcopy(adapter.pods)

    with pytest.raises(cluster_module.UnsafeState, match="identity changed"):
        cluster.ready()


def test_unready_case_pod_blocks_shared_health_observation(case_modules, monkeypatch):
    cluster_module, _ = case_modules
    adapter = _memory_adapter(tls=False)
    monkeypatch.setenv("BENCH_NAMESPACE", adapter.namespace)
    monkeypatch.setenv("BENCH_PARAM_CLUSTER_NAME", adapter.name)

    class CountingLibrary:
        calls = 0

        def probe_full_health(self, *_args, **_kwargs):
            self.calls += 1
            raise AssertionError("full health must follow the case Pod Ready contract")

    library = CountingLibrary()
    cluster = cluster_module.Cluster(library=library)
    cluster.deployment_ready = lambda: "initialized"
    cluster.statefulset = lambda: copy.deepcopy(adapter.sts)
    pods = copy.deepcopy(adapter.pods)
    pods[0]["status"]["conditions"][0]["status"] = "False"
    cluster.pods = lambda _sts: pods

    with pytest.raises(RuntimeError, match="pod is not Ready"):
        cluster.ready()
    assert library.calls == 0


class RecoveryCluster:
    """Small case runner double that records the original apply branches."""

    name = "db"

    def __init__(self, *, exists=True, states=None, ready_errors=(), sql_results=None, record=None):
        self.exists = exists
        self.states = list(states or ["initialized"])
        self.ready_errors = list(ready_errors)
        self.sql_results = list(sql_results or [])
        self.recovery_record = record
        self.events = []
        self._uid = "selected-sts"

    def get(self, kind, name=None, namespace=None):
        if kind == "statefulset":
            return {"metadata": {"uid": self._uid}} if self.exists else None
        if kind == "configmap":
            return self.recovery_record
        if kind == "pods":
            return {"items": self.pods(self.statefulset())}
        return None

    def statefulset(self):
        return {"metadata": {"uid": self._uid}, "spec": {"replicas": 3}}

    def deployment_ready(self):
        self.events.append("deployment_ready")
        return self.states.pop(0) if len(self.states) > 1 else self.states[0]

    def initialize(self):
        self.events.append("initialize")

    def bootstrap(self):
        self.events.append("bootstrap")
        self.exists = True

    def ready(self):
        self.events.append("ready")
        if self.ready_errors:
            raise self.ready_errors.pop(0)
        return True

    def wait(self, check, seconds):
        self.events.append(("wait", seconds))
        return check()

    def sql(self, query, ordinal):
        self.events.append(("sql", query, ordinal))
        return self.sql_results.pop(0) if self.sql_results else subprocess.CompletedProcess([], 0, "", "")

    def pods(self, _sts):
        return [
            {"metadata": {"name": f"db-{ordinal}"}, "status": {"conditions": [{"type": "Ready", "status": "True"}]}}
            for ordinal in range(3)
        ]

    def delete_pod(self, pod):
        self.events.append(("delete_pod", pod["metadata"]["name"]))


def _environment(case_modules, cluster):
    _, environment_module = case_modules
    environment = environment_module.Environment(cluster)
    environment.load = lambda: cluster.recovery_record
    environment.services = lambda: cluster.events.append("services")
    return environment


@pytest.mark.parametrize("tls", [False, True], ids=["insecure", "tls"])
def test_existing_healthy_environment_is_reused_without_init_or_reset(case_modules, tls):
    # The startup mode remains an observed property of the existing cluster;
    # apply does not recreate it to impose a case default.
    cluster = RecoveryCluster()
    cluster.tls = tls
    environment = _environment(case_modules, cluster)
    resets = []
    environment.reset = lambda record=None: resets.append(record)

    assert environment.apply() is None
    assert resets == []
    assert "initialize" not in cluster.events and "bootstrap" not in cluster.events
    assert cluster.events.count("services") == 2
    assert [event for event in cluster.events if isinstance(event, tuple) and event[0] == "wait"] == [
        ("wait", 90), ("wait", 180)
    ]


def test_original_apply_initializes_positive_uninitialized_existing_workload(case_modules):
    cluster = RecoveryCluster(states=["uninitialized", "initialized"])
    environment = _environment(case_modules, cluster)
    environment.reset = lambda *_args: pytest.fail("fresh deployed stores use explicit init, not reset")

    environment.apply()

    assert cluster.events.count("initialize") == 1
    assert "bootstrap" not in cluster.events


def test_original_apply_keeps_store_reset_path_for_persistently_unhealthy_owned_workload(case_modules):
    failures = [RuntimeError("node health failed")]
    sql_failures = [subprocess.CompletedProcess([], 1, "", "connection refused") for _ in range(3)]
    cluster = RecoveryCluster(ready_errors=failures, sql_results=sql_failures)
    environment = _environment(case_modules, cluster)
    resets = []

    def reset(record=None):
        resets.append(record)
        cluster.events.append("reset")

    environment.reset = reset
    environment.apply()

    assert resets == [None]
    assert "reset" in cluster.events
    assert cluster.events.count("services") == 2


def test_original_apply_resumes_owned_in_progress_reset(case_modules):
    record = {"metadata": {}, "data": {"phase": "resetting"}}
    cluster = RecoveryCluster(record=record)
    environment = _environment(case_modules, cluster)
    resumed = []

    def resume(value):
        resumed.append(value)
        value["data"]["phase"] = "ready"

    environment.reset = resume

    environment.apply()

    assert resumed == [record]
    assert "initialize" not in cluster.events
    assert "bootstrap" not in cluster.events


def test_original_apply_does_not_reset_after_control_plane_diagnostic(case_modules):
    cluster = RecoveryCluster(
        ready_errors=[RuntimeError("initial readiness failed")],
        sql_results=[subprocess.CompletedProcess([], 1, "", "TLS handshake timeout") for _ in range(3)],
    )
    environment = _environment(case_modules, cluster)
    resets = []
    environment.reset = lambda record=None: resets.append(record)

    with pytest.raises(RuntimeError, match="control-plane failure"):
        environment.apply()
    assert resets == []


def test_original_apply_bootstraps_an_absent_target_then_initializes(case_modules):
    cluster = RecoveryCluster(exists=False, states=["uninitialized", "initialized"])
    environment = _environment(case_modules, cluster)
    environment.reset = lambda *_args: pytest.fail("new stores do not use the reset path")

    environment.apply()

    assert cluster.events.index("bootstrap") < cluster.events.index("initialize")
    assert "reset" not in cluster.events

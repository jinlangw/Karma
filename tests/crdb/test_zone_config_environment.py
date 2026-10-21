"""Zone preparation keeps its original recovery policy around shared health."""

from __future__ import annotations

import copy
import importlib
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from karma.crdb import CrdbLibrary, ProbeStatus
from karma.crdb.types import KubernetesAccessError
from tests.crdb.test_library import MemoryAdapter


SCRIPTS = Path(__file__).resolve().parents[2] / "cases/cockroachdb/zone-config/scripts"


@pytest.fixture
def case_modules(monkeypatch):
    for name in ("cluster", "storage", "environment"):
        monkeypatch.delitem(sys.modules, name, raising=False)
    monkeypatch.syspath_prepend(str(SCRIPTS))
    cluster_module = importlib.import_module("cluster")
    storage_module = importlib.import_module("storage")
    environment_module = importlib.import_module("environment")
    yield cluster_module, storage_module, environment_module
    for name in ("cluster", "storage", "environment"):
        sys.modules.pop(name, None)


class FakeCluster:
    namespace = "zone-fixture"
    name = "db"
    labels = {"app.kubernetes.io/name": "cockroachdb", "app.kubernetes.io/instance": "db"}

    def __init__(self, *, present=True, record=None, deployment_states=(), usable_results=(), sql_results=()):
        self.sts = self._statefulset() if present else None
        self.record = record
        self.deployment_states = list(deployment_states or ["initialized"])
        self.usable_results = list(usable_results or [True])
        self.sql_results = list(sql_results or [SimpleNamespace(returncode=0, stderr="")])
        self.services = {}
        self.pod_items = [self._pod("db-0", ready=False), self._pod("db-1", ready=True)]
        self.bootstrap_calls = 0
        self.initialize_calls = 0
        self.usable_calls = 0
        self.wait_seconds = []
        self.created = []
        self.deleted_pods = []
        self.get_calls = []
        self.kubectl_calls = []

    def _statefulset(self):
        return {
            "metadata": {"name": self.name, "namespace": self.namespace, "uid": "sts-uid"},
            "spec": {
                "replicas": 2,
                "serviceName": self.name,
                "selector": {"matchLabels": {"app": self.name}},
                "template": {
                    "metadata": {"labels": {"app": self.name}},
                    "spec": {"containers": [{"name": "db", "image": "cockroachdb/cockroach:v24.1.0", "command": ["cockroach", "start", "--port=26257"]}]},
                },
            },
        }

    def _pod(self, name, *, ready):
        return {
            "metadata": {
                "name": name,
                "labels": {"app": self.name},
                "ownerReferences": [{"uid": self.sts["metadata"]["uid"], "controller": True}] if self.sts else [],
            },
            "status": {"conditions": [{"type": "Ready", "status": "True" if ready else "False"}]},
            "spec": {"volumes": []},
        }

    def get(self, kind, name=None, namespace=None):
        self.get_calls.append((kind, name, namespace))
        if kind == "statefulset" and name == self.name:
            return self.sts
        if kind == "configmap" and name == self.name + "-zone-config-recovery":
            return self.record
        if kind in ("service", "Service"):
            return self.services.get(name)
        if kind == "pods":
            return {"items": self.pod_items}
        return None

    def statefulset(self):
        return self.sts

    def deployment_ready(self):
        if len(self.deployment_states) > 1:
            return self.deployment_states.pop(0)
        return self.deployment_states[0]

    def usable(self):
        self.usable_calls += 1
        value = self.usable_results.pop(0) if len(self.usable_results) > 1 else self.usable_results[0]
        if isinstance(value, BaseException):
            raise value
        return value

    def pods(self, _sts):
        return self.pod_items

    def sql(self, _query, ordinal=0):
        result = self.sql_results[min(ordinal, len(self.sql_results) - 1)]
        return result

    def create(self, obj):
        self.created.append(copy.deepcopy(obj))
        if obj["kind"] == "Service":
            self.services[obj["metadata"]["name"]] = copy.deepcopy(obj)
        elif obj["kind"] == "ConfigMap":
            self.record = copy.deepcopy(obj)

    def identity(self, obj):
        labels = obj["metadata"].get("labels", {})
        if any(key in labels and labels[key] != value for key, value in self.labels.items()):
            raise RuntimeError("conflicting labels")

    def bootstrap(self):
        self.bootstrap_calls += 1
        self.sts = self._statefulset()
        for pod in self.pod_items:
            pod["metadata"]["ownerReferences"] = [{"uid": self.sts["metadata"]["uid"], "controller": True}]

    def initialize(self):
        self.initialize_calls += 1

    def wait(self, check, seconds):
        self.wait_seconds.append(seconds)
        return check()

    def delete_pod(self, pod):
        self.deleted_pods.append(pod["metadata"]["name"])

    def kubectl(self, *args, **kwargs):
        self.kubectl_calls.append((args, kwargs))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    @staticmethod
    def require(result):
        if result.returncode:
            raise RuntimeError(result.stderr)
        return result.stdout


def _recovery_record(uid="sts-uid", phase="ready"):
    return {
        "metadata": {"labels": {"karma.dev/fixture": "zone-config-recovery", "app.kubernetes.io/instance": "db"}},
        "data": {"statefulset_uid": uid, "phase": phase},
    }


def test_original_environment_healthy_reuse_keeps_services_and_does_not_reset(case_modules):
    _, _, environment_module = case_modules
    cluster = FakeCluster(usable_results=[True, True])
    environment = environment_module.Environment(cluster)
    resets = []
    environment.reset = lambda record=None: resets.append(record)

    assert environment.apply() is None

    assert cluster.bootstrap_calls == 0
    assert resets == []
    assert {item["metadata"]["name"] for item in cluster.created} == {"db", "db-public"}
    assert cluster.wait_seconds == [90, 180]
    assert cluster.usable_calls == 2


def test_owned_reset_record_resumes_original_reset_path(case_modules):
    _, _, environment_module = case_modules
    record = _recovery_record(phase="resetting")
    cluster = FakeCluster(record=record, usable_results=[True])
    environment = environment_module.Environment(cluster)
    resumed = []

    def reset(pending):
        resumed.append(pending)
        pending["data"]["phase"] = "ready"

    environment.reset = reset
    assert environment.apply() is None
    assert resumed == [record]
    assert cluster.wait_seconds == [180]


def test_existing_uninitialized_store_is_initialized_before_usable_health(case_modules):
    _, _, environment_module = case_modules
    cluster = FakeCluster(deployment_states=["uninitialized", "initialized"], usable_results=[True, True])
    environment = environment_module.Environment(cluster)
    resets = []
    environment.reset = lambda record=None: resets.append(record)

    environment.apply()

    assert cluster.initialize_calls == 1
    assert resets == []
    assert cluster.wait_seconds == [90, 180]


def test_fresh_environment_keeps_original_bootstrap_then_positive_uninitialized_init(case_modules):
    _, _, environment_module = case_modules
    cluster = FakeCluster(
        present=False,
        deployment_states=["uninitialized", "initialized"],
        usable_results=[True, True],
    )
    environment = environment_module.Environment(cluster)
    resets = []
    environment.reset = lambda record=None: resets.append(record)

    environment.apply()

    assert cluster.bootstrap_calls == 1
    assert cluster.initialize_calls == 1
    assert resets == []
    assert cluster.wait_seconds == [90, 180]


def test_persistent_unready_pod_restarts_then_enters_original_reset_escalation(case_modules):
    _, _, environment_module = case_modules
    cluster = FakeCluster(usable_results=[RuntimeError("unhealthy"), RuntimeError("still unhealthy"), True])
    cluster.sql_results = [SimpleNamespace(returncode=0, stderr=""), SimpleNamespace(returncode=0, stderr="")]
    environment = environment_module.Environment(cluster)
    resets = []
    environment.reset = lambda record=None: resets.append(record)

    environment.apply()

    assert cluster.deleted_pods == ["db-0"]
    assert resets == [None]
    assert cluster.wait_seconds == [90, 180, 180]


def test_all_node_sql_failures_keep_the_original_reset_branch(case_modules):
    _, _, environment_module = case_modules
    cluster = FakeCluster(usable_results=[RuntimeError("unhealthy"), True])
    cluster.sql_results = [SimpleNamespace(returncode=1, stderr="connection refused")]
    environment = environment_module.Environment(cluster)
    resets = []
    environment.reset = lambda record=None: resets.append(record)

    environment.apply()

    assert resets == [None]
    assert cluster.deleted_pods == []


def test_api_failure_from_shared_health_does_not_enter_case_reset_branch(case_modules, monkeypatch):
    cluster_module, _, environment_module = case_modules
    monkeypatch.setenv("BENCH_NAMESPACE", "crdb-fixture")
    monkeypatch.setenv("BENCH_PARAM_CLUSTER_NAME", "db")
    adapter = MemoryAdapter()
    adapter.query_error = KubernetesAccessError("forbidden")
    shared_cluster = cluster_module.Cluster(library=CrdbLibrary(adapter))
    shared_cluster.deployment_ready = lambda: "initialized"
    shared_cluster.statefulset = lambda: adapter.sts
    shared_cluster.pods = lambda _sts: adapter.pods

    case_cluster = FakeCluster(usable_results=[True, True])
    case_cluster.usable = shared_cluster.ready
    environment = environment_module.Environment(case_cluster)
    resets = []
    environment.reset = lambda record=None: resets.append(record)

    with pytest.raises(cluster_module.UnsafeState, match="shared health observation"):
        environment.apply()

    assert resets == []
    assert adapter.node_status_calls == []


@pytest.mark.parametrize("tls", [False, True])
def test_cluster_ready_calls_real_shared_health_observation(case_modules, monkeypatch, tls):
    cluster_module, _, _ = case_modules
    monkeypatch.setenv("BENCH_NAMESPACE", "crdb-fixture")
    monkeypatch.setenv("BENCH_PARAM_CLUSTER_NAME", "db")
    adapter = MemoryAdapter(tls=tls)
    cluster = cluster_module.Cluster(library=CrdbLibrary(adapter))
    cluster.deployment_ready = lambda: "initialized"
    cluster.statefulset = lambda: adapter.sts
    cluster.pods = lambda _sts: adapter.pods

    assert cluster.ready()

    assert len(adapter.node_status_calls) == 1
    assert len(adapter.liveness_query_calls) == 1
    assert {call["tls_mode"] for call in adapter.query_sql_calls} == {"tls" if tls else "insecure"}


def test_zone_usable_accepts_underreplication_while_ready_requires_full_health(case_modules, monkeypatch):
    cluster_module, _, _ = case_modules
    monkeypatch.setenv("BENCH_NAMESPACE", "crdb-fixture")
    monkeypatch.setenv("BENCH_PARAM_CLUSTER_NAME", "db")
    adapter = MemoryAdapter()
    adapter.node_status_output = (
        "id,is_available,ranges_unavailable,ranges_underreplicated\n"
        "1,true,0,2\n"
        "2,true,0,2\n"
    )
    cluster = cluster_module.Cluster(library=CrdbLibrary(adapter))
    cluster.deployment_ready = lambda: "initialized"
    cluster.statefulset = lambda: adapter.sts
    cluster.pods = lambda _sts: adapter.pods

    with pytest.raises(RuntimeError, match="under-replicated ranges"):
        cluster.ready()
    assert cluster.usable()
    assert len(adapter.node_status_calls) == 2


@pytest.mark.parametrize("error", [KubernetesAccessError("forbidden")])
def test_shared_typed_control_plane_error_is_not_converted_to_store_health(case_modules, monkeypatch, error):
    cluster_module, _, _ = case_modules
    monkeypatch.setenv("BENCH_NAMESPACE", "crdb-fixture")
    monkeypatch.setenv("BENCH_PARAM_CLUSTER_NAME", "db")
    adapter = MemoryAdapter()
    adapter.node_status_error = error
    cluster = cluster_module.Cluster(library=CrdbLibrary(adapter))
    cluster.deployment_ready = lambda: "initialized"
    cluster.statefulset = lambda: adapter.sts
    cluster.pods = lambda _sts: adapter.pods

    with pytest.raises(cluster_module.UnsafeState, match="shared health observation"):
        cluster.ready()

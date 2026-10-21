"""Monitoring preparation retains its original recovery policy around shared health."""

from __future__ import annotations

import copy
import importlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

from karma.crdb import CrdbLibrary
from karma.crdb.types import KubernetesAccessError
from tests.crdb.test_library import MemoryAdapter


SCRIPTS = Path(__file__).resolve().parents[2] / "cases/cockroachdb/monitoring-integration/scripts"


@pytest.fixture
def case_modules(monkeypatch):
    for name in ("cluster", "storage", "monitoring", "environment"):
        monkeypatch.delitem(sys.modules, name, raising=False)
    monkeypatch.syspath_prepend(str(SCRIPTS))
    cluster_module = importlib.import_module("cluster")
    environment_module = importlib.import_module("environment")
    yield cluster_module, environment_module
    for name in ("cluster", "storage", "monitoring", "environment"):
        sys.modules.pop(name, None)


def make_sts(*, uid="sts-monitoring", http_port=8080, replicas=2):
    labels = {"app.kubernetes.io/name": "cockroachdb", "app.kubernetes.io/instance": "db"}
    container = {
        "name": "db",
        "image": "cockroachdb/cockroach:v24.1.0",
        "args": ["start", "--insecure", f"--http-addr=0.0.0.0:{http_port}"],
        "ports": [
            {"name": "grpc", "containerPort": 26257},
            {"name": "http", "containerPort": http_port},
        ],
        "readinessProbe": {
            "httpGet": {"path": "/health?ready=1", "port": http_port, "scheme": "HTTP"}
        },
    }
    return {
        "metadata": {"name": "db", "namespace": "monitoring-test", "uid": uid, "resourceVersion": "10"},
        "spec": {
            "replicas": replicas,
            "serviceName": "db",
            "selector": {"matchLabels": labels},
            "template": {"metadata": {"labels": labels}, "spec": {"containers": [container]}},
            "updateStrategy": {"type": "RollingUpdate"},
        },
    }


def make_service(name, *, headless=False, port=8080):
    labels = {"app.kubernetes.io/name": "cockroachdb", "app.kubernetes.io/instance": "db"}
    spec = {
        "selector": labels,
        "ports": [{"name": "http", "port": port, "targetPort": port}],
    }
    if headless:
        spec.update(clusterIP="None", publishNotReadyAddresses=True)
    else:
        spec["clusterIP"] = "10.0.0.10"
    return {"metadata": {"name": name, "namespace": "monitoring-test", "uid": name + "-uid"}, "spec": spec}


class FakeCluster:
    namespace = "monitoring-test"
    name = "db"
    labels = {"app.kubernetes.io/name": "cockroachdb", "app.kubernetes.io/instance": "db"}

    def __init__(self, *, present=True, tls=False, http_port=8080):
        self.sts = make_sts(http_port=http_port) if present else None
        self.tls = tls
        self.events = []
        self.created = []
        self.deleted_pods = []
        self.wait_seconds = []
        self.client_calls = []
        self.sql_results = [SimpleNamespace(returncode=0, stdout="", stderr="")]
        self.ready_results = [True]
        self.deployment_results = ["initialized"]
        self.records = {}
        self.pods_by_name = {}
        self.services_by_name = {}
        self._make_pods()
        if present:
            self.services_by_name["db"] = make_service("db", headless=True)
            self.services_by_name["db-public"] = make_service("db-public")

    def _make_pods(self):
        if self.sts is None:
            self.pods_by_name = {}
            return
        labels = self.sts["spec"]["template"]["metadata"]["labels"]
        template_spec = self.sts["spec"]["template"]["spec"]
        self.pods_by_name = {
            f"db-{ordinal}": {
                "metadata": {
                    "name": f"db-{ordinal}",
                    "uid": f"pod-{ordinal}-uid",
                    "labels": dict(labels),
                    "ownerReferences": [{"uid": self.sts["metadata"]["uid"], "controller": True}],
                },
                "spec": copy.deepcopy(template_spec),
                "status": {"conditions": [{"type": "Ready", "status": "True"}]},
            }
            for ordinal in range(self.sts["spec"]["replicas"])
        }

    def get(self, kind, name=None, namespace=None):
        if kind in ("statefulset", "StatefulSet") and name == self.name:
            return self.sts
        if kind in ("service", "Service"):
            return self.services_by_name.get(name)
        if kind in ("configmap", "ConfigMap"):
            return self.records.get(name)
        if kind in ("pods", "Pods"):
            return {"items": list(self.pods_by_name.values())}
        if kind in ("pod", "Pod"):
            return self.pods_by_name.get(name)
        return None

    def statefulset(self):
        if self.sts is None:
            raise RuntimeError("selected StatefulSet is absent")
        return self.sts

    def pods(self, _sts):
        return list(self.pods_by_name.values())

    def identity(self, _obj):
        return None

    def create(self, obj):
        self.created.append(copy.deepcopy(obj))
        stored = copy.deepcopy(obj)
        stored["metadata"]["uid"] = obj["metadata"]["name"] + "-uid"
        stored["metadata"]["resourceVersion"] = "11"
        for port in stored.get("spec", {}).get("ports", []):
            port.setdefault("targetPort", port["port"])
        if obj["kind"] == "Service":
            self.services_by_name[obj["metadata"]["name"]] = stored
        elif obj["kind"] == "ConfigMap":
            self.records[obj["metadata"]["name"]] = stored

    def bootstrap(self):
        self.events.append("bootstrap")
        self.sts = make_sts()
        self._make_pods()

    def deployment_ready(self):
        self.events.append("deployment_ready")
        value = self.deployment_results.pop(0) if len(self.deployment_results) > 1 else self.deployment_results[0]
        return value

    def ready(self):
        self.events.append("ready")
        value = self.ready_results.pop(0) if len(self.ready_results) > 1 else self.ready_results[0]
        if isinstance(value, BaseException):
            raise value
        return value

    def connection_flags(self, _container=None):
        return ["--certs-dir=/cockroach/cockroach-certs"] if self.tls else ["--insecure"]

    def kubectl(self, *command, **kwargs):
        self.events.append(("kubectl", command))
        if command and command[0] == "patch":
            kind, name = command[1], command[2]
            payload = json.loads(command[command.index("-p") + 1])
            if kind.lower() == "configmap":
                obj = self.records[name]
            elif kind.lower() == "statefulset":
                obj = self.sts
            else:
                obj = None
            if obj:
                for operation in payload:
                    if operation.get("path") == "/data":
                        obj["data"] = copy.deepcopy(operation["value"])
                    elif operation.get("path", "").startswith("/spec/"):
                        obj["spec"][operation["path"].split("/", 2)[2]] = copy.deepcopy(operation["value"])
        if "exec" in command:
            return SimpleNamespace(returncode=0, stdout="sys_uptime 1\n", stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    @staticmethod
    def require(result):
        if result.returncode:
            raise RuntimeError(result.stderr or "command failed")
        return result.stdout

    def client(self, *command, **kwargs):
        self.client_calls.append(command)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    def sql(self, _query, ordinal=0):
        return self.sql_results[min(ordinal, len(self.sql_results) - 1)]

    def patch_spec(self, sts, fields):
        self.events.append("patch_spec")
        for key, value in fields.items():
            sts["spec"][key] = copy.deepcopy(value)

    def delete_pod(self, pod):
        self.events.append(("delete_pod", pod["metadata"]["name"]))
        self.deleted_pods.append(pod["metadata"]["name"])

    def wait(self, check, seconds):
        self.wait_seconds.append(seconds)
        result = check()
        if not result:
            raise RuntimeError("condition is not ready")
        return None

    @staticmethod
    def host(ordinal, _sts=None):
        return f"db-{ordinal}.db.monitoring-test.svc.cluster.local"


@pytest.fixture
def environment(case_modules, monkeypatch):
    _, environment_module = case_modules
    monkeypatch.setenv("BENCH_NAMESPACE", "monitoring-test")
    monkeypatch.setenv("BENCH_PARAM_CLUSTER_NAME", "db")
    monkeypatch.setenv("BENCH_PARAM_METRICS_PORT", "8080")
    monkeypatch.setenv("BENCH_PARAM_METRICS_PATH", "/_status/vars")
    cluster = FakeCluster()
    return environment_module.Environment(cluster), cluster


@pytest.mark.parametrize("tls,scheme", [(False, "http"), (True, "https")])
def test_original_apply_reuses_healthy_tls_and_insecure_cluster(environment, tls, scheme):
    environment, cluster = environment
    cluster.tls = tls
    cluster.sts["spec"]["template"]["spec"]["containers"][0]["args"] = [
        "start",
        "--certs-dir=/cockroach/cockroach-certs" if tls else "--insecure",
        "--http-addr=0.0.0.0:8080",
    ]
    cluster.connection_flags = lambda _container=None: ["--certs-dir=/cockroach/cockroach-certs"] if tls else ["--insecure"]
    resets = []
    environment.reset = lambda record=None: resets.append(record)

    environment.apply()

    assert resets == []
    assert cluster.created == []
    assert cluster.deleted_pods == []
    assert cluster.wait_seconds == [90, 180]
    assert any(f"{scheme}://localhost:8080/_status/vars" in str(call) for call in cluster.events)


def test_original_services_path_repairs_missing_public_service_before_health(environment):
    environment, cluster = environment
    del cluster.services_by_name["db-public"]

    environment.apply()

    assert [obj["metadata"]["name"] for obj in cluster.created] == ["db-public"]
    assert cluster.wait_seconds == [90, 180]


def test_original_listener_repair_updates_template_restarts_owned_pods_and_finishes(environment):
    environment, cluster = environment
    db = cluster.sts["spec"]["template"]["spec"]["containers"][0]
    db["args"][-1] = "--http-addr=0.0.0.0:9090"
    db["ports"][1]["containerPort"] = 9090
    db["readinessProbe"]["httpGet"]["port"] = 9090
    for pod in cluster.pods_by_name.values():
        pod["spec"] = copy.deepcopy(cluster.sts["spec"]["template"]["spec"])

    environment.apply()

    assert cluster.deleted_pods == ["db-1", "db-0"]
    assert "--http-addr=0.0.0.0:8080" in cluster.sts["spec"]["template"]["spec"]["containers"][0]["args"]
    record = cluster.records["db-monitoring-listener"]
    assert record["data"]["phase"] == "ready"
    assert cluster.sts["spec"]["updateStrategy"] == {"type": "RollingUpdate"}


def test_original_listener_repair_resumes_matching_pending_record(environment):
    environment, cluster = environment
    cluster.sts["spec"]["updateStrategy"] = {"type": "OnDelete"}
    record = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": "db-monitoring-listener",
            "uid": "listener-record-uid",
            "resourceVersion": "3",
            "labels": {"karma.dev/fixture": "monitoring-listener", "app.kubernetes.io/instance": "db"},
        },
        "data": {
            "statefulset_uid": cluster.sts["metadata"]["uid"],
            "original_strategy": json.dumps({"type": "RollingUpdate"}),
            "phase": "repairing",
        },
    }
    cluster.records[record["metadata"]["name"]] = record

    environment.apply()

    assert cluster.deleted_pods == []
    assert cluster.sts["spec"]["updateStrategy"] == {"type": "RollingUpdate"}
    assert cluster.records["db-monitoring-listener"]["data"]["phase"] == "ready"


def test_owned_store_reset_record_uses_original_resume_branch(environment):
    environment, cluster = environment
    record = {
        "metadata": {
            "labels": {"karma.dev/fixture": "monitoring-recovery", "app.kubernetes.io/instance": "db"}
        },
        "data": {"statefulset_uid": cluster.sts["metadata"]["uid"], "phase": "resetting"},
    }
    cluster.records["db-monitoring-recovery"] = record
    resumed = []

    def resume(current):
        resumed.append(current)
        current["data"]["phase"] = "ready"

    environment.reset = resume
    environment.apply()

    assert resumed == [record]
    assert cluster.wait_seconds == [180]


def test_fresh_fixture_uses_original_bootstrap_and_positive_uninitialized_init(case_modules, monkeypatch):
    _, environment_module = case_modules
    monkeypatch.setenv("BENCH_NAMESPACE", "monitoring-test")
    monkeypatch.setenv("BENCH_PARAM_CLUSTER_NAME", "db")
    monkeypatch.setenv("BENCH_PARAM_METRICS_PORT", "8080")
    cluster = FakeCluster(present=False)
    cluster.deployment_results = ["uninitialized", "initialized"]
    cluster.services_by_name.clear()
    environment = environment_module.Environment(cluster)

    environment.apply()

    assert cluster.events[0] == "bootstrap"
    assert cluster.client_calls == [("init",)]
    assert cluster.wait_seconds == [90, 180]


def test_original_unready_restart_then_reset_escalation_is_retained(environment):
    environment, cluster = environment
    cluster.ready_results = [RuntimeError("selected pod is unready"), RuntimeError("still unready"), True]
    cluster.pods_by_name["db-0"]["status"]["conditions"] = [{"type": "Ready", "status": "False"}]
    cluster.sql_results = [SimpleNamespace(returncode=0, stdout="", stderr="")]
    resets = []
    environment.reset = lambda record=None: resets.append(record)

    environment.apply()

    assert cluster.deleted_pods == ["db-0"]
    assert resets == [None]
    assert cluster.wait_seconds == [90, 180, 180]


@pytest.mark.parametrize("tls", [False, True])
def test_cluster_ready_uses_real_shared_library_observation(case_modules, monkeypatch, tls):
    cluster_module, _ = case_modules
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


def test_shared_access_failure_stays_out_of_original_store_reset_path(environment, case_modules, monkeypatch):
    cluster_module, _ = case_modules
    env, fake = environment
    monkeypatch.setenv("BENCH_NAMESPACE", "crdb-fixture")
    monkeypatch.setenv("BENCH_PARAM_CLUSTER_NAME", "db")
    adapter = MemoryAdapter()
    adapter.node_status_error = KubernetesAccessError("forbidden")
    shared_cluster = cluster_module.Cluster(library=CrdbLibrary(adapter))
    shared_cluster.deployment_ready = lambda: "initialized"
    shared_cluster.statefulset = lambda: adapter.sts
    shared_cluster.pods = lambda _sts: adapter.pods
    fake.ready = shared_cluster.ready
    resets = []
    env.reset = lambda record=None: resets.append(record)

    with pytest.raises(cluster_module.UnsafeState, match="forbidden"):
        env.apply()

    assert resets == []

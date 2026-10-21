"""Behavior checks for readonly-audit setup and its shared health seam."""

from __future__ import annotations

import copy
import hashlib
import importlib
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

from karma.crdb import CrdbLibrary, ProbeStatus, TLSMode


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "cases/cockroachdb/readonly-audit/scripts"


@pytest.fixture
def case_modules(monkeypatch):
    names = ("cluster", "storage", "environment")
    for name in names:
        monkeypatch.delitem(sys.modules, name, raising=False)
    monkeypatch.syspath_prepend(str(SCRIPTS))
    modules = tuple(importlib.import_module(name) for name in names)
    yield modules
    for name in names:
        sys.modules.pop(name, None)


def _template(name: str, *, tls: bool = False) -> dict:
    labels = {"app.kubernetes.io/name": "cockroachdb", "app.kubernetes.io/instance": name}
    command = [
        "/bin/bash",
        "-ec",
        "exec /cockroach/cockroach start --advertise-host=$(POD_NAME)." + name + ".$(POD_NAMESPACE).svc.cluster.local "
        "--port=26257 --join=" + name + "-0." + name + ".$(POD_NAMESPACE).svc.cluster.local:26257 "
        "--certs-dir=/cockroach/cockroach-certs" if tls else
        "exec /cockroach/cockroach start --advertise-host=$(POD_NAME)." + name + ".$(POD_NAMESPACE).svc.cluster.local "
        "--port=26257 --join=" + name + "-0." + name + ".$(POD_NAMESPACE).svc.cluster.local:26257 --insecure",
    ]
    container = {
        "name": "db",
        "image": "cockroachdb/cockroach:v24.1.0",
        "command": command,
        "volumeMounts": [{"name": "data", "mountPath": "/cockroach/cockroach-data"}],
    }
    volumes = []
    if tls:
        container["volumeMounts"].append({"name": "certs", "mountPath": "/cockroach/cockroach-certs", "readOnly": True})
        volumes.append({"name": "certs", "secret": {"secretName": "db-certs"}})
    return {
        "metadata": {"labels": labels},
        "spec": {"containers": [container], "volumes": volumes},
    }


def _statefulset(name="db", *, uid="sts-uid", replicas=2, tls=False):
    labels = {"app.kubernetes.io/name": "cockroachdb", "app.kubernetes.io/instance": name}
    return {
        "metadata": {"name": name, "namespace": "audit-fixture", "uid": uid, "resourceVersion": "7", "labels": labels},
        "spec": {
            "serviceName": name,
            "replicas": replicas,
            "selector": {"matchLabels": labels},
            "template": _template(name, tls=tls),
            "volumeClaimTemplates": [{"metadata": {"name": "data"}, "spec": {"resources": {"requests": {"storage": "1Gi"}}}}],
            "updateStrategy": {"type": "RollingUpdate", "rollingUpdate": {"partition": 0}},
        },
    }


def _pod(name: str, ordinal: int, sts_uid: str, *, ready=True):
    return {
        "metadata": {
            "name": f"{name}-{ordinal}",
            "namespace": "audit-fixture",
            "uid": f"pod-{ordinal}",
            "ownerReferences": [{"controller": True, "uid": sts_uid}],
            "labels": {"app.kubernetes.io/name": "cockroachdb", "app.kubernetes.io/instance": name},
            "annotations": {},
        },
        "spec": {"volumes": [{"persistentVolumeClaim": {"claimName": f"data-{name}-{ordinal}"}}]},
        "status": {"conditions": [{"type": "Ready", "status": "True" if ready else "False"}]},
    }


def _services(name="db"):
    selector = {"app.kubernetes.io/name": "cockroachdb", "app.kubernetes.io/instance": name}
    return {
        name: {
            "kind": "Service",
            "metadata": {"name": name, "namespace": "audit-fixture", "uid": "svc-headless", "resourceVersion": "3", "labels": selector},
            "spec": {"clusterIP": "None", "selector": selector, "publishNotReadyAddresses": True,
                     "ports": [{"name": "grpc", "port": 26257}, {"name": "http", "port": 8080}]},
        },
        name + "-public": {
            "kind": "Service",
            "metadata": {"name": name + "-public", "namespace": "audit-fixture", "uid": "svc-public", "resourceVersion": "4", "labels": selector},
            "spec": {"clusterIP": "10.0.0.9", "selector": selector,
                     "ports": [{"name": "sql", "port": 26257}]},
        },
    }


def test_secret_signatures_wrapper_keeps_cluster_get_and_local_error(case_modules):
    _, storage_module, _ = case_modules
    template = {
        "spec": {
            "volumes": [
                {"secret": {"secretName": "second"}},
                {"projected": {"sources": [{"secret": {"name": "first"}}, {"secret": {"name": "second"}}]}},
            ]
        }
    }
    calls = []
    secrets = {
        "first": {"metadata": {"uid": "uid-first"}, "data": {"key": "one"}},
        "second": {"metadata": {"uid": "uid-second"}, "data": {"key": "two"}},
    }
    cluster = SimpleNamespace(
        get=lambda kind, name: calls.append((kind, name)) or secrets.get(name)
    )

    result = storage_module.signatures(cluster, template)

    assert [call for call in calls] == [("secret", "first"), ("secret", "second")]
    assert result == {
        name: {
            "uid": secrets[name]["metadata"]["uid"],
            "sha256": hashlib.sha256(
                json.dumps(secrets[name]["data"], sort_keys=True).encode()
            ).hexdigest(),
        }
        for name in secrets
    }

    missing_cluster = SimpleNamespace(get=lambda kind, name: None)
    with pytest.raises(storage_module.UnsafeState, match="^mounted Secret is missing$"):
        storage_module.signatures(missing_cluster, template)


class FakeCluster:
    namespace = "audit-fixture"
    name = "db"

    def __init__(self, *, tls=False, present=True, state="initialized", replicas=2, pod_readiness=None):
        self.sts = _statefulset(uid="sts-uid", replicas=replicas, tls=tls) if present else None
        self.current_state = state
        self.deployment_states = []
        self.pods_data = [_pod(self.name, i, "sts-uid", ready=(pod_readiness or {}).get(i, True)) for i in range(replicas)] if present else []
        self.service_data = _services() if present else {}
        self.record = None
        self.bootstrap_calls = 0
        self.init_calls = []
        self.sql_calls = []
        self.delete_calls = []
        self.create_calls = []
        self.patch_spec_calls = []
        self.wait_calls = []
        self.reset_store_calls = []
        self.store_data = []
        self.sql_results = []
        self.events = []

    @property
    def labels(self):
        return {"app.kubernetes.io/name": "cockroachdb", "app.kubernetes.io/instance": self.name}

    def get(self, kind, name=None, namespace=None):
        if kind == "statefulset" and name == self.name:
            return self.sts
        if kind == "configmap" and name == self.name + "-audit-recovery":
            return self.record
        if kind == "service":
            return self.service_data.get(name)
        if kind == "pods":
            return {"items": self.pods_data}
        if kind == "pod":
            return next((pod for pod in self.pods_data if pod["metadata"]["name"] == name), None)
        if kind in {"pvc", "persistentvolumes", "statefulsets", "deployments", "daemonsets", "jobs", "replicasets", "replicationcontrollers", "cronjobs"}:
            return {"items": []}
        if kind == "secret":
            return None
        return None

    def statefulset(self):
        return self.sts

    def identity(self, _obj):
        return None

    def create(self, obj):
        self.create_calls.append(copy.deepcopy(obj))
        if obj.get("kind") == "Service":
            self.service_data[obj["metadata"]["name"]] = copy.deepcopy(obj)
        elif obj.get("kind") == "StatefulSet":
            self.sts = copy.deepcopy(obj)
            self.pods_data = [_pod(self.name, i, "sts-uid") for i in range(int(obj["spec"].get("replicas", 1)))]

    def bootstrap(self):
        self.bootstrap_calls += 1
        if self.sts is None:
            self.sts = _statefulset(uid="created-sts-uid", replicas=2)
            self.pods_data = [_pod(self.name, i, "created-sts-uid") for i in range(2)]
        return None

    def deployment_ready(self):
        self.events.append("deployment_ready")
        if self.deployment_states:
            self.current_state = self.deployment_states.pop(0)
        return self.current_state

    def ready(self):
        self.events.append("ready")
        return True

    def pods(self, _sts):
        return self.pods_data

    def wait(self, check, seconds):
        self.wait_calls.append(seconds)
        last = None
        for _ in range(5):
            try:
                if check():
                    return
            except (RuntimeError, ValueError) as error:
                last = error
        raise RuntimeError(str(last or "test wait expired"))

    def require(self, result):
        if result.returncode:
            raise RuntimeError(result.stderr or "command failed")
        return result.stdout

    def client(self, *args, **kwargs):
        self.init_calls.append((args, kwargs))
        if args == ("init",):
            self.current_state = "initialized"
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    def sql(self, query, ordinal=0, timeout=10):
        self.sql_calls.append((query, ordinal))
        if self.sql_results:
            return self.sql_results.pop(0)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    def stores(self, _sts, _count=None):
        return copy.deepcopy(self.store_data)

    def patch_spec(self, _sts, fields):
        fields = copy.deepcopy(fields)
        self.patch_spec_calls.append(fields)
        self.sts["spec"].update(fields)
        if fields.get("replicas") == 0:
            self.pods_data = []
        elif fields.get("replicas", 1) > 0 and not self.pods_data:
            self.pods_data = [_pod(self.name, i, self.sts["metadata"]["uid"]) for i in range(fields["replicas"])]

    def delete_pod(self, pod):
        self.delete_calls.append((pod["metadata"]["name"], pod["metadata"]["uid"]))
        self.pods_data = [current for current in self.pods_data if current["metadata"]["uid"] != pod["metadata"]["uid"]]

    def kubectl(self, *args, **kwargs):
        return SimpleNamespace(returncode=0, stdout="", stderr="")


def test_healthy_insecure_and_tls_apply_reuses_existing_cluster(case_modules):
    _, _, environment_module = case_modules
    for tls in (False, True):
        cluster = FakeCluster(tls=tls)
        environment = environment_module.Environment(cluster)

        environment.apply()

        assert cluster.bootstrap_calls == 0
        assert cluster.init_calls == []
        assert cluster.sql_calls == []
        assert cluster.delete_calls == []
        assert cluster.patch_spec_calls == []
        assert cluster.create_calls == []
        assert cluster.wait_calls == [90, 180]


def test_cluster_store_wrapper_keeps_pvc_binding_and_identity_checks_local(case_modules, monkeypatch):
    cluster_module, _, _ = case_modules
    cluster = cluster_module.Cluster(namespace="audit-fixture", name="db")
    sts = _statefulset(replicas=2)
    pvc_by_name = {
        f"data-db-{ordinal}": {
            "metadata": {
                "name": f"data-db-{ordinal}",
                "uid": f"pvc-{ordinal}",
                "labels": copy.deepcopy(cluster.labels),
                "ownerReferences": [],
            },
            "status": {"phase": "Bound"},
        }
        for ordinal in range(2)
    }
    lookups = []

    def get(kind, name=None, namespace=None):
        lookups.append((kind, name, namespace))
        return pvc_by_name.get(name)

    monkeypatch.setattr(cluster, "get", get)

    assert cluster.stores(sts) == [
        {"volume": "data", "relative": "", "claim": "data-db-0", "uid": "pvc-0"},
        {"volume": "data", "relative": "", "claim": "data-db-1", "uid": "pvc-1"},
    ]
    assert lookups == [("pvc", "data-db-0", None), ("pvc", "data-db-1", None)]


def test_cluster_store_wrapper_still_rejects_missing_pvc(case_modules, monkeypatch):
    cluster_module, _, _ = case_modules
    cluster = cluster_module.Cluster(namespace="audit-fixture", name="db")
    monkeypatch.setattr(cluster, "get", lambda *_args, **_kwargs: None)

    with pytest.raises(cluster_module.UnsafeState, match="^database store PVC is missing or not Bound$"):
        cluster.stores(_statefulset(replicas=1))


def test_existing_positive_uninitialized_state_is_initialized_in_place(case_modules):
    _, _, environment_module = case_modules
    cluster = FakeCluster(state="uninitialized")
    environment = environment_module.Environment(cluster)

    environment.apply()

    assert cluster.bootstrap_calls == 0
    assert cluster.init_calls == [(('init',), {})]
    assert cluster.current_state == "initialized"
    assert cluster.delete_calls == []
    assert cluster.patch_spec_calls == []


def test_environment_repairs_missing_headless_and_public_services(case_modules):
    _, _, environment_module = case_modules
    cluster = FakeCluster()
    cluster.service_data = {}

    environment_module.Environment(cluster).services()

    assert {obj["metadata"]["name"] for obj in cluster.create_calls} == {"db", "db-public"}
    headless = cluster.service_data["db"]["spec"]
    assert headless["clusterIP"] == "None"
    assert headless["publishNotReadyAddresses"] is True
    assert headless["selector"] == cluster.sts["spec"]["selector"]["matchLabels"]
    assert [(port["name"], port["port"]) for port in headless["ports"]] == [("grpc", 26257), ("http", 8080)]


def test_unready_owned_pod_is_restarted_then_original_reset_policy_escalates(case_modules):
    _, _, environment_module = case_modules
    cluster = FakeCluster(pod_readiness={1: False})
    wait_calls = []

    def wait(check, seconds):
        wait_calls.append((getattr(check, "__name__", "bound-check"), seconds))
        if seconds == 90 or getattr(check, "__name__", "") == "usable":
            raise RuntimeError("bounded readiness failed")
        return check()

    cluster.wait = wait
    environment = environment_module.Environment(cluster)
    reset_calls = []
    environment.reset = lambda record=None: reset_calls.append(record)

    environment.apply()

    assert wait_calls == [("usable", 90), ("usable", 180), ("probe", 180)]
    assert cluster.delete_calls == [("db-1", "pod-1")]
    assert reset_calls == [None]


def _reset_record(cluster, phase="starting"):
    sts = cluster.sts
    stores = [{"volume": "data", "relative": "", "claim": "data-db-0", "uid": "pvc-0"}]
    cluster.store_data = stores
    data = {
        "statefulset_uid": sts["metadata"]["uid"],
        "original_template": json.dumps(sts["spec"]["template"]),
        "original_strategy": json.dumps(sts["spec"]["updateStrategy"]),
        "workload_spec": json.dumps({key: value for key, value in sts["spec"].items() if key not in ("template", "replicas", "updateStrategy")}),
        "stores": json.dumps(stores),
        "secret_signatures": "{}",
        "replicas": "1",
        "nonce": "reset-123",
        "phase": phase,
    }
    return {
        "kind": "ConfigMap",
        "metadata": {
            "name": "db-audit-recovery",
            "namespace": cluster.namespace,
            "uid": "record-uid",
            "resourceVersion": "11",
            "labels": {"karma.dev/fixture": "audit-recovery", "app.kubernetes.io/instance": cluster.name},
        },
        "data": data,
    }


def test_interrupted_store_reset_resumes_original_reset_and_restores_strategy(case_modules):
    _, _, environment_module = case_modules
    cluster = FakeCluster(replicas=1)
    cluster.record = _reset_record(cluster, phase="resetting")
    cluster.pods_data = [_pod("db", 0, "sts-uid")]
    environment = environment_module.Environment(cluster)
    store_resets = []
    environment.reset_store = lambda record, store, index: store_resets.append((record["data"]["nonce"], store["claim"], index))

    def update_record(obj, fields):
        obj["data"].update(fields["data"])

    environment.patch = update_record

    environment.apply()

    assert store_resets == [("reset-123", "data-db-0", 0)]
    assert cluster.patch_spec_calls[0] == {"replicas": 0, "updateStrategy": {"type": "OnDelete"}}
    assert cluster.patch_spec_calls[1] == {"replicas": 1}
    assert cluster.patch_spec_calls[2] == {"updateStrategy": {"type": "RollingUpdate", "rollingUpdate": {"partition": 0}}}
    assert cluster.record["data"]["phase"] == "ready"


def test_fresh_fixture_bootstrap_initializes_then_applies_original_setting(case_modules):
    _, _, environment_module = case_modules
    cluster = FakeCluster(present=False, state="uninitialized")
    environment = environment_module.Environment(cluster)

    environment.apply()

    assert cluster.bootstrap_calls == 1
    assert cluster.init_calls == [(('init',), {})]
    assert cluster.sql_calls[-1] == ("SET CLUSTER SETTING kv.snapshot_rebalance.max_rate = '1MiB';", 0)
    assert cluster.current_state == "initialized"
    assert cluster.service_data.keys() == {"db", "db-public"}


def test_cluster_ready_calls_one_shared_full_health_observation_after_case_contract(case_modules):
    cluster_module, _, _ = case_modules
    cluster = cluster_module.Cluster(namespace="audit-fixture", name="db")
    order = []
    sts = _statefulset(replicas=1)
    cluster.deployment_ready = lambda: order.append("case-readiness-and-service") or "initialized"
    cluster.statefulset = lambda: sts
    cluster.pods = lambda _sts: [_pod("db", 0, "sts-uid")]
    cluster.node_rows = lambda *args, **kwargs: pytest.fail("generic node status must come from the library")
    cluster.liveness_rows = lambda *args, **kwargs: pytest.fail("generic liveness must come from the library")
    cluster.value = lambda *args, **kwargs: pytest.fail("generic SQL identity must come from the library")

    class Library:
        def __init__(self):
            self.calls = []

        def probe_full_health(self, ref, *, per_node_timeout):
            order.append("shared-full-health")
            self.calls.append((ref, per_node_timeout))
            return SimpleNamespace(status=ProbeStatus.SATISFIED, reasons=())

    library = Library()
    cluster._crdb_library = library

    assert cluster.ready()

    assert order == ["case-readiness-and-service", "shared-full-health"]
    assert len(library.calls) == 1
    assert library.calls[0][0].namespace == "audit-fixture"
    assert library.calls[0][0].name == "db"
    assert library.calls[0][1] == 5


def test_cluster_ready_rejects_shared_unsatisfied_result(case_modules):
    cluster_module, _, _ = case_modules
    cluster = cluster_module.Cluster(namespace="audit-fixture", name="db")
    cluster.deployment_ready = lambda: "initialized"
    cluster.statefulset = lambda: _statefulset(replicas=1)
    cluster.pods = lambda _sts: [_pod("db", 0, "sts-uid")]
    cluster._crdb_library = SimpleNamespace(
        probe_full_health=lambda *_args, **_kwargs: SimpleNamespace(
            status=ProbeStatus.UNSATISFIED,
            reasons=("node is unavailable",),
        )
    )

    with pytest.raises(RuntimeError, match="node is unavailable"):
        cluster.ready()


def _test_library_module():
    path = Path(__file__).with_name("test_library.py")
    spec = importlib.util.spec_from_file_location("readonly_audit_library_fixture", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(spec.name, None)
    return module


@pytest.mark.parametrize("tls", [False, True], ids=["insecure", "tls"])
def test_cluster_ready_bridges_real_library_for_insecure_and_tls_workloads(case_modules, tls):
    cluster_module, _, _ = case_modules
    test_library = _test_library_module()
    adapter = test_library.MemoryAdapter(tls=tls, replicas=2)
    for pod in adapter.pods:
        container = pod["spec"]["containers"][0]
        container["readinessProbe"] = {
            "httpGet": {"path": "/health?ready=1", "port": "http", "scheme": "HTTPS" if tls else "HTTP"}
        }
    template_container = adapter.sts["spec"]["template"]["spec"]["containers"][0]
    template_container["readinessProbe"] = {
        "httpGet": {"path": "/health?ready=1", "port": "http", "scheme": "HTTPS" if tls else "HTTP"}
    }

    cluster = cluster_module.Cluster(namespace=adapter.namespace, name=adapter.name)
    cluster._crdb_library = CrdbLibrary(adapter)
    cluster.deployment_ready = lambda: "initialized"
    cluster.statefulset = lambda: adapter.sts
    cluster.pods = lambda _sts: adapter.pods

    assert cluster.ready()

    assert len(adapter.node_status_calls) == 1
    assert len(adapter.liveness_query_calls) == 1
    assert adapter.patch_calls == []
    assert len(adapter.native_identity_calls) == 0
    assert len(adapter.query_sql_calls) > 0
    assert all(call["tls_mode"] == ("tls" if tls else "insecure") for call in adapter.query_sql_calls)

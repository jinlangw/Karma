"""Behavior checks for rollback-rehearsal's original preparation and shared health seam."""

from __future__ import annotations

import copy
import importlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys
from types import SimpleNamespace

import pytest

from cases.common.cockroachdb import CrdbLibrary, ProbeStatus


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "cases/tests/cockroachdb/rollback-rehearsal/scripts"
RESOURCE = ROOT / "cases/tests/cockroachdb/rollback-rehearsal/resource"


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


def _template(name="db", *, tls=False):
    labels = {"app.kubernetes.io/name": "cockroachdb", "app.kubernetes.io/instance": name}
    command = (
        f"exec /cockroach/cockroach start --advertise-host=$(POD_NAME).{name}.$(POD_NAMESPACE).svc.cluster.local "
        f"--port=26257 --join={name}-0.{name}.$(POD_NAMESPACE).svc.cluster.local:26257 "
        "--certs-dir=/cockroach/cockroach-certs" if tls else
        f"exec /cockroach/cockroach start --advertise-host=$(POD_NAME).{name}.$(POD_NAMESPACE).svc.cluster.local "
        f"--port=26257 --join={name}-0.{name}.$(POD_NAMESPACE).svc.cluster.local:26257 --insecure"
    )
    container = {
        "name": "db",
        "image": "cockroachdb/cockroach:v24.1.0",
        "command": ["/bin/bash", "-ec", command],
        "volumeMounts": [{"name": "data", "mountPath": "/cockroach/cockroach-data"}],
    }
    volumes = []
    if tls:
        container["volumeMounts"].append({"name": "certs", "mountPath": "/cockroach/cockroach-certs", "readOnly": True})
        volumes.append({"name": "certs", "secret": {"secretName": "db-certs"}})
    return {"metadata": {"labels": labels}, "spec": {"containers": [container], "volumes": volumes}}


def _statefulset(name="db", *, uid="sts-uid", replicas=2, tls=False):
    labels = {"app.kubernetes.io/name": "cockroachdb", "app.kubernetes.io/instance": name}
    return {
        "metadata": {
            "name": name,
            "namespace": "rollback-fixture",
            "uid": uid,
            "resourceVersion": "7",
            "labels": labels,
        },
        "spec": {
            "serviceName": name,
            "replicas": replicas,
            "selector": {"matchLabels": labels},
            "template": _template(name, tls=tls),
            "volumeClaimTemplates": [
                {"metadata": {"name": "data"}, "spec": {"resources": {"requests": {"storage": "1Gi"}}}}
            ],
            "updateStrategy": {"type": "RollingUpdate", "rollingUpdate": {"partition": 0}},
        },
    }


def _pod(name, ordinal, sts_uid, *, ready=True):
    return {
        "metadata": {
            "name": f"{name}-{ordinal}",
            "namespace": "rollback-fixture",
            "uid": f"pod-{ordinal}",
            "ownerReferences": [{"controller": True, "uid": sts_uid}],
            "labels": {"app.kubernetes.io/name": "cockroachdb", "app.kubernetes.io/instance": name},
            "annotations": {},
        },
        "spec": {"volumes": [{"persistentVolumeClaim": {"claimName": f"data-{name}-{ordinal}"}}]},
        "status": {
            "conditions": [{"type": "Ready", "status": "True" if ready else "False"}],
            "phase": "Running",
        },
    }


def _services(name="db"):
    selector = {"app.kubernetes.io/name": "cockroachdb", "app.kubernetes.io/instance": name}
    return {
        name: {
            "kind": "Service",
            "metadata": {"name": name, "namespace": "rollback-fixture", "uid": "svc-headless", "labels": selector},
            "spec": {
                "clusterIP": "None",
                "selector": selector,
                "publishNotReadyAddresses": True,
                "ports": [{"name": "grpc", "port": 26257}, {"name": "http", "port": 8080}],
            },
        },
        name + "-public": {
            "kind": "Service",
            "metadata": {"name": name + "-public", "namespace": "rollback-fixture", "uid": "svc-public", "labels": selector},
            "spec": {"clusterIP": "10.0.0.9", "selector": selector, "ports": [{"name": "grpc", "port": 26257}]},
        },
    }


class FakeCluster:
    namespace = "rollback-fixture"
    name = "db"

    def __init__(self, *, tls=False, present=True, state="initialized", replicas=2, pod_readiness=None):
        self.sts = _statefulset(uid="sts-uid", replicas=replicas, tls=tls) if present else None
        self.current_state = state
        self.deployment_states = []
        self.pods_data = [
            _pod(self.name, i, "sts-uid", ready=(pod_readiness or {}).get(i, True)) for i in range(replicas)
        ] if present else []
        self.service_data = _services() if present else {}
        self.record = None
        self.bootstrap_calls = 0
        self.init_calls = []
        self.sql_calls = []
        self.delete_calls = []
        self.create_calls = []
        self.patch_spec_calls = []
        self.wait_calls = []
        self.wait_errors = []
        self.store_data = []
        self.sql_results = []
        self.events = []

    @property
    def labels(self):
        return {"app.kubernetes.io/name": "cockroachdb", "app.kubernetes.io/instance": self.name}

    def get(self, kind, name=None, namespace=None):
        if kind == "statefulset" and name == self.name:
            return self.sts
        if kind == "configmap" and name == self.name + "-rollback-recovery":
            return self.record
        if kind == "service":
            return self.service_data.get(name)
        if kind == "pods":
            return {"items": self.pods_data}
        if kind == "pod":
            return next((pod for pod in self.pods_data if pod["metadata"]["name"] == name), None)
        if kind == "secret":
            return None
        return {"items": []}

    def statefulset(self):
        if self.sts is None:
            raise RuntimeError("selected StatefulSet is absent")
        return self.sts

    def identity(self, _obj):
        return None

    def create(self, obj):
        self.create_calls.append(copy.deepcopy(obj))
        if obj.get("kind") == "Service":
            self.service_data[obj["metadata"]["name"]] = copy.deepcopy(obj)
        elif obj.get("kind") == "StatefulSet":
            self.sts = copy.deepcopy(obj)
            self.current_state = "uninitialized"
            self.pods_data = [
                _pod(self.name, i, self.sts["metadata"]["uid"])
                for i in range(int(self.sts["spec"].get("replicas", 1)))
            ]

    def bootstrap(self):
        self.bootstrap_calls += 1
        self.sts = _statefulset(uid="created-sts-uid", replicas=2)
        self.current_state = "uninitialized"
        self.pods_data = [_pod(self.name, i, "created-sts-uid") for i in range(2)]

    def deployment_ready(self):
        self.events.append("deployment_ready")
        if self.deployment_states:
            self.current_state = self.deployment_states.pop(0)
        return self.current_state

    def ready(self):
        self.events.append("ready")
        if self.current_state != "initialized":
            raise RuntimeError("selected database is not initialized")
        if any(not any(c.get("type") == "Ready" and c.get("status") == "True" for c in p["status"].get("conditions", []))
               for p in self.pods_data):
            raise RuntimeError("selected database pod is not Ready")
        return True

    def pods(self, _sts):
        return self.pods_data

    def wait(self, check, seconds):
        self.wait_calls.append((getattr(check, "__name__", "check"), seconds))
        if self.wait_errors:
            error = self.wait_errors.pop(0)
            if error is not None:
                raise error
        if not check():
            raise RuntimeError("test wait expired")
        return True

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
            self.pods_data = [
                _pod(self.name, i, self.sts["metadata"]["uid"])
                for i in range(fields["replicas"])
            ]

    def delete_pod(self, pod):
        self.delete_calls.append((pod["metadata"]["name"], pod["metadata"]["uid"]))
        self.pods_data = [current for current in self.pods_data if current["metadata"]["uid"] != pod["metadata"]["uid"]]

    def kubectl(self, *args, **kwargs):
        if args and args[0] == "patch" and args[1].lower() == "configmap" and self.record is not None:
            patch = json.loads(args[-1])
            for operation in patch:
                if operation["path"] == "/data":
                    self.record["data"] = copy.deepcopy(operation["value"])
            self.record["metadata"]["resourceVersion"] = str(int(self.record["metadata"].get("resourceVersion", "0")) + 1)
        return SimpleNamespace(returncode=0, stdout="", stderr="")


def test_healthy_insecure_and_tls_apply_reuses_existing_cluster(case_modules):
    _, _, environment_module = case_modules
    for tls in (False, True):
        cluster = FakeCluster(tls=tls)
        environment_module.Environment(cluster).apply()

        assert cluster.bootstrap_calls == 0
        assert cluster.init_calls == []
        assert cluster.sql_calls == []
        assert cluster.delete_calls == []
        assert cluster.patch_spec_calls == []
        assert cluster.create_calls == []
        assert cluster.wait_calls == [("usable", 90), ("probe", 180)]


def test_existing_positive_uninitialized_state_is_initialized_in_place(case_modules):
    _, _, environment_module = case_modules
    cluster = FakeCluster(state="uninitialized")

    environment_module.Environment(cluster).apply()

    assert cluster.bootstrap_calls == 0
    assert cluster.init_calls == [(('init',), {})]
    assert cluster.current_state == "initialized"
    assert cluster.delete_calls == []
    assert cluster.patch_spec_calls == []


def test_environment_repairs_missing_headless_and_public_services(case_modules):
    _, _, environment_module = case_modules
    cluster = FakeCluster()
    cluster.service_data = {}

    environment_module.Environment(cluster).apply()

    assert {obj["metadata"]["name"] for obj in cluster.create_calls} == {"db", "db-public"}
    headless = cluster.service_data["db"]["spec"]
    assert headless["clusterIP"] == "None"
    assert headless["publishNotReadyAddresses"] is True
    assert headless["selector"] == cluster.sts["spec"]["selector"]["matchLabels"]
    assert [(port["name"], port["port"]) for port in headless["ports"]] == [("grpc", 26257), ("http", 8080)]


def test_unready_owned_pod_is_restarted_then_original_reset_policy_escalates(case_modules):
    _, _, environment_module = case_modules
    cluster = FakeCluster(pod_readiness={1: False})
    cluster.wait_errors = [RuntimeError("initial readiness failed"), RuntimeError("retry readiness failed")]
    cluster.sql_results = [
        SimpleNamespace(returncode=0, stdout="", stderr=""),
        SimpleNamespace(returncode=1, stdout="", stderr="connection refused"),
    ]
    environment = environment_module.Environment(cluster)
    reset_calls = []

    def reset(record=None):
        reset_calls.append(record)
        cluster.pods_data = [_pod("db", i, cluster.sts["metadata"]["uid"]) for i in range(2)]

    environment.reset = reset
    environment.apply()

    assert cluster.wait_calls[:2] == [("usable", 90), ("usable", 180)]
    assert cluster.sql_calls == [
        ("SELECT count(*) FROM system.namespace;", 0),
        ("SELECT count(*) FROM system.namespace;", 1),
    ]
    assert cluster.delete_calls == [("db-1", "pod-1")]
    assert reset_calls == [None]
    assert cluster.wait_calls[-1] == ("probe", 180)


def test_control_plane_failure_does_not_authorize_original_store_reset(case_modules):
    _, _, environment_module = case_modules
    cluster = FakeCluster()
    cluster.wait_errors = [RuntimeError("readiness wait failed")]
    cluster.sql_results = [
        SimpleNamespace(returncode=1, stdout="", stderr="Forbidden"),
        SimpleNamespace(returncode=0, stdout="", stderr=""),
    ]
    environment = environment_module.Environment(cluster)
    reset_calls = []
    environment.reset = lambda record=None: reset_calls.append(record)

    with pytest.raises(RuntimeError, match="control-plane failure is not permission to reset"):
        environment.apply()

    assert reset_calls == []
    assert cluster.delete_calls == []


def _reset_record(cluster):
    sts = cluster.sts
    stores = [{"volume": "data", "relative": "", "claim": "data-db-0", "uid": "pvc-0"}]
    cluster.store_data = stores
    original_strategy = copy.deepcopy(sts["spec"]["updateStrategy"])
    workload_spec = {key: value for key, value in sts["spec"].items() if key not in ("template", "replicas", "updateStrategy")}
    return {
        "kind": "ConfigMap",
        "metadata": {
            "name": "db-rollback-recovery",
            "namespace": cluster.namespace,
            "uid": "record-uid",
            "resourceVersion": "11",
            "labels": {"karma.dev/fixture": "rollback-recovery", "app.kubernetes.io/instance": cluster.name},
        },
        "data": {
            "statefulset_uid": sts["metadata"]["uid"],
            "original_template": json.dumps(sts["spec"]["template"]),
            "original_strategy": json.dumps(original_strategy),
            "workload_spec": json.dumps(workload_spec),
            "stores": json.dumps(stores),
            "secret_signatures": "{}",
            "replicas": "2",
            "nonce": "reset-123",
            "phase": "resetting",
        },
    }


def test_interrupted_store_reset_resumes_and_restores_original_strategy(case_modules):
    _, _, environment_module = case_modules
    cluster = FakeCluster(replicas=2)
    cluster.record = _reset_record(cluster)
    environment = environment_module.Environment(cluster)
    reset_stores = []
    environment.reset_store = lambda record, store, index: reset_stores.append((record["data"]["nonce"], store["claim"], index))

    environment.apply()

    assert reset_stores == [("reset-123", "data-db-0", 0)]
    assert cluster.patch_spec_calls == [
        {"replicas": 0, "updateStrategy": {"type": "OnDelete"}},
        {"replicas": 2},
        {"updateStrategy": {"type": "RollingUpdate", "rollingUpdate": {"partition": 0}}},
    ]
    assert cluster.record["data"]["phase"] == "ready"
    assert cluster.sts["spec"]["updateStrategy"]["type"] == "RollingUpdate"


def test_fresh_fixture_bootstrap_initializes_without_applying_task_owned_settings(case_modules):
    _, _, environment_module = case_modules
    cluster = FakeCluster(present=False, state="uninitialized")

    environment_module.Environment(cluster).apply()

    assert cluster.bootstrap_calls == 1
    assert cluster.init_calls == [(('init',), {})]
    assert cluster.sql_calls == []
    assert cluster.current_state == "initialized"
    assert cluster.service_data.keys() == {"db", "db-public"}


def test_cluster_ready_calls_one_shared_full_health_observation_after_case_contract(case_modules):
    cluster_module, _, _ = case_modules
    cluster = cluster_module.Cluster(namespace="rollback-fixture", name="db")
    order = []
    sts = _statefulset(replicas=1)
    cluster.deployment_ready = lambda: order.append("original-deployment-http-service-contract") or "initialized"
    cluster.statefulset = lambda: sts
    cluster.pods = lambda _sts: [_pod("db", 0, "sts-uid")]
    cluster.value = lambda *_args, **_kwargs: pytest.fail("generic SQL identity should be supplied by the library")

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

    assert order == ["original-deployment-http-service-contract", "shared-full-health"]
    assert len(library.calls) == 1
    assert library.calls[0][0].namespace == "rollback-fixture"
    assert library.calls[0][0].name == "db"
    assert library.calls[0][1] == 5
    assert not hasattr(cluster, "node_rows")
    assert not hasattr(cluster, "liveness_rows")


def test_cluster_ready_rejects_shared_unsatisfied_result(case_modules):
    cluster_module, _, _ = case_modules
    cluster = cluster_module.Cluster(namespace="rollback-fixture", name="db")
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
    spec = importlib.util.spec_from_file_location("rollback_library_fixture", path)
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


def test_constructor_defaults_to_original_namespace_name_and_manifest_directory(case_modules, monkeypatch):
    cluster_module, _, _ = case_modules
    monkeypatch.setenv("BENCH_NAMESPACE", "original-namespace")
    monkeypatch.setenv("BENCH_PARAM_CLUSTER_NAME", "original-db")

    cluster = cluster_module.Cluster()

    assert cluster.namespace == "original-namespace"
    assert cluster.name == "original-db"
    assert cluster.manifest_dir == RESOURCE


def test_manifest_directory_seam_runs_original_bootstrap_with_kubernetes_expansions(case_modules, tmp_path, monkeypatch):
    cluster_module, _, _ = case_modules
    for name in ("rbac.yaml", "services.yaml", "statefulset.yaml"):
        shutil.copy(RESOURCE / name, tmp_path / name)
    statefulset_path = tmp_path / "statefulset.yaml"
    statefulset_path.write_text(statefulset_path.read_text().replace("--cache=25%", "--cache=17%"))
    monkeypatch.setenv("BENCH_PARAM_REPLICA_COUNT", "2")
    cluster = cluster_module.Cluster(namespace="rollback-fixture", name="db", manifest_dir=tmp_path)
    created = []

    def get(kind, name=None, namespace=None):
        if kind == "namespace":
            return {"metadata": {"name": "rollback-fixture"}}
        if name is None:
            return {"items": []}
        return None

    cluster.get = get
    cluster.create = lambda obj: created.append(copy.deepcopy(obj))
    cluster.wait = lambda _check, _seconds: None

    cluster.bootstrap()

    statefulset = next(obj for obj in created if obj["kind"] == "StatefulSet")
    container = statefulset["spec"]["template"]["spec"]["containers"][0]
    command = container["command"][2]
    assert len(created) == 6
    assert statefulset["spec"]["replicas"] == 2
    assert "--cache=17%" in command
    assert "--join=db-0.db.rollback-fixture.svc.cluster.local:26257" in command
    assert "$(POD_NAME)" in command
    assert "$(POD_NAMESPACE)" in command
    assert "${BENCH_PARAM_CLUSTER_NAME}" not in command

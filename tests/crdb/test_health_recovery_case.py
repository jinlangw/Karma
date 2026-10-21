"""Routing tests for the health-recovery case's shared-library integration."""

import importlib
import sys
from types import SimpleNamespace

import pytest

from karma.crdb import CrdbLibrary, HTTPTransport, Lifecycle, ProbeStatus, Requirement, TLSMode, WorkloadRef
from karma.crdb.types import AuthenticationError, MissingResourceError, ProbeObservation


SCRIPTS = (
    __file__.rsplit("/tests/crdb/", 1)[0]
    + "/cases/cockroachdb/health-check-recovery/scripts"
)


@pytest.fixture
def case_modules(monkeypatch):
    names = ("cluster", "fault", "prepare")
    for name in names:
        monkeypatch.delitem(sys.modules, name, raising=False)
    monkeypatch.syspath_prepend(SCRIPTS)
    modules = tuple(importlib.import_module(name) for name in names)
    yield modules
    for name in names:
        sys.modules.pop(name, None)


def workload(*, prepared=False, tls=False):
    scheme = "HTTPS" if tls else "HTTP"
    port = "http"
    liveness = ProbeObservation(
        handler="httpGet" if prepared else "tcpSocket",
        path="/health" if prepared else None,
        port=port,
        scheme=scheme if prepared else None,
    )
    readiness = ProbeObservation(
        handler="httpGet",
        path="/health?ready=1",
        port=port,
        scheme=scheme,
    )
    return SimpleNamespace(
        tls_mode=TLSMode.TLS if tls else TLSMode.INSECURE,
        http_transport=HTTPTransport.HTTPS if tls else HTTPTransport.HTTP,
        http_bind_host="0.0.0.0",
        http_port=8080,
        http_port_name=port,
        liveness_probe=liveness,
        readiness_probe=readiness,
        pods=tuple(SimpleNamespace(phase="Running", pod_ready=True) for _ in range(3)),
    )


def assessment(status=ProbeStatus.SATISFIED, *, prepared=False, tls=False):
    return SimpleNamespace(
        status=status,
        reasons=("fixture is not ready",) if status is ProbeStatus.UNSATISFIED else (),
        workload=workload(prepared=prepared, tls=tls),
    )


def statefulset(*, marker=False, strategy="RollingUpdate"):
    command = ["/cockroach/cockroach", "start"]
    if marker:
        command.append("# karma-health-probe-fault-v1")
    return {
        "metadata": {"name": "db", "namespace": "crdb-fixture", "uid": "sts-uid"},
        "spec": {
            "template": {
                "spec": {
                    "containers": [
                        {"name": "db", "image": "cockroachdb/cockroach:v24.1.0", "command": command}
                    ]
                }
            },
            "updateStrategy": {"type": strategy},
        },
    }


class FakeCluster:
    namespace = "crdb-fixture"
    name = "db"

    def __init__(self, sts=None, configmap=None):
        self.sts = sts
        self.configmap = configmap
        self.bootstrap_calls = 0
        self.wait_calls = []
        self.recover_calls = []

    def get(self, kind, name):
        if kind == "statefulset" and name == self.name:
            return self.sts
        if kind == "configmap":
            return self.configmap if name == "db-health-recovery-baseline" else None
        return None

    def bootstrap(self):
        self.bootstrap_calls += 1
        self.sts = statefulset()

    def recover(self, readiness_check=None, propagate=()):
        self.recover_calls.append((readiness_check, propagate))
        return readiness_check() if readiness_check is not None else True

    def wait(self, check, seconds):
        self.wait_calls.append((check, seconds))
        return check()


class FakeFault:
    baseline_name = "db-health-recovery-baseline"

    def __init__(self, cluster, *, baseline=None, configured=False, readiness_error=None):
        self.cluster = cluster
        self.baseline = baseline
        self.is_configured = configured
        self.readiness_error = readiness_error
        self.load_calls = 0

    def load(self):
        self.load_calls += 1
        return self.baseline

    def configured(self, baseline, sts):
        return self.is_configured and baseline is not None

    def environment_ready(self):
        if self.readiness_error:
            raise self.readiness_error
        return True


class FakeLibrary:
    def __init__(self, result=None, *, error=None):
        self.result = result or assessment()
        self.error = error
        self.probe_calls = []
        self.reconcile_calls = []
        self.preparation_calls = []

    def probe(self, ref, requirement, **kwargs):
        self.probe_calls.append((ref, requirement, kwargs))
        if self.error:
            raise self.error
        return self.result

    def reconcile(self, ref, requirement, **kwargs):
        self.reconcile_calls.append((ref, requirement, kwargs))
        if self.error:
            raise self.error
        return SimpleNamespace(assessment=self.result)

    def prepare_health_recovery_probes(self, ref, **kwargs):
        self.preparation_calls.append((ref, kwargs))
        return SimpleNamespace(changed=True)


def run(case_modules, cluster, fault, library, mode):
    _, _, prepare = case_modules
    return prepare.prepare_cluster_unit(cluster, fault, library, mode)


def test_apply_reconciles_then_explicitly_prepares_missing_health_handlers(case_modules):
    cluster = FakeCluster(statefulset())
    fault = FakeFault(cluster)
    library = FakeLibrary(assessment(prepared=False))

    assert run(case_modules, cluster, fault, library, "apply")

    assert len(library.reconcile_calls) == 1
    assert len(library.probe_calls) == 1
    assert len(library.preparation_calls) == 1
    assert cluster.bootstrap_calls == 0
    assert len(cluster.recover_calls) == 1


def test_probe_and_verify_never_mutate_missing_health_handlers(case_modules):
    cluster = FakeCluster(statefulset())
    fault = FakeFault(cluster)
    library = FakeLibrary(assessment(prepared=False))

    with pytest.raises(RuntimeError, match="health probes need explicit preparation"):
        run(case_modules, cluster, fault, library, "probe")
    assert len(library.probe_calls) == 1
    assert library.preparation_calls == []

    with pytest.raises(RuntimeError, match="health probes need explicit preparation"):
        run(case_modules, cluster, fault, library, "verify")
    assert len(library.reconcile_calls) == 1
    assert library.preparation_calls == []
    assert cluster.recover_calls == []


@pytest.mark.parametrize("tls", [False, True])
def test_matching_health_handlers_are_noop_even_with_ondelete(case_modules, tls):
    cluster = FakeCluster(statefulset(strategy="OnDelete"))
    fault = FakeFault(cluster)
    library = FakeLibrary(assessment(prepared=True, tls=tls))

    assert run(case_modules, cluster, fault, library, "apply")

    assert len(library.reconcile_calls) == 1
    assert len(library.probe_calls) == 1
    assert library.preparation_calls == []
    assert cluster.bootstrap_calls == 0
    assert len(cluster.recover_calls) == 1
    assert cluster.wait_calls[-1][0] == fault.environment_ready


def test_completed_prior_baseline_does_not_bypass_library_or_refresh_baseline(case_modules):
    cluster = FakeCluster(statefulset(), configmap={"metadata": {"name": "baseline"}})
    original_baseline = {"data": {"original_template": "kept"}}
    fault = FakeFault(cluster, baseline=original_baseline, configured=False)
    library = FakeLibrary(assessment(prepared=False))

    assert run(case_modules, cluster, fault, library, "apply")

    assert len(library.reconcile_calls) == 1
    assert len(library.probe_calls) == 1
    assert len(library.preparation_calls) == 1
    assert len(cluster.wait_calls) == 1
    assert fault.baseline is original_baseline


def test_active_owned_fault_uses_case_local_readiness_without_normalizing(case_modules):
    cluster = FakeCluster(statefulset(marker=True, strategy="OnDelete"))
    baseline = {"data": {"original_template": "unchanged"}}
    fault = FakeFault(cluster, baseline=baseline, configured=True)
    library = FakeLibrary(assessment(prepared=False))

    assert run(case_modules, cluster, fault, library, "apply")

    assert len(cluster.wait_calls) == 1
    assert cluster.wait_calls[0][0] == fault.environment_ready
    assert cluster.recover_calls == []
    assert library.probe_calls == []
    assert library.reconcile_calls == []
    assert library.preparation_calls == []


def test_unowned_fault_marker_fails_closed(case_modules):
    cluster = FakeCluster(statefulset(marker=True, strategy="OnDelete"))
    fault = FakeFault(cluster, baseline={"data": {}}, configured=False)
    library = FakeLibrary()

    with pytest.raises(case_modules[0].UnsafeState, match="unrecognized case fault"):
        run(case_modules, cluster, fault, library, "apply")

    assert library.probe_calls == []
    assert library.reconcile_calls == []
    assert cluster.bootstrap_calls == 0


@pytest.mark.parametrize("mode", ["probe", "verify"])
def test_missing_selected_workload_is_never_implicitly_bootstrapped(case_modules, mode):
    cluster = FakeCluster()
    fault = FakeFault(cluster)
    library = FakeLibrary()

    with pytest.raises(MissingResourceError):
        run(case_modules, cluster, fault, library, mode)

    assert cluster.bootstrap_calls == 0
    assert library.probe_calls == []
    assert library.reconcile_calls == []


def test_explicit_apply_bootstrap_requires_no_stale_baseline(case_modules):
    cluster = FakeCluster(configmap={"metadata": {"name": "db-health-recovery-baseline"}})
    fault = FakeFault(cluster)
    library = FakeLibrary()

    with pytest.raises(case_modules[0].UnsafeState, match="baseline exists without"):
        run(case_modules, cluster, fault, library, "apply")

    assert cluster.bootstrap_calls == 0
    assert library.reconcile_calls == []


def test_explicit_apply_bootstraps_only_an_absent_clean_fixture(case_modules):
    cluster = FakeCluster()
    fault = FakeFault(cluster)
    library = FakeLibrary(assessment(prepared=True))

    assert run(case_modules, cluster, fault, library, "apply")

    assert cluster.bootstrap_calls == 1
    assert len(library.reconcile_calls) == 1
    assert library.preparation_calls == []


def test_existing_workload_authentication_failure_is_propagated_without_bootstrap(case_modules):
    cluster = FakeCluster(statefulset())
    fault = FakeFault(cluster)
    library = FakeLibrary(error=AuthenticationError("credentials rejected"))

    with pytest.raises(AuthenticationError, match="credentials rejected"):
        run(case_modules, cluster, fault, library, "apply")

    assert cluster.bootstrap_calls == 0
    assert library.reconcile_calls == []
    assert len(library.probe_calls) == 1
    assert library.preparation_calls == []
    assert len(cluster.recover_calls) == 1


def test_apply_still_checks_case_health_endpoints_after_shared_preparation(case_modules):
    cluster = FakeCluster(statefulset())
    fault = FakeFault(cluster, readiness_error=RuntimeError("health endpoint failed"))
    library = FakeLibrary(assessment(prepared=True))

    with pytest.raises(RuntimeError, match="health endpoint failed"):
        run(case_modules, cluster, fault, library, "apply")

    assert len(library.probe_calls) == 1
    assert len(library.reconcile_calls) == 1
    assert library.preparation_calls == []
    assert cluster.wait_calls == [(fault.environment_ready, 90)]


def test_unsatisfied_assessment_fails_before_probe_preparation(case_modules):
    cluster = FakeCluster(statefulset())
    fault = FakeFault(cluster)
    library = FakeLibrary(assessment(ProbeStatus.UNSATISFIED, prepared=False))

    with pytest.raises(RuntimeError, match="fixture is not ready"):
        run(case_modules, cluster, fault, library, "apply")

    assert library.preparation_calls == []


def recovery_cluster(cluster_module, *, ready=True, missing_services=(), conflicting_identity=False):
    cluster = cluster_module.Cluster.__new__(cluster_module.Cluster)
    cluster.namespace = "crdb-fixture"
    cluster.name = "db"
    cluster.labels = {"app.kubernetes.io/name": "cockroachdb", "app.kubernetes.io/instance": "db"}
    cluster.flag = "--certs-dir=/cockroach/cockroach-certs"
    labels = dict(cluster.labels)
    if conflicting_identity:
        labels["app.kubernetes.io/instance"] = "other"
    sts = {
        "metadata": {"name": "db", "namespace": cluster.namespace, "uid": "sts-uid", "labels": labels},
        "spec": {
            "ordinals": {"start": 0},
            "replicas": 1,
            "selector": {"matchLabels": dict(cluster.labels)},
            "template": {
                "metadata": {"labels": dict(cluster.labels)},
                "spec": {
                    "containers": [{
                        "name": "db",
                        "image": "cockroachdb/cockroach:v24.1.0",
                        "command": ["/cockroach/cockroach", "start", "--store=/cockroach/cockroach-data"],
                        "volumeMounts": [{"name": "datadir", "mountPath": "/cockroach/cockroach-data"}],
                    }],
                    "volumes": [],
                },
            },
            "volumeClaimTemplates": [{"metadata": {"name": "datadir"}}],
        },
    }
    pod = {
        "metadata": {
            "name": "db-0",
            "namespace": cluster.namespace,
            "uid": "pod-uid-1",
            "labels": dict(cluster.labels),
            "ownerReferences": [{"uid": "sts-uid", "controller": True}],
        },
        "spec": {"volumes": [{"name": "datadir", "persistentVolumeClaim": {"claimName": "datadir-db-0"}}]},
        "status": {
            "phase": "Running",
            "conditions": [{"type": "Ready", "status": "True" if ready else "False"}],
        },
    }
    services = {}
    for name in ("db", "db-public"):
        if name not in missing_services:
            services[name] = {"kind": "Service", "metadata": {"name": name}, "spec": {"selector": dict(cluster.labels)}}
    created = []
    deleted = []
    ready_state = {"value": ready}

    def get(kind, name=None, namespace=None):
        if kind == "statefulset":
            return sts if name == "db" else None
        if kind == "service":
            return services.get(name)
        if kind == "pods":
            return {"items": [pod]}
        if kind == "pod":
            return pod if name == "db-0" else None
        return None

    def template(_name):
        return [
            {"kind": "Service", "metadata": {"name": name}, "spec": {"selector": dict(cluster.labels)}}
            for name in ("db", "db-public")
        ]

    def create(obj):
        created.append(obj["metadata"]["name"])
        services[obj["metadata"]["name"]] = obj

    def ready_check():
        if not ready_state["value"]:
            raise RuntimeError("selected database pod is not Ready")
        return True

    def delete_pod(old_pod):
        deleted.append(old_pod["metadata"]["uid"])
        pod["metadata"]["uid"] = "pod-uid-2"
        pod["status"]["conditions"] = [{"type": "Ready", "status": "True"}]
        ready_state["value"] = True

    cluster.get = get
    cluster.template = template
    cluster.create = create
    cluster.ready = ready_check
    cluster.delete_pod = delete_pod
    cluster.created_services = created
    cluster.deleted_pods = deleted
    cluster.recovery_ready = ready_state
    return cluster


def fast_clock(monkeypatch, cluster_module):
    now = [0.0]
    monkeypatch.setattr(cluster_module.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(cluster_module.time, "sleep", lambda seconds: now.__setitem__(0, now[0] + seconds))


def test_recover_creates_missing_service_then_uses_shared_readiness(case_modules):
    cluster_module = case_modules[0]
    cluster = recovery_cluster(cluster_module, missing_services=("db-public",))
    callback_calls = []

    def shared_ready():
        callback_calls.append(tuple(cluster.created_services))
        return True

    cluster.recover(readiness_check=shared_ready)

    assert cluster.created_services == ["db-public"]
    assert callback_calls == [("db-public",)]
    assert cluster.deleted_pods == []


def test_recover_restarts_only_running_unready_pod_after_durable_guard(case_modules, monkeypatch):
    cluster_module = case_modules[0]
    cluster = recovery_cluster(cluster_module, ready=False)
    fast_clock(monkeypatch, cluster_module)

    callback_results = []

    def shared_ready():
        callback_results.append(cluster.recovery_ready["value"])
        return cluster.recovery_ready["value"]

    cluster.recover(readiness_check=shared_ready)

    assert cluster.deleted_pods == ["pod-uid-1"]
    assert callback_results[0] is False
    assert callback_results[-1] is True
    assert cluster.flag is None


def test_shared_initialized_result_does_not_accept_unready_pods(case_modules, monkeypatch):
    cluster_module = case_modules[0]
    _, _, prepare = case_modules
    cluster = recovery_cluster(cluster_module, ready=False)
    fast_clock(monkeypatch, cluster_module)

    def shared_result():
        result = assessment(ProbeStatus.SATISFIED)
        result.workload.pods = tuple(
            SimpleNamespace(phase="Running", pod_ready=cluster.recovery_ready["value"])
            for _ in range(3)
        )
        return prepare._recovery_assessment_ready(result, 3)

    cluster.recover(readiness_check=shared_result)

    assert cluster.deleted_pods == ["pod-uid-1"]
    assert cluster.recovery_ready["value"] is True


def test_real_library_can_report_initialized_while_case_gate_rejects_unready_pod(case_modules):
    from tests.crdb.test_library import MemoryAdapter

    _, _, prepare = case_modules
    adapter = MemoryAdapter(replicas=3, custom_ports=False)
    adapter.pods[2]["status"]["conditions"] = [{"type": "Ready", "status": "False"}]
    library = CrdbLibrary(adapter)

    result = library.probe(
        WorkloadRef(adapter.namespace, adapter.name),
        Requirement(Lifecycle.INITIALIZED, minimum_nodes=3),
    )

    assert result.status is ProbeStatus.SATISFIED
    assert not prepare._recovery_assessment_ready(result, 3)


def test_recover_durable_guard_prevents_pod_restart(case_modules, monkeypatch):
    cluster_module = case_modules[0]
    cluster = recovery_cluster(cluster_module, ready=False)
    fast_clock(monkeypatch, cluster_module)

    def reject_ephemeral_store(_sts):
        raise cluster_module.UnsafeState("health fault restart requires PVC-backed database stores")

    cluster.durable = reject_ephemeral_store
    with pytest.raises(cluster_module.UnsafeState, match="PVC-backed"):
        cluster.recover()

    assert cluster.deleted_pods == []


def test_recover_propagates_authentication_failure_without_restart(case_modules):
    cluster_module = case_modules[0]
    cluster = recovery_cluster(cluster_module)

    def reject_auth():
        raise AuthenticationError("credentials rejected")

    with pytest.raises(AuthenticationError, match="credentials rejected"):
        cluster.recover(readiness_check=reject_auth, propagate=(AuthenticationError,))

    assert cluster.deleted_pods == []


def test_recover_rejects_conflicting_workload_identity_before_repairs(case_modules):
    cluster_module = case_modules[0]
    cluster = recovery_cluster(cluster_module, missing_services=("db-public",), conflicting_identity=True)

    with pytest.raises(cluster_module.UnsafeState, match="conflicting cluster identity"):
        cluster.recover()

    assert cluster.created_services == []
    assert cluster.deleted_pods == []

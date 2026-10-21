"""Case-policy checks for the cluster-settings target helper."""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest
import yaml

from karma.crdb import KubectlAdapter, SQLConnectionObservation, TLSMode
from karma.crdb.types import (
    AuthenticationError,
    ConnectionError,
    KubernetesAccessError,
    RolloutInProgressError,
    TransientError,
    UnsupportedLayoutError,
)


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "cases/cockroachdb/cluster-settings/resource/ensure-target-cluster.py"


@pytest.fixture
def target_module(monkeypatch):
    monkeypatch.setenv("BENCH_NAMESPACE", "settings-test")
    monkeypatch.setenv("BENCH_PARAM_CLUSTER_NAME", "crdb-test")
    spec = importlib.util.spec_from_file_location("cluster_settings_target_under_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    yield module
    sys.modules.pop(spec.name, None)


def statefulset(uid="inherited-uid", tls=True):
    start = "exec /cockroach/cockroach start --certs-dir=/cockroach/cockroach-certs --listen-addr=:26258 --sql-addr=:26257 --advertise-host=$(POD_NAME).crdb-test.$(POD_NAMESPACE).svc.cluster.local"
    if not tls:
        start = "exec /cockroach/cockroach start --insecure --listen-addr=:26258 --sql-addr=:26257"
    return {
        "apiVersion": "apps/v1",
        "kind": "StatefulSet",
        "metadata": {
            "name": "crdb-test", "namespace": "settings-test", "uid": uid,
            "resourceVersion": "17", "generation": 2,
            "labels": {"app.kubernetes.io/name": "cockroachdb", "app.kubernetes.io/instance": "crdb-test"},
        },
        "spec": {
            "serviceName": "crdb-test", "replicas": 3,
            "selector": {"matchLabels": {"app.kubernetes.io/instance": "crdb-test"}},
            "template": {"metadata": {"labels": {"app.kubernetes.io/instance": "crdb-test"}},
                "spec": {"containers": [{"name": "db", "image": "cockroachdb/cockroach:v24.1.0",
                    "command": ["/bin/bash", "-c", start],
                    "env": [
                        {"name": "POD_NAME", "valueFrom": {"fieldRef": {"fieldPath": "metadata.name"}}},
                        {"name": "POD_NAMESPACE", "valueFrom": {"fieldRef": {"fieldPath": "metadata.namespace"}}},
                    ],
                    "volumeMounts": [{"name": "certs", "mountPath": "/cockroach/cockroach-certs", "readOnly": True}],
                    "resources": {"requests": {"cpu": "1", "memory": "2Gi"}},
                }] }},
            "volumeClaimTemplates": [{"metadata": {"name": "datadir", "labels": {"app.kubernetes.io/instance": "crdb-test"}}}],
        },
        "status": {"readyReplicas": 0},
    }


class FakeAdapter:
    def __init__(self, sts=None, outcomes=()):
        self.sts = sts
        self.pods = []
        self.pvcs = []
        self.services = {
            "crdb-test": {"kind": "Service", "metadata": {"name": "crdb-test", "namespace": "settings-test", "uid": "service-headless"}},
            "crdb-test-public": {"kind": "Service", "metadata": {"name": "crdb-test-public", "namespace": "settings-test", "uid": "service-public"}},
        }
        self.outcomes = list(outcomes)
        self.query_calls = []

    def get_resource(self, kind, namespace, name):
        assert namespace == "settings-test"
        if kind == "statefulset":
            return self.sts
        if kind == "pod":
            return next((pod for pod in self.pods if pod["metadata"]["name"] == name), None)
        if kind == "pvc":
            return next((pvc for pvc in self.pvcs if pvc["metadata"]["name"] == name), None)
        if kind == "service":
            return self.services.get(name)
        return None

    def list_resources(self, kind, namespace):
        assert namespace == "settings-test"
        if kind == "pod":
            return tuple(self.pods)
        if kind == "pvc":
            return tuple(self.pvcs)
        raise AssertionError(f"unexpected resource kind {kind!r}")

    def query_sql(self, **kwargs):
        self.query_calls.append(copy.deepcopy(kwargs))
        outcome = self.outcomes.pop(0) if self.outcomes else True
        if isinstance(outcome, BaseException):
            raise outcome
        if not outcome:
            raise TransientError("SQL is not ready")
        return "1\n"


class FakeLibrary:
    def __init__(self, adapter):
        self.adapter = adapter
        self.probe_calls = []
        self.connection_calls = []
        self.connection_outcomes = []
        self.connection_uid_override = None
        self.rpc_host = "crdb-test-0.crdb-test.settings-test.svc.cluster.local"
        self.inspect_calls = 0

    def inspect(self, _ref):
        self.inspect_calls += 1
        tls = TLSMode.TLS if "--insecure" not in self.adapter.sts["spec"]["template"]["spec"]["containers"][0]["command"][2] else TLSMode.INSECURE
        return SimpleNamespace(
            workload_uid=self.connection_uid_override or self.adapter.sts["metadata"]["uid"],
            pods=(SimpleNamespace(name="crdb-test-0", sql_host="crdb-test-0.crdb-test.settings-test.svc.cluster.local"),),
            container_name="db", sql_binary="/cockroach/cockroach",
            tls_mode=tls, certs_dir="/cockroach/cockroach-certs" if tls is TLSMode.TLS else None,
            sql_port=26257, rpc_port=26258,
            advertised_sql_host_template="$(POD_NAME).crdb-test.$(POD_NAMESPACE).svc.cluster.local",
        )

    def inspect_sql_connection(self, ref, ordinal=0):
        self.connection_calls.append((ref, ordinal))
        outcome = self.connection_outcomes.pop(0) if self.connection_outcomes else None
        if isinstance(outcome, BaseException):
            raise outcome
        container = self.adapter.sts["spec"]["template"]["spec"]["containers"][0]
        start = container["command"][2]
        tls = TLSMode.INSECURE if "--insecure" in start else TLSMode.TLS
        return SQLConnectionObservation(
            namespace=ref.namespace,
            workload_name=ref.name,
            workload_uid=self.connection_uid_override or self.adapter.sts["metadata"]["uid"],
            pod_name=f"{ref.name}-{ordinal}",
            pod_uid=f"pod-{ordinal}",
            container_name=container["name"],
            image=container["image"],
            sql_binary="/cockroach/cockroach",
            sql_host=f"{ref.name}-{ordinal}.{ref.name}.{ref.namespace}.svc.cluster.local",
            sql_port=26257,
            rpc_port=26258,
            tls_mode=tls,
            certs_dir="/cockroach/cockroach-certs" if tls is TLSMode.TLS else None,
            rpc_host=self.rpc_host,
        )

    def probe(self, _ref, requirement):
        self.probe_calls.append(requirement)
        raise AssertionError("target init must not add a Lifecycle.DEPLOYED API gate")


def make_target(module, adapter, command=None):
    library = FakeLibrary(adapter)
    target = module.TargetCluster(
        "settings-test", "crdb-test", adapter=adapter, library=library,
        command=command or (lambda *_args, **_kwargs: pytest.fail("unexpected Kubernetes mutation")),
    )
    return target, library


def test_shared_readiness_uses_observed_tls_sql_host_and_port(target_module):
    adapter = FakeAdapter(statefulset(tls=True))
    target, library = make_target(target_module, adapter)

    assert target.wait_for_sql(20)

    assert library.connection_calls == [(target.ref, 0)]
    assert library.inspect_calls == 0

    assert adapter.query_calls[0] == {
        "namespace": "settings-test", "pod_name": "crdb-test-0", "container_name": "db",
        "binary": "/cockroach/cockroach", "sql_host": "crdb-test-0.crdb-test.settings-test.svc.cluster.local",
        "sql_port": 26257, "tls_mode": "tls", "certs_dir": "/cockroach/cockroach-certs",
        "sql": "SELECT 1;", "timeout": 10,
    }


def test_shared_readiness_uses_observed_database_container_name(target_module):
    selected = statefulset(tls=True)
    container = selected["spec"]["template"]["spec"]["containers"][0]
    container["name"] = "cockroach"
    adapter = FakeAdapter(selected)
    target, _library = make_target(target_module, adapter)

    assert target.ref.container_name is None
    assert target.wait_for_sql(2)
    assert adapter.query_calls[0]["container_name"] == "cockroach"


@pytest.mark.parametrize("tls", [False, True])
def test_healthy_inherited_target_is_reused_without_mutation(target_module, tls):
    adapter = FakeAdapter(statefulset(tls=tls))
    adapter.services.pop("crdb-test-public")
    mutations = []
    target, _library = make_target(target_module, adapter, lambda *args, **_kwargs: mutations.append(args))

    target.apply()

    assert adapter.query_calls
    assert adapter.query_calls[0]["tls_mode"] == ("tls" if tls else "insecure")
    assert adapter.query_calls[0]["certs_dir"] == ("/cockroach/cockroach-certs" if tls else None)
    assert mutations == []


def test_absent_target_bootstrap_interleaves_sql_and_init_then_waits_ready(target_module, monkeypatch):
    adapter = FakeAdapter(sts=None)
    adapter.pods = [
        {"metadata": {
            "name": "legacy-crdb-test-0", "uid": "leftover-pod",
            "labels": {"app.kubernetes.io/name": "cockroachdb", "app.kubernetes.io/instance": "crdb-test"},
        }},
        {"metadata": {
            "name": "other-0", "uid": "unrelated-pod",
            "labels": {"app.kubernetes.io/name": "cockroachdb", "app.kubernetes.io/instance": "other"},
        }},
    ]
    adapter.pvcs = [
        {"metadata": {
            "name": "legacy-data-crdb-test-0", "uid": "leftover-pvc",
            "labels": {"app.kubernetes.io/name": "cockroachdb", "app.kubernetes.io/instance": "crdb-test"},
        }},
        {"metadata": {
            "name": "other-data-0", "uid": "unrelated-pvc",
            "labels": {"app.kubernetes.io/name": "cockroachdb", "app.kubernetes.io/instance": "other"},
        }},
    ]
    operations = []
    events = []

    def command(*args, input_text=None, **_kwargs):
        if args[0] == "delete":
            resource_path = args[1]
            name = resource_path.rsplit("/", 1)[-1]
            options = json.loads(input_text)
            if "/pods/" in resource_path:
                operations.append(("delete-pod", name, options["preconditions"]["uid"]))
                adapter.pods = [pod for pod in adapter.pods if pod["metadata"]["name"] != name]
            elif "/persistentvolumeclaims/" in resource_path:
                operations.append(("delete-pvc", name, options["preconditions"]["uid"]))
                adapter.pvcs = [pvc for pvc in adapter.pvcs if pvc["metadata"]["name"] != name]
            else:
                pytest.fail(f"unexpected cleanup command: {args}")
        elif args[0] == "apply":
            document = yaml.safe_load(input_text)
            operations.append(("apply", document.get("kind")))
            if document.get("kind") == "StatefulSet":
                document["metadata"]["uid"] = "fresh-uid"
                adapter.sts = document
        elif args[0] == "wait":
            operations.append(("wait-ready", args))
        else:
            pytest.fail(f"unexpected bootstrap command: {args}")
        return subprocess.CompletedProcess(args, 0, "", "")

    target, _library = make_target(target_module, adapter, command)
    target._wait_for_pod_created = lambda _sts, uid, **_kwargs: events.append(("pod-created", uid))
    target._wait_for_running = lambda _sts, uid, **_kwargs: events.append(("running", uid))
    sql_results = iter([False, False])
    target._sql_ready_once = lambda uid, **_kwargs: events.append(("sql", uid)) or next(sql_results)
    init_results = iter([False, True])
    target._init = lambda uid, **_kwargs: events.append(("init", uid)) or next(init_results)
    monkeypatch.setattr(target_module.time, "sleep", lambda _seconds: None)

    target.apply()

    assert operations[:2] == [
        ("delete-pod", "legacy-crdb-test-0", "leftover-pod"),
        ("delete-pvc", "legacy-data-crdb-test-0", "leftover-pvc"),
    ]
    assert [pod["metadata"]["name"] for pod in adapter.pods] == ["other-0"]
    assert [pvc["metadata"]["name"] for pvc in adapter.pvcs] == ["other-data-0"]
    assert [operation[1] for operation in operations if operation[0] == "apply"] == [
        "ServiceAccount", "Role", "RoleBinding", "Service", "Service", "StatefulSet",
    ]
    assert events == [
        ("pod-created", "fresh-uid"), ("running", "fresh-uid"),
        ("sql", "fresh-uid"), ("init", "fresh-uid"),
        ("sql", "fresh-uid"), ("init", "fresh-uid"),
    ]
    ready = operations[-1]
    assert ready[0] == "wait-ready"
    assert "--for=condition=ready" in ready[1]
    assert "--timeout=600s" in ready[1]


def test_fresh_bootstrap_attempt_budget_is_original_120_seconds(target_module, monkeypatch):
    adapter = FakeAdapter(statefulset())
    target, _library = make_target(target_module, adapter)
    elapsed = [0.0]
    sql_attempts, init_attempts = [], []
    monkeypatch.setattr(target_module.time, "monotonic", lambda: elapsed[0])
    monkeypatch.setattr(
        target_module.time, "sleep",
        lambda seconds: elapsed.__setitem__(0, elapsed[0] + seconds),
    )
    target._sql_ready_once = lambda uid, **_kwargs: sql_attempts.append(uid) or False
    target._init = lambda uid, **_kwargs: init_attempts.append(uid) or False

    with pytest.raises(RuntimeError, match="could not be initialized"):
        target._initialize_until_queryable("inherited-uid")

    assert elapsed == [120.0]
    assert len(sql_attempts) == len(init_attempts) == 40
    assert set(sql_attempts + init_attempts) == {"inherited-uid"}


@pytest.mark.parametrize("source,error_type", [
    ("query", AuthenticationError),
    ("query", ConnectionError),
    ("query", KubernetesAccessError),
    ("observe", AuthenticationError),
    ("observe", ConnectionError),
    ("observe", KubernetesAccessError),
])
def test_sql_readiness_errors_follow_original_bounded_recovery(target_module, monkeypatch, source, error_type):
    adapter = FakeAdapter(statefulset())
    target, library = make_target(target_module, adapter)
    error = error_type("readiness failed")
    if source == "query":
        adapter.outcomes = [error] * 100
    else:
        library.connection_outcomes = [error] * 100
    elapsed = [0.0]
    monkeypatch.setattr(target_module.time, "monotonic", lambda: elapsed[0])
    monkeypatch.setattr(
        target_module.time, "sleep",
        lambda seconds: elapsed.__setitem__(0, elapsed[0] + seconds),
    )
    restarted, recreated = [], []
    target._delete_owned_pods = lambda sts, uid, **_kwargs: restarted.append((sts["metadata"]["uid"], uid))
    target._recreate_inherited = lambda sts: recreated.append(sts["metadata"]["uid"])

    target.apply()

    assert restarted == [("inherited-uid", "inherited-uid")]
    assert recreated == ["inherited-uid"]
    assert elapsed[0] >= 70


def test_apply_retries_then_recreates_only_after_bounded_target_restart(target_module, monkeypatch):
    adapter = FakeAdapter(statefulset())
    commands = []
    target, _library = make_target(target_module, adapter, lambda *args, **_kwargs: commands.append(args))
    recovery = []
    timeouts = []

    def wait_for_sql(seconds, **_kwargs):
        timeouts.append(seconds)
        return False

    target.wait_for_sql = wait_for_sql
    target._delete_owned_pods = lambda sts, uid: recovery.append(("restart", sts["metadata"]["uid"], uid))
    target._recreate_inherited = lambda sts: recovery.append(("recreate", sts))

    target.apply()

    assert recovery[0] == ("restart", "inherited-uid", "inherited-uid")
    assert recovery[1][0] == "recreate"
    assert recovery[1][1]["metadata"]["uid"] == "inherited-uid"
    assert timeouts == [10, 60]


def test_recreated_statefulset_preserves_tls_version_topology_and_downward_expansions(target_module, capsys):
    original = statefulset()
    adapter = FakeAdapter(original)
    observation = FakeLibrary(adapter).inspect(None)
    commands = []

    def command(*args, input_text=None, **_kwargs):
        commands.append((args, input_text))
        if args[:3] == ("create", "-f", "-"):
            document = yaml.safe_load(input_text)
            document["metadata"]["uid"] = "recreated-uid"
            return subprocess.CompletedProcess(args, 0, json.dumps(document), "")
        return subprocess.CompletedProcess(args, 0, "", "")

    target, _library = make_target(target_module, adapter, command)

    uid = target._create_observed_statefulset(original)

    sent = yaml.safe_load(next(value for args, value in commands if args[0] == "create"))
    container = sent["spec"]["template"]["spec"]["containers"][0]
    assert uid == "recreated-uid"
    assert sent["spec"]["replicas"] == 3
    assert container["image"] == "cockroachdb/cockroach:v24.1.0"
    assert "--certs-dir=/cockroach/cockroach-certs" in container["command"][2]
    assert "$(POD_NAME)" in container["command"][2]
    assert "$(POD_NAMESPACE)" in container["command"][2]
    assert "uid" not in sent["metadata"] and "resourceVersion" not in sent["metadata"]
    assert "status" not in sent
    assert "recreated-uid" not in capsys.readouterr().out


def test_inherited_tls_init_uses_observed_rpc_port_without_http_lifecycle_gate(target_module):
    adapter = FakeAdapter(statefulset())
    commands = []
    target, library = make_target(
        target_module, adapter,
        lambda *args, **_kwargs: commands.append(args) or subprocess.CompletedProcess(args, 0, "", ""),
    )

    assert target._init("inherited-uid") is True

    assert library.probe_calls == []
    assert len(library.connection_calls) == 1
    init = next(command for command in commands if command[0] == "exec")
    assert "--certs-dir=/cockroach/cockroach-certs" in init
    assert "--host=crdb-test-0.crdb-test.settings-test.svc.cluster.local:26258" in init
    assert not any(argument.startswith("--port") for argument in init)


def test_present_case_services_are_not_touched_on_healthy_reuse(target_module):
    adapter = FakeAdapter(statefulset())
    adapter.services["crdb-test-public"]["spec"] = {
        "type": "NodePort", "ports": [{"port": 31415, "targetPort": 31415}], "selector": {"custom": "selector"},
    }
    before = copy.deepcopy(adapter.services)
    commands = []
    target, _library = make_target(
        target_module, adapter,
        lambda *args, **_kwargs: commands.append(args) or subprocess.CompletedProcess(args, 0, "", ""),
    )

    target.apply()

    assert adapter.services == before
    assert commands == []


@pytest.mark.parametrize("kind,name,uid,path", [
    ("statefulset", "crdb-test", "sts-uid", "/apis/apps/v1/namespaces/settings-test/statefulsets/crdb-test"),
    ("pod", "crdb-test-0", "pod-uid", "/api/v1/namespaces/settings-test/pods/crdb-test-0"),
    ("pvc", "datadir-crdb-test-0", "pvc-uid", "/api/v1/namespaces/settings-test/persistentvolumeclaims/datadir-crdb-test-0"),
])
def test_guarded_delete_uses_uid_precondition_and_suppresses_response(target_module, kind, name, uid, path, capsys):
    adapter = FakeAdapter(statefulset())
    commands = []

    def command(*args, input_text=None, **kwargs):
        commands.append((args, input_text, kwargs))
        return subprocess.CompletedProcess(args, 0, '{"kind":"Secret","data":{"x":"sensitive"}}', "")

    target, _library = make_target(target_module, adapter, command)
    if kind == "statefulset":
        adapter.sts["metadata"]["uid"] = uid
    elif kind == "pod":
        adapter.pods = [{"metadata": {"name": name, "uid": uid, "ownerReferences": [{"kind": "StatefulSet", "uid": "inherited-uid", "controller": True}]}}]
    else:
        adapter.pvcs = [{"metadata": {"name": name, "uid": uid}}]
    adapter.get_resource = lambda _kind, _namespace, _name: None

    target._delete_uid_guarded(kind, name, uid, wait_timeout=0, propagation_policy="Orphan" if kind == "statefulset" else None)

    args, body, kwargs = commands[0]
    assert args[:2] == ("delete", f"--raw={path}")
    assert json.loads(body)["preconditions"] == {"uid": uid}
    assert "--force" not in args
    assert kwargs["timeout"] == 15
    assert "sensitive" not in capsys.readouterr().out


def test_target_pvc_selection_uses_full_cluster_identity_including_legacy_claims(target_module):
    adapter = FakeAdapter(statefulset())
    adapter.pvcs = [
        {"metadata": {"name": "datadir-crdb-test-4", "labels": {"app.kubernetes.io/name": "cockroachdb", "app.kubernetes.io/instance": "crdb-test"}}},
        {"metadata": {"name": "legacy-data-crdb-test-7", "labels": {"app.kubernetes.io/name": "cockroachdb", "app.kubernetes.io/instance": "crdb-test"}}},
        {"metadata": {"name": "datadir-other-4", "labels": {"app.kubernetes.io/name": "cockroachdb", "app.kubernetes.io/instance": "other"}}},
        {"metadata": {"name": "datadir-crdb-test-5", "labels": {"app.kubernetes.io/instance": "crdb-test"}}},
    ]
    target, _library = make_target(target_module, adapter)

    selected = target._target_pvcs()

    assert [pvc["metadata"]["name"] for pvc in selected] == [
        "datadir-crdb-test-4",
        "legacy-data-crdb-test-7",
    ]


def test_guarded_delete_does_not_treat_replacement_uid_as_deleted_identity(target_module):
    adapter = FakeAdapter(statefulset())
    replacement = {
        "metadata": {
            "name": "crdb-test-0",
            "uid": "replacement-pod",
            "labels": {"app.kubernetes.io/instance": "crdb-test"},
            "ownerReferences": [{"kind": "StatefulSet", "uid": "inherited-uid", "controller": True}],
        },
    }
    target, _library = make_target(target_module, adapter, lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, "", ""))
    adapter.get_resource = lambda kind, _namespace, _name: replacement if kind == "pod" else adapter.sts

    with pytest.raises(RuntimeError, match="identity changed"):
        target._delete_uid_guarded("pod", "crdb-test-0", "old-pod", wait_timeout=0)


def test_bounded_restart_force_deletes_only_the_selected_pod_uid(target_module):
    adapter = FakeAdapter(statefulset())
    adapter.pods = [{
        "metadata": {
            "name": "crdb-test-0", "uid": "pod-uid",
            "labels": {"app.kubernetes.io/instance": "crdb-test"},
            "ownerReferences": [{"kind": "StatefulSet", "uid": "inherited-uid", "controller": True}],
        },
    }]
    commands = []

    def command(*args, input_text=None, **_kwargs):
        commands.append((args, json.loads(input_text)))
        return subprocess.CompletedProcess(args, 0, "", "")

    target, _library = make_target(target_module, adapter, command)
    target._delete_owned_pods(adapter.sts, "inherited-uid")

    assert len(commands) == 1
    args, options = commands[0]
    assert args[0] == "delete"
    assert args[1].endswith("/pods/crdb-test-0")
    assert options["preconditions"] == {"uid": "pod-uid"}
    assert options["gracePeriodSeconds"] == 0


def test_wait_for_sql_retries_rollout_then_observes_replacement(target_module, monkeypatch):
    adapter = FakeAdapter(statefulset())
    target, library = make_target(target_module, adapter)
    library.connection_outcomes = [RolloutInProgressError("selected pod is still coming up"), None]
    monkeypatch.setattr(target_module.time, "sleep", lambda _seconds: None)

    assert target.wait_for_sql(1)
    assert len(library.connection_calls) == 2


def test_readiness_propagates_unsupported_layout_instead_of_resetting(target_module):
    adapter = FakeAdapter(statefulset(), outcomes=[UnsupportedLayoutError("unknown startup layout")])
    target, _library = make_target(target_module, adapter)
    with pytest.raises(UnsupportedLayoutError, match="unknown startup layout"):
        target.wait_for_sql(1)


def test_init_uses_observed_connection_uid_and_cli_host_port_contract(target_module):
    adapter = FakeAdapter(statefulset())
    commands = []
    target, library = make_target(
        target_module, adapter,
        lambda *args, **_kwargs: commands.append(args) or subprocess.CompletedProcess(args, 0, "", ""),
    )

    assert target._init("inherited-uid") is True

    init = next(command for command in commands if command[0] == "exec")
    assert library.probe_calls == []
    assert len(library.connection_calls) == 1
    assert "--host=crdb-test-0.crdb-test.settings-test.svc.cluster.local:26258" in init


def test_init_nonzero_result_is_retried_by_bootstrap_loop(target_module):
    adapter = FakeAdapter(statefulset())
    commands = []
    target, _library = make_target(
        target_module, adapter,
        lambda *args, **_kwargs: commands.append(args) or subprocess.CompletedProcess(args, 1, "", "not ready"),
    )

    assert target._init("inherited-uid") is False
    assert commands[0][0] == "exec"


def test_init_rejects_a_connection_observation_for_a_replacement_uid(target_module):
    adapter = FakeAdapter(statefulset())
    commands = []
    target, library = make_target(
        target_module, adapter,
        lambda *args, **_kwargs: commands.append(args) or subprocess.CompletedProcess(args, 0, "", ""),
    )
    library.connection_uid_override = "replacement-uid"

    with pytest.raises(RuntimeError, match="identity changed"):
        target._init("inherited-uid")

    assert not commands


def test_rpc_init_rejects_sql_advertisement_without_observed_rpc_host(target_module):
    adapter = FakeAdapter(statefulset())
    adapter.sts["spec"]["template"]["spec"]["containers"][0]["command"][2] += " --advertise-sql-addr=sql.example:26257"
    commands = []
    target, library = make_target(
        target_module, adapter,
        lambda *args, **_kwargs: commands.append(args) or subprocess.CompletedProcess(args, 0, "", ""),
    )
    library.rpc_host = None

    with pytest.raises(UnsupportedLayoutError, match="RPC host"):
        target._init("inherited-uid")

    assert commands == []


def test_rpc_init_uses_rpc_advertisement_when_sql_advertisement_is_explicit(target_module):
    adapter = FakeAdapter(statefulset())
    adapter.sts["spec"]["template"]["spec"]["containers"][0]["command"][2] += (
        " --advertise-addr=$(POD_NAME).rpc.$(POD_NAMESPACE).svc.cluster.local:26258"
        " --advertise-sql-addr=$(POD_NAME).sql.$(POD_NAMESPACE).svc.cluster.local:26257"
    )
    commands = []
    target, library = make_target(
        target_module, adapter,
        lambda *args, **_kwargs: commands.append(args) or subprocess.CompletedProcess(args, 0, "", ""),
    )
    library.rpc_host = "crdb-test-0.rpc.settings-test.svc.cluster.local"

    target._init("inherited-uid")

    init = next(command for command in commands if command[0] == "exec")
    assert "--host=crdb-test-0.rpc.settings-test.svc.cluster.local:26258" in init


def test_zero_replica_recreation_uses_case_replica_count_and_preserves_tls(target_module):
    inherited = statefulset()
    inherited["spec"]["replicas"] = 0
    adapter = FakeAdapter(inherited)
    target, _library = make_target(target_module, adapter)

    recreated = target._recreation_spec(inherited)

    container = recreated["spec"]["template"]["spec"]["containers"][0]
    assert recreated["spec"]["replicas"] == 3
    assert container["image"] == "cockroachdb/cockroach:v24.1.0"
    assert "--certs-dir=/cockroach/cockroach-certs" in container["command"][2]
    assert inherited["spec"]["replicas"] == 0


def test_inherited_tls_recreation_restores_original_cleanup_and_support_apply(target_module, capsys):
    original = statefulset()
    adapter = FakeAdapter(original)
    adapter.pods = [
        {"metadata": {
            "name": f"crdb-test-{ordinal}", "uid": f"pod-{ordinal}",
            "labels": {"app.kubernetes.io/instance": "crdb-test"},
            "ownerReferences": [{"kind": "StatefulSet", "uid": "inherited-uid", "controller": True}],
        }}
        for ordinal in range(3)
    ]
    adapter.pvcs = [
        {"metadata": {
            "name": f"datadir-crdb-test-{ordinal}", "uid": f"pvc-{ordinal}",
            "labels": {"app.kubernetes.io/name": "cockroachdb", "app.kubernetes.io/instance": "crdb-test"},
        }}
        for ordinal in range(3)
    ]
    commands = []

    def command(*args, input_text=None, **_kwargs):
        commands.append((args, input_text))
        if args[0] == "delete":
            path = args[1].removeprefix("--raw=")
            uid = json.loads(input_text)["preconditions"]["uid"]
            if "/statefulsets/" in path:
                assert uid == "inherited-uid"
                adapter.sts = None
            elif "/pods/" in path:
                pod_name = path.rsplit("/", 1)[-1]
                adapter.pods = [pod for pod in adapter.pods if pod["metadata"]["name"] != pod_name]
            elif "/persistentvolumeclaims/" in path:
                name = path.rsplit("/", 1)[-1]
                adapter.pvcs = [pvc for pvc in adapter.pvcs if pvc["metadata"]["name"] != name]
            return subprocess.CompletedProcess(args, 0, '{"private":"not-for-output"}', "")
        if args[0] == "apply":
            document = yaml.safe_load(input_text)
            commands.append((("applied-kind", document["kind"]), None))
            return subprocess.CompletedProcess(args, 0, "", "")
        if args[:3] == ("create", "-f", "-"):
            document = yaml.safe_load(input_text)
            document["metadata"]["uid"] = "recreated-uid"
            adapter.sts = document
            return subprocess.CompletedProcess(args, 0, json.dumps(document), "")
        if args[0] == "wait":
            return subprocess.CompletedProcess(args, 0, "", "")
        return subprocess.CompletedProcess(args, 0, "", "")

    target, _library = make_target(target_module, adapter, command)
    events = []
    target._wait_for_pod_created = lambda _sts, uid, **_kwargs: events.append(("pod-created", uid))
    target._wait_for_running = lambda _sts, uid, **_kwargs: target._assert_statefulset_uid(uid)
    target._sql_ready_once = lambda uid, **_kwargs: events.append(("sql", uid)) or False
    initialized = []
    target._init = lambda uid, **_kwargs: initialized.append(uid) or True
    target._wait_for_ready = lambda: events.append(("ready",))

    target._recreate_inherited(original)

    assert initialized == ["recreated-uid"]
    assert events == [("pod-created", "recreated-uid"), ("sql", "recreated-uid"), ("ready",)]
    recreated = adapter.sts
    assert recreated["metadata"]["uid"] == "recreated-uid"
    assert recreated["spec"] == original["spec"]
    delete_options = [json.loads(body) for args, body in commands if args[0] == "delete"]
    assert [item["preconditions"]["uid"] for item in delete_options] == [
        "inherited-uid", "pod-0", "pod-1", "pod-2", "pvc-0", "pvc-1", "pvc-2",
    ]
    assert delete_options[0]["propagationPolicy"] == "Orphan"
    assert delete_options[0]["preconditions"] == {"uid": "inherited-uid"}
    assert delete_options[0].get("gracePeriodSeconds") is None
    assert all(item.get("gracePeriodSeconds") == 0 for item in delete_options[1:4])
    assert all(item.get("gracePeriodSeconds") is None for item in delete_options[4:])
    applied_kinds = [args[1] for args, _ in commands if args[:1] == ("applied-kind",)]
    assert applied_kinds == ["ServiceAccount", "Role", "RoleBinding", "Service", "Service"]
    statefulset_create = next(index for index, (args, _body) in enumerate(commands) if args[:3] == ("create", "-f", "-"))
    assert all(index < statefulset_create for index, (args, _body) in enumerate(commands) if args[:1] == ("applied-kind",))
    assert "not-for-output" not in capsys.readouterr().out


def test_persistently_missing_pods_reach_case_recreate_without_a_late_observation_gate(target_module, monkeypatch):
    adapter = FakeAdapter(statefulset())
    target, library = make_target(target_module, adapter)
    library.connection_outcomes = [RolloutInProgressError("selected pod is missing")] * 1000
    elapsed = [0.0]
    monkeypatch.setattr(target_module.time, "monotonic", lambda: elapsed[0])
    monkeypatch.setattr(target_module.time, "sleep", lambda seconds: elapsed.__setitem__(0, elapsed[0] + seconds))
    restarted = []
    recreated = []
    target._delete_owned_pods = lambda sts, uid: restarted.append((sts["metadata"]["uid"], uid))
    target._recreate_inherited = lambda sts: recreated.append(sts)

    target.apply()

    assert restarted == [("inherited-uid", "inherited-uid")]
    assert [sts["metadata"]["uid"] for sts in recreated] == ["inherited-uid"]
    assert elapsed[0] >= 70


def test_cluster_settings_readiness_query_is_a_fixed_sql_allowlist_entry(monkeypatch):
    import karma.crdb.adapter as adapter_module

    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, "1\n", "")

    monkeypatch.setattr(adapter_module.subprocess, "run", run)
    adapter = KubectlAdapter(kubectl="kubectl")
    assert adapter.query_sql(
        namespace="settings-test", pod_name="crdb-test-0", container_name="db",
        binary="/cockroach/cockroach", sql_host="crdb-test-0.crdb-test.settings-test.svc.cluster.local",
        sql_port=26257, tls_mode="tls", certs_dir="/cockroach/cockroach-certs",
        sql="SELECT 1;", timeout=5,
    ) == "1\n"
    assert calls[0][0][-2:] == ["-e", "SELECT 1;"]
    assert calls[0][0][1:3] == ["--namespace", "settings-test"]
    with pytest.raises(UnsupportedLayoutError):
        adapter.query_sql(
            namespace="settings-test", pod_name="crdb-test-0", container_name="db",
            binary="/cockroach/cockroach", sql_host="crdb-test-0.crdb-test.settings-test.svc.cluster.local",
            sql_port=26257, tls_mode="tls", certs_dir="/cockroach/cockroach-certs",
            sql="SELECT 1; DROP TABLE witness;", timeout=5,
        )
    assert len(calls) == 1


def test_owned_pod_recovery_uses_real_adapter_resource_kind(monkeypatch, target_module):
    target_sts = statefulset()
    target_sts["spec"]["replicas"] = 1
    target_uid = target_sts["metadata"]["uid"]
    pod = {
        "metadata": {
            "name": "crdb-test-0",
            "namespace": "settings-test",
            "uid": "pod-uid",
            "labels": {"app.kubernetes.io/instance": "crdb-test"},
            "ownerReferences": [{"kind": "StatefulSet", "uid": target_uid, "controller": True}],
        },
        "status": {"phase": "Running"},
    }
    adapter = KubectlAdapter(kubectl="kubectl")
    commands = []

    def run(command, timeout, operation, **_kwargs):
        commands.append((command, operation))
        if "statefulsets" in command:
            return subprocess.CompletedProcess(command, 0, json.dumps(target_sts), "")
        if "pods" in command:
            return subprocess.CompletedProcess(command, 0, json.dumps({"items": [pod]}), "")
        pytest.fail(f"unexpected read through the real adapter: {operation}")

    monkeypatch.setattr(adapter, "_run", run)
    target = target_module.TargetCluster("settings-test", "crdb-test", adapter=adapter)

    assert target._owned_pods(target_sts, target_uid) == [pod]
    target._wait_for_running(target_sts, target_uid, timeout=1)

    pod_list_commands = [command for command, operation in commands if operation == "listing pod"]
    assert len(pod_list_commands) == 2
    assert all(command[-2:] == ["pods", "--output=json"] for command in pod_list_commands)

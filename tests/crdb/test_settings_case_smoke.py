"""Safety tests for the cluster-settings live smoke harness."""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from karma.crdb.types import KubernetesAccessError


ROOT = Path(__file__).resolve().parents[2]
HARNESS_PATH = ROOT / "experiments/crdb-case-migration/settings_case_smoke.py"
SPEC = importlib.util.spec_from_file_location("settings_case_smoke_harness", HARNESS_PATH)
assert SPEC is not None and SPEC.loader is not None
HARNESS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HARNESS)


@pytest.fixture
def fixture():
    args = SimpleNamespace(
        kubectl="kubectl",
        context=None,
        docker="docker",
        node="kind-worker",
        image="cockroachdb/cockroach:v24.1.0",
    )
    return HARNESS.SettingsFixture(args, "insecure", "261019-abc")


def test_fixture_tls_uses_cluster_settings_oracle_cert_mount_and_rpc_tcp_probes(fixture):
    manifest = fixture.statefulset_manifest(tls=True)
    container = manifest["spec"]["template"]["spec"]["containers"][0]
    assert "--certs-dir=/cockroach/cockroach-certs" in container["command"][2]
    cert_mount = next(mount for mount in container["volumeMounts"] if mount["name"] == "certs")
    assert cert_mount["mountPath"] == "/cockroach/cockroach-certs"
    assert container["livenessProbe"]["tcpSocket"]["port"] == "rpc"
    assert container["readinessProbe"]["tcpSocket"]["port"] == "rpc"
    assert manifest["spec"]["replicas"] == 1
    assert manifest["metadata"]["labels"]["crdb-library-run"] == fixture.run_id


def test_observer_compat_fixture_uses_implicit_root_certs_and_combined_sql_rpc_listener():
    args = SimpleNamespace(
        kubectl="kubectl", context=None, docker="docker", node="kind-worker",
        image="cockroachdb/cockroach:v24.1.0",
    )
    fixture = HARNESS.SettingsFixture(args, "observer-compat", "261020-abc")
    manifest = fixture.statefulset_manifest(tls=True)
    container = manifest["spec"]["template"]["spec"]["containers"][0]
    script = container["command"][2]
    assert "--certs-dir=" not in script
    assert "--sql-addr=" not in script
    assert "--port=" not in script
    assert "--listen-addr=0.0.0.0:26258" in script
    assert "--advertise-addr=$(POD_NAME).db.$(POD_NAMESPACE).svc.cluster.local:26258" in script
    assert "--advertise-sql-addr=$(POD_NAME).db.$(POD_NAMESPACE).svc.cluster.local:26258" in script
    assert "--join=db-0.db.$(POD_NAMESPACE).svc.cluster.local:26258" in script
    cert_mount = next(mount for mount in container["volumeMounts"] if mount["name"] == "certs")
    assert cert_mount["mountPath"] == "/root/.cockroach-certs"
    assert next(port for port in container["ports"] if port["name"] == "sql")["containerPort"] == 26258
    service_ports = fixture.service_manifest()["spec"]["ports"]
    assert service_ports == [
        {"name": "sql", "port": 26258, "targetPort": "sql", "protocol": "TCP"},
        {"name": "http", "port": 8080, "targetPort": "http", "protocol": "TCP"},
    ]


def test_oracle_rebind_uses_the_same_root_cert_and_combined_listener_fixture(monkeypatch):
    args = SimpleNamespace(
        kubectl="kubectl", context=None, docker="docker", node="kind-worker",
        image="cockroachdb/cockroach:v24.1.0",
    )
    fixture = HARNESS.SettingsFixture(args, "oracle-rebind", "261020-oracle")
    manifest = fixture.statefulset_manifest(tls=True)
    container = manifest["spec"]["template"]["spec"]["containers"][0]
    script = container["command"][2]
    assert "--certs-dir=" not in script
    assert "--sql-addr=" not in script
    assert "--port=" not in script
    assert "--listen-addr=0.0.0.0:26258" in script
    assert next(mount for mount in container["volumeMounts"] if mount["name"] == "certs")["mountPath"] == "/root/.cockroach-certs"
    assert fixture.service_manifest()["spec"]["ports"] == [
        {"name": "sql", "port": 26258, "targetPort": "sql", "protocol": "TCP"},
        {"name": "http", "port": 8080, "targetPort": "http", "protocol": "TCP"},
    ]
    calls = []
    monkeypatch.setattr(HARNESS._BASE, "run", lambda command, **kwargs: calls.append((command, kwargs)))
    fixture.init(tls=True)
    assert "--certs-dir=/root/.cockroach-certs" in calls[0][0]
    assert f"--host=db-0.db.{fixture.namespace}.svc.cluster.local:26258" in calls[0][0]


def test_oracle_sql_connection_mode_reuses_root_cert_combined_listener_fixture():
    args = SimpleNamespace(
        kubectl="kubectl", context=None, docker="docker", node="kind-worker",
        image="cockroachdb/cockroach:v24.1.0",
    )
    fixture = HARNESS.SettingsFixture(args, "oracle-sql-connection", "261020-sql")
    manifest = fixture.statefulset_manifest(tls=True)
    container = manifest["spec"]["template"]["spec"]["containers"][0]
    assert "--certs-dir=" not in container["command"][2]
    assert "--sql-addr=" not in container["command"][2]
    assert "--port=" not in container["command"][2]
    assert "--listen-addr=0.0.0.0:26258" in container["command"][2]
    assert next(mount for mount in container["volumeMounts"] if mount["name"] == "certs")["mountPath"] == "/root/.cockroach-certs"
    assert fixture.service_manifest()["spec"]["ports"] == [
        {"name": "sql", "port": 26258, "targetPort": "sql", "protocol": "TCP"},
        {"name": "http", "port": 8080, "targetPort": "http", "protocol": "TCP"},
    ]


@pytest.mark.parametrize(
    ("statuses", "expect_success", "expected_returned_route"),
    [
        ([1, 1, 0], True, "observed-tls"),
        ([1, 1, 1], False, "legacy"),
    ],
)
def test_certificate_oracle_helper_journals_actual_module_tls_candidates_without_output(
    tmp_path, monkeypatch, statuses, expect_success, expected_returned_route
):
    class JournalFixture:
        run_id = "261020-sql"
        namespace = "karma-crdb-library-261020-sql-oracle-sql-connection"
        phase_data = {}

        def __init__(self):
            self.checkpoints = []

        def _checkpoint(self, name):
            self.checkpoints.append(name)

    fixture = JournalFixture()
    oracle = HARNESS._load_certificate_rotation_oracle(fixture)
    calls = []

    def fake_run(command, timeout=30):
        code = statuses[len(calls)]
        calls.append((list(command), timeout))
        return subprocess.CompletedProcess(
            list(command), code, "stdout-secret-sentinel", "stderr-secret-sentinel"
        )

    monkeypatch.setattr(oracle, "run", fake_run)

    def observed_retry():
        for cert_dir in ("/cockroach/cockroach-certs", "/root/.cockroach-certs"):
            result = oracle.run(
                [
                    "kubectl", "-n", fixture.namespace, "exec", "db-0", "--container", "db", "--",
                    "/cockroach/cockroach", "sql", f"--certs-dir={cert_dir}",
                    f"--host=db-0.db.{fixture.namespace}.svc.cluster.local", "--port=26258",
                    "-e", "SELECT 1;",
                ],
                timeout=15,
            )
            if result.returncode == 0:
                return result
        return None

    monkeypatch.setattr(oracle, "_observed_tls_sql_result", observed_retry)
    check = HARNESS._certificate_oracle_sql_check(
        fixture, oracle, label="focused-test", expect_success=expect_success
    )

    assert len(calls) == 3
    assert [attempt["route"] for attempt in check["attempts"]] == [
        "legacy", "observed-tls", "observed-tls",
    ]
    assert [attempt["certs_dir"] for attempt in check["attempts"]] == [
        "/cockroach/cockroach-certs", "/cockroach/cockroach-certs", "/root/.cockroach-certs",
    ]
    assert check["returned_route"] == expected_returned_route
    assert all(not attempt["insecure_flag"] for attempt in check["attempts"])
    assert "stdout-secret-sentinel" not in json.dumps(fixture.phase_data)
    assert "stderr-secret-sentinel" not in json.dumps(fixture.phase_data)
    assert fixture.checkpoints


def test_oracle_sql_connection_phase_rejects_before_init_then_checks_after_restart(monkeypatch):
    events = []

    class PhaseFixture:
        namespace = "karma-crdb-library-261020-sql-oracle-sql-connection"
        run_id = "261020-sql"
        phase_data = {}
        command_trace = []

        def wait_ready(self, timeout):
            events.append(("wait-ready", timeout))

        def _checkpoint(self, name):
            events.append(("checkpoint", name))

        def set_stage(self, name):
            events.append(("stage", name))

        def init(self, tls):
            assert tls is True
            self.command_trace.append({"operation": "cockroach init"})
            events.append(("init", len(self.command_trace)))

    fixture = PhaseFixture()
    pod_uid = {"value": "pod-before"}
    workload_uid = "sts-uid"
    workload = lambda: SimpleNamespace(
        workload_uid=workload_uid,
        http_transport=SimpleNamespace(value="https"),
        pods=(SimpleNamespace(uid=pod_uid["value"]),),
    )

    class FakeLibrary:
        def probe(self, *_args, **_kwargs):
            return SimpleNamespace(
                status=HARNESS.ProbeStatus.SATISFIED,
                health=SimpleNamespace(lifecycle=HARNESS.Lifecycle.DEPLOYED),
                workload=workload(),
            )

        def inspect_sql_connection(self, *_args, **_kwargs):
            return SimpleNamespace(
                namespace=fixture.namespace,
                workload_name="db",
                workload_uid=workload_uid,
                pod_name="db-0",
                pod_uid=pod_uid["value"],
                container_name="db",
                image="cockroachdb/cockroach:v24.1.0",
                sql_binary="/cockroach/cockroach",
                sql_host=f"db-0.db.{fixture.namespace}.svc.cluster.local",
                sql_port=26258,
                rpc_port=26258,
                tls_mode=HARNESS.TLSMode.TLS,
                certs_dir="/root/.cockroach-certs",
            )

        def reconcile(self, *_args, **_kwargs):
            return SimpleNamespace(
                assessment=SimpleNamespace(status=HARNESS.ProbeStatus.SATISFIED, workload=workload())
            )

        def probe_health_endpoint(self, *_args, **_kwargs):
            return (("db-0", 200, True),)

        def capture_accepted_state(self, *_args, **_kwargs):
            events.append(("capture-accepted", pod_uid["value"]))
            return {"cluster_id": "cluster-1"}

        def verify_accepted_state(self, *_args, **_kwargs):
            return SimpleNamespace(status=HARNESS.ProbeStatus.SATISFIED, workload=workload())

    monkeypatch.setattr(HARNESS, "CrdbLibrary", lambda *_args, **_kwargs: FakeLibrary())
    monkeypatch.setattr(HARNESS, "_load_certificate_rotation_oracle", lambda _fixture: object())

    def oracle_check(_fixture, _oracle, *, label, expect_success):
        init_count = sum(event.get("operation") == "cockroach init" for event in fixture.command_trace)
        events.append(("oracle-check", label, init_count))
        if label == "before-explicit-init":
            assert expect_success is False and init_count == 0
        else:
            assert expect_success is True and init_count == 1
        connection = FakeLibrary().inspect_sql_connection()
        return {
            "label": label,
            "accepted": expect_success,
            "returned_binding": {
                "namespace": connection.namespace,
                "pod_name": connection.pod_name,
                "container_name": connection.container_name,
                "sql_binary": connection.sql_binary,
                "sql_host": connection.sql_host,
                "sql_port": str(connection.sql_port),
                "certs_dir": connection.certs_dir,
            },
        }

    monkeypatch.setattr(HARNESS, "_certificate_oracle_sql_check", oracle_check)
    monkeypatch.setattr(HARNESS, "_run_observer_compat_sql", lambda *_args: events.append(("witness-sql",)) or "ok")
    monkeypatch.setattr(HARNESS, "_observer_compat_witness_hash", lambda *_args: (2, "witness-hash"))
    monkeypatch.setattr(
        HARNESS,
        "_observer_compat_setting_value",
        lambda *_args: events.append(("setting-set-read",)) or "128MiB",
    )
    monkeypatch.setattr(
        HARNESS,
        "_observer_compat_setting_readback",
        lambda *_args: events.append(("setting-read",)) or "128MiB",
    )
    monkeypatch.setattr(HARNESS, "_load_oracle", lambda *_args: {"values_match": lambda _expected, _actual: True})
    monkeypatch.setattr(HARNESS, "_accepted_summary", lambda state: state)
    monkeypatch.setattr(
        HARNESS,
        "_restart_pod_with_uid_guard",
        lambda *_args, **_kwargs: ("pod-before", pod_uid.update(value="pod-after") or "pod-after"),
    )

    result = HARNESS._exercise_observer_compat_phase(
        SimpleNamespace(kubectl="kubectl", ready_timeout=30, restart_timeout=20),
        fixture,
        oracle_sql_connection=True,
    )

    proof = result["certificate_rotation_sql_connection"]
    assert proof["preinit"]["label"] == "before-explicit-init"
    assert proof["preinit"]["accepted"] is False
    assert proof["explicit_init_count"] == 1
    assert proof["oracle_main_invoked"] is False
    assert [check["label"] for check in proof["checks"]] == [
        "after-explicit-init", "after-normal-pod-restart",
    ]
    assert result["pod_uids_before_after"] == [("pod-before",), ("pod-after",)]
    assert result["controlled_setting_before_after"] == ["128MiB", "128MiB"]
    assert result["case_apply_noop"] is None
    assert result["case_commands_run"] is False
    labels = [event[1] for event in events if event[0] == "oracle-check"]
    assert labels == ["before-explicit-init", "after-explicit-init", "after-normal-pod-restart"]
    assert events.index(("setting-set-read",)) < next(
        index for index, event in enumerate(events) if event[0] == "capture-accepted"
    )


def test_tls_transform_fixture_starts_insecure_with_tcp_probes_and_bounded_resources():
    args = SimpleNamespace(
        kubectl="kubectl", context=None, docker="docker", node="kind-worker",
        image="cockroachdb/cockroach:v24.1.0",
    )
    fixture = HARNESS.SettingsFixture(args, "tls-transform", "261020-transform")
    manifest = fixture.statefulset_manifest(tls=False)
    spec = manifest["spec"]
    container = spec["template"]["spec"]["containers"][0]
    script = container["command"][2]

    assert spec["replicas"] == 1
    assert "--insecure" in script
    assert "--cache=128MiB" in script
    assert container["imagePullPolicy"] == "Never"
    assert container["resources"] == {
        "requests": {"cpu": "100m", "memory": "256Mi"},
        "limits": {"cpu": "1", "memory": "1Gi"},
    }
    assert container["livenessProbe"]["tcpSocket"]["port"] == "rpc"
    assert container["readinessProbe"]["tcpSocket"]["port"] == "rpc"
    assert spec["volumeClaimTemplates"][0]["spec"]["resources"]["requests"]["storage"] == "1Gi"


def test_service_preservation_fixture_requests_server_allocated_public_nodeports():
    args = SimpleNamespace(
        kubectl="kubectl", context=None, docker="docker", node="kind-worker",
        image="cockroachdb/cockroach:v24.1.0",
    )
    fixture = HARNESS.SettingsFixture(args, "tls-service-preservation", "261020-service")
    service = fixture.public_service_manifest()
    assert service["spec"]["type"] == "NodePort"
    assert {item["port"] for item in service["spec"]["ports"]} >= {26257, 8080}
    assert all("nodePort" not in item for item in service["spec"]["ports"])


def test_health_endpoint_assertion_matches_public_tuple_contract():
    assert HARNESS._require_single_health_response((("db-0", 200, True),), path="/health") is None
    for result in (
        [],
        (("db-0", 200, True), ("db-1", 200, True)),
        (("db-0", 503, False),),
    ):
        with pytest.raises(HARNESS._BASE.SmokeFailure, match="one successful db-0 response"):
            HARNESS._require_single_health_response(result, path="/health")


def test_observer_compat_explicit_init_uses_root_cert_default_and_rpc_port(monkeypatch):
    args = SimpleNamespace(
        kubectl="kubectl", context=None, docker="docker", node="kind-worker",
        image="cockroachdb/cockroach:v24.1.0",
    )
    fixture = HARNESS.SettingsFixture(args, "observer-compat", "261020-abc")
    calls = []
    monkeypatch.setattr(HARNESS._BASE, "run", lambda command, **kwargs: calls.append((command, kwargs)))

    fixture.init(tls=True)

    command, options = calls[0]
    assert "--certs-dir=/root/.cockroach-certs" in command
    assert "--host=db-0.db.karma-crdb-library-261020-abc-observer-compat.svc.cluster.local:26258" in command
    assert options["operation"] == "cockroach init"
    assert "--certs-dir=/cockroach/cockroach-certs" not in command


def test_observer_compat_fixture_sql_client_uses_independent_expected_path_and_port(fixture, monkeypatch):
    fixture.phase = "observer-compat"
    calls = []
    monkeypatch.setattr(
        HARNESS._BASE,
        "run",
        lambda command, **kwargs: calls.append((command, kwargs)) or "ok",
    )

    assert HARNESS._run_observer_compat_sql(fixture, "SELECT 1;") == "ok"

    command, options = calls[0]
    assert "--host=localhost" in command
    assert "--port=26258" in command
    assert "--certs-dir=/root/.cockroach-certs" in command
    assert "--port=26257" not in command
    assert options["operation"] == "observer compatibility fixture SQL"


def test_fixture_waits_for_db_pod_creation_before_calling_ready_wait(fixture, monkeypatch):
    fixture.get = Mock(side_effect=[{}, {"status": {"phase": "Pending"}}, {"status": {"phase": "Running"}}])
    ready_calls = []
    monkeypatch.setattr(HARNESS._BASE.Fixture, "wait_ready", lambda _self, timeout: ready_calls.append(timeout))
    monkeypatch.setattr(HARNESS.time, "sleep", lambda _seconds: None)

    fixture.wait_ready(timeout=10)

    assert fixture.get.call_count == 3
    assert len(ready_calls) == 1
    assert 0 < ready_calls[0] <= 10


def test_fixture_running_wait_fails_within_bound_if_pod_never_appears(fixture, monkeypatch):
    fixture.get = Mock(return_value={})
    monkeypatch.setattr(HARNESS.time, "monotonic", iter([0.0, 0.0, 0.0, 10.0, 10.0]).__next__)
    monkeypatch.setattr(HARNESS.time, "sleep", lambda _seconds: None)
    with pytest.raises(HARNESS._BASE.SmokeFailure, match="did not reach Running"):
        fixture.wait_ready(timeout=10)


def test_small_fresh_manifest_set_is_one_node_bounded_and_preserves_kubelet_expansions(fixture):
    documents, statefulset = HARNESS._fresh_documents(fixture)
    assert [(doc["kind"], doc["metadata"]["name"]) for doc in documents] == [
        ("ServiceAccount", "${BENCH_PARAM_CLUSTER_NAME}-sa"),
        ("Role", "${BENCH_PARAM_CLUSTER_NAME}-role"),
        ("RoleBinding", "${BENCH_PARAM_CLUSTER_NAME}-rolebinding"),
        ("Service", "${BENCH_PARAM_CLUSTER_NAME}"),
        ("Service", "${BENCH_PARAM_CLUSTER_NAME}-public"),
        ("StatefulSet", "${BENCH_PARAM_CLUSTER_NAME}"),
    ]
    spec = statefulset["spec"]
    assert spec["replicas"] == 1
    assert spec["volumeClaimTemplates"][0]["spec"]["resources"]["requests"]["storage"] == "1Gi"
    pod_spec = spec["template"]["spec"]
    container = pod_spec["containers"][0]
    assert container["imagePullPolicy"] == "Never"
    assert container["resources"] == {
        "requests": {"cpu": "100m", "memory": "256Mi"},
        "limits": {"cpu": "1", "memory": "1Gi"},
    }
    assert "$(POD_NAME)" in container["command"][2]
    assert "$(POD_NAMESPACE)" in container["command"][2]
    assert all(doc["metadata"]["labels"]["crdb-library-run"] == fixture.run_id for doc in documents)


def test_case_helper_manifest_dir_seam_renders_six_documents_without_expanding_kubelet_fields(
    fixture, tmp_path
):
    HARNESS._write_small_manifest_dir(tmp_path, fixture)
    with HARNESS.case_environment(fixture.namespace):
        module_globals = HARNESS.runpy.run_path(str(HARNESS.TARGET_PATH))
    target = module_globals["TargetCluster"](
        fixture.namespace,
        "db",
        adapter=object(),
        library=object(),
        command=lambda *_args, **_kwargs: pytest.fail("manifest inspection must not call kubectl"),
        manifest_dir=tmp_path,
    )

    documents, statefulset = target._rendered_documents()

    assert len(documents) == 6
    assert statefulset["metadata"]["name"] == "db"
    assert statefulset["metadata"]["namespace"] == fixture.namespace
    script = statefulset["spec"]["template"]["spec"]["containers"][0]["command"][2]
    assert "$(POD_NAME)" in script
    assert "$(POD_NAMESPACE)" in script
    assert "${" not in script


def test_target_create_command_journals_each_uid_before_checkpoint(fixture):
    phase_data = {}
    checkpoints = []
    fixture.checkpoint_callback = lambda status: checkpoints.append(
        (status, set(fixture.created), len(phase_data.get("target_create_identities", [])))
    )

    def render(value):
        if isinstance(value, str):
            return (
                value.replace("${BENCH_PARAM_CLUSTER_NAME}", "db")
                .replace("${BENCH_NAMESPACE}", fixture.namespace)
            )
        if isinstance(value, list):
            return [render(item) for item in value]
        if isinstance(value, dict):
            return {key: render(item) for key, item in value.items()}
        return value

    def fake_kubectl(*args, input_text=None, **_kwargs):
        document = render(json.loads(input_text))
        created = copy.deepcopy(document)
        created["metadata"]["uid"] = f"uid-{document['kind'].lower()}-{len(checkpoints)}"
        return json.dumps(created)

    fixture.kubectl = fake_kubectl
    command = HARNESS._tracked_target_command(fixture, phase_data)
    documents, _ = HARNESS._fresh_documents(fixture)
    for document in documents:
        command("create", "-f", "-", "--output=json", input_text=json.dumps(render(document)))

    expected = [(render(doc)["kind"].lower(), render(doc)["metadata"]["name"]) for doc in documents]
    assert list(fixture.created) == expected
    assert [(row["kind"], row["name"]) for row in phase_data["target_create_identities"]] == expected
    assert len(checkpoints) == 6
    for index, (_, owned, progress_count) in enumerate(checkpoints, start=1):
        assert len(owned) == index
        assert progress_count == index


def test_recovery_target_commands_journal_uid_intents_before_create_and_delete(fixture):
    fixture.phase = "tls-recovery"
    phase_data = {"phase": "tls-recovery"}
    fixture.phase_data = phase_data
    fixture._record_storage_snapshot = Mock(return_value=[])
    observed = []

    def fake_kubectl(*args, input_text=None, **_kwargs):
        event = phase_data["target_resource_history"][-1]
        observed.append((args[0], event["action"], event["state"], event.get("uid")))
        if args[0] == "create":
            document = json.loads(input_text)
            document["metadata"]["uid"] = "created-statefulset-uid"
            return json.dumps(document)
        return "{}"

    fixture.kubectl = fake_kubectl
    command = HARNESS._tracked_target_command(fixture, phase_data)
    manifest = {
        "apiVersion": "apps/v1",
        "kind": "StatefulSet",
        "metadata": {"name": "db", "namespace": fixture.namespace},
        "spec": {},
    }
    command("create", "-f", "-", "--output=json", input_text=json.dumps(manifest))
    options = json.dumps({
        "apiVersion": "v1",
        "kind": "DeleteOptions",
        "preconditions": {"uid": "created-statefulset-uid"},
        "propagationPolicy": "Foreground",
    })
    command(
        "delete",
        f"--raw=/apis/apps/v1/namespaces/{fixture.namespace}/statefulsets/db",
        "-f", "-", input_text=options,
    )
    command(
        "exec", "db-0", "--container=db", "--", "/cockroach/cockroach", "init",
        "--certs-dir=/cockroach/cockroach-certs", "--host=db-0.db.test.svc.cluster.local:26258",
    )

    assert observed == [
        ("create", "create", "intent", None),
        ("delete", "delete", "intent", "created-statefulset-uid"),
        ("exec", "init", "intent", None),
    ]
    assert [(event["action"], event["state"]) for event in phase_data["target_resource_history"]] == [
        ("create", "created"),
        ("delete", "requested"),
        ("init", "requested"),
    ]
    assert phase_data["target_resource_history"][0]["manifest_sha256"]
    assert "certs-dir" not in json.dumps(phase_data["target_resource_history"])


def test_recovery_tls_secret_journals_only_uid_and_manifest_digest(fixture, tmp_path):
    fixture.phase = "tls-recovery"
    phase_data = {}
    fixture.phase_data = phase_data
    fixture.kubectl = lambda *args, **kwargs: (
        json.dumps({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": "db-certs"},
            "data": {"node.key": "PRIVATE_KEY_SENTINEL"},
        }) if "--dry-run=client" in args else "created-secret-uid"
    )

    fixture.make_secret(tmp_path)

    assert fixture.created[("secret", "db-certs")] == "created-secret-uid"
    encoded = json.dumps(phase_data)
    assert "PRIVATE_KEY_SENTINEL" not in encoded
    assert phase_data["target_resource_history"][0]["state"] == "created"
    assert len(phase_data["target_resource_history"][0]["manifest_sha256"]) == 64


def test_cleanup_recovers_exact_owned_identity_after_ambiguous_create_response(fixture):
    fixture.phase = "tls-recovery"
    fixture.namespace_uid = "owned-namespace-uid"
    fixture.phase_data = {"target_resource_history": [
        {"action": "create", "state": "ambiguous", "kind": "secret", "name": "db-certs"},
    ]}
    fixture.get = lambda kind, name=None, **_kwargs: {
        "metadata": {"name": name, "uid": "recovered-secret-uid", "labels": {"crdb-library-run": fixture.run_id}}
    } if (kind, name) == ("secret", "db-certs") else {}
    fixture._checkpoint = lambda _status: None

    fixture._refresh_recovery_identities_for_cleanup()

    assert fixture.created[("secret", "db-certs")] == "recovered-secret-uid"
    assert fixture.phase_data["target_resource_history"][0]["state"] == "created-after-ambiguous-response"


def test_recovery_identity_refresh_adopts_only_operation_journaled_replacements(fixture):
    fixture.phase = "tls-recovery"
    fixture.namespace_uid = "owned-namespace-uid"
    old_pvc = {"name": "data-db-0", "uid": "old-pvc", "volume_name": "old-pv", "pv": {
        "name": "old-pv", "uid": "old-pv-uid", "reclaim_policy": "Retain",
        "claim_ref": {"namespace": fixture.namespace, "name": "data-db-0", "uid": "old-pvc"},
    }}
    new_claim = {
        "metadata": {"name": "data-db-0", "uid": "new-pvc", "labels": {"crdb-library-run": fixture.run_id}},
        "spec": {"volumeName": "new-pv"},
    }
    new_pv = {
        "metadata": {"name": "new-pv", "uid": "new-pv-uid"},
        "spec": {"persistentVolumeReclaimPolicy": "Delete", "claimRef": {
            "namespace": fixture.namespace, "name": "data-db-0", "uid": "new-pvc",
        }},
    }
    fixture.created.update({
        ("statefulset", "db"): "old-sts",
        ("persistentvolumeclaim", "data-db-0"): "old-pvc",
        ("persistentvolume", "old-pv"): "old-pv-uid",
    })
    fixture.phase_data = {
        "initial_resource_uids": {"statefulset/db": "old-sts"},
        "storage_identity_history": [{"stage": "before", "claims": [old_pvc]}],
        "target_resource_history": [
            {"action": "delete", "state": "requested", "kind": "statefulset", "name": "db", "uid": "old-sts"},
            {"action": "delete", "state": "requested", "kind": "persistentvolumeclaim", "name": "data-db-0", "uid": "old-pvc"},
            {"action": "create", "state": "created", "kind": "statefulset", "name": "db", "uid": "new-sts"},
        ],
    }

    def get(kind, name=None, **_kwargs):
        if kind == "statefulset":
            return {"metadata": {"name": "db", "uid": "new-sts", "labels": {"crdb-library-run": fixture.run_id}}}
        if kind == "persistentvolumeclaims":
            return {"items": [new_claim]}
        if kind == "persistentvolume" and name == "new-pv":
            return new_pv
        return {}

    fixture.get = get
    fixture._checkpoint = lambda _status: None

    fixture._refresh_recovery_identities_for_cleanup()

    assert fixture.created[("statefulset", "db")] == "new-sts"
    assert fixture.created[("persistentvolumeclaim", "data-db-0")] == "new-pvc"
    assert fixture.created[("persistentvolume", "new-pv")] == "new-pv-uid"


def test_recovery_identity_refresh_rejects_unjournaled_statefulset_replacement(fixture):
    fixture.phase = "tls-recovery"
    fixture.namespace_uid = "owned-namespace-uid"
    fixture.created[("statefulset", "db")] = "old-sts"
    fixture.phase_data = {"initial_resource_uids": {"statefulset/db": "old-sts"}}
    fixture.get = lambda kind, *_args, **_kwargs: {
        "metadata": {"name": "db", "uid": "foreign-sts", "labels": {"crdb-library-run": fixture.run_id}}
    } if kind == "statefulset" else {}
    with pytest.raises(HARNESS._BASE.SmokeFailure, match="unjournaled StatefulSet replacement"):
        fixture._refresh_recovery_identities_for_cleanup()


def test_recovery_pv_cleanup_uses_only_recorded_uids_and_claim_references(fixture):
    fixture.phase = "tls-recovery"
    fixture.phase_data = {
        "storage_identity_history": [
            {"stage": "before", "claims": [
                {"name": "data-db-0", "uid": "old-pvc", "pv": {
                    "name": "old-pv", "uid": "old-pv-uid", "claim_ref": {
                        "namespace": fixture.namespace, "name": "data-db-0", "uid": "old-pvc",
                    },
                }},
            ]},
            {"stage": "after", "claims": [
                {"name": "data-db-0", "uid": "new-pvc", "pv": {
                    "name": "new-pv", "uid": "new-pv-uid", "claim_ref": {
                        "namespace": fixture.namespace, "name": "data-db-0", "uid": "new-pvc",
                    },
                }},
            ]},
        ],
    }
    current_pvs = {
        "old-pv": {"metadata": {"uid": "old-pv-uid"}, "spec": {"claimRef": {
            "namespace": fixture.namespace, "name": "data-db-0", "uid": "old-pvc",
        }}},
        "new-pv": {"metadata": {"uid": "new-pv-uid"}, "spec": {"claimRef": {
            "namespace": fixture.namespace, "name": "data-db-0", "uid": "new-pvc",
        }}},
    }
    fixture.get = lambda kind, name=None, **_kwargs: (
        current_pvs.get(name, {}) if kind == "persistentvolume"
        else {"items": []} if kind == "endpointslices"
        else {}
    )
    deleted = []
    fixture.raw_delete_uid = lambda kind, name, uid, **_kwargs: deleted.append((kind, name, uid))
    fixture.wait_absent = lambda *_args, **_kwargs: None
    fixture._checkpoint = lambda _status: None

    fixture.cleanup_additional_resources()

    assert deleted == [
        ("persistentvolume", "old-pv", "old-pv-uid"),
        ("persistentvolume", "new-pv", "new-pv-uid"),
    ]


def test_recovery_pv_cleanup_refuses_unrecorded_claim_reference(fixture):
    fixture.phase = "tls-recovery"
    fixture.phase_data = {"storage_identity_history": [{"stage": "before", "claims": [{
        "name": "data-db-0", "uid": "owned-pvc", "pv": {
            "name": "owned-pv", "uid": "owned-pv-uid", "claim_ref": {
                "namespace": fixture.namespace, "name": "data-db-0", "uid": "owned-pvc",
            },
        },
    }]}]}
    current = {"metadata": {"uid": "owned-pv-uid"}, "spec": {"claimRef": {
        "namespace": fixture.namespace, "name": "data-db-0", "uid": "foreign-pvc",
    }}}
    fixture.get = lambda kind, name=None, **_kwargs: current if kind == "persistentvolume" else (
        {"items": []} if kind == "endpointslices" else {}
    )
    deleted = []
    fixture.raw_delete_uid = lambda *args, **_kwargs: deleted.append(args)
    fixture._checkpoint = lambda _status: None
    with pytest.raises(HARNESS._BASE.SmokeFailure, match="PV changed ownership"):
        fixture.cleanup_additional_resources()
    assert deleted == []


def test_partial_create_cleanup_deletes_only_recorded_run_owned_resources(fixture):
    fixture.created.update({
        ("service", "db-public"): "public-uid",
        ("rolebinding", "db-rolebinding"): "binding-uid",
        ("role", "db-role"): "role-uid",
        ("serviceaccount", "db-sa"): "sa-uid",
    })
    deleted = []
    fixture.get = lambda kind, name=None, **_kwargs: {
        "metadata": {
            "uid": fixture.created[(kind, name)],
            "labels": {"crdb-library-run": fixture.run_id},
        }
    } if (kind, name) in fixture.created else ({"items": []} if kind == "endpointslices" else {})
    fixture.raw_delete_uid = lambda kind, name, uid, **_kwargs: deleted.append((kind, name, uid))
    fixture._delete_rbac_uid = lambda kind, name, uid: deleted.append((kind, name, uid))
    fixture.wait_absent = lambda *_args, **_kwargs: None
    fixture._checkpoint = lambda _status: None

    fixture.cleanup_additional_resources()

    assert deleted == [
        ("service", "db-public", "public-uid"),
        ("rolebinding", "db-rolebinding", "binding-uid"),
        ("role", "db-role", "role-uid"),
        ("serviceaccount", "db-sa", "sa-uid"),
    ]


def test_rbac_cleanup_uses_exact_uid_delete_options_and_namespaced_api_endpoint(fixture, monkeypatch):
    observed = {}

    def fake_run(command, **kwargs):
        observed["command"] = command
        observed["input"] = json.loads(kwargs["input_text"])
        return "{}"

    monkeypatch.setattr(HARNESS._BASE, "run", fake_run)
    fixture._delete_rbac_uid("rolebinding", "db-rolebinding", "owned-binding-uid")
    endpoint = (
        "--raw=/apis/rbac.authorization.k8s.io/v1/namespaces/"
        + fixture.namespace
        + "/rolebindings/db-rolebinding"
    )
    assert endpoint in observed["command"]
    assert observed["input"]["kind"] == "DeleteOptions"
    assert observed["input"]["preconditions"]["uid"] == "owned-binding-uid"


def test_partial_create_cleanup_refuses_a_replaced_resource_before_delete(fixture):
    fixture.created[("serviceaccount", "db-sa")] = "owned-sa-uid"
    fixture.get = lambda kind, name=None, **_kwargs: {
        "metadata": {
            "uid": "replacement-uid",
            "labels": {"crdb-library-run": fixture.run_id},
        }
    }
    deleted = []
    fixture._delete_rbac_uid = lambda *args: deleted.append(args)
    with pytest.raises(HARNESS._BASE.SmokeFailure, match="identity or ownership changed"):
        fixture.cleanup_additional_resources()
    assert deleted == []


def test_restart_uses_current_owned_uid_and_waits_for_a_different_pod(fixture, monkeypatch):
    original = {"metadata": {"uid": "old-uid", "labels": {"crdb-library-run": fixture.run_id}}}
    fixture.get = lambda *_args, **_kwargs: original
    deleted = []
    fixture.raw_delete_uid = lambda *args, **_kwargs: deleted.append(args)
    replacement = {"metadata": {"uid": "new-uid"}}
    monkeypatch.setattr(HARNESS, "_wait_for_replacement_pod", lambda *_args, **_kwargs: replacement)

    result = HARNESS._restart_pod_with_uid_guard(fixture, expected_uid="old-uid")

    assert result == ("old-uid", "new-uid")
    assert deleted == [("pod", "db-0", "old-uid")]


def test_restart_refuses_a_stale_uid_or_foreign_pod_without_deleting(fixture):
    fixture.get = lambda *_args, **_kwargs: {
        "metadata": {"uid": "replacement", "labels": {"crdb-library-run": fixture.run_id}}
    }
    deleted = []
    fixture.raw_delete_uid = lambda *args, **_kwargs: deleted.append(args)
    with pytest.raises(HARNESS._BASE.SmokeFailure, match="identity changed"):
        HARNESS._restart_pod_with_uid_guard(fixture, expected_uid="stale")
    assert deleted == []

    fixture.get = lambda *_args, **_kwargs: {
        "metadata": {"uid": "foreign", "labels": {"crdb-library-run": "other-run"}}
    }
    with pytest.raises(HARNESS._BASE.SmokeFailure, match="not owned"):
        HARNESS._restart_pod_with_uid_guard(fixture)
    assert deleted == []


def test_case_environment_restores_values_and_configures_requested_setting(fixture, monkeypatch):
    monkeypatch.setenv("BENCH_NAMESPACE", "caller-namespace")
    monkeypatch.delenv("BENCH_PARAM_SETTING_VALUE", raising=False)
    with HARNESS.case_environment(fixture.namespace, setting_value="256MiB"):
        assert HARNESS.os.environ["BENCH_NAMESPACE"] == fixture.namespace
        assert HARNESS.os.environ["BENCH_PARAM_CLUSTER_NAME"] == "db"
        assert HARNESS.os.environ["BENCH_PARAM_SETTING_NAME"] == HARNESS._SETTING_NAME
        assert HARNESS.os.environ["BENCH_PARAM_SETTING_VALUE"] == "256MiB"
    assert HARNESS.os.environ["BENCH_NAMESPACE"] == "caller-namespace"
    assert "BENCH_PARAM_SETTING_VALUE" not in HARNESS.os.environ


def test_namespace_cleanup_audit_includes_roles_and_rolebindings(fixture):
    fixture.get = lambda kind, **_kwargs: {
        "items": [{"metadata": {"name": kind, "uid": f"uid-{kind}"}}]
    }
    identities = fixture._namespace_resource_identities()
    assert ("roles", "roles", "uid-roles") in identities
    assert ("rolebindings", "rolebindings", "uid-rolebindings") in identities


def test_case_command_runs_real_script_with_current_interpreter_and_case_environment(fixture, monkeypatch):
    observed = {}

    def fake_run(command, **kwargs):
        observed["command"] = command
        observed["namespace"] = HARNESS.os.environ.get("BENCH_NAMESPACE")
        observed["setting"] = HARNESS.os.environ.get("BENCH_PARAM_SETTING_VALUE")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(HARNESS.subprocess, "run", fake_run)
    result = HARNESS.run_case_command(fixture, "apply", timeout=4, setting_value="64MiB")
    assert result["outcome"] == "passed"
    assert observed["command"] == [HARNESS.sys.executable, str(HARNESS.TARGET_PATH), "apply"]
    assert observed["namespace"] == fixture.namespace
    assert observed["setting"] == "64MiB"


def test_main_builds_fixtures_with_explicit_current_context_and_no_live_calls(tmp_path, monkeypatch):
    constructed = []

    def fake_phase(args, name, run_id, _evidence_dir):
        fixture = HARNESS.SettingsFixture(args, name, run_id)
        constructed.append((name, fixture.namespace, args.context))
        return {"namespace": fixture.namespace}

    monkeypatch.setattr(HARNESS, "phase", fake_phase)
    evidence = tmp_path / "settings-smoke"
    result = HARNESS.main(["--evidence-dir", str(evidence)])

    assert result == 0
    assert [name for name, _namespace, _context in constructed] == ["insecure", "tls", "fresh-create"]
    assert all(context is None for _name, _namespace, context in constructed)
    assert all(namespace.startswith("karma-crdb-library-") for _name, namespace, _context in constructed)
    assert (evidence / "live-summary.json").exists()


def test_main_opt_in_runs_only_the_tls_recovery_phase(tmp_path, monkeypatch):
    phases = []
    monkeypatch.setattr(
        HARNESS,
        "phase",
        lambda _args, name, run_id, _evidence: phases.append(name) or {
            "phase": name,
            "namespace": f"karma-crdb-library-{run_id}-{name}",
        },
    )
    evidence = tmp_path / "recovery-smoke"

    result = HARNESS.main(["--evidence-dir", str(evidence), "--proof-mode", "tls-recovery"])

    assert result == 0
    assert phases == ["tls-recovery"]
    summary = json.loads((evidence / "live-summary.json").read_text(encoding="utf-8"))
    assert [phase["phase"] for phase in summary["phases"]] == ["tls-recovery"]


def test_main_observer_compat_mode_runs_only_the_new_opt_in_phase(tmp_path, monkeypatch):
    phases = []
    monkeypatch.setattr(
        HARNESS,
        "phase",
        lambda _args, name, run_id, _evidence: phases.append(name) or {
            "phase": name,
            "namespace": f"karma-crdb-library-{run_id}-{name}",
        },
    )
    evidence = tmp_path / "observer-compat-smoke"

    result = HARNESS.main([
        "--evidence-dir", str(evidence), "--proof-mode", "observer-compat",
    ])

    assert result == 0
    assert phases == ["observer-compat"]
    summary = json.loads((evidence / "live-summary.json").read_text(encoding="utf-8"))
    assert [phase["phase"] for phase in summary["phases"]] == ["observer-compat"]


def test_main_oracle_rebind_mode_runs_only_its_opt_in_phase(tmp_path, monkeypatch):
    phases = []
    monkeypatch.setattr(
        HARNESS,
        "phase",
        lambda _args, name, run_id, _evidence: phases.append(name) or {
            "phase": name,
            "namespace": f"karma-crdb-library-{run_id}-{name}",
        },
    )
    evidence = tmp_path / "oracle-rebind-smoke"

    result = HARNESS.main([
        "--evidence-dir", str(evidence), "--proof-mode", "oracle-rebind",
    ])

    assert result == 0
    assert phases == ["oracle-rebind"]
    summary = json.loads((evidence / "live-summary.json").read_text(encoding="utf-8"))
    assert [phase["phase"] for phase in summary["phases"]] == ["oracle-rebind"]


def test_main_oracle_sql_connection_mode_runs_only_its_opt_in_phase(tmp_path, monkeypatch):
    phases = []
    monkeypatch.setattr(
        HARNESS,
        "phase",
        lambda _args, name, run_id, _evidence: phases.append(name) or {
            "phase": name,
            "namespace": f"karma-crdb-library-{run_id}-{name}",
        },
    )
    evidence = tmp_path / "oracle-sql-connection-smoke"

    result = HARNESS.main([
        "--evidence-dir", str(evidence), "--proof-mode", "oracle-sql-connection",
    ])

    assert result == 0
    assert phases == ["oracle-sql-connection"]
    summary = json.loads((evidence / "live-summary.json").read_text(encoding="utf-8"))
    assert [phase["phase"] for phase in summary["phases"]] == ["oracle-sql-connection"]


def test_main_tls_transform_mode_runs_only_the_component_phase(tmp_path, monkeypatch):
    phases = []
    monkeypatch.setattr(
        HARNESS,
        "phase",
        lambda _args, name, run_id, _evidence: phases.append(name) or {
            "phase": name,
            "namespace": f"karma-crdb-library-{run_id}-{name}",
        },
    )
    evidence = tmp_path / "tls-transform-smoke"

    result = HARNESS.main([
        "--evidence-dir", str(evidence), "--proof-mode", "tls-transform",
    ])

    assert result == 0
    assert phases == ["tls-transform"]
    summary = json.loads((evidence / "live-summary.json").read_text(encoding="utf-8"))
    assert [phase["phase"] for phase in summary["phases"]] == ["tls-transform"]


def test_main_service_preservation_mode_runs_only_its_opt_in_phase(tmp_path, monkeypatch):
    phases = []
    monkeypatch.setattr(
        HARNESS,
        "phase",
        lambda _args, name, run_id, _evidence: phases.append(name) or {
            "phase": name,
            "namespace": f"karma-crdb-library-{run_id}-{name}",
        },
    )
    evidence = tmp_path / "tls-service-preservation-smoke"

    result = HARNESS.main([
        "--evidence-dir", str(evidence), "--proof-mode", "tls-service-preservation",
    ])

    assert result == 0
    assert phases == ["tls-service-preservation"]
    summary = json.loads((evidence / "live-summary.json").read_text(encoding="utf-8"))
    assert [phase["phase"] for phase in summary["phases"]] == ["tls-service-preservation"]


@pytest.mark.parametrize(
    ("phase_name", "exercise_name"),
    [
        ("tls-recovery", "_exercise_tls_recovery_phase"),
        ("observer-compat", "_exercise_observer_compat_phase"),
        ("oracle-rebind", "_exercise_observer_compat_phase"),
        ("oracle-sql-connection", "_exercise_observer_compat_phase"),
        ("tls-transform", "_exercise_tls_transform_component"),
        ("tls-service-preservation", "_exercise_tls_transform_component"),
    ],
)
def test_phase_journals_safe_typed_failure_and_stage_before_cleanup(
    tmp_path, monkeypatch, phase_name, exercise_name
):
    class FakePhaseFixture:
        def __init__(self, _args, name, run_id):
            self.namespace = f"karma-crdb-library-{run_id}-{name}"
            self.namespace_uid = "namespace-uid"
            self.namespace_baseline = set()
            self.created = {}
            self.command_trace = []
            self.current_stage = "created"

        def set_stage(self, value):
            self.current_stage = value

        def stage_snapshot(self):
            return {
                "current_stage": self.current_stage,
                "completed_stages": [],
                "total_elapsed_ms": 7,
            }

        def prepare_namespace(self):
            self.namespace_uid = "namespace-uid"

        def service_manifest(self):
            return {"kind": "Service", "metadata": {"name": "db"}}

        def public_service_manifest(self):
            return {"kind": "Service", "metadata": {"name": "db-public"}}

        def statefulset_manifest(self, **_kwargs):
            return {"kind": "StatefulSet", "metadata": {"name": "db"}}

        def create(self, document):
            kind = document["kind"].lower()
            name = document["metadata"]["name"]
            self.created[(kind, name)] = f"{kind}-{name}-uid"

        def make_secret(self, *_args):
            self.created[("secret", "db-certs")] = "secret-uid"

        def capture_diagnostics(self, phase_data, *, label):
            phase_data.setdefault("runtime_diagnostics", {})[label] = {
                "stage": self.current_stage,
            }

        def cleanup(self):
            self.set_stage("uid-guarded-cleanup")

    exercise_kwargs = {}

    def fail_in_case_apply(_args, fixture, _phase_data=None, **kwargs):
        exercise_kwargs.update(kwargs)
        fixture.set_stage("case-bounded-tls-restart-recreate-init")
        raise KubernetesAccessError(
            "Kubernetes API rejected operation; token=diagnostic-secret-sentinel"
        )

    monkeypatch.setattr(HARNESS, "SettingsFixture", FakePhaseFixture)
    monkeypatch.setattr(HARNESS._BASE, "preflight", lambda *_args: {"storage_class": "standard"})
    monkeypatch.setattr(HARNESS._BASE, "make_certificates", lambda *_args: None)
    monkeypatch.setattr(HARNESS, exercise_name, fail_in_case_apply)
    evidence = tmp_path / "phase-failure"
    evidence.mkdir()

    with pytest.raises(HARNESS._BASE.SmokeFailure):
        HARNESS.phase(SimpleNamespace(), phase_name, "261020-abc", evidence)

    result = json.loads((evidence / f"{phase_name}-phase.json").read_text(encoding="utf-8"))
    assert result["execution_failure"]["type"] == "KubernetesAccessError"
    assert "Kubernetes API rejected operation" in result["execution_failure"]["detail"]
    assert "diagnostic-secret-sentinel" not in json.dumps(result)
    assert result["failure_stage"]["current_stage"] == "case-bounded-tls-restart-recreate-init"
    assert result["failure_stage"]["total_elapsed_ms"] == 7
    assert result["cleanup_verdict"] == "completed with UID preconditions and normal deletion"
    if phase_name == "oracle-rebind":
        assert exercise_kwargs == {"oracle_rebind": True, "oracle_sql_connection": False}
    elif phase_name == "oracle-sql-connection":
        assert exercise_kwargs == {"oracle_rebind": False, "oracle_sql_connection": True}
    if phase_name == "tls-service-preservation":
        assert exercise_kwargs == {"service_preservation": True}


@pytest.mark.parametrize(
    ("phase_name", "expected_kwargs"),
    [
        ("tls-transform", {}),
        ("tls-service-preservation", {"service_preservation": True}),
    ],
)
def test_tls_transform_phase_creates_fixture_then_calls_only_component(
    monkeypatch, tmp_path, phase_name, expected_kwargs
):
    events = []

    class FakePhaseFixture:
        def __init__(self, _args, name, run_id):
            self.phase = name
            self.namespace = f"karma-crdb-library-{run_id}-{name}"
            self.namespace_uid = "namespace-uid"
            self.namespace_baseline = set()
            self.created = {}
            self.command_trace = []
            self.stage = "created"
            self.run_id = run_id

        def set_stage(self, value):
            self.stage = value
            events.append(("stage", value))

        def stage_snapshot(self):
            return {"current_stage": self.stage, "completed_stages": [], "total_elapsed_ms": 1}

        def prepare_namespace(self):
            events.append(("namespace", self.namespace))

        def service_manifest(self):
            return {"kind": "Service", "metadata": {"name": "db"}}

        def public_service_manifest(self):
            return {"kind": "Service", "metadata": {"name": "db-public"}}

        def statefulset_manifest(self, *, tls):
            return {"kind": "StatefulSet", "metadata": {"name": "db"}, "tls": tls}

        def create(self, resource):
            identity = (resource["kind"].lower(), resource["metadata"]["name"])
            events.append(("create", *identity, resource.get("tls")))
            self.created[identity] = f"{identity[0]}-{identity[1]}-uid"

        def make_secret(self, _cert_dir):
            events.append(("secret", "db-certs"))
            self.created[("secret", "db-certs")] = "secret-uid"

        def capture_diagnostics(self, _phase_data, *, label):
            events.append(("diagnostics", label))

        def cleanup(self):
            events.append(("cleanup",))

    calls = []

    def exercise(args, selected_fixture, phase_data, **kwargs):
        calls.append((args, selected_fixture, phase_data, kwargs))
        selected_fixture.set_stage("component-proof")
        return {"tls_transform_component": {"scope": "component-only", "task_oracle": "not run"}}

    monkeypatch.setattr(HARNESS, "SettingsFixture", FakePhaseFixture)
    monkeypatch.setattr(HARNESS._BASE, "preflight", lambda *_args: {"storage_class": "standard"})
    monkeypatch.setattr(HARNESS._BASE, "make_certificates", lambda *_args: None)
    monkeypatch.setattr(HARNESS, "_exercise_tls_transform_component", exercise)
    evidence = tmp_path / "tls-transform-phase"
    evidence.mkdir()

    result = HARNESS.phase(SimpleNamespace(kubectl="kubectl"), phase_name, "261020-abc", evidence)

    assert [event for event in events if event[0] == "create"] == [
        ("create", "service", "db", None),
        ("create", "service", "db-public", None),
        ("create", "statefulset", "db", False),
    ]
    assert ("secret", "db-certs") in events
    assert len(calls) == 1
    assert calls[0][3] == expected_kwargs
    assert events[-1] == ("cleanup",)
    assert result["result"] == "passed"
    recorded = json.loads((evidence / f"{phase_name}-phase.json").read_text(encoding="utf-8"))
    assert recorded["tls_transform_component"]["task_oracle"] == "not run"


def test_secure_target_service_cli_builds_check_and_render_commands(fixture, monkeypatch, tmp_path):
    fixture._record_command = Mock()
    fixture.set_stage = Mock()
    calls = []

    def fake_run(command, **_kwargs):
        calls.append(command)
        if "service-check" in command:
            return subprocess.CompletedProcess(command, 4, "", "")
        return subprocess.CompletedProcess(
            command, 0, "apiVersion: v1\nkind: Service\nmetadata:\n  name: db\n", ""
        )

    monkeypatch.setattr(HARNESS.subprocess, "run", fake_run)
    plan_path = tmp_path / "plan.json"
    rendered_path = tmp_path / "rendered.yaml"

    checked = HARNESS._run_secure_target_component(
        fixture, "service-check", plan_path, service_name="db", expected_status=4
    )
    rendered = HARNESS._run_secure_target_component(
        fixture,
        "render-service",
        plan_path,
        service_name="db",
        services_manifest=HARNESS.CASE_SERVICES_MANIFEST,
        cluster_name="db",
        output_path=rendered_path,
    )

    assert checked["returncode"] == checked["expected_returncode"] == 4
    assert calls[0][2] == "service-check"
    assert calls[0][calls[0].index("--service") + 1] == "db"
    assert calls[1][2] == "render-service"
    assert calls[1][calls[1].index("--services-manifest") + 1] == str(HARNESS.CASE_SERVICES_MANIFEST)
    assert calls[1][calls[1].index("--cluster-name") + 1] == "db"
    assert rendered_path.read_text(encoding="utf-8").startswith("apiVersion: v1\nkind: Service")
    assert rendered["returncode"] == 0


def test_scaled_service_preservation_faults_and_repairs_only_headless_service(monkeypatch, tmp_path):
    labels = {"app.kubernetes.io/name": "cockroachdb", "app.kubernetes.io/instance": "db"}
    headless = {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": "db", "namespace": "bench", "uid": "headless-uid", "resourceVersion": "11"},
        "spec": {
            "clusterIP": "None", "publishNotReadyAddresses": True, "selector": labels,
            "ports": [
                {"name": "sql", "port": 26257, "targetPort": "sql", "protocol": "TCP"},
                {"name": "rpc", "port": 26258, "targetPort": "rpc", "protocol": "TCP"},
                {"name": "http", "port": 8080, "targetPort": "http", "protocol": "TCP"},
            ],
        },
    }
    public = {
        "metadata": {"name": "db-public", "namespace": "bench", "uid": "public-uid", "resourceVersion": "17"},
        "spec": {
            "type": "NodePort", "selector": labels,
            "ports": [
                {"name": "sql", "port": 26257, "targetPort": "sql", "nodePort": 31001, "protocol": "TCP"},
                {"name": "rpc", "port": 26258, "targetPort": "rpc", "nodePort": 31002, "protocol": "TCP"},
                {"name": "http", "port": 8080, "targetPort": "http", "nodePort": 31003, "protocol": "TCP"},
            ],
        },
    }
    static_headless = copy.deepcopy(headless)
    static_headless["metadata"]["labels"] = {
        "app.kubernetes.io/name": "cockroachdb",
        "app.kubernetes.io/instance": "db",
        "app.kubernetes.io/component": "database",
    }
    static_headless["spec"]["selector"] = {
        "app.kubernetes.io/name": "cockroachdb",
        "app.kubernetes.io/instance": "db",
    }
    static_headless["spec"]["ports"] = [
        {"name": "grpc", "port": 26257, "targetPort": 26257, "protocol": "TCP"},
        {"name": "http", "port": 8080, "targetPort": 8080, "protocol": "TCP"},
    ]

    class FakeServiceFixture:
        namespace = "bench"
        run_id = "fixture-run"
        args = SimpleNamespace(kubectl="kubectl")

        def __init__(self):
            self.services = {"db": copy.deepcopy(headless), "db-public": copy.deepcopy(public)}
            self.commands = []
            self.stages = []

        def _checkpoint(self, stage):
            self.stages.append(stage)

        def set_stage(self, stage):
            self.stages.append(stage)

        def get(self, kind, name):
            assert kind == "service"
            return copy.deepcopy(self.services[name])

        def kubectl(self, *argv, namespace=None, timeout=30):
            self.commands.append((argv, namespace, timeout))
            if argv[0] == "patch":
                name = argv[2]
                current = self.services[name]
                patch = json.loads(argv[argv.index("--patch") + 1])
                assert patch[0] == {"op": "test", "path": "/metadata/uid", "value": current["metadata"]["uid"]}
                assert patch[1] == {"op": "test", "path": "/metadata/resourceVersion", "value": current["metadata"]["resourceVersion"]}
                port_index = int(patch[2]["path"].split("/")[-2])
                current["spec"]["ports"][port_index]["targetPort"] = patch[2]["value"]
                current["metadata"]["resourceVersion"] = "12"
                return ""
            if argv[0] == "apply":
                import yaml
                rendered = Path(argv[argv.index("--filename") + 1])
                document = yaml.safe_load(rendered.read_text(encoding="utf-8"))
                current = self.services["db"]
                uid = current["metadata"]["uid"]
                prior_metadata = copy.deepcopy(current.get("metadata", {}))
                current.update(document)
                current["metadata"] = {**prior_metadata, **document.get("metadata", {})}
                current["metadata"]["uid"] = uid
                current["metadata"]["resourceVersion"] = "13"
                return ""
            raise AssertionError(f"unexpected kubectl call: {argv}")

    fake_fixture = FakeServiceFixture()
    checks = []

    def fake_component(selected_fixture, mode, _plan_path, **kwargs):
        if mode == "service-check":
            service_name = kwargs["service_name"]
            service = selected_fixture.services[service_name]
            target = next(item["targetPort"] for item in service["spec"]["ports"] if item["port"] == 26257)
            actual_status = 0 if target in {"sql", 26257} else 4
            assert actual_status == kwargs["expected_status"]
            checks.append((service_name, actual_status))
            return {"operation": mode, "returncode": actual_status, "expected_returncode": actual_status}
        if mode == "render-service":
            kwargs["output_path"].write_text(HARNESS.yaml.safe_dump(static_headless), encoding="utf-8")
            return {"operation": mode, "returncode": 0}
        raise AssertionError(mode)

    monkeypatch.setattr(HARNESS, "_run_secure_target_component", fake_component)
    phase_data = {}
    result = HARNESS._exercise_scaled_service_preservation(
        fake_fixture,
        tmp_path / "plan.json",
        public_service_before=copy.deepcopy(public),
        headless_service_before=copy.deepcopy(headless),
        phase_data=phase_data,
    )

    assert checks == [("db", 4), ("db-public", 0), ("db", 0), ("db-public", 0)]
    assert [call[0][0] for call in fake_fixture.commands] == ["patch", "apply"]
    assert fake_fixture.services["db"]["metadata"]["uid"] == "headless-uid"
    assert fake_fixture.services["db"]["spec"] == static_headless["spec"]
    assert fake_fixture.services["db"]["metadata"]["labels"]["crdb-library-run"] == "fixture-run"
    assert fake_fixture.services["db-public"] == public
    assert result["headless_sql_target_injected"] == 26256
    assert result["headless_repaired"]["uid"] == "headless-uid"
    assert result["original_case_service_spec_applied"] is True
    assert result["harness_ownership_metadata_added"] is True
    assert phase_data["service_preservation"]["rendered_case_service_spec_sha256"] == HARNESS._sha256_json(static_headless["spec"])
    assert phase_data["service_preservation"]["applied_document_delta"] == (
        "harness ownership label in metadata only; Service spec unchanged"
    )
    assert result["public_service_before"]["spec_sha256"] == result["public_service_after"]["spec_sha256"]
    assert result["extra_rpc_port_removal_assumed"] is False


def test_tls_service_preservation_projection_accepts_only_headless_spec_delta():
    before_services = {
        "db": {"uid": "headless-uid", "spec_sha256": "headless-before"},
        "db-public": {"uid": "public-uid", "spec_sha256": "public-spec"},
    }
    after_services = {
        "db": {"uid": "headless-uid", "spec_sha256": "headless-repaired"},
        "db-public": {"uid": "public-uid", "spec_sha256": "public-spec"},
    }
    before_routing = (
        ("db", "headless-uid", "headless-routing-before"),
        ("db-public", "public-uid", "public-routing"),
    )
    after_routing = (
        ("db", "headless-uid", "headless-routing-repaired"),
        ("db-public", "public-uid", "public-routing"),
    )
    repair = {
        "headless_repaired": {"uid": "headless-uid", "spec_sha256": "headless-repaired"},
        "checks_after_repair": {"headless": {"returncode": 0}, "public": {"returncode": 0}},
    }

    projection = HARNESS._assert_service_preservation_projection(
        before_services, after_services, before_routing, after_routing, repair
    )

    assert projection == {
        "headless_uid_preserved": True,
        "headless_spec_changed_by_original_repair": True,
        "public_service_identity_and_spec_preserved": True,
        "public_routing_preserved": True,
        "headless_routing_hash_before_after": [
            "headless-routing-before", "headless-routing-repaired",
        ],
    }


@pytest.mark.parametrize("drift", ["public_spec", "headless_uid", "extra_service", "public_route"])
def test_tls_service_preservation_projection_rejects_unplanned_service_drift(drift):
    before_services = {
        "db": {"uid": "headless-uid", "spec_sha256": "headless-before"},
        "db-public": {"uid": "public-uid", "spec_sha256": "public-spec"},
    }
    after_services = {
        "db": {"uid": "headless-uid", "spec_sha256": "headless-repaired"},
        "db-public": {"uid": "public-uid", "spec_sha256": "public-spec"},
    }
    before_routing = (
        ("db", "headless-uid", "headless-routing-before"),
        ("db-public", "public-uid", "public-routing"),
    )
    after_routing = (
        ("db", "headless-uid", "headless-routing-repaired"),
        ("db-public", "public-uid", "public-routing"),
    )
    repair = {
        "headless_repaired": {"uid": "headless-uid", "spec_sha256": "headless-repaired"},
        "checks_after_repair": {"headless": {"returncode": 0}, "public": {"returncode": 0}},
    }
    if drift == "public_spec":
        after_services["db-public"]["spec_sha256"] = "unexpected-public-spec"
    elif drift == "headless_uid":
        after_services["db"]["uid"] = "replacement-headless-uid"
    elif drift == "extra_service":
        after_services["unexpected"] = {"uid": "other-uid", "spec_sha256": "other-spec"}
    else:
        after_routing = (
            after_routing[0],
            ("db-public", "public-uid", "unexpected-public-routing"),
        )

    with pytest.raises(HARNESS._BASE.SmokeFailure):
        HARNESS._assert_service_preservation_projection(
            before_services, after_services, before_routing, after_routing, repair
        )


def test_secure_target_component_failure_keeps_only_sanitized_diagnostic(fixture, monkeypatch, tmp_path):
    fixture._record_command = Mock()

    def fake_run(command, **_kwargs):
        return subprocess.CompletedProcess(command, 1, "", "API rejected token=component-secret-sentinel")

    monkeypatch.setattr(HARNESS.subprocess, "run", fake_run)

    with pytest.raises(HARNESS._BASE.SmokeFailure) as raised:
        HARNESS._run_secure_target_component(
            fixture, "prepare", tmp_path / "private-plan.json"
        )

    assert "API rejected" in str(raised.value)
    assert "component-secret-sentinel" not in str(raised.value)
    event = raised.value.command_event
    assert event["operation"] == "certificate-rotation target component prepare"
    assert event["returncode"] == 1
    assert "command" not in event
    fixture._record_command.assert_called_once_with(event)


def test_oracle_rebind_uses_one_check_function_and_observes_replacement_binding(fixture, monkeypatch):
    fixture.phase = "oracle-rebind"
    fixture.phase_data = {}
    fixture._checkpoint = Mock()
    fixture.set_stage = Mock()
    pod_uids = iter(("pod-before", "pod-after"))
    fixture.get = Mock(side_effect=lambda *_args, **_kwargs: {
        "metadata": {"uid": next(pod_uids), "labels": {"crdb-library-run": fixture.run_id}},
    })
    accepted = SimpleNamespace(state="accepted")
    verified = SimpleNamespace(status=HARNESS.ProbeStatus.SATISFIED)

    class FakeLibrary:
        def capture_accepted_state(self, *_args, **_kwargs):
            return accepted

        def verify_accepted_state(self, *_args, **_kwargs):
            return verified

    def connection(uid):
        return SimpleNamespace(
            workload_uid="sts-uid",
            pod_name="db-0",
            pod_uid=uid,
            container_name="db",
            image="cockroachdb/cockroach:v24.1.0",
            sql_binary="/cockroach/cockroach",
            sql_host="db-0.db.example.svc.cluster.local",
            sql_port=26258,
            tls_mode=HARNESS.TLSMode.TLS,
            certs_dir="/root/.cockroach-certs",
        )

    checks = []
    check_globals = {
        "connection_iterator": iter((connection("pod-before"), connection("pod-before"), connection("pod-after"))),
        "errors_by_phase": {
            "before configured setting change": [
                f"{HARNESS._SETTING_NAME} is '256MiB', expected '128MiB'"
            ],
            "after configured setting change": [],
            "after pod restart": [],
        },
        "checks": checks,
        "_SQL_CONNECTION": None,
    }
    exec(
        "def check(errors, phase):\n"
        "    checks.append(phase)\n"
        "    global _SQL_CONNECTION\n"
        "    _SQL_CONNECTION = next(connection_iterator)\n"
        "    errors.extend(errors_by_phase[phase])\n",
        check_globals,
    )
    oracle = {
        "check": check_globals["check"],
        "SETTING_NAME": HARNESS._SETTING_NAME,
        "values_match": lambda left, right: left.casefold() == right.casefold(),
    }
    loads = []
    monkeypatch.setattr(HARNESS, "_load_oracle", lambda *_args: loads.append(oracle) or oracle)
    readbacks = iter(("256MiB", "128MiB"))
    monkeypatch.setattr(HARNESS, "_observer_compat_setting_value", lambda *_args: next(readbacks))
    restarts = []
    monkeypatch.setattr(
        HARNESS,
        "_restart_pod_with_uid_guard",
        lambda _fixture, **kwargs: restarts.append(kwargs) or ("pod-before", "pod-after"),
    )
    monkeypatch.setattr(HARNESS, "_observer_compat_witness_hash", lambda _fixture: (2, "same-witness"))
    expected_connection = connection("pod-before")

    result = HARNESS._exercise_oracle_rebind(
        SimpleNamespace(restart_timeout=30),
        fixture,
        FakeLibrary(),
        "workload-ref",
        expected_connection=expected_connection,
        accepted_before=accepted,
        pod_uid_before="pod-before",
        witness_before=(2, "same-witness"),
    )

    assert loads == [oracle]
    assert checks == [
        "before configured setting change",
        "after configured setting change",
        "after pod restart",
    ]
    assert restarts == [{"expected_uid": "pod-before", "timeout": 30}]
    assert [row["binding"]["pod_uid"] for row in result["checks"]] == [
        "pod-before", "pod-before", "pod-after",
    ]
    assert [row["accepted"] for row in result["checks"]] == [False, True, True]
    assert result["checks"][0]["value_mismatch_reported"] is True
    assert result["single_oracle_check_function_reused"] is True
    assert result["oracle_main_invoked"] is False
    assert result["accepted_state_preserved"] is True
    assert result["witness_sha256_before_after"] == ["same-witness", "same-witness"]
    assert fixture._checkpoint.call_count >= 7


@pytest.mark.parametrize(
    ("wrong_error", "expected_failure"),
    [
        (
            f"{HARNESS._SETTING_NAME} is '256MiB', expected '128MiB'",
            "stale Pod binding",
        ),
        (
            f"Failed to read {HARNESS._SETTING_NAME}: connection refused",
            "did not reject the wrong value as a value mismatch",
        ),
    ],
)
def test_oracle_rebind_requires_value_mismatch_and_fresh_binding(
    fixture, monkeypatch, wrong_error, expected_failure
):
    fixture.phase_data = {}
    fixture._checkpoint = Mock()
    fixture.set_stage = Mock()

    class FakeLibrary:
        def capture_accepted_state(self, *_args, **_kwargs):
            return "accepted"

        def verify_accepted_state(self, *_args, **_kwargs):
            return SimpleNamespace(status=HARNESS.ProbeStatus.SATISFIED)

    def connection(uid):
        return SimpleNamespace(
            workload_uid="sts", pod_name="db-0", pod_uid=uid, container_name="db",
            image="v24.1.0", sql_binary="/cockroach/cockroach", sql_host="db-0", sql_port=26258,
            tls_mode=HARNESS.TLSMode.TLS, certs_dir="/root/.cockroach-certs",
        )
    connections = [connection("old"), connection("old"), connection("old")]
    check_globals = {
        "connections": iter(connections),
        "_SQL_CONNECTION": None,
        "errors_by_phase": {
            "before configured setting change": [wrong_error],
            "after configured setting change": [],
            "after pod restart": [],
        },
    }
    exec(
        "def check(errors, phase):\n"
        "    global _SQL_CONNECTION\n"
        "    _SQL_CONNECTION = next(connections)\n"
        "    errors.extend(errors_by_phase[phase])\n",
        check_globals,
    )
    oracle = {
        "check": check_globals["check"], "SETTING_NAME": HARNESS._SETTING_NAME,
        "values_match": lambda left, right: left.casefold() == right.casefold(),
    }
    monkeypatch.setattr(HARNESS, "_load_oracle", lambda *_args: oracle)
    readbacks = iter(("256MiB", "128MiB"))
    monkeypatch.setattr(HARNESS, "_observer_compat_setting_value", lambda *_args: next(readbacks))
    restarts = []
    monkeypatch.setattr(
        HARNESS,
        "_restart_pod_with_uid_guard",
        lambda *_args, **_kwargs: restarts.append(True) or ("old", "new"),
    )
    monkeypatch.setattr(HARNESS, "_observer_compat_witness_hash", lambda _fixture: (2, "same"))

    with pytest.raises(HARNESS._BASE.SmokeFailure, match=expected_failure):
        HARNESS._exercise_oracle_rebind(
            SimpleNamespace(restart_timeout=30),
            fixture,
            FakeLibrary(),
            "workload-ref",
            expected_connection=connection("old"),
            accepted_before="accepted",
            pod_uid_before="old",
            witness_before=(2, "same"),
        )
    rows = fixture.phase_data["oracle_rebind"]["checks"]
    wrong_value_row = rows[0]
    assert wrong_value_row["binding"]["pod_uid"] == "old"
    if "connection refused" in wrong_error:
        assert wrong_value_row["value_mismatch_reported"] is False
        assert restarts == []
    else:
        assert wrong_value_row["value_mismatch_reported"] is True
        assert restarts == [True]
        assert rows[-1]["label"] == "post-restart"
        assert rows[-1]["binding"]["pod_uid"] == "old"


def test_witness_hash_rejects_missing_or_changed_persisted_rows(fixture, monkeypatch):
    monkeypatch.setattr(
        HARNESS,
        "_run_sql",
        lambda *_args: "id,payload\n1,preserve across case setup\n2,preserve across pod restart\n",
    )
    count, digest = HARNESS._witness_hash(fixture, tls=False)
    assert count == 2
    assert len(digest) == 64

    monkeypatch.setattr(HARNESS, "_run_sql", lambda *_args: "id,payload\n1,preserve across case setup\n")
    with pytest.raises(HARNESS._BASE.SmokeFailure, match="two expected rows"):
        HARNESS._witness_hash(fixture, tls=False)


def test_target_value_selector_avoids_the_live_default():
    oracle = {"values_match": lambda left, right: left.casefold() == right.casefold()}
    assert HARNESS._choose_different_setting_value(oracle, "128MiB") == "256MiB"
    assert HARNESS._choose_different_setting_value(oracle, "64MiB") == "128MiB"


def test_existing_phase_checks_oracle_before_and_after_setting_and_restart(fixture, monkeypatch):
    accepted = SimpleNamespace(
        cluster_id="cluster-id",
        node_ids=(1,),
        sql_versions=(("db-0", "24.1.0"),),
        tls_mode=SimpleNamespace(value="TLS"),
        image="cockroachdb/cockroach:v24.1.0",
        desired_replicas=1,
        workload_spec_hash="full-spec-hash",
        pvc_identities=(("datadir-db-0", "pvc-uid", "pv", "claim", "Bound"),),
        certificate_fingerprints=(("secret", "db-certs", "node.crt", "fingerprint"),),
        service_routing=(("db", "db-0", "26257"),),
    )

    class FakeLibrary:
        def __init__(self):
            self.states = iter((accepted, accepted, accepted))

        def reconcile(self, *_args, **_kwargs):
            return SimpleNamespace(assessment=SimpleNamespace(status=HARNESS.ProbeStatus.SATISFIED))

        def capture_accepted_state(self, *_args, **_kwargs):
            return next(self.states)

        def verify_accepted_state(self, *_args, **_kwargs):
            return SimpleNamespace(status=HARNESS.ProbeStatus.SATISFIED)

    fixture.wait_ready = Mock()
    fixture.init = Mock()
    fixture.get = Mock(return_value={"metadata": {"uid": "old-pod", "labels": {"crdb-library-run": fixture.run_id}}})
    monkeypatch.setattr(HARNESS, "CrdbLibrary", lambda *_args: FakeLibrary())
    monkeypatch.setattr(HARNESS, "_run_sql", lambda *_args: "")
    monkeypatch.setattr(HARNESS, "_witness_hash", Mock(side_effect=[(2, "same-hash")] * 3))
    monkeypatch.setattr(HARNESS, "_load_oracle", lambda *_args: {
        "resolve_setting_name": lambda: HARNESS._SETTING_NAME,
        "get_setting": lambda: ("32MiB", None),
        "values_match": lambda left, right: left.casefold() == right.casefold(),
    })
    monkeypatch.setattr(HARNESS, "_oracle_check", lambda _fixture, _value, phase: (
        ["setting is 32MiB, expected '128MiB'"]
        if phase == "before controlled setting change" else []
    ))
    monkeypatch.setattr(HARNESS, "_restart_pod_with_uid_guard", lambda *_args, **_kwargs: ("old-pod", "new-pod"))
    commands = []
    monkeypatch.setattr(
        HARNESS,
        "run_case_command",
        lambda _fixture, mode, **_kwargs: commands.append(mode) or {"mode": mode},
    )

    result = HARNESS._exercise_existing_phase(
        SimpleNamespace(kubectl="kubectl", ready_timeout=30, restart_timeout=30), fixture, tls=True
    )

    assert fixture.wait_ready.call_args.kwargs == {"timeout": 30}
    assert fixture.init.call_args.args == (True,)
    assert commands == ["probe", "apply", "verify"]
    assert result["case_apply_noop"] is True
    assert result["oracle_rejected_before_change"] is True
    assert result["oracle_accepted_after_change"] is True
    assert result["oracle_accepted_after_restart"] is True
    assert result["pod_uid_before_after_restart"] == ["old-pod", "new-pod"]
    assert result["witness_sha256_before_after_apply_and_restart"] == ["same-hash"] * 3


def test_observer_compat_phase_requires_expected_observation_then_runs_real_case_command_sequence(
    fixture, monkeypatch
):
    pod = SimpleNamespace(uid="pod-uid")
    workload = SimpleNamespace(
        workload_uid="sts-uid",
        pods=(pod,),
        http_transport=SimpleNamespace(value="https"),
    )
    deployed = SimpleNamespace(
        status=HARNESS.ProbeStatus.SATISFIED,
        health=SimpleNamespace(lifecycle=HARNESS.Lifecycle.DEPLOYED),
        workload=workload,
    )
    initialized = SimpleNamespace(
        status=HARNESS.ProbeStatus.SATISFIED,
        workload=workload,
    )
    observed_connection = SimpleNamespace(
        workload_uid="sts-uid",
        tls_mode=HARNESS.TLSMode.TLS,
        certs_dir="/root/.cockroach-certs",
        sql_port=26258,
        rpc_port=26258,
    )
    accepted = SimpleNamespace(
        cluster_id="cluster-id",
        node_ids=(1,),
        sql_versions=(("db-0", "24.1.0"),),
        tls_mode=HARNESS.TLSMode.TLS,
        image="cockroachdb/cockroach:v24.1.0",
        desired_replicas=1,
        workload_spec_hash="full-workload-hash",
        pvc_identities=(("data-db-0", "pvc-uid", "pv-uid", "Bound", "pvc-spec"),),
        certificate_fingerprints=(("db-certs", "secret-uid", "node.crt", "fingerprint"),),
        service_routing=(("db", "service-uid", "routing-hash"),),
    )
    order = []

    class FakeLibrary:
        def __init__(self, *_args):
            pass

        def probe(self, _ref, requirement, **_kwargs):
            order.append(("probe", requirement.lifecycle))
            assert requirement.tls_mode is HARNESS.TLSMode.TLS
            return deployed

        def inspect_sql_connection(self, _ref, *, ordinal):
            order.append(("inspect-sql-connection", ordinal))
            return observed_connection

        def reconcile(self, _ref, requirement, **_kwargs):
            order.append(("reconcile", requirement.lifecycle))
            return SimpleNamespace(assessment=initialized)

        def probe_health_endpoint(self, _ref, *, path, **_kwargs):
            order.append(("health", path))
            return (("db-0", 200, True),)

        def capture_accepted_state(self, *_args, **_kwargs):
            return accepted

        def verify_accepted_state(self, *_args, **_kwargs):
            return initialized

    fixture.phase = "observer-compat"
    fixture.wait_ready = Mock()
    fixture.init = Mock(side_effect=lambda *, tls: order.append(("init", tls)))
    fixture._checkpoint = Mock()
    fixture.set_stage = Mock()
    monkeypatch.setattr(HARNESS, "CrdbLibrary", FakeLibrary)
    monkeypatch.setattr(HARNESS, "KubectlAdapter", lambda **_kwargs: object())
    monkeypatch.setattr(HARNESS, "_run_observer_compat_sql", lambda _fixture, sql: order.append(("sql", sql)) or "")
    monkeypatch.setattr(
        HARNESS, "_observer_compat_witness_hash", lambda _fixture: (2, "same-witness-hash")
    )
    case_commands = []
    monkeypatch.setattr(
        HARNESS,
        "run_case_command",
        lambda _fixture, mode, **_kwargs: case_commands.append(mode) or {"mode": mode},
    )

    result = HARNESS._exercise_observer_compat_phase(
        SimpleNamespace(kubectl="kubectl", ready_timeout=30), fixture
    )

    assert order[0] == ("probe", HARNESS.Lifecycle.DEPLOYED)
    assert order.index(("init", True)) > order.index(("inspect-sql-connection", 0))
    assert order.count(("health", "/health")) == 1
    assert order.count(("health", "/health?ready=1")) == 1
    assert case_commands == ["probe", "apply", "verify"]
    assert result["case_apply_noop"] is True
    assert result["lifecycle_before_explicit_init"] == "deployed"
    assert result["observer_expected_endpoint_match"]["sql_port"] == 26258
    assert result["witness_row_count"] == 2
    assert result["witness_sha256_before_after"] == ["same-witness-hash"] * 2
    assert result["task_oracle"].startswith("not run:")


def test_observer_compat_phase_fails_before_init_if_observer_disagrees_with_fixture(fixture, monkeypatch):
    workload = SimpleNamespace(
        workload_uid="sts-uid",
        pods=(SimpleNamespace(uid="pod-uid"),),
        http_transport=SimpleNamespace(value="https"),
    )
    deployed = SimpleNamespace(
        status=HARNESS.ProbeStatus.SATISFIED,
        health=SimpleNamespace(lifecycle=HARNESS.Lifecycle.DEPLOYED),
        workload=workload,
    )

    class WrongPortLibrary:
        def __init__(self, *_args):
            pass

        def probe(self, *_args, **_kwargs):
            return deployed

        def inspect_sql_connection(self, *_args, **_kwargs):
            return SimpleNamespace(
                workload_uid="sts-uid",
                tls_mode=HARNESS.TLSMode.TLS,
                certs_dir="/root/.cockroach-certs",
                sql_port=26257,
                rpc_port=26258,
            )

    fixture.phase = "observer-compat"
    fixture.wait_ready = Mock()
    fixture.init = Mock()
    monkeypatch.setattr(HARNESS, "CrdbLibrary", WrongPortLibrary)
    monkeypatch.setattr(HARNESS, "KubectlAdapter", lambda **_kwargs: object())
    monkeypatch.setattr(HARNESS, "_run_observer_compat_sql", lambda *_args: pytest.fail("SQL must not run"))

    with pytest.raises(HARNESS._BASE.SmokeFailure, match="expected TLS/26258 endpoints"):
        HARNESS._exercise_observer_compat_phase(
            SimpleNamespace(kubectl="kubectl", ready_timeout=30), fixture
        )

    fixture.init.assert_not_called()


def test_observer_compat_empty_health_results_fail_and_phase_still_cleans(tmp_path, monkeypatch):
    created_resources = []

    class FakeFixture:
        def __init__(self, args, name, run_id):
            self.args = args
            self.namespace = f"karma-crdb-library-{run_id}-{name}"
            self.namespace_uid = None
            self.namespace_baseline = set()
            self.created = {}
            self.command_trace = []
            self.stage = "created"
            self.storage_class = None
            self.cleaned = False

        def set_stage(self, value):
            self.stage = value

        def stage_snapshot(self):
            return {"current_stage": self.stage, "completed_stages": [], "total_elapsed_ms": 0}

        def prepare_namespace(self):
            self.namespace_uid = "namespace-uid"

        def service_manifest(self):
            return {"kind": "Service", "metadata": {"name": "db"}}

        def public_service_manifest(self):
            return {"kind": "Service", "metadata": {"name": "db-public"}}

        def statefulset_manifest(self, **_kwargs):
            return {"kind": "StatefulSet", "metadata": {"name": "db"}}

        def create(self, resource):
            identity = (resource["kind"].lower(), resource["metadata"]["name"])
            self.created[identity] = f"{identity[0]}-uid"
            created_resources.append(identity)

        def make_secret(self, *_args):
            self.created[("secret", "db-certs")] = "secret-uid"

        def wait_ready(self, **_kwargs):
            pass

        def init(self, **_kwargs):
            pass

        def _checkpoint(self, _label):
            pass

        def capture_diagnostics(self, phase_data, *, label):
            phase_data.setdefault("runtime_diagnostics", {})[label] = {"captured": True}

        def cleanup(self):
            self.cleaned = True

    workload = SimpleNamespace(
        workload_uid="sts-uid",
        pods=(SimpleNamespace(uid="pod-uid"),),
        http_transport=SimpleNamespace(value="https"),
    )
    deployed = SimpleNamespace(
        status=HARNESS.ProbeStatus.SATISFIED,
        health=SimpleNamespace(lifecycle=HARNESS.Lifecycle.DEPLOYED),
        workload=workload,
    )

    class EmptyEndpointLibrary:
        def __init__(self, *_args):
            pass

        def probe(self, *_args, **_kwargs):
            return deployed

        def inspect_sql_connection(self, *_args, **_kwargs):
            return SimpleNamespace(
                workload_uid="sts-uid",
                tls_mode=HARNESS.TLSMode.TLS,
                certs_dir="/root/.cockroach-certs",
                sql_port=26258,
                rpc_port=26258,
            )

        def reconcile(self, *_args, **_kwargs):
            return SimpleNamespace(assessment=SimpleNamespace(status=HARNESS.ProbeStatus.SATISFIED))

        def probe_health_endpoint(self, *_args, **_kwargs):
            return ()

    monkeypatch.setattr(HARNESS, "SettingsFixture", FakeFixture)
    monkeypatch.setattr(HARNESS, "CrdbLibrary", EmptyEndpointLibrary)
    monkeypatch.setattr(HARNESS, "KubectlAdapter", lambda **_kwargs: object())
    monkeypatch.setattr(HARNESS._BASE, "preflight", lambda *_args: {"storage_class": "standard"})
    monkeypatch.setattr(HARNESS._BASE, "make_certificates", lambda *_args: None)
    evidence = tmp_path / "empty-endpoint"
    evidence.mkdir()

    with pytest.raises(HARNESS._BASE.SmokeFailure):
        HARNESS.phase(SimpleNamespace(kubectl="kubectl", ready_timeout=30), "observer-compat", "261020-abc", evidence)

    result = json.loads((evidence / "observer-compat-phase.json").read_text(encoding="utf-8"))
    assert result["result"] == "failed"
    assert created_resources[:2] == [("service", "db"), ("service", "db-public")]
    assert "exactly one successful db-0 response" in result["execution_failure"]["detail"]
    assert result["cleanup_verdict"] == "completed with UID preconditions and normal deletion"


def test_tls_recovery_phase_starts_uninitialized_and_invokes_case_apply_before_accepting_state(
    fixture, monkeypatch
):
    before_observation = SimpleNamespace(
        workload_uid="old-sts",
        tls_mode=HARNESS.TLSMode.TLS,
        pods=(SimpleNamespace(uid="old-pod", pod_ready=True),),
        image="cockroachdb/cockroach:v24.1.0",
        desired_replicas=1,
        workload_spec_hash="same-workload-spec",
        services=(SimpleNamespace(name="db", uid="svc-db", routing_hash="headless-hash"),
                  SimpleNamespace(name="db-public", uid="svc-public", routing_hash="public-hash")),
        secrets=(SimpleNamespace(
            name="db-certs", uid="secret-uid", keys=("node.crt",),
            sha256_by_key=(("node.crt", "certificate-fingerprint"),),
        ),),
    )
    after_observation = SimpleNamespace(**{
        **vars(before_observation),
        "workload_uid": "new-sts",
        "pods": (SimpleNamespace(uid="new-pod", pod_ready=True),),
    })
    before_assessment = SimpleNamespace(
        status=HARNESS.ProbeStatus.SATISFIED,
        health=SimpleNamespace(lifecycle=HARNESS.Lifecycle.DEPLOYED),
        workload=before_observation,
    )
    after_assessment = SimpleNamespace(
        status=HARNESS.ProbeStatus.SATISFIED,
        health=SimpleNamespace(lifecycle=HARNESS.Lifecycle.INITIALIZED),
        workload=after_observation,
    )
    accepted = SimpleNamespace(
        cluster_id="cluster-id",
        node_ids=(1,),
        sql_versions=(("db-0", "24.1.0"),),
        tls_mode=HARNESS.TLSMode.TLS,
        image=before_observation.image,
        desired_replicas=1,
        workload_spec_hash=before_observation.workload_spec_hash,
        pvc_identities=(("data-db-0", "new-pvc", "new-pv", "Bound", "pvc-spec"),),
        certificate_fingerprints=(("db-certs", "secret-uid", "node.crt", "certificate-fingerprint"),),
        service_routing=(("db", "svc-db", "headless-hash"), ("db-public", "svc-public", "public-hash")),
    )

    class FakeLibrary:
        def __init__(self):
            self.assessments = iter((before_assessment, after_assessment))
            self.requirements = []

        def probe(self, _ref, requirement, **_kwargs):
            self.requirements.append(requirement.lifecycle)
            return next(self.assessments)

        def accepted_state(self, _assessment):
            return accepted

        def verify_accepted_state(self, *_args, **_kwargs):
            return after_assessment

    library = FakeLibrary()
    fixture.phase = "tls-recovery"
    fixture.phase_data = {"target_resource_history": []}
    fixture.created.update({
        ("statefulset", "db"): "old-sts",
        ("service", "db"): "svc-db",
        ("service", "db-public"): "svc-public",
        ("secret", "db-certs"): "secret-uid",
    })
    fixture.wait_ready = Mock()
    fixture._record_storage_snapshot = Mock(side_effect=[
        [{"name": "data-db-0", "uid": "old-pvc", "pv": {"name": "old-pv", "uid": "old-pv-uid"}}],
        [{"name": "data-db-0", "uid": "new-pvc", "pv": {"name": "new-pv", "uid": "new-pv-uid"}}],
    ])
    fixture._refresh_recovery_identities_for_cleanup = Mock()
    fixture._checkpoint = Mock()
    current = {"metadata": {"uid": "old-sts"}, "spec": {"replicas": 1, "template": {"spec": {}}}}
    fixture.get = lambda kind, name=None, **_kwargs: current if kind == "statefulset" and name == "db" else {}
    fixture.init = Mock()
    phase_data = fixture.phase_data

    class FakeTarget:
        def __init__(self, *_args, **_kwargs):
            pass

        def apply(self):
            assert fixture.init.call_count == 0
            current["metadata"]["uid"] = "new-sts"
            phase_data["target_resource_history"].extend([
                {"action": "delete", "kind": "statefulset", "uid": "old-sts", "propagation_policy": "Foreground"},
                {"action": "init", "state": "requested"},
            ])

    monkeypatch.setattr(HARNESS, "CrdbLibrary", lambda *_args: library)
    monkeypatch.setattr(HARNESS.runpy, "run_path", lambda *_args: {"TargetCluster": FakeTarget})
    monkeypatch.setattr(HARNESS, "run_case_command", lambda _fixture, mode, **_kwargs: {"mode": mode})

    result = HARNESS._exercise_tls_recovery_phase(
        SimpleNamespace(kubectl="kubectl", ready_timeout=30), fixture, phase_data
    )

    assert library.requirements == [HARNESS.Lifecycle.DEPLOYED, HARNESS.Lifecycle.INITIALIZED]
    assert fixture.wait_ready.call_count == 2
    fixture.init.assert_not_called()
    assert result["pre_recovery_lifecycle"] == "DEPLOYED"
    assert result["post_recovery_lifecycle"] == "INITIALIZED"
    assert result["target_apply_recovered_and_recreated_tls_cluster"] is True

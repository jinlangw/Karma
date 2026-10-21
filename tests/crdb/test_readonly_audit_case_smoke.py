"""Contract tests for the bounded readonly-audit live proof harness."""

from __future__ import annotations

import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[2]
HARNESS_PATH = ROOT / "experiments/crdb-case-migration/readonly_audit_case_smoke.py"
SPEC = importlib.util.spec_from_file_location("readonly_audit_case_smoke_harness", HARNESS_PATH)
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
    value = HARNESS.AuditFixture(args, "tls", "261019-audit")
    value.storage_class = "local-path"
    return value


def test_tls_fixture_has_native_https_readiness_and_case_cert_path(fixture):
    manifest = fixture.statefulset_manifest(tls=True)
    container = manifest["spec"]["template"]["spec"]["containers"][0]

    assert container["livenessProbe"]["httpGet"] == {
        "path": "/health",
        "port": "http",
        "scheme": "HTTPS",
    }
    assert container["readinessProbe"]["httpGet"] == {
        "path": "/health?ready=1",
        "port": "http",
        "scheme": "HTTPS",
    }
    assert "--certs-dir=/cockroach/cockroach-certs" in container["command"][2]
    assert next(mount for mount in container["volumeMounts"] if mount["name"] == "certs")["mountPath"] == (
        "/cockroach/cockroach-certs"
    )
    assert manifest["spec"]["replicas"] == 3


def test_manifest_override_uses_original_bootstrap_and_keeps_kubelet_expansions(fixture, tmp_path):
    documents, statefulset = HARNESS.small_bootstrap_documents(fixture)
    assert [(doc["kind"], doc["metadata"]["name"]) for doc in documents] == [
        ("ServiceAccount", "db-sa"),
        ("Role", "db-role"),
        ("RoleBinding", "db-rolebinding"),
        ("Service", "db"),
        ("Service", "db-public"),
        ("StatefulSet", "db"),
    ]
    spec = statefulset["spec"]
    pod_spec = spec["template"]["spec"]
    container = pod_spec["containers"][0]
    assert spec["replicas"] == 3
    assert spec["volumeClaimTemplates"][0]["spec"]["resources"]["requests"]["storage"] == "1Gi"
    assert pod_spec["terminationGracePeriodSeconds"] >= 30
    assert pod_spec["nodeSelector"] == {"kubernetes.io/hostname": "kind-worker"}
    assert container["image"] == fixture.args.image
    assert container["imagePullPolicy"] == "Never"
    assert container["resources"] == {
        "requests": {"cpu": "100m", "memory": "256Mi"},
        "limits": {"cpu": "1", "memory": "1Gi"},
    }
    assert "--cache=128MiB" in container["command"][2]
    assert "--max-sql-memory=128MiB" in container["command"][2]
    assert "$(POD_NAME)" in container["command"][2]
    assert "$(POD_NAMESPACE)" in container["command"][2]

    HARNESS.write_small_manifest_dir(tmp_path, fixture)
    with HARNESS.case_modules() as modules:
        case_cluster = modules.cluster.Cluster(fixture.namespace, "db", manifest_dir=tmp_path)
        created = []

        def get(kind, name=None, namespace=None):
            if kind == "namespace":
                return {"metadata": {"name": fixture.namespace}}
            if name is None:
                return {"items": []}
            return None

        case_cluster.get = get
        case_cluster.create = lambda obj: created.append(copy.deepcopy(obj))
        case_cluster.wait = lambda _check, _seconds: None
        case_cluster.bootstrap()

    rendered_sts = next(obj for obj in created if obj["kind"] == "StatefulSet")
    rendered_container = rendered_sts["spec"]["template"]["spec"]["containers"][0]
    assert [(obj["kind"], obj["metadata"]["name"]) for obj in created] == [
        ("ServiceAccount", "db-sa"),
        ("Role", "db-role"),
        ("RoleBinding", "db-rolebinding"),
        ("Service", "db"),
        ("Service", "db-public"),
        ("StatefulSet", "db"),
    ]
    assert "$(POD_NAME)" in rendered_container["command"][2]
    assert "$(POD_NAMESPACE)" in rendered_container["command"][2]
    assert ":26257" in rendered_container["command"][2]
    assert "$(BENCH_NAMESPACE)" not in rendered_container["command"][2]


def test_initialize_requires_running_positive_deployed_observation_before_init(fixture, monkeypatch):
    order = []
    expected_pods = {f"db-{ordinal}" for ordinal in range(3)}
    fixture.get = lambda *_args, **_kwargs: {
        "items": [
            {"metadata": {"name": name}, "status": {"phase": "Running"}}
            for name in sorted(expected_pods)
        ]
    }
    fixture._checkpoint = lambda status: order.append(status)
    fixture.set_stage = lambda stage: order.append(stage)
    monkeypatch.setattr(HARNESS, "time", SimpleNamespace(monotonic=lambda: 10, sleep=lambda _: None))

    def reconcile(_fixture, lifecycle, tls, timeout):
        order.append("reconcile-" + lifecycle.value)
        health = SimpleNamespace(
            lifecycle=lifecycle,
            uninitialized_pods=tuple(sorted(expected_pods)) if lifecycle is HARNESS.Lifecycle.DEPLOYED else (),
        )
        return SimpleNamespace(assessment=SimpleNamespace(health=health))

    monkeypatch.setattr(HARNESS, "_reconcile", reconcile)
    fixture.init = lambda tls: order.append("explicit-init")
    fixture.wait_ready = lambda timeout: order.append("kubernetes-ready")

    result = HARNESS._initialize_fixture(fixture, tls=True, timeout=30)

    assert result["preinit_lifecycle"] == "deployed"
    assert order.index("reconcile-deployed") < order.index("explicit-init")
    assert order.index("explicit-init") < order.index("reconcile-initialized")
    assert order.index("reconcile-initialized") < order.index("kubernetes-ready")


def test_tls_phase_creates_witness_before_any_snapshot_and_rechecks_setting(fixture, monkeypatch):
    order = []
    accepted = SimpleNamespace(
        cluster_id="cluster",
        node_ids=(1, 2, 3),
        sql_versions=(("db-0", "24.1.0"), ("db-1", "24.1.0"), ("db-2", "24.1.0")),
        tls_mode=SimpleNamespace(value="TLS"),
        image="cockroachdb/cockroach:v24.1.0",
        desired_replicas=3,
        workload_spec_hash="full-spec",
        pvc_identities=(("data-db-0", "pvc-uid", "pv", "claim", "Bound"),),
        certificate_fingerprints=(("secret", "db-certs", "node.crt", "fingerprint"),),
        service_routing=(("db", "db-0", "26257"),),
    )
    baseline = {"name": "baseline", "uid": "baseline-uid", "encrypted_baseline_sha256": "cipher-hash"}

    monkeypatch.setattr(HARNESS, "_initialize_fixture", lambda *_args, **_kwargs: {"ready": True})
    monkeypatch.setattr(HARNESS, "_run_settings_preconditions", lambda *_args: [{"passed": True}])
    monkeypatch.setattr(HARNESS, "_controlled_setting", lambda *_args, **_kwargs: order.append("setting-set") or "128MiB")
    monkeypatch.setattr(HARNESS, "_create_witness", lambda *_args, **_kwargs: order.append("witness-created") or (2, "witness-hash"))

    def snapshot(*_args, **_kwargs):
        assert "witness-created" in order
        order.append("snapshot")
        return accepted, {"db-0": "p0", "db-1": "p1", "db-2": "p2"}, (2, "witness-hash")

    monkeypatch.setattr(HARNESS, "_snapshot_inherited", snapshot)
    monkeypatch.setattr(HARNESS, "_run_audit_units", lambda _fixture, unit, **_kwargs: order.append("units-" + unit) or [])
    monkeypatch.setattr(HARNESS, "run_case_command", lambda *_args, **_kwargs: {"outcome": "passed", "returncode": 0})
    monkeypatch.setattr(HARNESS, "_artifact_summary", lambda *_args: baseline)
    monkeypatch.setattr(HARNESS, "_run_oracle", lambda _fixture, _key, *, should_accept: order.append("oracle-" + str(should_accept)) or {"returncode": 0})
    monkeypatch.setattr(HARNESS, "_audit_report_from_live_observations", lambda *_args: order.append("report-snapshot") or ({"report": True}, {"state_sha256": "state"}))
    monkeypatch.setattr(HARNESS, "_create_observed_report", lambda *_args: {"uid": "report-uid"})
    monkeypatch.setattr(HARNESS, "_assert_preserved", lambda *_args, **_kwargs: {"accepted_state_verified": True})
    monkeypatch.setattr(HARNESS, "_read_controlled_setting", lambda *_args, **_kwargs: order.append("setting-read") or "128MiB")

    result = HARNESS._run_tls_audit_phase(
        SimpleNamespace(ready_timeout=30), fixture, {"phase": "tls", "tls_mode": "TLS"}
    )

    assert order.index("witness-created") < order.index("snapshot")
    assert order.index("setting-set") < order.index("units-environment")
    assert order.count("setting-read") == 1
    assert result["controlled_setting_after_audit"] == "128MiB"
    assert "independent_live_report_observation" not in result
    assert "same reader used by the oracle" in result["report_observation_method"]


def test_node_status_diagnostic_keeps_only_csv_headers_and_count(fixture, monkeypatch):
    diagnostic = {"pod": {"metadata": {"name": "db-0"}}}
    monkeypatch.setattr(HARNESS._HEALTH.HealthCaseFixture, "capture_diagnostics", lambda *_args, **_kwargs: diagnostic)
    monkeypatch.setattr(
        HARNESS._BASE,
        "run",
        lambda *_args, **_kwargs: "id,is_available,ranges_unavailable\n1,true,0\nsecret-row,false,private",
    )
    fixture._checkpoint = lambda _status: None
    phase_data = {"tls_mode": "TLS"}

    result = fixture.capture_diagnostics(phase_data, label="before-cleanup")

    assert result["node_status_csv"] == {
        "available": True,
        "headers": ["id", "is_available", "ranges_unavailable"],
        "row_count": 2,
    }
    assert "secret-row" not in json.dumps(phase_data)
    assert "private" not in json.dumps(phase_data)


def test_case_environment_sets_stage_context_and_restores_caller_values(fixture, monkeypatch):
    monkeypatch.setenv("BENCH_NAMESPACE", "caller-namespace")
    monkeypatch.setenv("BENCH_RUN_ID", "caller-run")
    monkeypatch.setenv("BENCH_PARAM_REPLICA_COUNT", "99")
    monkeypatch.delenv("BENCH_STAGE_ID", raising=False)
    monkeypatch.setattr(HARNESS.shutil, "which", lambda _name: None)

    with HARNESS.case_environment(fixture, setting_name="kv.setting", setting_value="128MiB"):
        assert os.environ["BENCH_NAMESPACE"] == fixture.namespace
        assert os.environ["BENCH_PARAM_CLUSTER_NAME"] == "db"
        assert os.environ["BENCH_PARAM_REPLICA_COUNT"] == "3"
        assert os.environ["BENCH_RUN_ID"] == fixture.run_id
        assert os.environ["BENCH_STAGE_ID"] == fixture.stage_id
        assert os.environ["BENCH_PARAM_SETTING_NAME"] == "kv.setting"
        assert os.environ["BENCH_PARAM_SETTING_VALUE"] == "128MiB"

    assert os.environ["BENCH_NAMESPACE"] == "caller-namespace"
    assert os.environ["BENCH_PARAM_REPLICA_COUNT"] == "99"
    assert os.environ["BENCH_RUN_ID"] == "caller-run"
    assert "BENCH_STAGE_ID" not in os.environ


def test_trusted_stage_key_is_sent_only_on_stdin_not_argv_env_or_evidence(fixture, monkeypatch):
    observed = {}
    secret = "private-stage-key-sentinel"
    fixture.record_artifact_intent = lambda _name: None
    fixture.capture_artifact_if_owned = lambda _name: None
    monkeypatch.setattr(HARNESS.shutil, "which", lambda _name: None)

    def fake_run(command, **kwargs):
        observed["command"] = command
        observed.update(kwargs)
        return subprocess.CompletedProcess(command, 0, "ok", "")

    monkeypatch.setattr(HARNESS.subprocess, "run", fake_run)
    event = HARNESS.run_case_command(
        fixture,
        HARNESS.AUDIT_PREPARE,
        ("baseline", "apply"),
        timeout=10,
        trusted_input=HARNESS._audit_private(secret, frozen=False),
        create_intent_name=fixture.audit_context["baseline_name"],
    )

    assert secret in observed["input"]
    assert secret not in " ".join(observed["command"])
    assert secret not in json.dumps(observed["env"])
    assert secret not in json.dumps(event)
    assert secret not in json.dumps(fixture.phase_data)


def test_baseline_artifact_journal_stores_only_uid_and_ciphertext_hash(fixture):
    fixture.record_artifact_intent(fixture.audit_context["baseline_name"])
    payload = "encrypted-payload-sentinel"
    artifact = {
        "kind": "ConfigMap",
        "metadata": {
            "name": fixture.audit_context["baseline_name"],
            "uid": "baseline-uid",
            "labels": fixture.audit_context["labels"],
        },
        "data": {"snapshot.enc": payload},
    }

    summary = fixture.record_created_artifact(artifact)

    assert summary["uid"] == "baseline-uid"
    assert summary["encrypted_baseline_sha256"] == HARNESS.hashlib.sha256(payload.encode()).hexdigest()
    assert payload not in json.dumps(summary)
    assert payload not in json.dumps(fixture.phase_data)


def test_artifact_capture_failure_preserves_safe_original_error_and_redacts_trusted_material(fixture, monkeypatch):
    fixture.record_artifact_intent = lambda _name: None
    fixture.capture_artifact_if_owned = lambda _name: (_ for _ in ()).throw(RuntimeError("capture blocked"))
    monkeypatch.setattr(HARNESS.shutil, "which", lambda _name: None)
    stage_key = "private-stage-key-sentinel"
    pem = "private-pem-sentinel"
    token = "eyJabcdefgh.abcdefgh.abcdefgh"
    monkeypatch.setattr(
        HARNESS.subprocess,
        "run",
        lambda command, **_kwargs: subprocess.CompletedProcess(
            command,
            1,
            "",
            f"original failure key={stage_key} -----BEGIN PRIVATE KEY-----{pem}-----END PRIVATE KEY----- {token}",
        ),
    )

    with pytest.raises(HARNESS._BASE.SmokeFailure, match="did not meet its expected command result") as error:
        HARNESS.run_case_command(
            fixture,
            HARNESS.AUDIT_PREPARE,
            ("baseline", "apply"),
            timeout=10,
            trusted_input=HARNESS._audit_private(stage_key, frozen=False),
            create_intent_name=fixture.audit_context["baseline_name"],
        )

    assert fixture.phase_data["artifact_capture_failures"][0]["type"] == "RuntimeError"
    evidence = json.dumps(fixture.phase_data)
    assert "original failure" in str(error.value)
    assert "original failure" in evidence
    assert stage_key not in str(error.value) + evidence
    assert pem not in str(error.value) + evidence
    assert token not in str(error.value) + evidence


def test_tracked_create_persists_intent_before_request_and_uid_after_response(fixture):
    phase_data = {}
    events = []
    fixture.phase_data = phase_data
    fixture.checkpoint_callback = lambda status: events.append(
        (status, set(fixture.created), len(phase_data.get("created_resource_identities", [])))
    )

    def fake_kubectl(*_args, input_text=None, **_kwargs):
        document = json.loads(input_text)
        events.append(("request", set(fixture.created), len(phase_data.get("created_resource_identities", []))))
        created = copy.deepcopy(document)
        created["metadata"]["uid"] = "new-serviceaccount-uid"
        return json.dumps(created)

    fixture.kubectl = fake_kubectl
    case_cluster = SimpleNamespace(require=lambda response: response.stdout)
    HARNESS._install_tracked_case_cluster(case_cluster, fixture, phase_data)
    case_cluster.create(
        {
            "apiVersion": "v1",
            "kind": "ServiceAccount",
            "metadata": {"name": "db-sa", "namespace": fixture.namespace},
        }
    )

    assert events[0] == ("create-intent-serviceaccount-db-sa", set(), 0)
    assert events[1][0] == "request"
    assert fixture.created[("serviceaccount", "db-sa")] == "new-serviceaccount-uid"
    assert phase_data["created_resource_identities"] == [
        {"kind": "serviceaccount", "name": "db-sa", "uid": "new-serviceaccount-uid"}
    ]


def test_cleanup_refuses_foreign_audit_artifact_without_uid_delete(fixture):
    name = fixture.audit_context["report_name"]
    fixture.artifact_create_intents.add(name)
    fixture.get = lambda kind, resource_name=None, **_kwargs: (
        {
            "metadata": {
                "name": resource_name,
                "uid": "foreign-uid",
                "labels": {"karma.dev/audit-id": "foreign-audit"},
            }
        }
        if kind == "configmaps" and resource_name == name
        else {}
    )
    deleted = []
    fixture.raw_delete_uid = lambda *args, **_kwargs: deleted.append(args)

    with pytest.raises(HARNESS._BASE.SmokeFailure, match="labels do not match"):
        fixture.cleanup_additional_resources()

    assert deleted == []


def test_main_runs_only_reviewed_phases_sequentially_and_refuses_existing_evidence(tmp_path, monkeypatch):
    evidence = tmp_path / "run"
    phases = []

    def fake_phase(args, name, run_id, evidence_dir):
        assert args.context is None
        phases.append(name)
        return {"phase": name, "namespace": "owned-" + name}

    monkeypatch.setattr(HARNESS, "phase", fake_phase)
    assert HARNESS.main(["--evidence-dir", str(evidence)]) == 0
    assert phases == ["tls", "fresh"]
    assert (evidence / "live-summary.json").exists()

    with pytest.raises(HARNESS._BASE.SmokeFailure, match="must be new"):
        HARNESS.main(["--evidence-dir", str(evidence)])

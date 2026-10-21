"""Contract tests for the version-check environment proof callback."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[2]
HARNESS_PATH = ROOT / "experiments/crdb-case-migration/version_check_environment_smoke.py"
SPEC = importlib.util.spec_from_file_location("version_check_environment_smoke", HARNESS_PATH)
assert SPEC is not None and SPEC.loader is not None
HARNESS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HARNESS)
ROLLBACK = HARNESS._ROLLBACK
AUDIT = ROLLBACK._AUDIT


def _fixture(run_id="261019-version"):
    args = SimpleNamespace(
        kubectl="kubectl",
        context=None,
        docker="docker",
        node="kind-worker",
        image="cockroachdb/cockroach:v24.1.0",
    )
    fixture = AUDIT.AuditFixture(args, "tls", run_id)
    fixture.stage_id = HARNESS.VERSION_CHECK_PROOF.stage_id
    return fixture


def _csv_setting(name, value):
    return f'{name}\n"{value}"\n'


def test_version_environment_commands_send_valid_private_input_only_on_stdin_and_pin_stage(monkeypatch):
    fixture = _fixture()
    calls = []
    monkeypatch.setattr(AUDIT.shutil, "which", lambda _name: None)

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(AUDIT.subprocess, "run", fake_run)
    events = HARNESS.VERSION_CHECK_PROOF.run_commands(fixture)

    assert [event["outcome"] for event in events] == ["passed"] * 3
    assert len(calls) == 3
    for (command, kwargs), mode in zip(calls, ("probe", "apply", "verify")):
        assert command[-3:] == [str(HARNESS.VERSION_PREPARE), "environment", mode]
        private = json.loads(kwargs["input"])
        assert set(private) == {"key", "frozen"}
        assert private["frozen"] is False
        HARNESS.Fernet(private["key"].encode())
        assert private["key"] not in " ".join(command)
        assert private["key"] not in json.dumps(kwargs["env"])
        assert kwargs["env"]["BENCH_NAMESPACE"] == fixture.namespace
        assert kwargs["env"]["BENCH_PARAM_CLUSTER_NAME"] == "db"
        assert kwargs["env"]["BENCH_PARAM_REPLICA_COUNT"] == "3"
        assert kwargs["env"]["BENCH_RUN_ID"] == fixture.run_id
        assert kwargs["env"]["BENCH_STAGE_ID"] == HARNESS.VERSION_CHECK_PROOF.stage_id


def test_active_feature_version_is_held_and_read_back_before_commands(monkeypatch):
    fixture = _fixture()
    queries = []
    observations = []

    def sql(_fixture, query, *, tls):
        queries.append(query)
        assert tls is True
        if query == "SHOW CLUSTER SETTING version":
            return _csv_setting("version", "24.1")
        if query == "SHOW CLUSTER SETTING cluster.preserve_downgrade_option":
            return _csv_setting("cluster.preserve_downgrade_option", "24.1")
        if query == "SET CLUSTER SETTING cluster.preserve_downgrade_option = '24.1'":
            return ""
        raise AssertionError(query)

    monkeypatch.setattr(AUDIT, "_sql", sql)
    controls = HARNESS.VERSION_CHECK_PROOF.prepare_controls(fixture, observations.append)

    assert controls == {"active_feature_version": "24.1", "preserve_downgrade_option": "24.1"}
    assert queries == [
        "SHOW CLUSTER SETTING version",
        "SET CLUSTER SETTING cluster.preserve_downgrade_option = '24.1'",
        "SHOW CLUSTER SETTING cluster.preserve_downgrade_option",
    ]
    assert observations[-1]["active_feature_version"] == "24.1"
    assert observations[-1]["preserve_downgrade_option_readback"] == "24.1"


@pytest.mark.parametrize("empty_version", ['version\n""\n', "version\n"])
def test_active_version_must_be_nonempty_and_is_journaled_before_failure(monkeypatch, empty_version):
    fixture = _fixture()
    observations = []
    queries = []

    def sql(_fixture, query, *, tls):
        queries.append(query)
        assert tls is True
        if query == "SHOW CLUSTER SETTING version":
            return empty_version
        raise AssertionError("a missing active version must not authorize a setting change")

    monkeypatch.setattr(AUDIT, "_sql", sql)
    with pytest.raises(AUDIT._BASE.SmokeFailure, match="active feature version"):
        HARNESS.VERSION_CHECK_PROOF.prepare_controls(fixture, observations.append)
    assert queries == ["SHOW CLUSTER SETTING version"]
    assert observations == [
        {
            "stage": "before-environment-commands",
            "active_feature_version": "",
            "requested_preserve_downgrade_option": "",
            "preserve_downgrade_option_readback": None,
        }
    ]


@pytest.mark.parametrize(
    ("active_after", "hold_after"),
    [("24.3", "24.1"), ("24.1", "24.3")],
)
def test_environment_verification_rejects_changed_active_version_or_hold(
    monkeypatch, active_after, hold_after
):
    fixture = _fixture()
    observations = []

    def sql(_fixture, query, *, tls):
        assert tls is True
        if query == "SHOW CLUSTER SETTING version":
            return _csv_setting("version", active_after)
        if query == "SHOW CLUSTER SETTING cluster.preserve_downgrade_option":
            return _csv_setting("cluster.preserve_downgrade_option", hold_after)
        raise AssertionError(query)

    monkeypatch.setattr(AUDIT, "_sql", sql)
    with pytest.raises(ROLLBACK._AUDIT._BASE.SmokeFailure, match="active version or hold"):
        HARNESS.VERSION_CHECK_PROOF.verify_controls(
            fixture,
            {"active_feature_version": "24.1", "preserve_downgrade_option": "24.1"},
            observations.append,
        )
    assert observations[-1]["active_feature_version_after"] == active_after
    assert observations[-1]["hold_after"] == hold_after


def test_version_check_command_failure_redacts_private_key_from_error_and_evidence(monkeypatch):
    fixture = _fixture()
    observed = {}
    monkeypatch.setattr(AUDIT.shutil, "which", lambda _name: None)

    def fake_run(command, **kwargs):
        key = json.loads(kwargs["input"])["key"]
        observed["key"] = key
        return subprocess.CompletedProcess(command, 1, "", f"failure key={key}")

    monkeypatch.setattr(AUDIT.subprocess, "run", fake_run)
    with pytest.raises(AUDIT._BASE.SmokeFailure) as error:
        HARNESS.VERSION_CHECK_PROOF.run_commands(fixture)

    evidence = json.dumps(fixture.phase_data)
    assert observed["key"] not in str(error.value) + evidence
    assert "<REDACTED stage key>" in str(error.value)


def test_version_check_phase_failure_redacts_private_key_and_cleans_before_return(monkeypatch, tmp_path):
    args = SimpleNamespace(
        kubectl="kubectl",
        context=None,
        docker="docker",
        node="kind-worker",
        image="cockroachdb/cockroach:v24.1.0",
        ready_timeout=30,
    )
    fixture = AUDIT.AuditFixture(args, "tls", "261019-version")
    cleanup = []
    observed = {}
    fixture.prepare_namespace = lambda: None
    fixture.cleanup = lambda: cleanup.append("completed")
    fixture.capture_diagnostics = lambda phase_data, *, label: phase_data.update(
        {"diagnostics_label": label}
    )
    monkeypatch.setattr(AUDIT, "AuditFixture", lambda *_args: fixture)
    monkeypatch.setattr(AUDIT._HEALTH, "preflight", lambda *_args: {"storage_class": "local-path"})
    monkeypatch.setattr(AUDIT, "_create_existing_fixture", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(AUDIT, "_initialize_fixture", lambda *_args, **_kwargs: {"initialized": True})
    monkeypatch.setattr(AUDIT, "_controlled_setting", lambda *_args, **_kwargs: "128MiB")
    monkeypatch.setattr(AUDIT, "_create_witness", lambda *_args, **_kwargs: (2, "witness-hash"))
    monkeypatch.setattr(
        ROLLBACK,
        "_set_owned_witness_gc_policy",
        lambda _fixture, *, record_observation: record_observation(
            {
                "range_default_ttl_seconds": 14400,
                "requested_table_ttl_seconds": 3600,
                "table_readback_ttl_seconds": 3600,
            }
        )
        or {
            "range_default_ttl_seconds": 14400,
            "requested_table_ttl_seconds": 3600,
            "table_readback_ttl_seconds": 3600,
        },
    )
    accepted = object()
    pod_uids = {f"db-{ordinal}": f"pod-{ordinal}" for ordinal in range(3)}
    monkeypatch.setattr(AUDIT, "_snapshot_inherited", lambda *_args, **_kwargs: (accepted, pod_uids, (2, "witness-hash")))
    monkeypatch.setattr(AUDIT, "_accepted_summary", lambda _state: {"captured": True})
    monkeypatch.setattr(ROLLBACK, "_assert_preserved", lambda *_args, **_kwargs: {"accepted_state_verified": True})

    def sql(_fixture, query, *, tls):
        assert tls is True
        if query == "SHOW CLUSTER SETTING version":
            return _csv_setting("version", "24.1")
        if query == "SET CLUSTER SETTING cluster.preserve_downgrade_option = '24.1'":
            return ""
        if query == "SHOW CLUSTER SETTING cluster.preserve_downgrade_option":
            return _csv_setting("cluster.preserve_downgrade_option", "24.1")
        raise AssertionError(query)

    monkeypatch.setattr(AUDIT, "_sql", sql)
    monkeypatch.setattr(AUDIT.shutil, "which", lambda _name: None)

    def failed_subprocess(command, **kwargs):
        key = json.loads(kwargs["input"])["key"]
        observed["key"] = key
        return subprocess.CompletedProcess(command, 1, "", f"failure key={key}")

    monkeypatch.setattr(AUDIT.subprocess, "run", failed_subprocess)
    with pytest.raises(AUDIT._BASE.SmokeFailure, match="version-check TLS proof failed"):
        ROLLBACK._run_tls_phase(
            args,
            "261019-version",
            tmp_path,
            proof=HARNESS.VERSION_CHECK_PROOF,
        )

    phase = json.loads((tmp_path / "tls-phase.json").read_text())
    journal = json.loads((tmp_path / "tls-journal.json").read_text())
    serialized = json.dumps({"phase": phase, "journal": journal})
    assert cleanup == ["completed"]
    assert phase["result"] == "failed"
    assert phase["cleanup_verdict"].startswith("completed")
    assert phase["diagnostics_label"] == "before-cleanup"
    assert phase["case_control_observations"][-1]["active_feature_version"] == "24.1"
    assert observed["key"] not in serialized
    assert "<REDACTED stage key>" in serialized
    assert journal["status"] == "phase-finished"

"""Contract tests for the compact rollback environment proof harness."""

from __future__ import annotations

import csv
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[2]
HARNESS_PATH = ROOT / "experiments/crdb-case-migration/rollback_rehearsal_case_smoke.py"
SPEC = importlib.util.spec_from_file_location("rollback_rehearsal_case_smoke_harness", HARNESS_PATH)
assert SPEC is not None and SPEC.loader is not None
HARNESS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HARNESS)


def _csv_zone_config(yaml_text):
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["full_config_yaml"])
    writer.writerow([yaml_text])
    return output.getvalue()


@pytest.mark.parametrize(("range_default_ttl", "expected_ttl"), [(14400, 3600), (3600, 7200)])
def test_owned_gc_policy_selects_and_records_a_nondefault_value(monkeypatch, range_default_ttl, expected_ttl):
    calls = []
    observations = []

    def sql(_fixture, query, *, tls):
        calls.append((query, tls))
        if query.startswith("ALTER TABLE"):
            return ""
        value = range_default_ttl if "RANGE default" in query else expected_ttl
        return _csv_zone_config(f"gc:\n  ttlseconds: {value}\n")

    monkeypatch.setattr(HARNESS._AUDIT, "_sql", sql)

    result = HARNESS._set_owned_witness_gc_policy(object(), record_observation=observations.append)
    assert result == {
        "range_default_ttl_seconds": range_default_ttl,
        "requested_table_ttl_seconds": expected_ttl,
        "table_readback_ttl_seconds": expected_ttl,
    }
    assert observations[0] == {
        "range_default_ttl_seconds": range_default_ttl,
        "requested_table_ttl_seconds": expected_ttl,
        "table_readback_ttl_seconds": None,
    }
    assert observations[1] == result
    assert calls[1] == (
        "ALTER TABLE crdb_readonly_audit_smoke.public.witness "
        f"CONFIGURE ZONE USING gc.ttlseconds = {expected_ttl}",
        True,
    )
    assert "RANGE default" in calls[0][0]
    assert "SHOW ZONE CONFIGURATION FOR TABLE crdb_readonly_audit_smoke.public.witness" in calls[2][0]
    assert all(tls for _query, tls in calls)


def test_wrong_gc_readback_is_recorded_before_failure(monkeypatch):
    observations = []

    def sql(_fixture, query, *, tls):
        if "RANGE default" in query:
            return _csv_zone_config("gc:\n  ttlseconds: 14400\n")
        if query.startswith("ALTER TABLE"):
            return ""
        return _csv_zone_config("gc:\n  ttlseconds: 7200\n")

    monkeypatch.setattr(HARNESS._AUDIT, "_sql", sql)
    with pytest.raises(HARNESS._AUDIT._BASE.SmokeFailure, match="did not read back"):
        HARNESS._set_owned_witness_gc_policy(object(), record_observation=observations.append)
    assert observations[-1] == {
        "range_default_ttl_seconds": 14400,
        "requested_table_ttl_seconds": 3600,
        "table_readback_ttl_seconds": 7200,
    }


def test_owned_gc_policy_rejects_missing_or_noninteger_readback(monkeypatch):
    monkeypatch.setattr(
        HARNESS._AUDIT,
        "_sql",
        lambda *_args, **_kwargs: _csv_zone_config("gc:\n  ttlseconds: '14400'\n"),
    )

    with pytest.raises(HARNESS._AUDIT._BASE.SmokeFailure, match="integer TTL"):
        HARNESS._table_gc_ttl_seconds(object())


def test_environment_commands_are_actual_probe_apply_verify_calls(monkeypatch):
    fixture = SimpleNamespace(stage_id="rollback-rehearsal-smoke")
    calls = []

    def run_case_command(_fixture, script, arguments, *, timeout):
        calls.append((script, arguments, timeout))
        return {"operation": f"{script.name} {' '.join(arguments)}", "outcome": "passed"}

    monkeypatch.setattr(HARNESS._AUDIT, "run_case_command", run_case_command)

    result = HARNESS._run_environment_probe_apply_verify(fixture)

    assert [arguments for _script, arguments, _timeout in calls] == [
        ("environment", "probe"),
        ("environment", "apply"),
        ("environment", "verify"),
    ]
    assert all(script == HARNESS.ROLLBACK_PREPARE and timeout == 180 for script, _args, timeout in calls)
    assert [event["outcome"] for event in result] == ["passed"] * 3


def test_preservation_rejects_a_changed_cluster_setting(monkeypatch):
    monkeypatch.setattr(HARNESS._AUDIT, "_assert_preserved", lambda *_args, **_kwargs: {"accepted_state_verified": True})
    monkeypatch.setattr(HARNESS._AUDIT, "_read_controlled_setting", lambda *_args, **_kwargs: "64MiB")

    with pytest.raises(HARNESS._AUDIT._BASE.SmokeFailure, match="controlled cluster setting"):
        HARNESS._assert_preserved(
            object(),
            accepted=object(),
            pod_uids={"db-0": "pod-uid"},
            witness=(2, "witness-hash"),
            setting_value="128MiB",
            gc_policy={
                "requested_table_ttl_seconds": 3600,
                "table_readback_ttl_seconds": 3600,
                "range_default_ttl_seconds": 90000,
            },
        )


def test_preservation_rejects_a_changed_or_normalized_gc_policy(monkeypatch):
    monkeypatch.setattr(HARNESS._AUDIT, "_assert_preserved", lambda *_args, **_kwargs: {"accepted_state_verified": True})
    monkeypatch.setattr(HARNESS._AUDIT, "_read_controlled_setting", lambda *_args, **_kwargs: "128MiB")
    monkeypatch.setattr(HARNESS, "_table_gc_ttl_seconds", lambda *_args: 90000)
    monkeypatch.setattr(HARNESS, "_range_default_gc_ttl_seconds", lambda *_args: 90000)

    with pytest.raises(HARNESS._AUDIT._BASE.SmokeFailure, match="witness table GC policy"):
        HARNESS._assert_preserved(
            object(),
            accepted=object(),
            pod_uids={"db-0": "pod-uid"},
            witness=(2, "witness-hash"),
            setting_value="128MiB",
            gc_policy={
                "requested_table_ttl_seconds": 3600,
                "table_readback_ttl_seconds": 3600,
                "range_default_ttl_seconds": 90000,
            },
        )


@pytest.mark.parametrize(
    ("fail_at_commands", "failure_type"),
    [
        (False, None),
        (True, HARNESS._AUDIT._BASE.SmokeFailure),
        (True, HARNESS._AUDIT._HEALTH._BASE.SmokeFailure),
    ],
)
def test_phase_journals_cleanup_and_keeps_failure_result(monkeypatch, tmp_path, fail_at_commands, failure_type):
    class Fixture:
        def __init__(self, _args, _phase, run_id):
            self.namespace = "rollback-proof-test"
            self.run_id = run_id
            self.stage_id = "rollback-rehearsal-smoke"
            self.namespace_uid = "namespace-uid"
            self.namespace_baseline = set()
            self.created = {}
            self.command_trace = []
            self.phase_data = {}
            self.checkpoint_callback = None
            self.cleanup_calls = 0

        def set_stage(self, _stage):
            return None

        def prepare_namespace(self):
            return None

        def cleanup(self):
            self.cleanup_calls += 1

        def stage_snapshot(self):
            return {"events": []}

        def capture_diagnostics(self, phase_data, *, label):
            phase_data["diagnostics_label"] = label
            return {"captured": True}

    fixture_holder = []

    def make_fixture(*args):
        fixture = Fixture(*args)
        fixture_holder.append(fixture)
        return fixture

    monkeypatch.setattr(HARNESS._AUDIT, "AuditFixture", make_fixture)
    monkeypatch.setattr(HARNESS._AUDIT._HEALTH, "preflight", lambda *_args: {"storage_class": "local-path"})
    monkeypatch.setattr(
        HARNESS._AUDIT,
        "_create_existing_fixture",
        lambda _args, _fixture, **_kwargs: None,
    )
    monkeypatch.setattr(
        HARNESS._AUDIT,
        "_initialize_fixture",
        lambda *_args, **_kwargs: {"initialized": True},
    )
    monkeypatch.setattr(HARNESS._AUDIT, "_controlled_setting", lambda *_args, **_kwargs: "128MiB")
    monkeypatch.setattr(HARNESS._AUDIT, "_create_witness", lambda *_args, **_kwargs: (2, "rows-hash"))
    monkeypatch.setattr(
        HARNESS,
        "_set_owned_witness_gc_policy",
        lambda _fixture, *, record_observation: record_observation(
            {
                "range_default_ttl_seconds": 90000,
                "requested_table_ttl_seconds": 3600,
                "table_readback_ttl_seconds": 3600,
            }
        )
        or {
            "range_default_ttl_seconds": 90000,
            "requested_table_ttl_seconds": 3600,
            "table_readback_ttl_seconds": 3600,
        },
    )
    accepted = object()
    pods = {"db-0": "pod-uid"}
    witness = (2, "rows-hash")
    monkeypatch.setattr(HARNESS._AUDIT, "_snapshot_inherited", lambda *_args, **_kwargs: (accepted, pods, witness))
    monkeypatch.setattr(HARNESS._AUDIT, "_accepted_summary", lambda _state: {"captured": True})
    monkeypatch.setattr(
        HARNESS,
        "_assert_preserved",
        lambda *_args, **_kwargs: {"accepted_state_verified": True},
    )

    def commands(_fixture):
        if fail_at_commands:
            raise failure_type("planned command failure")
        return [{"outcome": "passed"} for _mode in ("probe", "apply", "verify")]

    monkeypatch.setattr(HARNESS, "_run_environment_probe_apply_verify", commands)
    args = SimpleNamespace(ready_timeout=30)

    if fail_at_commands:
        with pytest.raises(HARNESS._AUDIT._BASE.SmokeFailure, match="proof failed"):
            HARNESS._run_tls_phase(args, "261019-proof", tmp_path)
    else:
        result = HARNESS._run_tls_phase(args, "261019-proof", tmp_path)
        assert result["result"] == "passed"

    fixture = fixture_holder[0]
    phase_data = json.loads((tmp_path / "tls-phase.json").read_text())
    journal = json.loads((tmp_path / "tls-journal.json").read_text())
    assert fixture.cleanup_calls == 1
    assert phase_data["result"] == ("failed" if fail_at_commands else "passed")
    assert phase_data["cleanup_verdict"].startswith("completed")
    assert journal["status"] == "phase-finished"
    if fail_at_commands:
        assert phase_data["execution_failure"]["type"] == "SmokeFailure"
        assert phase_data["execution_failure"]["detail"] == "planned command failure"
        assert phase_data["diagnostics_label"] == "before-cleanup"


def test_main_refuses_to_overwrite_existing_evidence(monkeypatch, tmp_path):
    existing = tmp_path / "previous-run"
    existing.mkdir()
    sentinel = existing / "sentinel.json"
    sentinel.write_text('{"result":"preserve"}')
    monkeypatch.setattr(HARNESS, "_run_tls_phase", lambda *_args, **_kwargs: pytest.fail("must not launch"))

    with pytest.raises(HARNESS._AUDIT._BASE.SmokeFailure, match="must be new"):
        HARNESS.main(["--evidence-dir", str(existing)])

    assert sentinel.read_text() == '{"result":"preserve"}'

"""Safety-contract tests for the compact zone-config live proof harness."""

from __future__ import annotations

import csv
import importlib.util
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from karma.crdb import ProbeStatus
from karma.crdb.types import KubernetesAccessError, TransientError


ROOT = Path(__file__).resolve().parents[2]
HARNESS_PATH = ROOT / "experiments/crdb-case-migration/zone_config_case_smoke.py"
SPEC = importlib.util.spec_from_file_location("zone_config_case_smoke_harness", HARNESS_PATH)
assert SPEC is not None and SPEC.loader is not None
HARNESS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HARNESS)


def _observation(
    status: ProbeStatus,
    *,
    underreplicated: tuple[int, ...] = (0, 0, 0),
    unavailable: tuple[int, ...] = (0, 0, 0),
    reasons: tuple[str, ...] = (),
    node_ids: tuple[int, ...] = (1, 2, 3),
    pod_names: tuple[str, ...] = ("db-0", "db-1", "db-2"),
) -> SimpleNamespace:
    assert len(node_ids) == len(pod_names) == len(underreplicated) == len(unavailable)
    return SimpleNamespace(
        status=status,
        reasons=reasons,
        pod_node_ids=tuple(zip(pod_names, node_ids, strict=True)),
        node_status=tuple(
            SimpleNamespace(
                node_id=node_id,
                ranges_underreplicated=under,
                ranges_unavailable=not_available,
            )
            for node_id, under, not_available in zip(node_ids, underreplicated, unavailable, strict=True)
        ),
        node_liveness=tuple(SimpleNamespace(node_id=node_id) for node_id in node_ids),
    )


def test_underreplication_evidence_requires_full_healthy_baseline_then_only_range_reason():
    baseline = _observation(ProbeStatus.SATISFIED)
    assert HARNESS._underreplication_evidence(
        baseline,
        _observation(ProbeStatus.SATISFIED),
        expected_node_ids=(1, 2, 3),
    ) is None

    evidence = HARNESS._underreplication_evidence(
        _observation(
            ProbeStatus.UNSATISFIED,
            underreplicated=(1, 1, 1),
            reasons=(HARNESS._UNDERREPLICATION_ONLY_REASON,),
        ),
        _observation(ProbeStatus.SATISFIED, underreplicated=(1, 1, 1)),
        expected_node_ids=(1, 2, 3),
    )

    assert evidence["selected_node_ids"] == (1, 2, 3)
    assert evidence["underreplicated_count_sum"] == 3
    assert evidence["unavailable_count_sum"] == 0


def test_underreplication_evidence_rejects_an_additional_full_health_failure():
    full = _observation(
        ProbeStatus.UNSATISFIED,
        underreplicated=(1, 1, 1),
        reasons=(
            HARNESS._UNDERREPLICATION_ONLY_REASON,
            "KV liveness does not match the selected StatefulSet replicas",
        ),
    )

    with pytest.raises(HARNESS._AUDIT._BASE.SmokeFailure, match="Only positive under-replication"):
        HARNESS._underreplication_evidence(
            full,
            _observation(ProbeStatus.SATISFIED, underreplicated=(1, 1, 1)),
            expected_node_ids=(1, 2, 3),
        )


def test_underreplication_transition_samples_may_be_zero_or_differ_in_count():
    full_healthy = _observation(ProbeStatus.SATISFIED)
    serving_after_policy = _observation(ProbeStatus.SATISFIED, underreplicated=(1, 0, 0))
    assert HARNESS._underreplication_evidence(
        full_healthy,
        serving_after_policy,
        expected_node_ids=(1, 2, 3),
    ) is None

    full_after_policy = _observation(
        ProbeStatus.UNSATISFIED,
        underreplicated=(1, 0, 0),
        reasons=(HARNESS._UNDERREPLICATION_ONLY_REASON,),
    )
    serving_later = _observation(ProbeStatus.SATISFIED, underreplicated=(2, 1, 0))
    evidence = HARNESS._underreplication_evidence(
        full_after_policy,
        serving_later,
        expected_node_ids=(1, 2, 3),
    )
    assert evidence["underreplicated_count_sum"] == 1
    assert evidence["serving_underreplicated_count_sum"] == 3


@pytest.mark.parametrize(
    "full,serving",
    [
        (
            _observation(
                ProbeStatus.UNSATISFIED,
                underreplicated=(1, 1, 1),
                unavailable=(1, 0, 0),
                reasons=(HARNESS._UNDERREPLICATION_ONLY_REASON,),
            ),
            _observation(ProbeStatus.UNSATISFIED, underreplicated=(1, 1, 1)),
        ),
        (
            _observation(
                ProbeStatus.UNSATISFIED,
                underreplicated=(1, 1, 1),
                reasons=(HARNESS._UNDERREPLICATION_ONLY_REASON,),
            ),
            _observation(ProbeStatus.UNSATISFIED, underreplicated=(1, 1, 1), reasons=("serving failure",)),
        ),
    ],
)
def test_underreplication_evidence_rejects_unavailable_or_unsatisfied_serving(full, serving):
    with pytest.raises(HARNESS._AUDIT._BASE.SmokeFailure):
        HARNESS._underreplication_evidence(full, serving, expected_node_ids=(1, 2, 3))


def test_underreplication_evidence_requires_exact_fresh_fixture_node_sets():
    historical = _observation(
        ProbeStatus.UNSATISFIED,
        reasons=(HARNESS._UNDERREPLICATION_ONLY_REASON,),
        node_ids=(1, 2, 3, 4),
        pod_names=("db-0", "db-1", "db-2", "old-db-3"),
        underreplicated=(1, 1, 1, 0),
        unavailable=(0, 0, 0, 0),
    )
    with pytest.raises(HARNESS._AUDIT._BASE.SmokeFailure, match="three owned fixture Pods"):
        HARNESS._underreplication_evidence(
            historical,
            historical,
            expected_node_ids=(1, 2, 3),
        )


def test_full_health_baseline_must_be_fully_replicated_before_policy_change():
    class Library:
        def __init__(self, result):
            self.result = result
            self.calls = []

        def wait_for_full_health(self, ref, **kwargs):
            self.calls.append((ref, kwargs))
            return self.result

    baseline = _observation(ProbeStatus.SATISFIED)
    library = Library(baseline)
    ref = object()
    observed, node_ids = HARNESS._wait_for_fully_replicated_baseline(library, ref)
    assert observed is baseline
    assert node_ids == (1, 2, 3)
    assert library.calls == [(ref, {"timeout": 90, "poll_interval": 2, "per_node_timeout": 5})]

    already_underreplicated = _observation(
        ProbeStatus.SATISFIED,
        underreplicated=(1, 0, 0),
    )
    with pytest.raises(HARNESS._AUDIT._BASE.SmokeFailure, match="not fully replicated"):
        HARNESS._wait_for_fully_replicated_baseline(Library(already_underreplicated), ref)


def test_wait_for_underreplication_waits_for_transition_from_zero_underreplication():
    full_results = [
        _observation(ProbeStatus.SATISFIED),
        _observation(
            ProbeStatus.UNSATISFIED,
            underreplicated=(1, 1, 1),
            reasons=(HARNESS._UNDERREPLICATION_ONLY_REASON,),
        ),
    ]
    serving_results = [
        _observation(ProbeStatus.SATISFIED),
        _observation(ProbeStatus.SATISFIED, underreplicated=(1, 1, 1)),
    ]

    class Library:
        def probe_full_health(self, *_args, **_kwargs):
            return full_results.pop(0)

        def probe_serving_health(self, *_args, **_kwargs):
            return serving_results.pop(0)

    clock = [0.0]

    def sleep(seconds):
        clock[0] += seconds

    result = HARNESS.wait_for_underreplication(
        Library(),
        object(),
        expected_node_ids=(1, 2, 3),
        timeout=5,
        poll_interval=1,
        monotonic=lambda: clock[0],
        sleep=sleep,
    )

    assert result["attempts"] == 2
    assert clock[0] == 1


def test_wait_for_underreplication_retries_only_typed_transient_observations():
    underreplicated = _observation(
        ProbeStatus.UNSATISFIED,
        underreplicated=(1, 1, 1),
        reasons=(HARNESS._UNDERREPLICATION_ONLY_REASON,),
    )
    serving = _observation(ProbeStatus.SATISFIED, underreplicated=(1, 1, 1))

    class Library:
        full_calls = 0

        def probe_full_health(self, *_args, **_kwargs):
            self.full_calls += 1
            if self.full_calls == 1:
                raise TransientError("temporary rollout")
            return underreplicated

        def probe_serving_health(self, *_args, **_kwargs):
            return serving

    clock = [0.0]
    result = HARNESS.wait_for_underreplication(
        Library(),
        object(),
        expected_node_ids=(1, 2, 3),
        timeout=5,
        poll_interval=1,
        monotonic=lambda: clock[0],
        sleep=lambda seconds: clock.__setitem__(0, clock[0] + seconds),
    )

    assert result["attempts"] == 2
    assert clock[0] == 1


def test_wait_for_underreplication_does_not_retry_api_failures():
    class Library:
        calls = 0

        def probe_full_health(self, *_args, **_kwargs):
            self.calls += 1
            raise KubernetesAccessError("fixture API denied")

        def probe_serving_health(self, *_args, **_kwargs):
            pytest.fail("serving health must not run after an API failure")

    library = Library()
    with pytest.raises(KubernetesAccessError, match="fixture API denied"):
        HARNESS.wait_for_underreplication(
            library,
            object(),
            expected_node_ids=(1, 2, 3),
            timeout=5,
            monotonic=lambda: 0,
            sleep=lambda _seconds: pytest.fail("API errors must not be retried"),
        )
    assert library.calls == 1


def test_policy_carryover_sample_records_real_health_and_counters_without_expectation_of_underreplication():
    full = _observation(ProbeStatus.SATISFIED)
    serving = _observation(ProbeStatus.SATISFIED)

    sample, ready = HARNESS._policy_carryover_sample(
        full,
        serving,
        expected_node_ids=(1, 2, 3),
        attempt=1,
    )

    assert ready is True
    assert sample["full_health"]["status"] == "satisfied"
    assert sample["serving_health"]["status"] == "satisfied"
    assert sample["full_health"]["ranges_underreplicated_sum"] == 0
    assert sample["full_health"]["ranges_unavailable_sum"] == 0
    assert sample["full_health"]["node_status"] == [
        {"node_id": 1, "ranges_underreplicated": 0, "ranges_unavailable": 0},
        {"node_id": 2, "ranges_underreplicated": 0, "ranges_unavailable": 0},
        {"node_id": 3, "ranges_underreplicated": 0, "ranges_unavailable": 0},
    ]


def test_policy_carryover_wait_records_transition_samples_and_accepts_healthy_state():
    full_results = [
        _observation(
            ProbeStatus.UNSATISFIED,
            underreplicated=(1, 0, 0),
            reasons=(HARNESS._UNDERREPLICATION_ONLY_REASON,),
        ),
        _observation(ProbeStatus.SATISFIED),
    ]
    serving_results = [
        _observation(ProbeStatus.SATISFIED, underreplicated=(1, 0, 0)),
        _observation(ProbeStatus.SATISFIED),
    ]

    class Library:
        def probe_full_health(self, *_args, **_kwargs):
            return full_results.pop(0)

        def probe_serving_health(self, *_args, **_kwargs):
            return serving_results.pop(0)

    samples = []
    clock = [0.0]
    result = HARNESS.wait_for_policy_carryover_health(
        Library(),
        object(),
        expected_node_ids=(1, 2, 3),
        on_sample=samples.append,
        timeout=5,
        poll_interval=1,
        monotonic=lambda: clock[0],
        sleep=lambda seconds: clock.__setitem__(0, clock[0] + seconds),
    )

    assert result["attempts"] == 2
    assert [sample["attempt"] for sample in samples] == [1, 2]
    assert samples[0]["full_health"]["ranges_underreplicated_sum"] == 1
    assert samples[1]["full_health"]["ranges_underreplicated_sum"] == 0


def test_policy_carryover_records_unexpected_identity_before_bounded_failure():
    historical = _observation(
        ProbeStatus.SATISFIED,
        node_ids=(1, 2, 3, 4),
        pod_names=("db-0", "db-1", "db-2", "legacy-db"),
        underreplicated=(0, 0, 0, 0),
        unavailable=(0, 0, 0, 0),
    )

    class Library:
        def probe_full_health(self, *_args, **_kwargs):
            return historical

        def probe_serving_health(self, *_args, **_kwargs):
            return historical

    samples = []
    clock = [0.0]
    with pytest.raises(HARNESS._AUDIT._BASE.SmokeFailure, match="did not reach a healthy"):
        HARNESS.wait_for_policy_carryover_health(
            Library(),
            object(),
            expected_node_ids=(1, 2, 3),
            on_sample=samples.append,
            timeout=1,
            poll_interval=1,
            monotonic=lambda: clock[0],
            sleep=lambda seconds: clock.__setitem__(0, clock[0] + seconds),
        )

    assert samples
    assert samples[0]["identity_failure"] == "Health observations did not select the three owned fixture Pods"
    assert samples[0]["full_health"]["ranges_underreplicated_sum"] == 0


def test_policy_carryover_records_typed_api_error_then_propagates_without_retry():
    class Library:
        calls = 0

        def probe_full_health(self, *_args, **_kwargs):
            self.calls += 1
            raise KubernetesAccessError("fixture API denied")

        def probe_serving_health(self, *_args, **_kwargs):
            pytest.fail("serving health must not run after an API failure")

    library = Library()
    samples = []
    with pytest.raises(KubernetesAccessError, match="fixture API denied"):
        HARNESS.wait_for_policy_carryover_health(
            library,
            object(),
            expected_node_ids=(1, 2, 3),
            on_sample=samples.append,
            timeout=5,
            monotonic=lambda: 0,
            sleep=lambda _seconds: pytest.fail("API errors must not be retried"),
        )

    assert library.calls == 1
    assert samples == [{"attempt": 1, "error_type": "KubernetesAccessError"}]


def test_zone_policy_readback_parses_csv_field_with_multiline_yaml(monkeypatch):
    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(["full_config_yaml"])
    writer.writerow(["num_replicas: 5\nconstraints: []\nlease_preferences: []"])
    observed = {}

    def sql(_fixture, query, *, tls):
        observed.update(query=query, tls=tls)
        return output.getvalue()

    monkeypatch.setattr(HARNESS._AUDIT, "_sql", sql)
    assert HARNESS._zone_policy_replica_count(object(), tls=True) == 5
    assert "SHOW ZONE CONFIGURATION FOR TABLE " + HARNESS._WITNESS_TABLE in observed["query"]
    assert observed["tls"] is True


@pytest.mark.parametrize("yaml_text", ["constraints: []\n", "num_replicas: five\n"])
def test_zone_policy_readback_rejects_missing_or_noninteger_replica_count(monkeypatch, yaml_text):
    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(["full_config_yaml"])
    writer.writerow([yaml_text])
    monkeypatch.setattr(HARNESS._AUDIT, "_sql", lambda *_args, **_kwargs: output.getvalue())

    with pytest.raises(HARNESS._AUDIT._BASE.SmokeFailure):
        HARNESS._zone_policy_replica_count(object(), tls=False)


def test_zone_case_environment_pins_three_desired_nodes_and_restores_caller_values(monkeypatch):
    monkeypatch.setenv("BENCH_PARAM_NUM_REPLICAS", "99")
    with HARNESS.zone_case_environment(object()):
        assert os.environ["BENCH_PARAM_NUM_REPLICAS"] == "3"
        assert os.environ["BENCH_PARAM_TARGET_SCHEMA"] == "tenant_b"
    assert os.environ["BENCH_PARAM_NUM_REPLICAS"] == "99"
    assert "BENCH_PARAM_TARGET_SCHEMA" not in os.environ


def test_environment_commands_run_probe_apply_verify_with_the_three_node_parameters(monkeypatch):
    calls = []
    fixture = SimpleNamespace()
    trusted = {"key": "private-test-key", "frozen": False}

    def run_case_command(_fixture, script, arguments, **kwargs):
        calls.append((script, arguments, dict(kwargs), os.environ["BENCH_PARAM_NUM_REPLICAS"]))
        return {"outcome": "passed", "returncode": 0}

    monkeypatch.setattr(HARNESS._AUDIT, "run_case_command", run_case_command)
    events = HARNESS._run_zone_environment_units(fixture, trusted)

    assert [arguments for _script, arguments, _kwargs, _replicas in calls] == [
        ("environment", "probe"),
        ("environment", "apply"),
        ("environment", "verify"),
    ]
    assert all(script == HARNESS.ZONE_PREPARE for script, _args, _kwargs, _replicas in calls)
    assert all(replicas == "3" for _script, _args, _kwargs, replicas in calls)
    assert all(kwargs["trusted_input"] is trusted for _script, _args, kwargs, _replicas in calls)
    assert len(events) == 3


def test_main_sets_current_context_for_reused_fixture_without_live_actions(monkeypatch, tmp_path):
    observed = {}

    def phase(args, run_id, evidence_dir, *, proof):
        observed.update(context=args.context, run_id=run_id, evidence_dir=evidence_dir, proof=proof)
        return {"result": "test-only"}

    monkeypatch.setattr(HARNESS, "_run_tls_zone_phase", phase)
    evidence_dir = tmp_path / "new-zone-evidence"
    result = HARNESS.main(["--evidence-dir", str(evidence_dir), "--proof", "policy-carryover"])

    assert result == 0
    assert observed["context"] is None
    assert observed["evidence_dir"] == evidence_dir.resolve()
    assert observed["proof"] == "policy-carryover"
    assert (evidence_dir / "live-summary.json").exists()


@pytest.mark.parametrize("proof", ["underreplication", "policy-carryover"])
@pytest.mark.parametrize("failure_source", ["audit", "health"])
def test_phase_failure_keeps_diagnostics_and_cleanup_journal_without_success_summary(
    monkeypatch,
    tmp_path,
    proof,
    failure_source,
):
    instances = []

    class Fixture:
        def __init__(self, args, _phase, run_id):
            self.args = args
            self.run_id = run_id
            self.namespace = "zone-proof-test"
            self.namespace_uid = "namespace-uid"
            self.namespace_baseline = set()
            self.created = {}
            self.command_trace = []
            self.storage_class = None
            self.cleanup_called = False
            instances.append(self)

        def set_stage(self, stage):
            self.current_stage = stage

        def stage_snapshot(self):
            return [{"stage": getattr(self, "current_stage", "unknown")}]

        def prepare_namespace(self):
            self.namespace_prepared = True

        def capture_diagnostics(self, phase_data, *, label):
            phase_data.setdefault("runtime_diagnostics", {})[label] = {"captured": True}
            return {"captured": True}

        def cleanup(self):
            self.cleanup_called = True

    class Library:
        def wait_for_full_health(self, *_args, **_kwargs):
            return _observation(ProbeStatus.SATISFIED)

    monkeypatch.setattr(HARNESS._AUDIT, "AuditFixture", Fixture)
    monkeypatch.setattr(HARNESS._AUDIT._HEALTH, "preflight", lambda *_args: {"storage_class": "local-path"})
    monkeypatch.setattr(HARNESS._AUDIT, "_create_existing_fixture", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(HARNESS._AUDIT, "_initialize_fixture", lambda *_args, **_kwargs: {"ready": True})
    monkeypatch.setattr(HARNESS._AUDIT, "_controlled_setting", lambda *_args, **_kwargs: "128MiB")
    monkeypatch.setattr(HARNESS._AUDIT, "_read_controlled_setting", lambda *_args, **_kwargs: "128MiB")
    monkeypatch.setattr(HARNESS._AUDIT, "_create_witness", lambda *_args, **_kwargs: (2, "witness-hash"))
    policy_readbacks = iter((3, 5))
    monkeypatch.setattr(HARNESS, "_zone_policy_replica_count", lambda *_args, **_kwargs: next(policy_readbacks))
    monkeypatch.setattr(HARNESS._AUDIT, "_library", lambda *_args: (Library(), object()))
    accepted = SimpleNamespace()
    monkeypatch.setattr(
        HARNESS._AUDIT,
        "_snapshot_inherited",
        lambda *_args, **_kwargs: (accepted, {"db-0": "p0", "db-1": "p1", "db-2": "p2"}, (2, "witness-hash")),
    )
    monkeypatch.setattr(HARNESS._AUDIT, "_accepted_summary", lambda _accepted: {"captured": True})
    monkeypatch.setattr(HARNESS._AUDIT, "_sql", lambda *_args, **_kwargs: "applied")
    if proof == "underreplication":
        monkeypatch.setattr(
            HARNESS,
            "wait_for_underreplication",
            lambda *_args, **_kwargs: {"selected_node_ids": (1, 2, 3), "underreplicated_count_sum": 1},
        )
    else:
        carryover_sample = {
            "attempt": 1,
            "full_health": {
                "status": "satisfied",
                "reasons": [],
                "pod_node_ids": [
                    {"pod": "db-0", "node_id": 1},
                    {"pod": "db-1", "node_id": 2},
                    {"pod": "db-2", "node_id": 3},
                ],
                "node_liveness_ids": [1, 2, 3],
                "node_status": [
                    {"node_id": node_id, "ranges_underreplicated": 0, "ranges_unavailable": 0}
                    for node_id in (1, 2, 3)
                ],
                "ranges_underreplicated_sum": 0,
                "ranges_unavailable_sum": 0,
            },
            "serving_health": {
                "status": "satisfied",
                "reasons": [],
                "pod_node_ids": [
                    {"pod": "db-0", "node_id": 1},
                    {"pod": "db-1", "node_id": 2},
                    {"pod": "db-2", "node_id": 3},
                ],
                "node_liveness_ids": [1, 2, 3],
                "node_status": [
                    {"node_id": node_id, "ranges_underreplicated": 0, "ranges_unavailable": 0}
                    for node_id in (1, 2, 3)
                ],
                "ranges_underreplicated_sum": 0,
                "ranges_unavailable_sum": 0,
            },
        }

        def wait_for_carryover(*_args, on_sample, **_kwargs):
            on_sample(carryover_sample)
            return {"attempts": 1, "last_sample": carryover_sample}

        monkeypatch.setattr(HARNESS, "wait_for_policy_carryover_health", wait_for_carryover)
    failure_type = (
        HARNESS._AUDIT._BASE.SmokeFailure
        if failure_source == "audit"
        else HARNESS._AUDIT._HEALTH._BASE.SmokeFailure
    )
    command_failure = failure_type(
        "environment apply failed token=phase-test-secret",
        command_event={"operation": "prepare.py environment apply", "returncode": 2},
    )
    monkeypatch.setattr(HARNESS, "_run_zone_environment_units", lambda *_args: (_ for _ in ()).throw(command_failure))

    evidence = tmp_path / "zone-phase"
    evidence.mkdir()
    args = SimpleNamespace(ready_timeout=30)
    with pytest.raises(HARNESS._AUDIT._BASE.SmokeFailure, match="zone-config TLS proof failed"):
        HARNESS._run_tls_zone_phase(args, "261019-test", evidence, proof=proof)

    assert instances[0].cleanup_called is True
    phase = json.loads((evidence / "tls-phase.json").read_text())
    journal = json.loads((evidence / "tls-journal.json").read_text())
    assert phase["result"] == "failed"
    assert phase["cleanup_verdict"].startswith("completed")
    assert phase["proof_mode"] == proof
    assert phase["failure_command"]["operation"] == "prepare.py environment apply"
    assert phase["execution_failure"]["detail"] == "environment apply failed token=<REDACTED>"
    assert phase["runtime_diagnostics"]["before-cleanup"]["captured"] is True
    assert journal["phase"] == f"tls-zone-{proof}"
    assert journal["status"] == "phase-finished"
    assert "phase-test-secret" not in json.dumps(phase)
    assert "phase-test-secret" not in json.dumps(journal)
    if proof == "policy-carryover":
        assert phase["policy_health_samples_after_policy"] == [carryover_sample]
        assert journal["safe_observations"]["policy_health_samples_after_policy"] == [carryover_sample]
    assert not (evidence / "live-summary.json").exists()

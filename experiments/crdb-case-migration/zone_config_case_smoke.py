#!/usr/bin/env python3
"""Bounded TLS proof for zone-config's migrated environment precondition.

Reuses the reviewed readonly-audit fixture and its exact-UID cleanup. The proof
does not run the zone task units/oracle or perform a fresh bootstrap.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import csv
import importlib.util
import io
import json
import math
import os
from pathlib import Path
import sys
import time
from typing import Any, Iterator, Mapping

import yaml


ROOT = Path(__file__).resolve().parents[2]
AUDIT_PATH = ROOT / "experiments" / "crdb-case-migration" / "readonly_audit_case_smoke.py"
ZONE_PREPARE = ROOT / "cases" / "cockroachdb" / "zone-config" / "scripts" / "prepare.py"
_AUDIT_SPEC = importlib.util.spec_from_file_location("readonly_audit_case_smoke", AUDIT_PATH)
if _AUDIT_SPEC is None or _AUDIT_SPEC.loader is None:
    raise RuntimeError("Could not load the reviewed readonly-audit fixture helpers")
_AUDIT = importlib.util.module_from_spec(_AUDIT_SPEC)
_AUDIT_SPEC.loader.exec_module(_AUDIT)

from cryptography.fernet import Fernet  # noqa: E402
from karma.crdb import ProbeStatus, WorkloadRef  # noqa: E402
from karma.crdb.types import RolloutInProgressError, TransientError  # noqa: E402


_NODE_COUNT = 3
_WITNESS_TABLE = _AUDIT._WITNESS_TABLE
_WITNESS_POLICY_SQL = f"ALTER TABLE {_WITNESS_TABLE} CONFIGURE ZONE USING num_replicas=5"
_CONTROLLED_SETTING = "kv.snapshot_rebalance.max_rate"
_UNDERREPLICATION_ONLY_REASON = "CockroachDB reports unavailable or under-replicated ranges"
_PROOF_MODES = ("underreplication", "policy-carryover")
_SAFE_SMOKE_FAILURE_TYPES = (
    _AUDIT._BASE.SmokeFailure,
    _AUDIT._HEALTH._BASE.SmokeFailure,
)


def _is_safe_smoke_failure(error: BaseException) -> bool:
    """Recognize sanitized fixture errors from both independently loaded helpers."""
    return isinstance(error, _SAFE_SMOKE_FAILURE_TYPES)


@contextmanager
def zone_case_environment(fixture: Any) -> Iterator[None]:
    """Set the actual zone parameters around the reused case-command runner."""
    updates = {
        "BENCH_PARAM_NUM_REPLICAS": str(_NODE_COUNT),
        "BENCH_PARAM_TARGET_SCHEMA": "tenant_b",
        "BENCH_PARAM_PROTECTED_SCHEMA": "tenant_a",
        "BENCH_PARAM_GC_TTL_SECONDS": "14400",
        "BENCH_PARAM_RANGE_MIN_BYTES": "134217728",
        "BENCH_PARAM_RANGE_MAX_BYTES": "536870912",
    }
    previous = {key: os.environ.get(key) for key in updates}
    os.environ.update(updates)
    try:
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _selected_node_ids(assessment: Any) -> tuple[int, ...]:
    pairs = tuple(assessment.pod_node_ids)
    expected_pods = {f"db-{ordinal}" for ordinal in range(_NODE_COUNT)}
    pod_names = {pod_name for pod_name, _node_id in pairs}
    node_ids = tuple(sorted(node_id for _pod_name, node_id in pairs))
    if len(pairs) != _NODE_COUNT or pod_names != expected_pods or len(set(node_ids)) != _NODE_COUNT:
        raise _AUDIT._BASE.SmokeFailure("Health observations did not select the three owned fixture Pods")

    status_ids = tuple(sorted(row.node_id for row in assessment.node_status))
    liveness_ids = tuple(sorted(row.node_id for row in assessment.node_liveness))
    # This is a brand-new, three-node fixture. Historical/decommissioned nodes
    # are not expected here and must not make an unrelated result look healthy.
    if status_ids != node_ids or liveness_ids != node_ids:
        raise _AUDIT._BASE.SmokeFailure("Health observations included missing or historical node identities")
    return node_ids


def _wait_for_fully_replicated_baseline(library: Any, ref: WorkloadRef) -> tuple[Any, tuple[int, ...]]:
    baseline = library.wait_for_full_health(ref, timeout=90, poll_interval=2, per_node_timeout=5)
    if baseline.status is not ProbeStatus.SATISFIED or baseline.reasons:
        raise _AUDIT._BASE.SmokeFailure("Fixture must be fully healthy before the witness-only policy change")
    node_ids = _selected_node_ids(baseline)
    if any(
        row.ranges_underreplicated != 0 or row.ranges_unavailable != 0
        for row in baseline.node_status
    ):
        raise _AUDIT._BASE.SmokeFailure("Pre-policy baseline was not fully replicated and available")
    return baseline, node_ids


def _underreplication_evidence(
    full_health: Any,
    serving_health: Any,
    *,
    expected_node_ids: tuple[int, ...],
) -> dict[str, Any] | None:
    """Accept only under-replication as the sole health distinction."""
    full_ids = _selected_node_ids(full_health)
    serving_ids = _selected_node_ids(serving_health)
    if full_ids != expected_node_ids or serving_ids != expected_node_ids:
        raise _AUDIT._BASE.SmokeFailure("Health observations did not cover the same selected node IDs")
    if any(row.ranges_unavailable != 0 for row in full_health.node_status + serving_health.node_status):
        raise _AUDIT._BASE.SmokeFailure("Witness policy introduced unavailable ranges")

    full_underreplicated = sum(row.ranges_underreplicated for row in full_health.node_status)
    serving_underreplicated = sum(row.ranges_underreplicated for row in serving_health.node_status)
    if serving_health.status is not ProbeStatus.SATISFIED or serving_health.reasons:
        raise _AUDIT._BASE.SmokeFailure("Serving health had a failure unrelated to range under-replication")
    if full_health.status is ProbeStatus.SATISFIED:
        if full_health.reasons or full_underreplicated:
            raise _AUDIT._BASE.SmokeFailure("Full-health result contradicted its range counters")
        return None
    if full_health.status is not ProbeStatus.UNSATISFIED or full_health.reasons != (_UNDERREPLICATION_ONLY_REASON,):
        raise _AUDIT._BASE.SmokeFailure(
            "Only positive under-replication may distinguish full-health from serving-health"
        )
    if full_underreplicated <= 0 or serving_underreplicated <= 0:
        # The two read-only commands run sequentially while the zone policy is
        # propagating. A still-zero sample is not proof yet; keep polling.
        return None
    return {
        "selected_node_ids": expected_node_ids,
        "full_health": full_health.status.value,
        "serving_health": serving_health.status.value,
        "underreplicated_count_sum": full_underreplicated,
        "serving_underreplicated_count_sum": serving_underreplicated,
        "unavailable_count_sum": sum(row.ranges_unavailable for row in full_health.node_status),
    }


def wait_for_underreplication(
    library: Any,
    ref: WorkloadRef,
    *,
    expected_node_ids: tuple[int, ...],
    timeout: float = 90.0,
    poll_interval: float = 2.0,
    per_node_timeout: float = 5.0,
    monotonic=time.monotonic,
    sleep=time.sleep,
) -> dict[str, Any]:
    """Bounded polling; retry only typed transient rollout observations."""
    if not math.isfinite(timeout) or timeout <= 0 or not math.isfinite(poll_interval) or poll_interval <= 0:
        raise ValueError("under-replication timeout and poll interval must be finite and positive")
    deadline = monotonic() + timeout
    attempts = 0
    while True:
        attempts += 1
        try:
            full = library.probe_full_health(ref, per_node_timeout=per_node_timeout)
            serving = library.probe_serving_health(ref, per_node_timeout=per_node_timeout)
            result = _underreplication_evidence(full, serving, expected_node_ids=expected_node_ids)
        except (TransientError, RolloutInProgressError):
            result = None
        if result is not None:
            return {**result, "attempts": attempts}
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise _AUDIT._BASE.SmokeFailure("Owned witness policy did not produce bounded under-replication evidence")
        sleep(min(poll_interval, remaining))


def _health_observation_summary(assessment: Any) -> dict[str, Any]:
    """Return bounded, structured public health evidence with no command text."""
    return {
        "status": assessment.status.value,
        "reasons": [
            _AUDIT._BASE._safe_diagnostic_text(str(reason))
            for reason in assessment.reasons
        ],
        "pod_node_ids": [
            {"pod": pod_name, "node_id": node_id}
            for pod_name, node_id in assessment.pod_node_ids
        ],
        "node_liveness_ids": sorted(row.node_id for row in assessment.node_liveness),
        "node_status": [
            {
                "node_id": row.node_id,
                "ranges_underreplicated": row.ranges_underreplicated,
                "ranges_unavailable": row.ranges_unavailable,
            }
            for row in assessment.node_status
        ],
        "ranges_underreplicated_sum": sum(
            row.ranges_underreplicated for row in assessment.node_status
        ),
        "ranges_unavailable_sum": sum(
            row.ranges_unavailable for row in assessment.node_status
        ),
    }


def _policy_carryover_sample(
    full_health: Any,
    serving_health: Any,
    *,
    expected_node_ids: tuple[int, ...],
    attempt: int,
) -> tuple[dict[str, Any], bool]:
    """Summarize two fixed health probes and decide whether the sample is ready."""
    full = _health_observation_summary(full_health)
    serving = _health_observation_summary(serving_health)
    sample = {
        "attempt": attempt,
        "full_health": full,
        "serving_health": serving,
    }

    try:
        full_ids = _selected_node_ids(full_health)
        serving_ids = _selected_node_ids(serving_health)
    except _AUDIT._BASE.SmokeFailure as error:
        sample["identity_failure"] = _AUDIT._BASE._safe_diagnostic_text(str(error))
        return sample, False
    if full_ids != expected_node_ids or serving_ids != expected_node_ids:
        sample["identity_failure"] = "Health observation did not match the three owned node IDs"
        return sample, False

    full_ready = (
        full_health.status is ProbeStatus.SATISFIED
        and not full_health.reasons
        and full["ranges_underreplicated_sum"] == 0
        and full["ranges_unavailable_sum"] == 0
    )
    serving_ready = (
        serving_health.status is ProbeStatus.SATISFIED
        and not serving_health.reasons
        and serving["ranges_unavailable_sum"] == 0
    )
    return sample, full_ready and serving_ready


def wait_for_policy_carryover_health(
    library: Any,
    ref: WorkloadRef,
    *,
    expected_node_ids: tuple[int, ...],
    on_sample: Any,
    timeout: float = 30.0,
    poll_interval: float = 2.0,
    per_node_timeout: float = 5.0,
    monotonic=time.monotonic,
    sleep=time.sleep,
) -> dict[str, Any]:
    """Wait for actual health after policy carryover and retain every sample.

    Unlike the original under-replication proof mode, this operation does not
    expect a five-replica table policy to make a three-node cluster unhealthy.
    """
    if not math.isfinite(timeout) or timeout <= 0 or not math.isfinite(poll_interval) or poll_interval <= 0:
        raise ValueError("policy-carryover timeout and poll interval must be finite and positive")
    deadline = monotonic() + timeout
    attempts = 0
    while True:
        attempts += 1
        try:
            full = library.probe_full_health(ref, per_node_timeout=per_node_timeout)
            serving = library.probe_serving_health(ref, per_node_timeout=per_node_timeout)
            sample, ready = _policy_carryover_sample(
                full,
                serving,
                expected_node_ids=expected_node_ids,
                attempt=attempts,
            )
        except (TransientError, RolloutInProgressError) as error:
            sample = {
                "attempt": attempts,
                "transient_error_type": type(error).__name__,
            }
            on_sample(sample)
            ready = False
        except BaseException as error:
            on_sample(
                {
                    "attempt": attempts,
                    "error_type": type(error).__name__,
                }
            )
            raise
        else:
            on_sample(sample)
        if ready:
            return {"attempts": attempts, "last_sample": sample}
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise _AUDIT._BASE.SmokeFailure(
                "Policy-carryover health did not reach a healthy serving/full-health observation"
            )
        sleep(min(poll_interval, remaining))


def _zone_policy_replica_count(fixture: Any, *, tls: bool) -> int:
    output = _AUDIT._sql(
        fixture,
        "SELECT full_config_yaml FROM [SHOW ZONE CONFIGURATION FOR TABLE " + _WITNESS_TABLE + "]",
        tls=tls,
    )
    rows = list(csv.DictReader(io.StringIO(output)))
    if len(rows) != 1 or not rows[0].get("full_config_yaml"):
        raise _AUDIT._BASE.SmokeFailure("Witness table zone policy did not return one effective configuration")
    config = yaml.safe_load(rows[0]["full_config_yaml"])
    if not isinstance(config, dict) or type(config.get("num_replicas")) is not int:
        raise _AUDIT._BASE.SmokeFailure("Witness table zone policy omitted an integer replica count")
    return config["num_replicas"]


def _run_zone_environment_units(fixture: Any, trusted_input: Mapping[str, Any]) -> list[dict[str, Any]]:
    modes = ("probe", "apply", "verify")
    events = []
    with zone_case_environment(fixture):
        for mode in modes:
            events.append(
                _AUDIT.run_case_command(
                    fixture,
                    ZONE_PREPARE,
                    ("environment", mode),
                    timeout={"probe": 300, "apply": 300, "verify": 300}[mode],
                    trusted_input=trusted_input,
                )
            )
    return events


def _run_tls_zone_phase(
    args: argparse.Namespace,
    run_id: str,
    evidence_dir: Path,
    *,
    proof: str = "underreplication",
) -> dict[str, Any]:
    if proof not in _PROOF_MODES:
        raise ValueError(f"Unsupported zone proof mode: {proof}")
    fixture = _AUDIT.AuditFixture(args, "tls", run_id)
    fixture.stage_id = "zone-config-smoke"
    phase_data: dict[str, Any] = {
        "phase": f"tls-zone-{proof}",
        "run_id": run_id,
        "namespace": fixture.namespace,
        "tls_mode": "TLS",
        "proof_mode": proof,
        "proof_scope": (
            "actual zone environment probe/apply/verify with an owned five-replica witness policy; "
            "observe health without expecting positive under-replication; no task units, oracle, or fresh bootstrap"
            if proof == "policy-carryover"
            else "actual zone environment probe/apply/verify plus an owned under-replication observation; "
            "no task units, oracle, or fresh bootstrap"
        ),
    }
    fixture.phase_data = phase_data
    failure: BaseException | None = None
    cleanup_failure: BaseException | None = None

    def checkpoint(status: str) -> None:
        _AUDIT._BASE.write_json_atomic(
            evidence_dir / "tls-journal.json",
            {
                "phase": phase_data["phase"],
                "run_id": run_id,
                "namespace": fixture.namespace,
                "status": status,
                "namespace_uid": fixture.namespace_uid,
                "namespace_baseline": sorted(fixture.namespace_baseline),
                "owned_resource_uids": [
                    {"kind": kind, "name": name, "uid": uid}
                    for (kind, name), uid in sorted(fixture.created.items())
                ],
                "safe_observations": phase_data,
            },
        )

    fixture.checkpoint_callback = checkpoint
    checkpoint("preflight-started")
    try:
        fixture.set_stage("three-node-capacity-preflight")
        capacity = _AUDIT._HEALTH.preflight(args, fixture)
        fixture.storage_class = capacity["storage_class"]
        phase_data["capacity_preflight"] = capacity
        checkpoint("preflight-passed")

        fixture.set_stage("create-isolated-namespace")
        fixture.prepare_namespace()
        _AUDIT._create_existing_fixture(args, fixture, tls=True, phase_data=phase_data)
        phase_data["startup"] = _AUDIT._initialize_fixture(fixture, tls=True, timeout=args.ready_timeout)

        fixture.set_stage("create-owned-witness-and-controlled-setting")
        _AUDIT._controlled_setting(fixture, tls=True)
        phase_data["controlled_setting_before"] = _AUDIT._read_controlled_setting(fixture, tls=True)
        witness = _AUDIT._create_witness(fixture, tls=True)
        policy_before = _zone_policy_replica_count(fixture, tls=True)
        if policy_before != _NODE_COUNT:
            raise _AUDIT._BASE.SmokeFailure("New witness table did not begin with the selected three-node policy")

        library, ref = _AUDIT._library(fixture)
        initial_full, initial_node_ids = _wait_for_fully_replicated_baseline(library, ref)
        accepted, pod_uids, witness_before = _AUDIT._snapshot_inherited(fixture, tls=True)
        if witness_before != witness:
            raise _AUDIT._BASE.SmokeFailure("Witness changed while capturing the accepted pre-policy snapshot")
        phase_data["pre_policy_baseline"] = {
            "full_health": initial_full.status.value,
            "node_ids": initial_node_ids,
            "underreplicated_count_sum": 0,
            "unavailable_count_sum": 0,
            "witness_policy_num_replicas": policy_before,
            "accepted_state": _AUDIT._accepted_summary(accepted),
            "pod_uids": pod_uids,
            "witness_row_count": witness_before[0],
            "witness_sha256": witness_before[1],
            "controlled_setting": phase_data["controlled_setting_before"],
        }
        checkpoint("fully-replicated-pre-policy-baseline-recorded")

        fixture.set_stage("apply-owned-witness-five-replica-policy")
        _AUDIT._sql(fixture, _WITNESS_POLICY_SQL, tls=True)
        phase_data["witness_policy_num_replicas_after"] = _zone_policy_replica_count(fixture, tls=True)
        if phase_data["witness_policy_num_replicas_after"] != 5:
            raise _AUDIT._BASE.SmokeFailure("Owned witness table did not retain its five-replica policy")
        if proof == "underreplication":
            phase_data["underreplication_evidence"] = wait_for_underreplication(
                library, ref, expected_node_ids=initial_node_ids, timeout=90
            )
            checkpoint("serving-health-satisfied-full-health-rejected-underreplication-proven")
        else:
            phase_data["policy_health_samples_after_policy"] = []

            def record_policy_sample(sample: dict[str, Any]) -> None:
                phase_data["policy_health_samples_after_policy"].append(sample)
                checkpoint("policy-carryover-health-sample-recorded")

            phase_data["policy_health_after_policy"] = wait_for_policy_carryover_health(
                library,
                ref,
                expected_node_ids=initial_node_ids,
                on_sample=record_policy_sample,
            )
            checkpoint("five-replica-policy-carryover-health-confirmed")

        fixture.set_stage("actual-zone-environment-probe-apply-verify")
        trusted_input = {"key": Fernet.generate_key().decode("ascii"), "frozen": False}
        phase_data["zone_environment_commands"] = _run_zone_environment_units(
            fixture, trusted_input
        )
        phase_data["stage_key_written_to_evidence"] = False

        fixture.set_stage("verify-policy-setting-and-state-preservation")
        policy_after = _zone_policy_replica_count(fixture, tls=True)
        if policy_after != 5:
            raise _AUDIT._BASE.SmokeFailure("Zone environment preparation changed the witness-only policy")
        setting_after = _AUDIT._read_controlled_setting(fixture, tls=True)
        if setting_after.replace(" ", "").casefold() != phase_data["controlled_setting_before"].replace(" ", "").casefold():
            raise _AUDIT._BASE.SmokeFailure("Zone environment preparation changed the controlled cluster setting")
        phase_data["preservation"] = _AUDIT._assert_preserved(
            fixture,
            tls=True,
            accepted=accepted,
            pods=pod_uids,
            witness=witness_before,
        )
        phase_data["witness_policy_num_replicas_after_commands"] = policy_after
        phase_data["controlled_setting_after"] = setting_after
        phase_data["witness_policy_was_scoped_to_owned_table"] = True
        if proof == "policy-carryover":
            phase_data["policy_health_samples_after_commands"] = []

            def record_command_sample(sample: dict[str, Any]) -> None:
                phase_data["policy_health_samples_after_commands"].append(sample)
                checkpoint("policy-carryover-post-command-sample-recorded")

            phase_data["policy_health_after_commands"] = wait_for_policy_carryover_health(
                library,
                ref,
                expected_node_ids=initial_node_ids,
                on_sample=record_command_sample,
            )
        else:
            phase_data["underreplication_after_commands"] = wait_for_underreplication(
                library, ref, expected_node_ids=initial_node_ids, timeout=90
            )
        checkpoint("case-commands-and-preservation-verified")
    except BaseException as error:
        failure = error
        phase_data["failure_stage"] = fixture.stage_snapshot()
        phase_data["execution_failure"] = {
            "type": type(error).__name__,
            "detail": _AUDIT._BASE._safe_diagnostic_text(error)
            if _is_safe_smoke_failure(error)
            else "details withheld",
        }
        if _is_safe_smoke_failure(error) and error.command_event:
            phase_data["failure_command"] = dict(error.command_event)
        try:
            fixture.capture_diagnostics(phase_data, label="before-cleanup")
        except BaseException as diagnostic_error:
            phase_data["diagnostic_capture_failure"] = {
                "type": type(diagnostic_error).__name__,
                "detail": _AUDIT._BASE._safe_diagnostic_text(diagnostic_error),
            }

    try:
        fixture.cleanup()
        phase_data["cleanup_verdict"] = "completed with exact UID preconditions and normal deletion grace"
    except BaseException as error:
        cleanup_failure = error
        phase_data["cleanup_failure"] = {
            "type": type(error).__name__,
            "detail": _AUDIT._BASE._safe_diagnostic_text(error)
            if _is_safe_smoke_failure(error)
            else "details withheld",
        }
        phase_data["cleanup_verdict"] = "incomplete; ownership journal retained"
    phase_data["stage_timing"] = fixture.stage_snapshot()
    phase_data["command_trace"] = list(fixture.command_trace[-80:])
    phase_data["result"] = "passed" if failure is None and cleanup_failure is None else "failed"
    _AUDIT._BASE.write_json_atomic(evidence_dir / "tls-phase.json", phase_data)
    checkpoint("phase-finished")
    if failure or cleanup_failure:
        raise _AUDIT._BASE.SmokeFailure(
            f"zone-config TLS proof failed; inspect {evidence_dir / 'tls-phase.json'} and its ownership journal"
        ) from (failure or cleanup_failure)
    return phase_data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kubectl", default="kubectl")
    parser.add_argument("--docker", default="docker")
    parser.add_argument("--node", default="kind-worker")
    parser.add_argument("--image", default="cockroachdb/cockroach:v24.1.0")
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--ready-timeout", type=float, default=300.0)
    parser.add_argument("--proof", choices=_PROOF_MODES, required=True)
    args = parser.parse_args(argv)
    args.context = None
    if not math.isfinite(args.ready_timeout) or not 0 < args.ready_timeout <= 300:
        raise _AUDIT._BASE.SmokeFailure("Ready timeout must be finite and within its bounded range")
    if not _AUDIT._BASE.re.fullmatch(r"cockroachdb/cockroach:v24\.1\.0", args.image):
        raise _AUDIT._BASE.SmokeFailure("Zone proof supports only cached CockroachDB v24.1.0")
    if args.kubectl != "kubectl" and Path(args.kubectl).name != "kubectl":
        raise _AUDIT._BASE.SmokeFailure("Native case scripts require a kubectl executable named 'kubectl'")
    evidence_dir = args.evidence_dir.expanduser().resolve()
    if evidence_dir.exists():
        raise _AUDIT._BASE.SmokeFailure("Evidence directory must be new; refusing to overwrite previous records")
    evidence_dir.mkdir(parents=True, exist_ok=False)
    run_id = f"{time.strftime('%y%m%d')}-{os.getpid():x}"
    if not _AUDIT._BASE.re.fullmatch(r"[a-z0-9-]{1,16}", run_id):
        raise _AUDIT._BASE.SmokeFailure("Generated run identity is not a valid Kubernetes label")
    result = _run_tls_zone_phase(args, run_id, evidence_dir, proof=args.proof)
    _AUDIT._BASE.write_json_atomic(evidence_dir / "live-summary.json", {"run_id": run_id, "phase": result})
    print(f"Zone-config TLS case proof passed; safe evidence at {evidence_dir}", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except _AUDIT._BASE.SmokeFailure as error:
        print(f"ZONE-CONFIG CASE PROOF STOPPED: {error}", file=sys.stderr, flush=True)
        raise SystemExit(2)

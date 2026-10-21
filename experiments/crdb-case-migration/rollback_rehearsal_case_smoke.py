#!/usr/bin/env python3
"""Bounded inherited-TLS proof for rollback-rehearsal environment readiness.

Reuses the reviewed three-node HTTPS fixture, diagnostics, journal, and exact-UID
cleanup from the readonly-audit proof. It runs only rollback Environment
probe/apply/verify; it does not run the rollback oracle, task targets, or fresh
bootstrap path.
"""

from __future__ import annotations

import argparse
import csv
import importlib.util
import io
import json
import math
import os
from pathlib import Path
import sys
import time
from typing import Any, Callable

import yaml


ROOT = Path(__file__).resolve().parents[2]
AUDIT_PATH = ROOT / "experiments" / "crdb-case-migration" / "readonly_audit_case_smoke.py"
ROLLBACK_PREPARE = ROOT / "cases" / "cockroachdb" / "rollback-rehearsal" / "scripts" / "prepare.py"
_AUDIT_SPEC = importlib.util.spec_from_file_location("readonly_audit_case_smoke", AUDIT_PATH)
if _AUDIT_SPEC is None or _AUDIT_SPEC.loader is None:
    raise RuntimeError("Could not load the reviewed readonly-audit fixture helpers")
_AUDIT = importlib.util.module_from_spec(_AUDIT_SPEC)
_AUDIT_SPEC.loader.exec_module(_AUDIT)

_WITNESS_TABLE = _AUDIT._WITNESS_TABLE
_SAFE_SMOKE_FAILURE_TYPES = (
    _AUDIT._BASE.SmokeFailure,
    _AUDIT._HEALTH._BASE.SmokeFailure,
)


class EnvironmentProofCallbacks:
    """Case-specific hooks around the shared inherited-TLS proof lifecycle."""

    def __init__(
        self,
        *,
        case_name: str,
        phase_name: str,
        stage_id: str,
        proof_scope: str,
        command_stage: str,
        run_commands: Callable[[Any], list[dict[str, Any]]],
        prepare_controls: Callable[[Any, Callable[[dict[str, Any]], None]], Any] | None = None,
        verify_controls: Callable[
            [Any, Any, Callable[[dict[str, Any]], None]], dict[str, Any]
        ] | None = None,
    ) -> None:
        self.case_name = case_name
        self.phase_name = phase_name
        self.stage_id = stage_id
        self.proof_scope = proof_scope
        self.command_stage = command_stage
        self.run_commands = run_commands
        self.prepare_controls = prepare_controls
        self.verify_controls = verify_controls


def _is_safe_smoke_failure(error: BaseException) -> bool:
    return isinstance(error, _SAFE_SMOKE_FAILURE_TYPES)


def _gc_ttl_seconds(fixture: Any, query: str, label: str) -> int:
    output = _AUDIT._sql(
        fixture,
        query,
        tls=True,
    )
    rows = list(csv.DictReader(io.StringIO(output)))
    if len(rows) != 1 or not rows[0].get("full_config_yaml"):
        raise _AUDIT._BASE.SmokeFailure(f"{label} GC policy did not return one effective configuration")
    try:
        config = yaml.safe_load(rows[0]["full_config_yaml"])
    except yaml.YAMLError as error:
        raise _AUDIT._BASE.SmokeFailure(f"{label} GC policy returned invalid YAML") from error
    gc = config.get("gc") if isinstance(config, dict) else None
    ttl = gc.get("ttlseconds") if isinstance(gc, dict) else None
    if type(ttl) is not int:
        raise _AUDIT._BASE.SmokeFailure(f"{label} GC policy omitted an integer TTL")
    return ttl


def _table_gc_ttl_seconds(fixture: Any) -> int:
    return _gc_ttl_seconds(
        fixture,
        "SELECT full_config_yaml FROM [SHOW ZONE CONFIGURATION FOR TABLE " + _WITNESS_TABLE + "]",
        "Witness table",
    )


def _range_default_gc_ttl_seconds(fixture: Any) -> int:
    return _gc_ttl_seconds(
        fixture,
        "SELECT full_config_yaml FROM crdb_internal.zones WHERE target='RANGE default'",
        "Range default",
    )


def _set_owned_witness_gc_policy(fixture: Any, *, record_observation: Any) -> dict[str, int]:
    range_default_ttl = _range_default_gc_ttl_seconds(fixture)
    requested_ttl = 7200 if range_default_ttl == 3600 else 3600
    observation: dict[str, Any] = {
        "range_default_ttl_seconds": range_default_ttl,
        "requested_table_ttl_seconds": requested_ttl,
        "table_readback_ttl_seconds": None,
    }
    record_observation(dict(observation))
    _AUDIT._sql(
        fixture,
        f"ALTER TABLE {_WITNESS_TABLE} CONFIGURE ZONE USING gc.ttlseconds = {requested_ttl}",
        tls=True,
    )
    try:
        observed = _table_gc_ttl_seconds(fixture)
    except BaseException as error:
        observation["table_readback_error_type"] = type(error).__name__
        record_observation(dict(observation))
        raise
    observation["table_readback_ttl_seconds"] = observed
    record_observation(dict(observation))
    if observed != requested_ttl:
        raise _AUDIT._BASE.SmokeFailure("Owned witness table GC policy did not read back at the requested value")
    if observed == range_default_ttl:
        raise _AUDIT._BASE.SmokeFailure("Owned witness table GC policy did not differ from the range default")
    return observation


def _run_environment_probe_apply_verify(fixture: Any) -> list[dict[str, Any]]:
    fixture.stage_id = "rollback-rehearsal-smoke"
    commands = []
    for mode in ("probe", "apply", "verify"):
        commands.append(
            _AUDIT.run_case_command(
                fixture,
                ROLLBACK_PREPARE,
                ("environment", mode),
                timeout=180,
            )
        )
    return commands


def _run_rollback_environment_commands(fixture: Any) -> list[dict[str, Any]]:
    # Keep the default case path dynamically bound to its established command
    # runner, while callers with a different contract pass an explicit hook.
    return _run_environment_probe_apply_verify(fixture)


ROLLBACK_ENVIRONMENT_PROOF = EnvironmentProofCallbacks(
    case_name="rollback-rehearsal",
    phase_name="tls-inherited-environment",
    stage_id="rollback-rehearsal-smoke",
    proof_scope=(
        "actual rollback Environment probe/apply/verify on an inherited native-shaped HTTPS cluster; "
        "controlled setting, owned witness-table GC policy, accepted state, Pods, and SQL rows are checked; "
        "no rollback oracle, task targets, or fresh bootstrap"
    ),
    command_stage="actual-rollback-environment-probe-apply-verify",
    run_commands=_run_rollback_environment_commands,
)


def _assert_preserved(
    fixture: Any,
    *,
    accepted: Any,
    pod_uids: dict[str, str],
    witness: tuple[int, str],
    setting_value: str,
    gc_policy: dict[str, int],
) -> dict[str, Any]:
    preserved = _AUDIT._assert_preserved(
        fixture,
        tls=True,
        accepted=accepted,
        pods=pod_uids,
        witness=witness,
    )
    setting_after = _AUDIT._read_controlled_setting(fixture, tls=True)
    if setting_after.replace(" ", "").casefold() != setting_value.replace(" ", "").casefold():
        raise _AUDIT._BASE.SmokeFailure("Rollback environment preparation changed the controlled cluster setting")
    gc_after = _table_gc_ttl_seconds(fixture)
    range_default_after = _range_default_gc_ttl_seconds(fixture)
    if (
        gc_after != gc_policy["table_readback_ttl_seconds"]
        or gc_after != gc_policy["requested_table_ttl_seconds"]
        or range_default_after != gc_policy["range_default_ttl_seconds"]
    ):
        raise _AUDIT._BASE.SmokeFailure("Rollback environment preparation changed the owned witness table GC policy")
    if gc_after == range_default_after:
        raise _AUDIT._BASE.SmokeFailure("Owned witness table GC policy no longer differs from the range default")

    return {
        **preserved,
        "controlled_setting": setting_after,
        "owned_witness_table_gc_ttl_seconds": gc_after,
        "range_default_gc_ttl_seconds": range_default_after,
    }


def _run_tls_phase(
    args: argparse.Namespace,
    run_id: str,
    evidence_dir: Path,
    *,
    proof: EnvironmentProofCallbacks = ROLLBACK_ENVIRONMENT_PROOF,
) -> dict[str, Any]:
    fixture = _AUDIT.AuditFixture(args, "tls", run_id)
    fixture.stage_id = proof.stage_id
    phase_data: dict[str, Any] = {
        "phase": proof.phase_name,
        "run_id": run_id,
        "namespace": fixture.namespace,
        "tls_mode": "TLS",
        "case": proof.case_name,
        "proof_scope": proof.proof_scope,
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

    def record_case_observation(observation: dict[str, Any]) -> None:
        phase_data.setdefault("case_control_observations", []).append(dict(observation))
        checkpoint("case-control-observation-recorded")

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

        fixture.set_stage("create-witness-and-preservation-controls")
        setting_value = _AUDIT._controlled_setting(fixture, tls=True)
        witness = _AUDIT._create_witness(fixture, tls=True)
        def record_gc_policy_observation(observation: dict[str, Any]) -> None:
            phase_data["witness_gc_policy_observation"] = observation
            checkpoint("witness-gc-policy-observation-recorded")

        gc_policy = _set_owned_witness_gc_policy(
            fixture,
            record_observation=record_gc_policy_observation,
        )
        case_controls = None
        if proof.prepare_controls is not None:
            fixture.set_stage(f"prepare-{proof.case_name}-environment-controls")
            case_controls = proof.prepare_controls(fixture, record_case_observation)
        accepted, pod_uids, captured_witness = _AUDIT._snapshot_inherited(fixture, tls=True)
        if captured_witness != witness:
            raise _AUDIT._BASE.SmokeFailure("Witness changed while capturing the accepted pre-apply state")

        phase_data["initial_preservation_state"] = {
            "accepted_state": _AUDIT._accepted_summary(accepted),
            "pod_uids": pod_uids,
            "witness_row_count": witness[0],
            "witness_sha256": witness[1],
            "controlled_setting": setting_value,
            "owned_witness_table_gc_ttl_seconds": gc_policy["table_readback_ttl_seconds"],
            "range_default_gc_ttl_seconds": gc_policy["range_default_ttl_seconds"],
        }
        checkpoint("preservation-controls-recorded")

        fixture.set_stage(proof.command_stage)
        phase_data["environment_commands"] = proof.run_commands(fixture)
        phase_data["stage_key_values_written_to_evidence"] = False

        fixture.set_stage("verify-workload-setting-policy-and-witness-preservation")
        phase_data["preservation"] = _assert_preserved(
            fixture,
            accepted=accepted,
            pod_uids=pod_uids,
            witness=witness,
            setting_value=setting_value,
            gc_policy=gc_policy,
        )
        if proof.verify_controls is not None:
            fixture.set_stage(f"verify-{proof.case_name}-environment-controls")
            phase_data["case_control_preservation"] = proof.verify_controls(
                fixture,
                case_controls,
                record_case_observation,
            )
        checkpoint("environment-commands-and-preservation-verified")
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
            f"{proof.case_name} TLS proof failed; inspect {evidence_dir / 'tls-phase.json'} and its ownership journal"
        ) from (failure or cleanup_failure)
    return phase_data


def main(
    argv: list[str] | None = None,
    *,
    proof: EnvironmentProofCallbacks = ROLLBACK_ENVIRONMENT_PROOF,
) -> int:
    parser = argparse.ArgumentParser(description=proof.proof_scope)
    parser.add_argument("--kubectl", default="kubectl")
    parser.add_argument("--docker", default="docker")
    parser.add_argument("--node", default="kind-worker")
    parser.add_argument("--image", default="cockroachdb/cockroach:v24.1.0")
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--ready-timeout", type=float, default=300.0)
    args = parser.parse_args(argv)
    args.context = None
    if not math.isfinite(args.ready_timeout) or not 0 < args.ready_timeout <= 300:
        raise _AUDIT._BASE.SmokeFailure("Ready timeout must be finite and within its bounded range")
    if args.image != "cockroachdb/cockroach:v24.1.0":
        raise _AUDIT._BASE.SmokeFailure("Inherited environment proof supports only cached CockroachDB v24.1.0")
    if args.kubectl != "kubectl" and Path(args.kubectl).name != "kubectl":
        raise _AUDIT._BASE.SmokeFailure("Native case scripts require a kubectl executable named 'kubectl'")
    evidence_dir = args.evidence_dir.expanduser().resolve()
    if evidence_dir.exists():
        raise _AUDIT._BASE.SmokeFailure("Evidence directory must be new; refusing to overwrite previous records")
    evidence_dir.mkdir(parents=True, exist_ok=False)
    run_id = f"{time.strftime('%y%m%d')}-{os.getpid():x}"
    if not _AUDIT._BASE.re.fullmatch(r"[a-z0-9-]{1,16}", run_id):
        raise _AUDIT._BASE.SmokeFailure("Generated run identity is not a valid Kubernetes label")
    result = _run_tls_phase(args, run_id, evidence_dir, proof=proof)
    _AUDIT._BASE.write_json_atomic(
        evidence_dir / "live-summary.json",
        {"run_id": run_id, "case": proof.case_name, "phase": result},
    )
    print(f"{proof.case_name} TLS environment proof passed; safe evidence at {evidence_dir}", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except _AUDIT._BASE.SmokeFailure as error:
        print(f"ROLLBACK-REHEARSAL CASE PROOF STOPPED: {error}", file=sys.stderr, flush=True)
        raise SystemExit(2)

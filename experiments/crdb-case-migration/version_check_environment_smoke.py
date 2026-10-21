#!/usr/bin/env python3
"""Bounded inherited-TLS proof for version-check Environment readiness."""

from __future__ import annotations

import csv
import importlib.util
import io
from pathlib import Path
import re
import sys
from typing import Any, Callable

from cryptography.fernet import Fernet


ROOT = Path(__file__).resolve().parents[2]
ROLLBACK_PATH = ROOT / "experiments" / "crdb-case-migration" / "rollback_rehearsal_case_smoke.py"
VERSION_PREPARE = ROOT / "cases" / "cockroachdb" / "version-check" / "scripts" / "prepare.py"
_ROLLBACK_SPEC = importlib.util.spec_from_file_location("rollback_rehearsal_case_smoke", ROLLBACK_PATH)
if _ROLLBACK_SPEC is None or _ROLLBACK_SPEC.loader is None:
    raise RuntimeError("Could not load the shared inherited-TLS proof orchestration")
_ROLLBACK = importlib.util.module_from_spec(_ROLLBACK_SPEC)
_ROLLBACK_SPEC.loader.exec_module(_ROLLBACK)
_AUDIT = _ROLLBACK._AUDIT

_ACTIVE_VERSION = re.compile(r"v?\d+\.\d+(?:\.\d+)?")


def _setting(fixture: Any, name: str, *, allow_empty: bool = False) -> str:
    output = _AUDIT._sql(fixture, f"SHOW CLUSTER SETTING {name}", tls=True)
    rows = list(csv.reader(io.StringIO(output)))
    if allow_empty and rows == [[name]]:
        return ""
    if len(rows) != 2 or any(len(row) != 1 for row in rows):
        raise _AUDIT._BASE.SmokeFailure(f"Version-check {name} observation did not return one CSV value")
    return rows[1][0].strip()


def _prepare_active_version_hold(
    fixture: Any,
    record_observation: Callable[[dict[str, Any]], None],
) -> dict[str, str]:
    active = _setting(fixture, "version", allow_empty=True)
    observation: dict[str, Any] = {
        "stage": "before-environment-commands",
        "active_feature_version": active,
        "requested_preserve_downgrade_option": active,
        "preserve_downgrade_option_readback": None,
    }
    record_observation(dict(observation))
    if not active or not _ACTIVE_VERSION.fullmatch(active):
        raise _AUDIT._BASE.SmokeFailure("Version-check fixture did not report a supported active feature version")

    _AUDIT._sql(
        fixture,
        f"SET CLUSTER SETTING cluster.preserve_downgrade_option = '{active}'",
        tls=True,
    )
    hold_readback = _setting(fixture, "cluster.preserve_downgrade_option")
    observation["preserve_downgrade_option_readback"] = hold_readback
    record_observation(dict(observation))
    if hold_readback != active:
        raise _AUDIT._BASE.SmokeFailure("Version-check fixture could not hold the observed active feature version")
    return {
        "active_feature_version": active,
        "preserve_downgrade_option": hold_readback,
    }


def _verify_active_version_hold(
    fixture: Any,
    expected: dict[str, str],
    record_observation: Callable[[dict[str, Any]], None],
) -> dict[str, str]:
    active_after = _setting(fixture, "version")
    hold_after = _setting(fixture, "cluster.preserve_downgrade_option")
    observation = {
        "stage": "after-environment-commands",
        "expected_active_feature_version": expected["active_feature_version"],
        "active_feature_version_after": active_after,
        "expected_preserve_downgrade_option": expected["preserve_downgrade_option"],
        "hold_after": hold_after,
    }
    record_observation(observation)
    if (
        active_after != expected["active_feature_version"]
        or hold_after != expected["preserve_downgrade_option"]
    ):
        raise _AUDIT._BASE.SmokeFailure("Version-check environment preparation changed the active version or hold")
    return observation


def _run_environment_probe_apply_verify(fixture: Any) -> list[dict[str, Any]]:
    private_input = {"key": Fernet.generate_key().decode("ascii"), "frozen": False}
    fixture.phase_data["version_check_trusted_input"] = {
        "provided_on_stdin": True,
        "frozen": False,
        "key_written_to_evidence": False,
    }
    commands = []
    for mode in ("probe", "apply", "verify"):
        commands.append(
            _AUDIT.run_case_command(
                fixture,
                VERSION_PREPARE,
                ("environment", mode),
                timeout=180,
                trusted_input=private_input,
            )
        )
    return commands


VERSION_CHECK_PROOF = _ROLLBACK.EnvironmentProofCallbacks(
    case_name="version-check",
    phase_name="tls-inherited-version-check-environment",
    stage_id="version-check-environment-smoke",
    proof_scope=(
        "actual version-check Environment probe/apply/verify on an inherited native-shaped HTTPS cluster; "
        "active feature version, preserve-downgrade hold, controlled setting, witness-table GC policy, "
        "accepted state, Pods, and SQL rows are checked; no Gap.apply, version transition, task oracle, or fresh bootstrap"
    ),
    command_stage="actual-version-check-environment-probe-apply-verify",
    run_commands=_run_environment_probe_apply_verify,
    prepare_controls=_prepare_active_version_hold,
    verify_controls=_verify_active_version_hold,
)


def main(argv: list[str] | None = None) -> int:
    return _ROLLBACK.main(argv, proof=VERSION_CHECK_PROOF)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except _AUDIT._BASE.SmokeFailure as error:
        print(f"VERSION-CHECK ENVIRONMENT PROOF STOPPED: {error}", file=sys.stderr, flush=True)
        raise SystemExit(2)

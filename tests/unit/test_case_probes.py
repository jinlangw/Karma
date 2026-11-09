"""Guard against the always-pass precondition probe anti-pattern.

A precondition probe signals "is the target state already present?" via its
exit code: exit 0 -> present (skip apply), non-zero -> absent (run apply).
A probe that can never fail (e.g. ending in ``|| true``) makes the harness
believe the scenario is always already set up, so the apply that deploys the
workload is silently skipped. A port once did exactly this to 57 cases
(``kubectl get pods | grep -c Running || true``), leaving every StatefulSet
case undeployed. This test keeps that from recurring.
"""
from pathlib import Path

import pytest
import yaml

RES = Path(__file__).resolve().parents[2] / "cases" / "tests"


def _probe_commands(unit):
    raw = unit.get("probe") or unit.get("probe_commands") or []
    out = []
    for item in raw if isinstance(raw, list) else [raw]:
        if isinstance(item, dict):
            cmd = item.get("command", "")
        else:
            cmd = item
        out.append(cmd if isinstance(cmd, str) else " ".join(cmd))
    return out


def _all_cases():
    return sorted(RES.glob("*/*/test.yaml"))


@pytest.mark.parametrize("case_file", _all_cases(), ids=lambda p: f"{p.parent.parent.name}/{p.parent.name}")
def test_no_always_pass_probe(case_file):
    data = yaml.safe_load(case_file.read_text()) or {}
    units = data.get("preconditionUnits") or data.get("precondition_units") or []
    for unit in units:
        for cmd in _probe_commands(unit):
            stripped = cmd.strip()
            # A probe that unconditionally exits 0 defeats the readiness gate.
            assert not stripped.endswith("|| true"), (
                f"{case_file}: probe ends in '|| true' (always passes -> apply "
                f"skipped -> workload never deployed): {cmd!r}"
            )

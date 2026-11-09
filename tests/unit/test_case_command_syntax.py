"""Shell-syntax guard for every case command.

The harness runs precondition/oracle commands via ``subprocess.run(cmd,
shell=True)`` -> ``/bin/sh -c "<cmd>"``. A command that is not valid shell
(e.g. ``mongosh --eval '...'`` nested inside ``/bin/sh -c '...'``, where the
inner quote closes the outer one) fails at parse time. A port introduced dozens
of these across mongodb cases. ``sh -n`` (parse, no exec) is exactly the check
the harness's shell would do, so this lints every command without a cluster.
"""
import subprocess
from pathlib import Path

import pytest
import yaml

RES = Path(__file__).resolve().parents[2] / "cases" / "tests"


def _items(block):
    if block is None:
        return []
    if isinstance(block, str):
        return [block]
    out = []
    for it in block:
        if isinstance(it, dict):
            c = it.get("command", "")
            out.append(c if isinstance(c, str) else " ".join(c) if isinstance(c, list) else "")
        elif isinstance(it, str):
            out.append(it)
    return out


def _commands(data):
    out = []
    for u in (data.get("preconditionUnits") or []):
        for k in ("probe", "apply", "verify"):
            out += _items(u.get(k))
    oracle = data.get("oracle") or {}
    for k in ("verify", "before", "after"):
        v = oracle.get(k)
        if isinstance(v, dict):
            out += _items(v.get("commands"))
    return [c for c in out if c and c.strip()]


@pytest.mark.parametrize("case_file", sorted(RES.glob("*/*/test.yaml")),
                         ids=lambda p: f"{p.parent.parent.name}/{p.parent.name}")
def test_commands_are_valid_shell(case_file):
    data = yaml.safe_load(case_file.read_text()) or {}
    for cmd in _commands(data):
        r = subprocess.run(["/bin/sh", "-n", "-c", cmd], capture_output=True, text=True)
        assert r.returncode == 0, (
            f"{case_file}: shell syntax error: {r.stderr.strip()}\n  cmd: {cmd[:200]!r}"
        )

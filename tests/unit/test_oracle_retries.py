"""Unit tests for case-authored oracle verify retries (M6).

An eventually-consistent oracle check can author `oracle.verify.retries` /
`interval_sec` so the verify re-runs on FAIL instead of losing the race once.
The normalizer must surface those fields (it silently dropped them) and
run_oracle must honor them without disturbing the transient-blip retry or a
genuine, non-converging FAIL.
"""

import tempfile
from pathlib import Path
from unittest.mock import patch

import karma.oracle as O
from karma.definitions.cases import normalize_oracle_config


def _run(cfg, seq):
    """Run run_oracle with _evaluate_oracle returning verdicts from `seq`."""
    calls = {"n": 0}

    def fake_eval(_cfg, **_kw):
        r = seq[min(calls["n"], len(seq) - 1)]
        calls["n"] += 1
        return {"verdict": r, "output": r, "error": None}

    with patch.object(O, "_evaluate_oracle", side_effect=fake_eval):
        with tempfile.TemporaryDirectory() as d:
            res = O.run_oracle(cfg, role_bindings={}, run_dir=Path(d), stage_id="s1")
    return res, calls["n"]


class TestOracleVerifyRetries:
    def test_normalizer_surfaces_retries(self):
        c = normalize_oracle_config(
            {"oracle": {"verify": {"commands": ["true"], "retries": 5, "interval_sec": 0.1}}})
        assert c["verify_retries"] == 5
        assert c["verify_interval_sec"] == 0.1

    def test_normalizer_defaults_to_single_check(self):
        c = normalize_oracle_config({"oracle": {"verify": {"commands": ["true"]}}})
        assert c["verify_retries"] == 1

    def test_converging_check_retries_then_passes(self):
        cfg = {"verify_commands": [{"command": "x"}],
               "verify_retries": 3, "verify_interval_sec": 0.0}
        res, n = _run(cfg, ["fail", "fail", "pass"])
        assert res["verdict"] == "pass"
        assert n == 3

    def test_genuine_fail_is_not_retried_by_default(self):
        # retries defaults to 1: a real (non-transient) FAIL is trusted at once.
        cfg = {"verify_commands": [{"command": "x"}],
               "verify_retries": 1, "verify_interval_sec": 0.0}
        res, n = _run(cfg, ["fail", "pass"])  # would pass on retry, but must not retry
        assert res["verdict"] == "fail"
        assert n == 1

    def test_still_fails_if_never_converges(self):
        cfg = {"verify_commands": [{"command": "x"}],
               "verify_retries": 3, "verify_interval_sec": 0.0}
        res, n = _run(cfg, ["fail"])  # always fails
        assert res["verdict"] == "fail"
        assert n == 3


class TestEmptyOracleGuard:
    """SR3 runtime guard: an oracle that checks nothing must never be a pass.

    normalize_case rejects an empty oracle at load, but _evaluate_oracle also
    guards any path that builds an oracle_config directly (e.g. a standalone
    run_oracle call). _run_commands([]) returns ok=True, which would otherwise
    score as an unconditional "pass".
    """

    def test_no_verify_and_no_script_is_error(self):
        with tempfile.TemporaryDirectory() as d:
            res = O.run_oracle(
                {"verify_commands": [], "script_path": None},
                role_bindings={}, run_dir=Path(d), stage_id="s1",
            )
        assert res["verdict"] == "error"
        assert "nothing was checked" in (res.get("error") or "")

    def test_script_only_oracle_is_allowed(self):
        # A script-backed oracle (no verify commands) checks something, so the
        # guard must NOT fire -- it runs the script and reports its verdict.
        with tempfile.TemporaryDirectory() as d:
            res = O.run_oracle(
                {"verify_commands": [], "script_path": "/nonexistent/oracle.py"},
                role_bindings={}, run_dir=Path(d), stage_id="s1",
            )
        # The script path is bogus, so the verify fails -- but crucially the
        # verdict is NOT a fabricated "pass" and NOT the empty-oracle "error".
        assert res["verdict"] == "fail"

"""Unit tests for karma.runtime.case."""

import time
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch
from karma.runtime.case import _wait_for_submit, _run_operation_units


class TestWaitForSubmit:
    def test_returns_true_when_file_appears(self, tmp_path):
        submit = tmp_path / "submit.txt"
        submit.write_text("done")
        found, content, exited = _wait_for_submit(submit, agent_timeout_sec=5)
        assert found is True
        assert content == "done"
        assert exited is False

    def test_returns_false_on_timeout(self, tmp_path):
        submit = tmp_path / "submit.txt"
        found, content, exited = _wait_for_submit(
            submit, agent_timeout_sec=0, poll_interval_sec=0.01
        )
        assert found is False
        assert content is None
        assert exited is False

    def test_reads_content_correctly(self, tmp_path):
        submit = tmp_path / "submit.txt"
        submit.write_text("agent answer here")
        _, content, _exited = _wait_for_submit(submit, agent_timeout_sec=5)
        assert content == "agent answer here"

    def test_agent_exit_ends_wait_without_submit(self, tmp_path):
        # A process that has stopped before writing submit.txt ends the wait
        # immediately with agent_exited=True instead of burning the timeout.
        class _Dead:
            def is_running(self):
                return False
        submit = tmp_path / "submit.txt"
        found, content, exited = _wait_for_submit(
            submit, agent_timeout_sec=30, poll_interval_sec=0.01,
            agent_process=_Dead(),
        )
        assert found is False
        assert exited is True


class TestRunOperationUnits:
    def test_returns_ok_false_when_apply_fails(self, tmp_path):
        # Probe fails (precondition not yet satisfied), so the apply path
        # runs; when apply itself fails the unit is reported as not ok.
        units = [
            {
                "id": "unit:precondition",
                "probe_commands": [{"command": "false", "sleep": 0}],
                "apply_commands": [{"command": "false", "sleep": 0}],
                "verify_commands": [{"command": "echo verify", "sleep": 0}],
                "verify_retries": 1,
                "verify_interval_sec": 0.0,
                "on_probe_fail": "error",
            }
        ]
        log = tmp_path / "ops.log"
        result = _run_operation_units(
            units, role_bindings={}, log_path=log
        )
        assert result["ok"] is False

    def test_returns_ok_true_on_success(self, tmp_path):
        units = [
            {
                "id": "unit:precondition",
                "probe_commands": [{"command": "true", "sleep": 0}],
                "apply_commands": [{"command": "true", "sleep": 0}],
                "verify_commands": [{"command": "true", "sleep": 0}],
                "verify_retries": 1,
                "verify_interval_sec": 0.0,
                "on_probe_fail": "error",
            }
        ]
        log = tmp_path / "ops.log"
        result = _run_operation_units(
            units, role_bindings={}, log_path=log
        )
        assert result["ok"] is True

    def test_skip_on_probe_fail_does_not_error(self, tmp_path):
        units = [
            {
                "id": "unit:precondition",
                "probe_commands": [{"command": "false", "sleep": 0}],
                "apply_commands": [{"command": "true", "sleep": 0}],
                "verify_commands": [{"command": "true", "sleep": 0}],
                "verify_retries": 1,
                "verify_interval_sec": 0.0,
                "on_probe_fail": "skip",
            }
        ]
        log = tmp_path / "ops.log"
        result = _run_operation_units(
            units, role_bindings={}, log_path=log
        )
        assert result["ok"] is True

    def test_error_gate_retries_probe_until_it_converges(self, tmp_path):
        # An on_probe_fail="error" gate is a readiness/convergence condition the
        # apply cannot create. Under load it may need a few seconds to settle, so
        # the probe is retried up to verify_retries times before failing. Here the
        # probe passes only on its 3rd try (counter file): with verify_retries=5
        # the unit must converge to ok rather than failing on the one-shot first
        # sample.
        counter = tmp_path / "n"
        probe = (
            f'n=$(cat {counter} 2>/dev/null || echo 0); n=$((n+1)); '
            f'echo $n > {counter}; [ "$n" -ge 3 ]'
        )
        units = [
            {
                "id": "unit:gate",
                "probe_commands": [{"command": probe, "sleep": 0}],
                "apply_commands": [{"command": "true", "sleep": 0}],
                "verify_commands": [{"command": "true", "sleep": 0}],
                "verify_retries": 5,
                "verify_interval_sec": 0.0,
                "on_probe_fail": "error",
            }
        ]
        log = tmp_path / "ops.log"
        result = _run_operation_units(units, role_bindings={}, log_path=log)
        assert result["ok"] is True
        assert counter.read_text().strip() == "3"

    def test_error_gate_fails_after_exhausting_probe_retries(self, tmp_path):
        # If the required state never converges, the error gate still fails after
        # its retry budget -- retrying only waits, it never turns a miss into a
        # pass.
        units = [
            {
                "id": "unit:gate",
                "probe_commands": [{"command": "false", "sleep": 0}],
                "apply_commands": [{"command": "true", "sleep": 0}],
                "verify_commands": [{"command": "true", "sleep": 0}],
                "verify_retries": 3,
                "verify_interval_sec": 0.0,
                "on_probe_fail": "error",
            }
        ]
        log = tmp_path / "ops.log"
        result = _run_operation_units(units, role_bindings={}, log_path=log)
        assert result["ok"] is False

    def test_empty_units_returns_ok(self, tmp_path):
        log = tmp_path / "ops.log"
        result = _run_operation_units([], role_bindings={}, log_path=log)
        assert result["ok"] is True

    def test_result_contains_output_key(self, tmp_path):
        log = tmp_path / "ops.log"
        result = _run_operation_units([], role_bindings={}, log_path=log)
        assert "output" in result

    def test_phase_timeout_aborts_slow_apply(self, tmp_path):
        # A precondition apply that sleeps past the phase budget must be
        # aborted -- this is what makes --setup-timeout actually bound the
        # precondition phase. The call returns near the budget with
        # timed_out=True instead of running the full sleep.
        units = [
            {
                "id": "unit:slow",
                "probe_commands": [{"command": "false", "sleep": 0}],
                "apply_commands": [{"command": "sleep 30", "sleep": 0}],
                "verify_commands": [{"command": "true", "sleep": 0}],
                "verify_retries": 1,
                "verify_interval_sec": 0.0,
                "on_probe_fail": "skip",
            }
        ]
        log = tmp_path / "ops.log"
        start = time.monotonic()
        result = _run_operation_units(
            units, role_bindings={}, log_path=log, phase_timeout_sec=1
        )
        elapsed = time.monotonic() - start
        assert result["ok"] is False
        assert result["timed_out"] is True
        assert elapsed < 10  # aborted near the 1s budget, not the 30s sleep

    def test_phase_timeout_none_runs_fast_units_to_completion(self, tmp_path):
        # The default (unbounded) path is unchanged: fast units succeed and
        # timed_out is False.
        units = [
            {
                "id": "unit:fast",
                "probe_commands": [{"command": "false", "sleep": 0}],
                "apply_commands": [{"command": "true", "sleep": 0}],
                "verify_commands": [{"command": "true", "sleep": 0}],
                "verify_retries": 1,
                "verify_interval_sec": 0.0,
                "on_probe_fail": "skip",
            }
        ]
        log = tmp_path / "ops.log"
        result = _run_operation_units(
            units, role_bindings={}, log_path=log, phase_timeout_sec=None
        )
        assert result["ok"] is True
        assert result["timed_out"] is False


class TestPreconditionAutoBudget:
    """The 'auto' setup-timeout budget computed per case."""

    def test_budget_sums_unit_timeouts_plus_slack(self):
        from karma.runtime.case import _precondition_auto_budget_seconds

        units = [
            {
                "probe_commands": [{"command": "x", "timeout_sec": 5}],
                "apply_commands": [{"command": "y", "timeout_sec": 50}],
                "verify_commands": [{"command": "z", "timeout_sec": 10}],
                "verify_retries": 3,
                "verify_interval_sec": 2,
            }
        ]
        # verify is budgeted as one run + the inter-retry waits (not command*retries):
        # probe 5 + apply 50 + verify_once 10 + interval 2*3 = 71, + 60 slack
        assert _precondition_auto_budget_seconds(units) == 131

    def test_empty_units_budget_is_slack_only(self):
        from karma.runtime.case import _precondition_auto_budget_seconds

        assert _precondition_auto_budget_seconds([]) == 60


class TestRunStage:
    """Smoke tests for run_stage error capture behavior."""

    def test_returns_error_status_on_setup_failure(self, tmp_path):
        from karma.runtime.case import run_stage

        row = {
            "stage_id": "stage_1",
            "service": "svc",
            "case_name": "case",
            "case": {"oracle": {}, "precondition_units": [], "decoys": []},
            "namespace_roles": ["default"],
            "adversary_deploy": [],
            "adversary_lift": [],
            "adversary_hint": None,
            "prompt_mode": "progressive",
            "agent_timeout_sec": 1,
            "retries": 0,
        }
        environment = MagicMock()
        environment.bind_namespace_roles.side_effect = RuntimeError("cluster unreachable")

        result = run_stage(
            row,
            run_dir=tmp_path,
            resources_dir=tmp_path,
            agent_meta={"sandbox_mode": "local"},
            sandbox_mode="local",
            environment=environment,
            prior_stage_ids=[],
            stage_prompts=["do the thing"],
            prompt_mode="progressive",
        )
        assert result["status"] == "error"
        assert result["stage_id"] == "stage_1"
        assert "cluster unreachable" in (result.get("error") or "")

    def test_no_agent_run_skips_launch_and_uses_oracle_verdict(self, tmp_path):
        # `resolve_agent(None, sandbox_mode="local")` yields a descriptor with no
        # folder/entrypoint. A no-agent run must NOT try to launch an agent
        # (which previously crashed with FileNotFoundError on "entrypoint.sh");
        # it stands the scenario up and the oracle verdict drives the status.
        from karma.runtime.case import run_stage

        row = {
            "stage_id": "stage_1",
            "service": "demo",
            "case_name": "configmap-update",
            "case": {"prompt": "patch the configmap", "oracle": {}, "precondition_units": [], "decoys": []},
            "namespace_roles": ["default"],
            "adversary_deploy": [],
            "adversary_lift": [],
            "adversary_hint": None,
            "prompt_mode": "progressive",
            "agent_timeout_sec": 1,
            "retries": 0,
        }
        no_agent_meta = {
            "folder": None,
            "dockerfile": None,
            "entrypoint": None,
            "sandbox_mode": "local",
            "image_tag": None,
        }
        environment = MagicMock()
        environment.bind_namespace_roles.return_value = {"default": "karma-ns"}
        environment.build_env_vars.return_value = {}

        proxy = MagicMock()
        proxy.port = 0

        with patch("karma.runtime.case.launch_proxy", return_value=proxy), \
             patch("karma.runtime.case.write_agent_bundle", return_value=tmp_path / "kc"), \
             patch("karma.runtime.case.collect_evidence", return_value={}), \
             patch("karma.runtime.case.run_oracle", return_value={"verdict": "pass"}), \
             patch("karma.runtime.case.launch_agent") as mock_launch:
            result = run_stage(
                row,
                run_dir=tmp_path,
                resources_dir=tmp_path,
                agent_meta=no_agent_meta,
                sandbox_mode="local",
                environment=environment,
                prior_stage_ids=[],
                stage_prompts=["do the thing"],
                prompt_mode="progressive",
            )

        mock_launch.assert_not_called()
        assert result["status"] == "pass"
        assert result["submitted"] is False
        assert result["oracle_verdict"] == "pass"


def test_apply_namespace_binding_maps_roles_to_identities():
    """A stage's namespace_binding maps case roles onto identity namespaces."""
    from karma.runtime.case import _apply_namespace_binding
    ident = {"cluster_a": "ns-a", "cluster_b": "ns-b"}
    # alternating migration: a_to_b
    out = _apply_namespace_binding(ident, {"source": "cluster_a", "target": "cluster_b", "default": "cluster_b"})
    assert out["source"] == "ns-a"
    assert out["target"] == "ns-b"
    assert out["default"] == "ns-b"
    # identities are kept so manifests referencing them still resolve
    assert out["cluster_a"] == "ns-a" and out["cluster_b"] == "ns-b"


def test_apply_namespace_binding_passthrough_without_binding():
    """Without a binding the identities are the roles (unchanged behaviour)."""
    from karma.runtime.case import _apply_namespace_binding
    ident = {"default": "ns-x"}
    assert _apply_namespace_binding(ident, None) == ident
    assert _apply_namespace_binding(ident, {}) == ident


def test_debug_namespace_override_preserves_generated_cleanup_binding():
    from karma.runtime.case import _bind_namespace_identities
    environment = MagicMock()
    environment.bind_namespace_roles.return_value = {
        "default": "karma-run",
        "worker": "karma-run-worker",
    }

    generated_bindings, effective_bindings = _bind_namespace_identities(
        environment,
        ["default", "worker"],
        "run",
        {"default": "cockroachdb"},
    )

    assert generated_bindings == {
        "default": "karma-run",
        "worker": "karma-run-worker",
    }
    assert effective_bindings == {
        "default": "cockroachdb",
        "worker": "karma-run-worker",
    }


def test_run_stage_debug_namespace_override_routes_but_cleans_generated_namespace(tmp_path):
    from karma.runtime.case import run_stage

    row = {
        "stage_id": "stage_1",
        "service": "demo",
        "case_name": "configmap-update",
        "case": {"prompt": "patch the configmap", "oracle": {}, "precondition_units": [], "decoys": []},
        "namespace_roles": ["default"],
        "adversary_deploy": [],
        "adversary_lift": [],
        "adversary_hint": None,
        "prompt_mode": "progressive",
        "agent_timeout_sec": 1,
        "retries": 0,
    }
    no_agent_meta = {
        "folder": None,
        "dockerfile": None,
        "entrypoint": None,
        "sandbox_mode": "local",
        "image_tag": None,
    }
    environment = MagicMock()
    environment.bind_namespace_roles.return_value = {"default": "karma-ns"}
    environment.build_namespace_env_vars.return_value = {"BENCH_NAMESPACE": "cockroachdb"}
    environment.build_env_vars.return_value = {}
    environment.list_namespaces.return_value = set()

    proxy = MagicMock()
    proxy.port = 0

    with patch("karma.runtime.case.launch_proxy", return_value=proxy), \
         patch("karma.runtime.case.write_agent_bundle", return_value=tmp_path / "kc"), \
         patch("karma.runtime.case.collect_evidence", return_value={}), \
         patch("karma.runtime.case.run_oracle", return_value={"verdict": "pass"}), \
         patch("karma.runtime.case.launch_agent") as mock_launch:
        result = run_stage(
            row,
            run_dir=tmp_path,
            resources_dir=tmp_path,
            agent_meta=no_agent_meta,
            sandbox_mode="local",
            environment=environment,
            prior_stage_ids=[],
            stage_prompts=["do the thing"],
            prompt_mode="progressive",
            namespace_overrides={"default": "cockroachdb"},
        )

    mock_launch.assert_not_called()
    assert result["status"] == "pass"
    stage_dir = tmp_path / "stages" / "stage_1"
    environment.ensure_namespaces.assert_called_once_with({}, run_dir=stage_dir)
    environment.build_namespace_env_vars.assert_called_once_with(
        {"default": "cockroachdb"}
    )
    environment.cleanup_namespaces.assert_called_once_with(
        {"default": "karma-ns"}, run_dir=stage_dir
    )


def test_resolve_workflow_carries_namespace_binding(tmp_path):
    """resolve_workflow_rows must carry a stage's namespace_binding onto the row."""
    from karma.definitions.workflows import normalize_workflow, resolve_workflow_rows
    from pathlib import Path
    raw = {
        "metadata": {"id": "wf"},
        "spec": {"stages": [{
            "id": "s1", "service": "demo", "case": "configmap-update",
            "namespaces": ["cluster_a", "cluster_b"],
            "namespace_binding": {"source": "cluster_a", "target": "cluster_b"},
        }]},
    }
    norm = normalize_workflow(raw, resources_dir=Path("cases/tests"))
    assert norm["stages"][0]["namespace_binding"] == {"source": "cluster_a", "target": "cluster_b"}
    rows = resolve_workflow_rows(norm, resources_dir=Path("cases/tests"))
    assert rows[0]["namespace_binding"] == {"source": "cluster_a", "target": "cluster_b"}

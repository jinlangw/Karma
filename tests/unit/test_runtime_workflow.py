"""Unit tests for karma.runtime.workflow."""

import json
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch, call
from karma.runtime.workflow import (
    _write_workflow_state,
    _should_retry,
    run_workflow_loop,
)
from karma import protocol


class TestWriteWorkflowState:
    def test_writes_json_to_state_path(self, tmp_path):
        state = {"run_id": "r1", "status": "running"}
        _write_workflow_state(tmp_path, state)
        path = protocol.workflow_state_path(tmp_path)
        assert path.exists()
        data = json.loads(path.read_text())
        assert data["run_id"] == "r1"

    def test_does_not_raise_on_write_error(self, tmp_path):
        # Write to a path where the parent does not exist.
        _write_workflow_state(tmp_path / "nonexistent" / "subdir", {"x": 1})


class TestShouldRetry:
    def test_retries_on_error_status(self):
        assert _should_retry({"status": "error"}, retries_remaining=1) is True

    def test_retries_on_timeout_status(self):
        assert _should_retry({"status": "timeout"}, retries_remaining=2) is True

    def test_retries_on_oracle_fail_when_attempts_remain(self):
        # Restored behaviour: max_attempts re-runs a stage on oracle fail.
        assert _should_retry({"status": "fail"}, retries_remaining=3) is True
        assert _should_retry({"status": "fail"}, retries_remaining=0) is False

    def test_does_not_retry_when_budget_exhausted(self):
        assert _should_retry({"status": "error"}, retries_remaining=0) is False

    def test_does_not_retry_on_pass(self):
        assert _should_retry({"status": "pass"}, retries_remaining=5) is False


class TestRunWorkflowLoop:
    def _make_row(self, stage_id: str) -> dict:
        return {
            "stage_id": stage_id,
            "service": "svc",
            "case_name": "case",
            "case": {},
            "namespace_roles": ["default"],
            "adversary_deploy": [],
            "adversary_lift": [],
            "adversary_hint": None,
            "prompt_mode": "progressive",
            "agent_timeout_sec": 60,
            "retries": 0,
        }

    def test_complete_status_when_all_stages_pass(self, tmp_path):
        rows = [self._make_row("stage_1"), self._make_row("stage_2")]
        pass_result = {"stage_id": None, "status": "pass", "oracle_verdict": "pass",
                       "submitted": True, "duration_sec": 0.1, "error": None,
                       "evidence_path": "", "oracle_path": ""}

        with patch("karma.runtime.workflow.run_stage") as mock_run:
            mock_run.side_effect = [
                {**pass_result, "stage_id": "stage_1"},
                {**pass_result, "stage_id": "stage_2"},
            ]
            result = run_workflow_loop(
                rows,
                run_id="r1",
                run_dir=tmp_path,
                resources_dir=tmp_path,
                agent_meta={},
                sandbox_mode="local",
                environment=MagicMock(),
                prompt_mode="progressive",
            )
        assert result["status"] == "complete"
        assert len(result["stages"]) == 2

    def test_failed_status_on_first_stage_failure(self, tmp_path):
        rows = [self._make_row("stage_1"), self._make_row("stage_2")]
        fail_result = {"stage_id": "stage_1", "status": "fail",
                       "oracle_verdict": "fail", "submitted": True,
                       "duration_sec": 0.1, "error": None,
                       "evidence_path": "", "oracle_path": ""}

        with patch("karma.runtime.workflow.run_stage", return_value=fail_result):
            result = run_workflow_loop(
                rows,
                run_id="r1",
                run_dir=tmp_path,
                resources_dir=tmp_path,
                agent_meta={},
                sandbox_mode="local",
                environment=MagicMock(),
                prompt_mode="progressive",
            )
        assert result["status"] == "failed"
        assert len(result["stages"]) == 1

    def test_on_stage_complete_called_after_each_stage(self, tmp_path):
        rows = [self._make_row("stage_1")]
        pass_result = {"stage_id": "stage_1", "status": "pass",
                       "oracle_verdict": "pass", "submitted": True,
                       "duration_sec": 0.1, "error": None,
                       "evidence_path": "", "oracle_path": ""}
        callback = MagicMock()

        with patch("karma.runtime.workflow.run_stage", return_value=pass_result):
            run_workflow_loop(
                rows,
                run_id="r1",
                run_dir=tmp_path,
                resources_dir=tmp_path,
                agent_meta={},
                sandbox_mode="local",
                environment=MagicMock(),
                prompt_mode="progressive",
                on_stage_complete=callback,
            )
        callback.assert_called_once()

    def test_run_meta_written_to_disk(self, tmp_path):
        rows = [self._make_row("stage_1")]
        pass_result = {"stage_id": "stage_1", "status": "pass",
                       "oracle_verdict": "pass", "submitted": True,
                       "duration_sec": 0.1, "error": None,
                       "evidence_path": "", "oracle_path": ""}

        with patch("karma.runtime.workflow.run_stage", return_value=pass_result):
            run_workflow_loop(
                rows,
                run_id="r1",
                run_dir=tmp_path,
                resources_dir=tmp_path,
                agent_meta={},
                sandbox_mode="local",
                environment=MagicMock(),
                prompt_mode="progressive",
            )
        assert protocol.run_meta_path(tmp_path).exists()

    def test_defers_namespace_cleanup_to_workflow_end(self, tmp_path):
        # run_stage must be told to defer cleanup, and the workflow tears the
        # namespaces down once at the end (after the sweeps), so cross-stage
        # state survives and the regression sweep runs against a live cluster.
        rows = [self._make_row("stage_1")]
        pass_result = {"stage_id": "stage_1", "status": "pass",
                       "oracle_verdict": "pass", "submitted": True,
                       "duration_sec": 0.1, "error": None,
                       "evidence_path": "", "oracle_path": ""}
        env = MagicMock()
        env.bind_namespace_roles.return_value = {"default": "ns-x"}
        env.build_namespace_env_vars.return_value = {}

        with patch("karma.runtime.workflow.run_stage",
                   return_value=pass_result) as mock_run:
            run_workflow_loop(
                rows,
                run_id="r1",
                run_dir=tmp_path,
                resources_dir=tmp_path,
                agent_meta={},
                sandbox_mode="local",
                environment=env,
                prompt_mode="progressive",
            )
        assert mock_run.call_args.kwargs["defer_cleanup"] is True
        env.cleanup_namespaces.assert_called_once_with(
            {"default": "ns-x"}, run_dir=tmp_path
        )

    def test_retry_on_error_status(self, tmp_path):
        row = {**self._make_row("stage_1"), "retries": 1}
        error_result = {"stage_id": "stage_1", "status": "error",
                        "oracle_verdict": None, "submitted": False,
                        "duration_sec": 0.0, "error": "timeout",
                        "evidence_path": "", "oracle_path": ""}
        pass_result = {**error_result, "status": "pass", "oracle_verdict": "pass",
                       "error": None}

        with patch("karma.runtime.workflow.run_stage",
                   side_effect=[error_result, pass_result]) as mock_run:
            result = run_workflow_loop(
                [row],
                run_id="r1",
                run_dir=tmp_path,
                resources_dir=tmp_path,
                agent_meta={},
                sandbox_mode="local",
                environment=MagicMock(),
                prompt_mode="progressive",
            )
        assert mock_run.call_count == 2
        assert result["status"] == "complete"


class TestStagePromptDistribution:
    def _make_row(self, stage_id: str) -> dict:
        return {
            "stage_id": stage_id,
            "service": "svc",
            "case_name": "case",
            "case": {},
            "namespace_roles": ["default"],
            "adversary_deploy": [],
            "adversary_lift": [],
            "adversary_hint": None,
            "prompt_mode": "concat_stateful",
            "agent_timeout_sec": 60,
            "retries": 0,
        }

    def test_full_static_prompt_list_passed_to_every_stage(self, tmp_path):
        # New model: the whole workflow's prompts are pre-rendered statically
        # from the definition and handed to EVERY stage (concat spans the full
        # list, future included) -- not accumulated from prior stages' prompt.txt.
        rows = [self._make_row("s1"), self._make_row("s2")]
        rows[0]["case"] = {"prompt": "TASK ONE"}
        rows[1]["case"] = {"prompt": "TASK TWO"}
        pass_r = lambda sid: {
            "stage_id": sid, "status": "pass", "oracle_verdict": "pass",
            "submitted": True, "duration_sec": 0.1, "error": None,
            "evidence_path": "", "oracle_path": "",
        }

        def fake_run_stage(row, **kwargs):
            return pass_r(row["stage_id"])

        with patch("karma.runtime.workflow.run_stage", side_effect=fake_run_stage) as mock_run:
            run_workflow_loop(
                rows,
                run_id="r1",
                run_dir=tmp_path,
                resources_dir=tmp_path,
                agent_meta={},
                sandbox_mode="local",
                environment=MagicMock(),
                prompt_mode="concat_stateful",
            )
        # Stage 1 (index 0) already carries the FUTURE stage-2 prompt.
        first = mock_run.call_args_list[0][1]
        assert first["stage_prompts"] == ["TASK ONE", "TASK TWO"]
        assert first["stage_index"] == 0
        # The same full list is handed to stage 2.
        second = mock_run.call_args_list[1][1]
        assert second["stage_prompts"] == ["TASK ONE", "TASK TWO"]
        assert second["stage_index"] == 1

    def test_stage_prologue_forwarded_to_run_stage(self, tmp_path):
        # The mode prologue resolved upstream must reach run_stage for every stage.
        row = self._make_row("s1"); row["case"] = {"prompt": "TASK"}
        pass_r = lambda sid: {
            "stage_id": sid, "status": "pass", "oracle_verdict": "pass",
            "submitted": True, "duration_sec": 0.1, "error": None,
            "evidence_path": "", "oracle_path": "",
        }
        with patch("karma.runtime.workflow.run_stage",
                   side_effect=lambda r, **k: pass_r(r["stage_id"])) as m:
            run_workflow_loop(
                [row], run_id="r1", run_dir=tmp_path, resources_dir=tmp_path,
                agent_meta={}, sandbox_mode="local", environment=MagicMock(),
                prompt_mode="concat_blind", stage_prologue="ORIENT-BLIND",
            )
        assert m.call_args_list[0].kwargs["prologue"] == "ORIENT-BLIND"

    def test_teardown_runs_when_a_callback_raises(self, tmp_path):
        # SR8: the deferred namespace teardown lives in a `finally`, so a stage
        # callback that raises (a broken should_cancel / on_progress from the
        # HTTP/dispatcher layer) must NOT orphan the run's namespaces.
        row = self._make_row("s1"); row["case"] = {"prompt": "TASK"}
        env = MagicMock()
        env.list_namespaces.return_value = {"pre-existing"}       # -> ns_baseline truthy
        env.bind_namespace_roles.return_value = {"default": "karma-abc"}
        env.build_namespace_env_vars.return_value = {}

        def boom():
            raise RuntimeError("dispatcher died")

        with pytest.raises(RuntimeError, match="dispatcher died"):
            run_workflow_loop(
                [row], run_id="r1", run_dir=tmp_path, resources_dir=tmp_path,
                agent_meta={}, sandbox_mode="local", environment=env,
                prompt_mode="progressive", should_cancel=boom,
            )
        # Both teardown paths still ran despite the raised callback.
        env.cleanup_namespaces.assert_called_once()
        env.cleanup_created_namespaces.assert_called_once()

    def test_failed_stage_prompt_not_accumulated(self, tmp_path):
        rows = [self._make_row("s1"), self._make_row("s2")]
        fail_r = {"stage_id": "s1", "status": "fail", "oracle_verdict": "fail",
                  "submitted": True, "duration_sec": 0.1, "error": None,
                  "evidence_path": "", "oracle_path": ""}

        with patch("karma.runtime.workflow.run_stage", return_value=fail_r) as mock_run:
            run_workflow_loop(
                rows,
                run_id="r1",
                run_dir=tmp_path,
                resources_dir=tmp_path,
                agent_meta={},
                sandbox_mode="local",
                environment=MagicMock(),
                prompt_mode="concat_stateful",
            )
        assert mock_run.call_count == 1


class TestFailFast:
    def _make_row(self, stage_id: str, retries: int = 0) -> dict:
        return {
            "stage_id": stage_id,
            "service": "svc",
            "case_name": "case",
            "case": {},
            "namespace_roles": ["default"],
            "adversary_deploy": [],
            "adversary_lift": [],
            "adversary_hint": None,
            "prompt_mode": "single",
            "agent_timeout_sec": 60,
            "retries": retries,
        }

    def test_second_stage_skipped_after_first_fails(self, tmp_path):
        rows = [self._make_row("s1"), self._make_row("s2")]
        fail_r = {"stage_id": "s1", "status": "fail", "oracle_verdict": "fail",
                  "submitted": True, "duration_sec": 0.0, "error": None,
                  "evidence_path": "", "oracle_path": ""}

        with patch("karma.runtime.workflow.run_stage", return_value=fail_r) as mock_run:
            result = run_workflow_loop(
                rows,
                run_id="r1",
                run_dir=tmp_path,
                resources_dir=tmp_path,
                agent_meta={},
                sandbox_mode="local",
                environment=MagicMock(),
                prompt_mode="single",
            )
        assert mock_run.call_count == 1
        assert result["status"] == "failed"
        assert len(result["stages"]) == 1

    def test_timeout_triggers_fail_fast(self, tmp_path):
        rows = [self._make_row("s1"), self._make_row("s2")]
        timeout_r = {"stage_id": "s1", "status": "timeout", "oracle_verdict": None,
                     "submitted": False, "duration_sec": 60.0, "error": None,
                     "evidence_path": "", "oracle_path": ""}

        with patch("karma.runtime.workflow.run_stage", return_value=timeout_r) as mock_run:
            result = run_workflow_loop(
                rows,
                run_id="r1",
                run_dir=tmp_path,
                resources_dir=tmp_path,
                agent_meta={},
                sandbox_mode="local",
                environment=MagicMock(),
                prompt_mode="single",
            )
        assert mock_run.call_count == 1
        assert result["status"] == "failed"

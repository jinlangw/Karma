"""Unit tests for karma.runtime.service run metadata."""

import json
from unittest.mock import patch

from karma.runtime import service


class TestConfigPersistsPromptMode:
    """#3: the run's config.json must record prompt_mode so the run self-documents
    its mode and the UI can surface + reproduce it. config.json is written before
    the heavy setup, so a run that fails right after still persists it."""

    def test_cli_config_records_prompt_mode(self, tmp_path):
        wf = {
            "id": "wf-x",
            "prompt_mode": "concat_blind",
            "stages": [{"id": "s1", "service": "svc", "case_name": "c"}],
        }
        # Stop right after the config.json write (before any cluster/agent work).
        with patch.object(service, "resolve_workflow_rows",
                          side_effect=RuntimeError("stop after config")):
            res = service.run_workflow(
                wf, runs_dir=tmp_path, resources_dir=tmp_path,
                agent_name="claude_code", run_id="test-run",
            )
        assert res["status"] == "error"      # failed as intended, after the write
        cfg = json.loads((tmp_path / "test-run" / "config.json").read_text())
        assert cfg["prompt_mode"] == "concat_blind"

    def test_defaults_to_progressive_when_unset(self, tmp_path):
        wf = {"id": "wf-y", "stages": [{"id": "s1", "service": "svc", "case_name": "c"}]}
        with patch.object(service, "resolve_workflow_rows",
                          side_effect=RuntimeError("stop")):
            service.run_workflow(
                wf, runs_dir=tmp_path, resources_dir=tmp_path,
                agent_name="claude_code", run_id="test-run-2",
            )
        cfg = json.loads((tmp_path / "test-run-2" / "config.json").read_text())
        assert cfg["prompt_mode"] == "progressive"

    def test_cli_config_records_all_reproduction_knobs(self, tmp_path):
        # Every behavior-affecting knob must be recorded so the rerun command can
        # reproduce the launch configuration.
        wf = {"id": "wf-z", "prompt_mode": "concat_blind", "agent_session": "per_stage",
              "stages": [{"id": "s1", "service": "svc", "case_name": "c",
                          "agent_timeout_sec": 300}]}
        with patch.object(service, "resolve_workflow_rows",
                          side_effect=RuntimeError("stop")):
            service.run_workflow(
                wf, runs_dir=tmp_path, resources_dir=tmp_path,
                agent_name="claude_code", run_id="test-run-3",
                max_attempts=3, stage_failure_mode="continue", final_sweep_mode="full",
            )
        cfg = json.loads((tmp_path / "test-run-3" / "config.json").read_text())
        assert cfg["prompt_mode"] == "concat_blind"
        assert cfg["agent_session"] == "per_stage"        # from the workflow
        assert cfg["max_attempts"] == 3                    # from the param
        assert cfg["stage_failure_mode"] == "continue"
        assert cfg["final_sweep_mode"] == "full"
        assert cfg["stages"][0]["agent_timeout_sec"] == 300

    def test_cli_config_records_debug_namespace_overrides(self, tmp_path):
        wf = {"id": "wf-debug", "stages": []}
        overrides = {"default": "cockroachdb"}
        with patch.object(service, "resolve_workflow_rows",
                          side_effect=RuntimeError("stop after config")):
            result = service.run_workflow(
                wf, runs_dir=tmp_path, resources_dir=tmp_path,
                namespace_overrides=overrides, run_id="debug-run",
            )

        assert result["status"] == "error"
        cfg = json.loads((tmp_path / "debug-run" / "config.json").read_text())
        assert cfg["debug_namespace_overrides"] == overrides

    def test_rejects_debug_override_for_unknown_workflow_role(self, tmp_path):
        wf = {"id": "wf-debug", "stages": []}
        with patch.object(service, "resolve_workflow_rows", return_value=[
            {"namespace_roles": ["default"]}
        ]):
            result = service.run_workflow(
                wf, runs_dir=tmp_path, resources_dir=tmp_path,
                namespace_overrides={"typo": "cockroachdb"}, run_id="bad-debug-run",
            )

        assert result["status"] == "error"
        assert "unknown workflow namespace role" in result["error"]

    def test_accepts_default_override_when_row_uses_implicit_default(self, tmp_path):
        wf = {"id": "wf-debug", "stages": []}
        with patch.object(service, "resolve_workflow_rows", return_value=[
            {"namespace_roles": None}
        ]), patch.object(service, "get_environment"), patch.object(
            service, "resolve_agent", return_value={}
        ), patch.object(
            service, "run_workflow_loop", return_value={"status": "complete", "stages": []}
        ) as run_loop:
            result = service.run_workflow(
                wf, runs_dir=tmp_path, resources_dir=tmp_path,
                namespace_overrides={"default": "cockroachdb"}, run_id="implicit-default",
            )

        assert result["status"] == "complete"
        assert run_loop.call_args.kwargs["namespace_overrides"] == {
            "default": "cockroachdb"
        }

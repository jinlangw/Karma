"""
Golden-path smoke test for the demo workflow.

Verifies that the demo workflow resolves into a valid row list without
requiring a live cluster. Uses the actual demo resources from disk.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from karma.environments.k8s import K8sEnvironment
from karma.interfaces.cli.main import main
from karma.definitions.workflows import (
    load_workflow_file,
    normalize_workflow,
    resolve_workflow_rows,
)

_REPO_ROOT = Path(__file__).parent.parent.parent
_RESOURCES_DIR = _REPO_ROOT / "cases" / "tests"
_WORKFLOWS_DIR = _REPO_ROOT / "workflows"


@pytest.mark.skipif(
    not _RESOURCES_DIR.exists(),
    reason="cases/tests/ directory not present in this environment",
)
class TestDemoWorkflowSmoke:
    def _find_demo_workflow(self) -> Path | None:
        candidates = list(_WORKFLOWS_DIR.glob("*demo*.yaml")) if _WORKFLOWS_DIR.exists() else []
        return candidates[0] if candidates else None

    def test_demo_workflow_loads_without_error(self):
        wf_path = self._find_demo_workflow()
        if wf_path is None:
            pytest.skip("no demo workflow file found")
        raw = load_workflow_file(wf_path)
        workflow = normalize_workflow(raw, resources_dir=_RESOURCES_DIR)
        assert len(workflow["stages"]) >= 1

    def test_demo_workflow_rows_resolve(self):
        wf_path = self._find_demo_workflow()
        if wf_path is None:
            pytest.skip("no demo workflow file found")
        raw = load_workflow_file(wf_path)
        workflow = normalize_workflow(raw, resources_dir=_RESOURCES_DIR)
        rows = resolve_workflow_rows(workflow, resources_dir=_RESOURCES_DIR)
        assert len(rows) == len(workflow["stages"])
        for row in rows:
            assert "case" in row
            assert "namespace_roles" in row


@pytest.mark.parametrize("debug", [False, True], ids=["normal", "debug"])
def test_workflow_debug_namespace_routing_and_cleanup(
    debug, resources_dir, tmp_path, monkeypatch, capsys,
):
    workflow = tmp_path / "workflow.yaml"
    workflow.write_text("""
metadata:
  id: debug-workflow
spec:
  debug:
    namespace_overrides:
      default: debug-ns
  stages:
    - {id: first, service: demo, case: configmap-update}
    - {id: second, service: demo, case: configmap-update}
""")
    (resources_dir / "demo/configmap-update/test.yaml").write_text("""
prompt: Set up the fixture.
namespace_contract:
  required_roles: [default]
preconditionUnits:
  - name: setup
    verify_retries: 1
    probe: 'test -f "$NAMESPACE_MARKER"'
    apply: 'printf "%s" "$BENCH_NAMESPACE" > "$NAMESPACE_MARKER"'
    verify: 'test -s "$NAMESPACE_MARKER"'
oracle:
  verify:
    commands:
      - command: 'test "$(cat "$NAMESPACE_MARKER")" = "$BENCH_NAMESPACE"'
""")
    marker = tmp_path / "namespace"
    monkeypatch.setenv("NAMESPACE_MARKER", str(marker))
    namespaces = set()
    k8s = K8sEnvironment()
    environment = MagicMock(spec=K8sEnvironment)
    environment.bind_namespace_roles.side_effect = k8s.bind_namespace_roles
    environment.build_namespace_env_vars.side_effect = k8s.build_namespace_env_vars
    environment.build_env_vars.side_effect = k8s.build_env_vars
    environment.ensure_namespaces.side_effect = (
        lambda bindings, **_: namespaces.update(bindings.values())
    )
    # Setup creates the selected namespace if needed, plus one owned namespace.
    environment.list_namespaces.side_effect = lambda: namespaces | (
        {marker.read_text(), "setup-owned"} if marker.exists() else set()
    )
    with patch("karma.runtime.service.get_environment", return_value=environment), \
         patch("karma.runtime.case.launch_proxy", return_value=MagicMock(port=0)), \
         patch("karma.runtime.case.write_agent_bundle", return_value=tmp_path / "kubeconfig"):
        args = ["run-workflow", str(workflow), "--resources-dir", str(resources_dir),
                "--runs-dir", str(tmp_path / "runs"), "--output", "json"]
        main(args + (["--debug"] if debug else []))

    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "complete", json.dumps(result)
    assert {stage: check["verdict"] for stage, check in result["regression_sweep"].items()} == {
        "first": "pass", "second": "pass",
    }
    run_dir = tmp_path / "runs" / result["run_id"]
    environment.cleanup_created_namespaces.assert_called_once_with({"setup-owned"}, run_dir=run_dir)
    if debug:
        assert marker.read_text() == "debug-ns"
        assert not namespaces
        environment.cleanup_namespaces.assert_not_called()
    else:
        namespace = marker.read_text()
        assert namespace in namespaces - {"debug-ns"}
        environment.cleanup_namespaces.assert_called_once_with({"default": namespace}, run_dir=run_dir)

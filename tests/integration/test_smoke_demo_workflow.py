"""
Golden-path smoke test for the demo workflow.

Verifies that the demo workflow resolves into a valid row list without
requiring a live cluster. Uses the actual demo resources from disk.
"""

import pytest
from pathlib import Path
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

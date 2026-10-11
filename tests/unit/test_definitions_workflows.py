"""Unit tests for karma.definitions.workflows."""

import pytest
from pathlib import Path
from karma.definitions.workflows import (
    load_workflow_file,
    normalize_workflow,
    resolve_workflow_rows,
    single_case_to_workflow,
    get_all_stage_ids,
    _parse_stage_param_ref,
    _namespace_aliases_for_stage,
)


class TestLoadWorkflowFile:
    def test_loads_valid_yaml(self, tmp_path):
        p = tmp_path / "workflow.yaml"
        p.write_text("metadata:\n  id: wf-1\n")
        data = load_workflow_file(p)
        assert data["metadata"]["id"] == "wf-1"

    def test_raises_when_missing(self, tmp_path):
        with pytest.raises(RuntimeError, match="not found"):
            load_workflow_file(tmp_path / "missing.yaml")

    def test_raises_when_not_a_mapping(self, tmp_path):
        p = tmp_path / "bad.yaml"
        p.write_text("- item\n")
        with pytest.raises(RuntimeError, match="YAML object"):
            load_workflow_file(p)


class TestParseStageParamRef:
    def test_valid_reference(self):
        result = _parse_stage_param_ref("${stages.stage_1.params.target_node}")
        assert result == {"stage_id": "stage_1", "param": "target_node"}

    def test_returns_none_for_literal(self):
        assert _parse_stage_param_ref("rabbit@pod-0") is None

    def test_returns_none_for_partial_match(self):
        assert _parse_stage_param_ref("prefix-${stages.s.params.p}") is None

    def test_whitespace_is_stripped(self):
        result = _parse_stage_param_ref("  ${stages.s1.params.key}  ")
        assert result == {"stage_id": "s1", "param": "key"}


class TestStageParamRefResolvesDefaults:
    # SS-7: a later stage referencing ${stages.X.params.Y} must get X's EFFECTIVE
    # value -- the case default when X never overrode Y -- not None.
    def _wf(self, s1_overrides, s2_overrides):
        return {"metadata": {"id": "wf"}, "spec": {"stages": [
            {"id": "s1", "service": "demo", "case": "configmap-update",
             "param_overrides": s1_overrides},
            {"id": "s2", "service": "demo", "case": "configmap-update",
             "param_overrides": s2_overrides},
        ]}}

    def test_ref_to_defaulted_param_resolves_to_case_default(self):
        # s1 leaves target_value at its case default ("x"); s2 references it and
        # must get "x", not None (the pre-fix behavior).
        wf = normalize_workflow(
            self._wf({}, {"target_value": "${stages.s1.params.target_value}"}),
            resources_dir=Path("cases"),
        )
        s2 = next(s for s in wf["stages"] if s["id"] == "s2")
        assert s2["param_overrides"]["target_value"] == "x"

    def test_ref_to_overridden_param_still_wins(self):
        wf = normalize_workflow(
            self._wf({"target_value": "custom"},
                     {"target_value": "${stages.s1.params.target_value}"}),
            resources_dir=Path("cases"),
        )
        s2 = next(s for s in wf["stages"] if s["id"] == "s2")
        assert s2["param_overrides"]["target_value"] == "custom"


class TestNamespaceAliasesForStage:
    def test_returns_empty_when_none_declared(self):
        # No default is applied here; resolve_workflow_rows defers to the
        # case's namespace_contract.required_roles (which may be an explicit
        # [] for literal-namespace cases) before falling back to ["default"].
        assert _namespace_aliases_for_stage({}) == []

    def test_returns_declared_aliases(self):
        stage = {"namespaces": ["primary", "secondary"]}
        assert _namespace_aliases_for_stage(stage) == ["primary", "secondary"]

    def test_ignores_blank_entries(self):
        stage = {"namespaces": ["primary", "", "  "]}
        assert _namespace_aliases_for_stage(stage) == ["primary"]


class TestNormalizeWorkflow:
    def test_raises_on_missing_id(self, tmp_path):
        raw = {"metadata": {}, "spec": {"stages": []}}
        with pytest.raises(ValueError):
            normalize_workflow(raw, resources_dir=tmp_path)

    def test_raises_on_invalid_prompt_mode(self, tmp_path):
        raw = {
            "metadata": {"id": "wf"},
            "spec": {"prompt_mode": "invalid", "stages": []},
        }
        with pytest.raises(ValueError, match="prompt_mode"):
            normalize_workflow(raw, resources_dir=tmp_path)

    def test_returns_normalized_dict(self, tmp_path):
        raw = {
            "metadata": {"id": "my-wf"},
            "spec": {
                "stages": [
                    {"id": "stage_1", "service": "svc", "case": "my-case"}
                ]
            },
        }
        result = normalize_workflow(raw, resources_dir=tmp_path)
        assert result["id"] == "my-wf"
        assert len(result["stages"]) == 1
        assert result["adversary"] == []

    def test_preserves_debug_namespace_overrides(self, tmp_path):
        raw = {
            "metadata": {"id": "debug-wf"},
            "spec": {
                "debug": {"namespace_overrides": {"default": "cockroachdb"}},
                "stages": [
                    {"id": "stage_1", "service": "svc", "case": "my-case"}
                ],
            },
        }

        result = normalize_workflow(raw, resources_dir=tmp_path)

        assert result["debug"]["namespace_overrides"] == {
            "default": "cockroachdb"
        }

    @pytest.mark.parametrize("namespace", ["CockroachDB", "bad_name", "-bad", "a" * 64])
    def test_rejects_invalid_debug_namespace_override(self, tmp_path, namespace):
        raw = {
            "metadata": {"id": "debug-wf"},
            "spec": {
                "debug": {"namespace_overrides": {"default": namespace}},
                "stages": [
                    {"id": "stage_1", "service": "svc", "case": "my-case"}
                ],
            },
        }

        with pytest.raises(ValueError, match="workflow schema validation failed"):
            normalize_workflow(raw, resources_dir=tmp_path)


class TestSingleCaseToWorkflow:
    def test_produces_single_stage(self):
        wf = single_case_to_workflow("svc", "my-case")
        assert len(wf["stages"]) == 1
        assert wf["stages"][0]["id"] == "stage_1"

    def test_stage_references_service_and_case(self):
        wf = single_case_to_workflow("rabbitmq", "failover")
        stage = wf["stages"][0]
        assert stage["service"] == "rabbitmq"
        assert stage["case_name"] == "failover"

    def test_param_overrides_attached(self):
        wf = single_case_to_workflow("svc", "case", {"key": "val"})
        assert wf["stages"][0]["param_overrides"]["key"] == "val"

    def test_adversary_list_is_empty(self):
        wf = single_case_to_workflow("svc", "case")
        assert wf["adversary"] == []

    def test_no_explicit_roles_passes_none_for_case_contract(self):
        # Must NOT force ["default"] -- that masks a multi-role case's contract.
        wf = single_case_to_workflow("svc", "case")
        assert wf["stages"][0]["namespaces"] is None


class TestResolveRowsNamespaceRoles:
    """resolve_workflow_rows must honour the case's required_roles."""

    def test_multi_role_case_binds_its_required_roles(self):
        # A single run-case never sets stage namespaces; the resolver must take
        # the roles from the case's namespace_contract (regression for the bug
        # where multi-role cases silently bound only "default").
        wf = single_case_to_workflow("demo", "configmap-update-two-ns")
        rows = resolve_workflow_rows(wf, resources_dir=Path("cases"))
        assert rows[0]["namespace_roles"] == ["source", "target"]

    def test_single_role_case_defaults(self):
        wf = single_case_to_workflow("demo", "configmap-update")
        rows = resolve_workflow_rows(wf, resources_dir=Path("cases"))
        assert rows[0]["namespace_roles"] == ["default"]

    def test_explicit_stage_namespaces_win(self):
        wf = single_case_to_workflow("demo", "configmap-update-two-ns",
                                     namespace_roles=["only"])
        rows = resolve_workflow_rows(wf, resources_dir=Path("cases"))
        assert rows[0]["namespace_roles"] == ["only"]


class TestGetAllStageIds:
    def test_returns_ordered_ids(self):
        wf = {"stages": [{"id": "a"}, {"id": "b"}, {"id": "c"}]}
        assert get_all_stage_ids(wf) == ["a", "b", "c"]

    def test_empty_workflow(self):
        assert get_all_stage_ids({}) == []


class TestStageIdValidation:
    def test_traversal_stage_id_is_rejected(self):
        # A stage id becomes a path segment; a traversal id must not be accepted
        # (it would write artifacts outside runs/) -- C4.
        wf = {"metadata": {"id": "t"}, "spec": {"stages": [
            {"id": "../../../x", "service": "rabbitmq", "case": "failover"}]}}
        with pytest.raises(ValueError, match="invalid stage id"):
            normalize_workflow(wf, resources_dir=Path("cases"))

    def test_valid_stage_id_passes(self):
        wf = {"metadata": {"id": "t"}, "spec": {"stages": [
            {"id": "stage_01", "service": "rabbitmq", "case": "failover"}]}}
        out = normalize_workflow(wf, resources_dir=Path("cases"))
        assert len(out["stages"]) == 1

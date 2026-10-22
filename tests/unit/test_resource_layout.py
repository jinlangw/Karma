"""The built-in corpus is nested while caller-owned roots stay direct."""

from pathlib import Path

from karma.adversary.definitions import resolve_adversary_scenario
from karma.definitions.cases import load_case_file
from karma.interfaces.http import catalog
from karma.interfaces.http.cli_preview import get_cli_options
from karma.settings import DEFAULT_RESOURCES_DIR, Settings, top_level_adversaries_dir


def _scenario_file(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "deploy:\n"
        "  probe: kubectl get pods\n"
        "  apply: kubectl delete pod example\n"
        "  verify: kubectl get pods\n"
    )


def test_builtin_defaults_and_catalog_use_nested_corpus(monkeypatch):
    monkeypatch.delenv("KARMA_RESOURCES_DIR", raising=False)
    assert DEFAULT_RESOURCES_DIR == Path("cases/tests")
    assert Settings.from_env().resources_dir == Path("cases/tests")
    monkeypatch.setenv("KARMA_RESOURCES_DIR", "external-resources")
    assert Settings.from_env().resources_dir == Path("external-resources")
    assert get_cli_options()["defaults"]["resources_dir"] == "cases/tests"

    services = catalog.list_services(DEFAULT_RESOURCES_DIR)
    names = {service["name"]: set(service["cases"]) for service in services}
    assert "configmap-update" in names["demo"]
    assert "cluster-settings" in names["cockroachdb"]
    assert "common" not in names
    assert load_case_file(DEFAULT_RESOURCES_DIR, "demo", "configmap-update")["prompt"]
    assert ("ray", "block_gcs_port") in {
        (entry["service"], entry["scenario"])
        for entry in catalog.list_adversary_scenarios(DEFAULT_RESOURCES_DIR)
    }


def test_builtin_adversary_root_resolves_from_installed_style_cwd(tmp_path, monkeypatch):
    """Installed framework code resolves the checkout corpus from its cwd."""
    monkeypatch.chdir(tmp_path)
    resources = tmp_path / "cases" / "tests"
    (resources / "demo" / "example").mkdir(parents=True)
    (resources / "demo" / "example" / "test.yaml").write_text("prompt: hi\n")
    scenario = tmp_path / "adversaries" / "demo" / "partition" / "scenario.yaml"
    _scenario_file(scenario)

    assert top_level_adversaries_dir(Path("cases/tests")) == tmp_path / "adversaries"
    listed = catalog.list_adversary_scenarios(Path("cases/tests"))
    assert [(item["service"], item["scenario"]) for item in listed] == [
        ("demo", "partition")
    ]
    resolved = resolve_adversary_scenario(
        {
            "scenario": "partition",
            "inject_at_stage": "stage_1",
            "lift_at_stage": None,
            "param_overrides": {},
        },
        {"stage_1": "demo"},
        resources_dir=Path("cases/tests"),
    )
    assert resolved["id"] == "partition"
    assert resolved["deploy_unit"]["probe_commands"] == [
        {"command": "kubectl get pods", "sleep": 0}
    ]


def test_custom_resource_root_keeps_direct_layout_and_sibling_adversaries(tmp_path):
    resources = tmp_path / "custom-resources"
    case_file = resources / "rabbitmq" / "failover" / "test.yaml"
    case_file.parent.mkdir(parents=True)
    case_file.write_text("prompt: custom root\n")
    assert load_case_file(resources, "rabbitmq", "failover")["prompt"] == "custom root"
    assert catalog.list_cases_by_service(resources) == {"rabbitmq": ["failover"]}

    _scenario_file(
        tmp_path / "adversaries" / "rabbitmq" / "custom" / "scenario.yaml"
    )
    _scenario_file(
        resources / "rabbitmq" / "adversarial" / "legacy" / "scenario.yaml"
    )
    scenarios = catalog.list_adversary_scenarios(resources)
    assert [(item["service"], item["scenario"]) for item in scenarios] == [
        ("rabbitmq", "custom"),
        ("rabbitmq", "legacy"),
    ]


def test_common_helpers_are_importable_packages():
    from cases.common.cockroachdb import CrdbLibrary
    from cases.common.rabbitmq import setup_check_utils
    from cases.common.ray import oracle_lib as ray_oracle
    from cases.common.spark import oracle_lib as spark_oracle

    assert CrdbLibrary is not None
    assert setup_check_utils is not None
    assert ray_oracle is not None
    assert spark_oracle is not None

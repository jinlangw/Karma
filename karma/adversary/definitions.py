"""
Adversary scenario loading, validation, and per-stage operation collection.

An adversary scenario introduces an intentional fault into the cluster
during a workflow run to evaluate how well the agent diagnoses and
recovers from unexpected environmental conditions.

Scenarios live in a top-level ``adversaries/`` directory, grouped by service::

    adversaries/{service}/{scenario}/scenario.yaml

The legacy ``{service}/adversarial/{scenario}/`` layout under the configured
resource root is still accepted as a fallback. The service is derived from
``inject_at_stage`` via the stage service map, enforcing that a scenario
references resources from within the same test suite that owns the inject
stage.

No runtime imports. Consumed by ``definitions.workflows`` during row
resolution and by ``runtime.workflow`` during the final lifecycle sweep.
"""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ValidationError
from ..settings import top_level_adversaries_dir

_SCENARIO_FILE_NAME = "scenario.yaml"
# Scenarios live in a top-level ``adversaries/`` directory, grouped by service:
# ``adversaries/{service}/{scenario}/``.
# The legacy in-resources location is still accepted as a fallback.
_ADVERSARIES_DIR_NAME = "adversaries"
_ADVERSARIAL_DIR_NAME = "adversarial"  # legacy in-resource adversary layout


def _is_safe_segment(name: str) -> bool:
    """Return ``True`` when *name* is a single safe path component.

    Rejects empty, ``.``/``..``, and any value containing a path separator, so
    a scenario/service name taken from a request body or workflow spec cannot
    escape the ``adversaries/`` tree via traversal (SR5). Mirrors the guard on
    case service/case names in ``definitions.cases``.
    """
    return bool(name) and name not in (".", "..") and "/" not in name and "\\" not in name
_VALID_ON_PROBE_FAIL = {"error", "skip"}


# ---------------------------------------------------------------------------
# Pydantic schema models
# ---------------------------------------------------------------------------

class _ScenarioOperationBlock(BaseModel):
    """A probe/apply/verify block inside a scenario deploy or lift section."""

    probe: Any
    apply: Any
    verify: Any
    on_probe_fail: Literal["error", "skip"] = "error"


class _ScenarioPromptHints(BaseModel):
    """Optional agent prompt hints declared in a scenario file."""

    deploy: str | None = None
    active: str | None = None


class ScenarioSchema(BaseModel):
    """Top-level schema for an adversary ``scenario.yaml`` file.

    Validation fails immediately when ``deploy`` is absent or when
    ``lift`` is present but malformed. The error message identifies
    the exact field path and reason.
    """

    deploy: _ScenarioOperationBlock
    lift: _ScenarioOperationBlock | None = None
    params: dict[str, Any] = {}
    prompt_hints: _ScenarioPromptHints = _ScenarioPromptHints()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _coerce_int(value: Any, default: int) -> int:
    """Return *value* coerced to ``int``, or *default* on failure."""
    try:
        return int(value)
    except Exception:
        return default


def _coerce_float(value: Any, default: float) -> float:
    """Return *value* coerced to ``float``, or *default* on failure."""
    try:
        return float(value)
    except Exception:
        return default


def _normalize_commands(raw: Any) -> list[dict[str, Any]]:
    """Return a list of canonical command dicts from *raw*.

    Accepts a command string, a command dict, or a list of either.
    Invalid entries are skipped silently.
    """
    if raw is None:
        return []
    if isinstance(raw, (str, dict)):
        raw = [raw]
    if not isinstance(raw, list):
        return []
    result = []
    for item in raw:
        if isinstance(item, str):
            item = item.strip()
            if item:
                result.append({"command": item, "sleep": 0})
        elif isinstance(item, dict) and item.get("command") is not None:
            entry: dict[str, Any] = {
                "command": item["command"],
                "sleep": _coerce_int(item.get("sleep", 0), default=0),
            }
            ns = item.get("namespace_role") or item.get("namespaceRole")
            if ns is not None:
                entry["namespace_role"] = str(ns).strip()
            ts = item.get("timeout_sec") or item.get("timeoutSec")
            if ts is not None:
                entry["timeout_sec"] = _coerce_int(ts, default=60)
            result.append(entry)
    return result


def _normalize_operation_block(
    raw: Any,
    label: str,
    scenario_id: str,
    *,
    default_on_probe_fail: str = "error",
) -> dict[str, Any]:
    """Return a canonical operation unit dict for an adversary deploy or lift block.

    Parameters
    ----------
    raw:
        Raw dict from the scenario YAML deploy or lift section.
    label:
        ``"deploy"`` or ``"lift"``, used in error messages.
    scenario_id:
        Scenario name used in error messages.
    default_on_probe_fail:
        Fallback ``on_probe_fail`` value when not specified in *raw*.

    Raises
    ------
    ValueError
        When *raw* is not a dict, when any sub-block lacks commands, or
        when ``on_probe_fail`` is invalid.
    """
    if not isinstance(raw, dict):
        raise ValueError(
            f"adversary scenario '{scenario_id}' {label} block must be an object"
        )

    probe_commands = _normalize_commands(raw.get("probe"))
    apply_commands = _normalize_commands(raw.get("apply"))
    verify_commands = _normalize_commands(raw.get("verify"))

    if not probe_commands:
        raise ValueError(
            f"adversary scenario '{scenario_id}' {label}.probe command(s) are required"
        )
    if not apply_commands:
        raise ValueError(
            f"adversary scenario '{scenario_id}' {label}.apply command(s) are required"
        )
    if not verify_commands:
        raise ValueError(
            f"adversary scenario '{scenario_id}' {label}.verify command(s) are required"
        )

    probe_raw = raw.get("probe")
    on_probe_fail = default_on_probe_fail
    # Honor an explicit on_probe_fail at the operation-block level (how every
    # scenario authors it, as a sibling of probe/apply/verify) or, legacy,
    # inside a probe mapping. Without this the field was silently ignored.
    explicit = raw.get("on_probe_fail")
    if explicit is None and isinstance(probe_raw, dict):
        explicit = probe_raw.get("on_probe_fail")
    if explicit is not None:
        on_probe_fail = str(explicit).strip().lower()
    if on_probe_fail not in _VALID_ON_PROBE_FAIL:
        raise ValueError(
            f"adversary scenario '{scenario_id}' {label}.probe.on_probe_fail "
            f"must be one of: {', '.join(sorted(_VALID_ON_PROBE_FAIL))}"
        )

    vd = raw.get("verify") if isinstance(raw.get("verify"), dict) else {}
    retries = _coerce_int(
        vd.get("retries") if isinstance(vd, dict) else None, default=1
    )
    interval_sec = _coerce_float(
        (vd.get("interval_sec") or vd.get("intervalSec")) if isinstance(vd, dict) else None,
        default=0.0,
    )

    return {
        "id": f"{scenario_id}:{label}",
        "probe_commands": probe_commands,
        "apply_commands": apply_commands,
        "verify_commands": verify_commands,
        "verify_retries": max(1, retries),
        "verify_interval_sec": max(0.0, interval_sec),
        "on_probe_fail": on_probe_fail,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def validate_adversary_workflow_block(
    spec: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """Validate the ``spec.adversary`` list in a workflow YAML and return raw entries.

    Performs field-presence and type checks only. Does not access the
    filesystem. Cross-field checks (e.g. verifying that ``inject_at_stage``
    and ``lift_at_stage`` reference declared stage IDs) are deferred to
    workflow loading, which has access to the full stage list.

    Parameters
    ----------
    spec:
        The ``spec`` dict from the workflow YAML, or ``None``.

    Raises
    ------
    ValueError
        When any entry is structurally invalid.

    Returns
    -------
    list[dict]
        Each entry has keys ``scenario`` (str), ``inject_at_stage`` (str),
        ``lift_at_stage`` (str or ``None``), ``param_overrides`` (dict).
    """
    raw_list = (spec or {}).get("adversary") or []
    if not isinstance(raw_list, list):
        raise ValueError("spec.adversary must be a list")

    validated: list[dict[str, Any]] = []
    for i, entry in enumerate(raw_list):
        if not isinstance(entry, dict):
            raise ValueError(f"spec.adversary[{i}] must be a dict")
        scenario = entry.get("scenario")
        if not scenario or not isinstance(scenario, str):
            raise ValueError(f"spec.adversary[{i}].scenario is required and must be a string")
        inject_at = entry.get("inject_at_stage")
        if not inject_at or not isinstance(inject_at, str):
            raise ValueError(
                f"spec.adversary[{i}].inject_at_stage is required and must be a string"
            )
        lift_at = entry.get("lift_at_stage")
        if lift_at is not None and not isinstance(lift_at, str):
            raise ValueError(f"spec.adversary[{i}].lift_at_stage must be a string or null")
        validated.append({
            "scenario": str(scenario).strip(),
            "inject_at_stage": str(inject_at).strip(),
            "lift_at_stage": str(lift_at).strip() if lift_at else None,
            "param_overrides": dict(entry.get("param_overrides") or {}),
        })
    return validated


def resolve_adversary_scenario(
    entry: dict[str, Any],
    stage_service_map: dict[str, str],
    *,
    resources_dir: Path,
) -> dict[str, Any]:
    """Load and resolve one adversary entry into a fully normalized injection dict.

    The service is derived from
    ``stage_service_map[entry["inject_at_stage"]]``, then the scenario
    file is loaded from ``adversaries/{service}/{scenario}/scenario.yaml``
    (top-level for the built-in corpus, or sibling of a custom resource root),
    falling back to the legacy
    ``{service}/adversarial/{scenario}/scenario.yaml`` location within the
    configured resource root.
    Parameter substitution uses the same ``{{params.foo}}`` syntax as
    ``test.yaml`` files.

    Parameters
    ----------
    entry:
        Raw adversary entry from :func:`validate_adversary_workflow_block`.
    stage_service_map:
        Map of stage ID to service name for the current workflow.
    resources_dir:
        Root resources directory.

    Raises
    ------
    RuntimeError
        When the scenario file is missing, unparseable, fails pydantic
        schema validation, or is otherwise structurally invalid. The
        error message names the offending field path and the reason.

    Returns
    -------
    dict
        Keys: ``id`` (str), ``inject_at_stage`` (str),
        ``lift_at_stage`` (str or ``None``), ``deploy_unit`` (dict),
        ``lift_unit`` (dict or ``None``),
        ``prompt_hints`` (``{"deploy": str|None, "active": str|None}``).
    """
    inject_at = entry["inject_at_stage"]
    lift_at = entry.get("lift_at_stage")
    scenario_name = entry["scenario"]
    param_overrides = entry.get("param_overrides") or {}

    # The scenario name flows straight into a filesystem path below
    # (adversaries/<service>/<scenario>/scenario.yaml). Reject traversal (SR5):
    # a name like "../../../../tmp/evil" would otherwise escape adversaries/ to a
    # scenario.yaml whose deploy commands run via shell=True. The name is
    # attacker-supplied (a /api/manual adversary-deploy body or spec.adversary[]
    # in a /api/run workflow); the upstream validation only .strip()s it.
    if not _is_safe_segment(scenario_name):
        raise RuntimeError(
            f"adversary scenario '{scenario_name}': invalid name -- must be a "
            f"single path segment (no '/', '\\', or '..')"
        )

    service = stage_service_map.get(inject_at)
    if not service:
        raise RuntimeError(
            f"adversary scenario '{scenario_name}': inject_at_stage '{inject_at}' "
            f"not found in stage service map"
        )
    # service is derived from the workflow's stage map (already load-validated),
    # but it is the other path segment, so guard it too as defense-in-depth.
    if not _is_safe_segment(service):
        raise RuntimeError(
            f"adversary scenario '{scenario_name}': invalid service '{service}' "
            f"-- must be a single path segment"
        )

    # Prefer the top-level adversaries/ tree; fall back to the legacy
    # in-resources location for back-compat.
    adversaries_dir = top_level_adversaries_dir(resources_dir)
    candidates = [
        adversaries_dir / service / scenario_name / _SCENARIO_FILE_NAME,
        resources_dir / service / _ADVERSARIAL_DIR_NAME / scenario_name / _SCENARIO_FILE_NAME,
    ]
    scenario_path = next((p for p in candidates if p.exists()), None)
    if scenario_path is None:
        raise RuntimeError(
            f"adversary scenario '{scenario_name}': file not found "
            f"(looked in {candidates[0]} and the legacy {candidates[1]})"
        )
    try:
        raw_data = yaml.safe_load(scenario_path.read_text()) or {}
    except Exception as exc:
        raise RuntimeError(
            f"adversary scenario '{scenario_name}': failed to parse {scenario_path}: {exc}"
        ) from exc
    if not isinstance(raw_data, dict):
        raise RuntimeError(
            f"adversary scenario '{scenario_name}': {scenario_path} must be a YAML object"
        )

    try:
        ScenarioSchema.model_validate(raw_data)
    except ValidationError as exc:
        details = "; ".join(
            f"{'.' .join(str(loc) for loc in e['loc'])}: {e['msg']}"
            for e in exc.errors()
        )
        raise RuntimeError(
            f"adversary scenario '{scenario_name}': schema validation failed: {details}"
        ) from exc

    data = deepcopy(raw_data)

    # Resolve declared params to their default values (a param may be declared
    # either as a bare value or as a ``{"default": ...}`` definition, mirroring
    # case params), then apply param_overrides on top. The merged scalar values
    # are what {{params.key}} tokens substitute to.
    declared_params = data.get("params") or {}
    resolved_params: dict[str, Any] = {}
    for key, definition in declared_params.items():
        if isinstance(definition, dict):
            resolved_params[key] = definition.get("default")
        else:
            resolved_params[key] = definition
    params: dict[str, Any] = {**resolved_params, **param_overrides}

    def _sub(obj: Any) -> Any:
        if isinstance(obj, str):
            for k, v in params.items():
                obj = obj.replace(f"{{{{params.{k}}}}}", str(v))
            return obj
        if isinstance(obj, list):
            return [_sub(item) for item in obj]
        if isinstance(obj, dict):
            return {kk: _sub(vv) for kk, vv in obj.items()}
        return obj

    data = _sub(data)

    try:
        deploy_unit = _normalize_operation_block(
            data.get("deploy") or {}, "deploy", scenario_name
        )
    except ValueError as exc:
        raise RuntimeError(str(exc)) from exc

    lift_unit: dict[str, Any] | None = None
    if data.get("lift") is not None:
        try:
            lift_unit = _normalize_operation_block(
                data["lift"], "lift", scenario_name,
                default_on_probe_fail="skip",
            )
        except ValueError as exc:
            raise RuntimeError(str(exc)) from exc

    hints_raw = data.get("prompt_hints") or {}
    prompt_hints = {
        "deploy": str(hints_raw.get("deploy") or "").strip() or None,
        "active": str(hints_raw.get("active") or "").strip() or None,
    }

    return {
        "id": scenario_name,
        "inject_at_stage": inject_at,
        "lift_at_stage": lift_at,
        "deploy_unit": deploy_unit,
        "lift_unit": lift_unit,
        "prompt_hints": prompt_hints,
    }


def collect_stage_operations(
    injections: list[dict[str, Any]],
    stage_id: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return ``(deploy_units, lift_units)`` for injections targeting *stage_id*.

    An injection contributes a deploy unit when
    ``inject_at_stage == stage_id`` and a lift unit when
    ``lift_at_stage == stage_id``. Both can match on the same stage.

    Parameters
    ----------
    injections:
        Resolved injection dicts from :func:`resolve_adversary_scenario`.
    stage_id:
        ID of the stage being prepared.
    """
    deploy_units: list[dict[str, Any]] = []
    lift_units: list[dict[str, Any]] = []
    for inj in injections or []:
        if inj.get("inject_at_stage") == stage_id:
            deploy_units.append(deepcopy(inj["deploy_unit"]))
        if inj.get("lift_at_stage") == stage_id and inj.get("lift_unit") is not None:
            lift_units.append(deepcopy(inj["lift_unit"]))
    return deploy_units, lift_units


def collect_pending_lift_units(
    injections: list[dict[str, Any]],
    deployed_scenario_ids: set[str],
    completed_stage_ids: set[str],
) -> list[dict[str, Any]]:
    """Return lift units for injections whose lift stage never ran.

    Used by the final cleanup sweep in ``runtime.workflow`` to ensure no
    adversarial conditions are left in the cluster after an early workflow
    exit.

    An injection is considered pending when its ID is in
    *deployed_scenario_ids* and its ``lift_at_stage`` is not in
    *completed_stage_ids*.

    Parameters
    ----------
    injections:
        All resolved injection dicts for the workflow.
    deployed_scenario_ids:
        IDs of scenarios whose deploy unit executed successfully.
    completed_stage_ids:
        IDs of stages that ran to completion.
    """
    result: list[dict[str, Any]] = []
    for inj in injections or []:
        if inj.get("id") not in deployed_scenario_ids:
            continue
        lift_at = inj.get("lift_at_stage")
        if lift_at and lift_at in completed_stage_ids:
            continue
        if inj.get("lift_unit") is not None:
            result.append(deepcopy(inj["lift_unit"]))
    return result


def collect_stage_hint(
    injections: list[dict[str, Any]],
    stage_id: str,
    all_stage_ids: list[str],
) -> str | None:
    """Return the adversary prompt hint for *stage_id*, or ``None``.

    Returns the ``deploy`` hint for the ``inject_at_stage`` and the
    ``active`` hint for all intermediate stages strictly between
    ``inject_at_stage`` and ``lift_at_stage``. When multiple injections
    are active at the same stage their hints are joined with two newlines.

    Parameters
    ----------
    injections:
        Resolved injection dicts for the workflow.
    stage_id:
        Stage for which to collect hints.
    all_stage_ids:
        Ordered list of all stage IDs in the workflow.
    """
    hints: list[str] = []
    for inj in injections or []:
        inject_at = inj.get("inject_at_stage")
        lift_at = inj.get("lift_at_stage")
        ph = inj.get("prompt_hints") or {}

        if inject_at == stage_id:
            h = ph.get("deploy")
            if h:
                hints.append(h.strip())
        elif lift_at and inject_at and inject_at in all_stage_ids and lift_at in all_stage_ids:
            inject_idx = all_stage_ids.index(inject_at)
            lift_idx = all_stage_ids.index(lift_at)
            try:
                current_idx = all_stage_ids.index(stage_id)
            except ValueError:
                continue
            if inject_idx < current_idx < lift_idx:
                h = ph.get("active")
                if h:
                    hints.append(h.strip())

    return "\n\n".join(hints) if hints else None

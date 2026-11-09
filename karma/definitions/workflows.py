"""
Workflow loading, stage resolution, namespace alias handling, and the
single-case-to-workflow conversion.

A *workflow* is an ordered sequence of stages defined in a YAML file.
This module loads that file, validates its structure, resolves cross-stage
parameter references, and builds the row list consumed by ``runtime.workflow``.

A *workflow row* is the unit of work for one stage::

    {
        "stage_id":            str,
        "service":             str,
        "case_name":           str,
        "case":                dict,        # normalized case descriptor
        "namespace_roles":     list[str],
        "namespace_binding":   dict | None,
        "adversary_deploy":    list[dict],
        "adversary_lift":      list[dict],
        "adversary_hint":      str | None,
        "adversary_injections": list[dict],
        "prompt_mode":         str,
        "agent_timeout_sec":   int,
        "retries":             int,
    }

Single-case UI runs are normalized into a 1-stage workflow by
:func:`single_case_to_workflow` so that both the CLI and HTTP paths
execute through an identical runtime stack.
"""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any, Literal
import re

import yaml
from pydantic import BaseModel, Field, ValidationError, model_validator

_VALID_PROMPT_MODES = ("progressive", "concat_stateful", "concat_blind")
_DEFAULT_PROMPT_MODE = "progressive"
_DEFAULT_AGENT_SESSION = "persistent"
_DEFAULT_AGENT_TIMEOUT_SEC = 900
_DEFAULT_NAMESPACE_ALIAS = "default"
_STAGE_PARAM_REF_RE = re.compile(
    r"^\s*\$\{stages\.([a-zA-Z0-9_.-]+)\.params\.([a-zA-Z0-9_.-]+)\}\s*$"
)


# ---------------------------------------------------------------------------
# Pydantic schema models
# ---------------------------------------------------------------------------

class _StageSpec(BaseModel):
    """One stage entry in a workflow YAML spec.stages list."""

    id: str
    service: str
    case: str
    param_overrides: dict[str, Any] = {}
    namespaces: list[str] = []
    # Maps a case's logical roles (e.g. source/target/default) onto the
    # physical namespace identities declared in `namespaces` (e.g.
    # cluster_a/cluster_b). Lets a migration alternate direction across stages.
    namespace_binding: dict[str, str] = {}
    agent_timeout_sec: int = _DEFAULT_AGENT_TIMEOUT_SEC
    retries: int = 0


class _WorkflowDebugSpec(BaseModel):
    """Opt-in settings used only when a workflow is launched with ``--debug``."""

    namespace_overrides: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _validate_namespace_overrides(self) -> "_WorkflowDebugSpec":
        namespace_pattern = re.compile(r"^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$")
        for role, namespace in self.namespace_overrides.items():
            if not _is_valid_name(role):
                raise ValueError(
                    f"debug namespace override role {role!r} is invalid; "
                    "use letters, digits, '-' or '_'"
                )
            if len(namespace) > 63 or not namespace_pattern.fullmatch(namespace):
                raise ValueError(
                    f"debug namespace override for role {role!r} has invalid "
                    f"Kubernetes namespace name {namespace!r}"
                )
        return self


class _WorkflowMetadata(BaseModel):
    """The metadata block at the top of a workflow YAML."""

    id: str
    label: str | None = None


class _WorkflowSpec(BaseModel):
    """The spec block of a workflow YAML."""

    stages: list[_StageSpec] = Field(min_length=1)
    prompt_mode: Literal["progressive", "concat_stateful", "concat_blind"] = _DEFAULT_PROMPT_MODE
    # ``per_stage`` (default) launches a fresh agent each stage; ``persistent``
    # keeps ONE agent conversation alive across all stages (the CLI/api session
    # is resumed each stage) so the agent carries its own reasoning forward, not
    # just the re-fed prompts. With ``persistent`` the recommended prompt_mode is
    # ``progressive`` -- the live session already holds the history.
    agent_session: Literal["per_stage", "persistent"] = _DEFAULT_AGENT_SESSION
    # Optional workflow-level system prompt delivered to every agent (claude via
    # --append-system-prompt; codex/copilot/api prepend it). For experiments --
    # e.g. telling the agent a regression sweep will re-check earlier stages. It
    # must NOT describe the submit mechanism (the wrapper handles that).
    system_prompt: str | None = None
    adversary: list[Any] = []
    # These physical namespace bindings are inert unless the CLI is invoked
    # with --debug. Ordinary workflow runs always use generated namespaces.
    debug: _WorkflowDebugSpec = Field(default_factory=_WorkflowDebugSpec)

    @model_validator(mode="after")
    def _progressive_requires_persistent(self) -> "_WorkflowSpec":
        """progressive prompt_mode only makes sense with a persistent agent.

        progressive sends ONLY the current stage's prompt, relying on the agent's
        own memory for prior stages -- a fresh per_stage agent would lose all
        earlier context. Reject that combination at validation time.
        """
        if self.prompt_mode == "progressive" and self.agent_session == "per_stage":
            raise ValueError(
                "prompt_mode 'progressive' requires agent_session 'persistent': "
                "progressive sends only the current stage, so a fresh per_stage "
                "agent has no prior-stage context. Use agent_session: persistent, "
                "or a concat_* prompt_mode."
            )
        return self


class WorkflowSchema(BaseModel):
    """Top-level schema for a workflow YAML file.

    Validation fails immediately when ``metadata.id`` is absent,
    ``spec.stages`` is missing or empty, or ``prompt_mode`` is not
    one of the three accepted values.
    """

    metadata: _WorkflowMetadata
    spec: _WorkflowSpec


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _is_valid_name(name: str) -> bool:
    """Return ``True`` when *name* contains only alphanumerics, hyphens, and underscores."""
    return bool(re.match(r'^[a-zA-Z0-9_-]+$', name))


def _parse_stage_param_ref(value: str) -> dict[str, str] | None:
    """Return ``{"stage_id": str, "param": str}`` for a ``${stages.<id>.params.<n>}``
    expression, or ``None`` when *value* does not match the pattern.
    """
    match = _STAGE_PARAM_REF_RE.match(value)
    if not match:
        return None
    return {"stage_id": match.group(1), "param": match.group(2)}


def _resolve_stage_param_overrides(
    stage: dict[str, Any],
    stage_index: int,
    all_stages: list[dict[str, Any]],
    prior_stage_params: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any], list[str]]:
    """Resolve ``${stages.<id>.params.<n>}`` references in a stage's ``param_overrides``.

    References to the current or a future stage raise :class:`ValueError`.
    A reference resolves to the referenced stage's EFFECTIVE value for that
    param -- its override if set, else the case default (SS-7). A param name
    absent from the referenced stage's effective params (neither overridden nor
    declared by its case) produces a warning and resolves to ``None``.

    Parameters
    ----------
    stage:
        The stage dict being resolved.
    stage_index:
        Zero-based index of *stage* within *all_stages*.
    all_stages:
        Ordered list of all stage dicts in the workflow.
    prior_stage_params:
        Map of stage ID to each preceding stage's effective params (case
        defaults merged with resolved overrides).

    Returns
    -------
    tuple[dict, list[str]]
        ``(resolved_overrides, warnings)``.
    """
    overrides = dict(stage.get("param_overrides") or {})
    warnings: list[str] = []
    current_id = stage.get("id", "")
    resolved: dict[str, Any] = {}

    for key, value in overrides.items():
        if not isinstance(value, str):
            resolved[key] = value
            continue
        ref = _parse_stage_param_ref(value)
        if ref is None:
            resolved[key] = value
            continue

        ref_stage_id = ref["stage_id"]
        ref_param = ref["param"]

        # Reject forward references and self-references.
        ref_index = next(
            (j for j, s in enumerate(all_stages) if s.get("id") == ref_stage_id),
            None,
        )
        if ref_index is None:
            raise ValueError(
                f"stage '{current_id}' param_overrides['{key}'] references "
                f"unknown stage '{ref_stage_id}'"
            )
        if ref_index >= stage_index:
            raise ValueError(
                f"stage '{current_id}' param_overrides['{key}'] references "
                f"stage '{ref_stage_id}' which is at the same index or later"
            )

        if ref_stage_id not in prior_stage_params:
            raise ValueError(
                f"stage '{current_id}' param_overrides['{key}'] references "
                f"stage '{ref_stage_id}' which has no resolved params yet"
            )
        prior_params = prior_stage_params[ref_stage_id]
        if ref_param not in prior_params:
            warnings.append(
                f"stage '{current_id}' param_overrides['{key}'] references "
                f"param '{ref_param}' not found in stage '{ref_stage_id}' params"
            )
            resolved[key] = None
        else:
            resolved[key] = prior_params[ref_param]

    return resolved, warnings


def _namespace_aliases_for_stage(stage: dict[str, Any]) -> list[str]:
    """Return the namespace aliases the stage *explicitly* declares.

    Returns ``[]`` when the stage does not list any namespaces. The default
    is NOT applied here: ``resolve_workflow_rows`` resolves an empty list
    against the case's ``namespace_contract.required_roles`` (honouring an
    explicit ``[]`` for literal-namespace cases like spark) and only then
    falls back to ``["default"]``. Stamping ``["default"]`` here would mask
    that contract and bind a stray ``karma-*`` namespace.
    """
    return [
        str(a).strip()
        for a in (stage.get("namespaces") or [])
        if str(a).strip()
    ]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load_workflow_file(path: Path) -> dict[str, Any]:
    """Load and parse a workflow YAML file from disk.

    Raises
    ------
    RuntimeError
        When *path* does not exist or cannot be parsed as a YAML object.
    """
    if not path.exists():
        raise RuntimeError(f"workflow file not found: {path}")
    try:
        data = yaml.safe_load(path.read_text()) or {}
    except Exception as exc:
        raise RuntimeError(f"failed to parse workflow file {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise RuntimeError(f"workflow file {path} must be a YAML object")
    return data


def parse_and_normalize_workflow(yaml_text: str, resources_dir: Path) -> dict[str, Any]:
    """Parse workflow YAML *text* (not a path) and return the normalized dict.

    The string-input counterpart to :func:`load_workflow_file`; used by the
    HTTP layer for builder/import/preview flows. Raises ``ValueError`` when the
    text is unparseable or is not a YAML object.
    """
    try:
        raw = yaml.safe_load(yaml_text or "") or {}
    except Exception as exc:
        raise ValueError(f"failed to parse YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError("workflow must be a YAML object")
    return normalize_workflow(raw, resources_dir=resources_dir)


def normalize_workflow(
    raw: dict[str, Any],
    *,
    resources_dir: Path,
) -> dict[str, Any]:
    """Validate and normalize a raw workflow dict.

    Validates the metadata and spec blocks, validates adversary entries
    via ``adversary.definitions``, and resolves cross-stage param
    references. Does not load case files or adversary scenario files;
    those are deferred to :func:`resolve_workflow_rows`.

    Parameters
    ----------
    raw:
        Parsed workflow YAML dict.
    resources_dir:
        Root resources directory; used to load each stage's case so
        cross-stage param references resolve against effective values.

    Raises
    ------
    ValueError
        When pydantic schema validation fails. The error message
        identifies the exact field path and reason.

    Returns
    -------
    dict
        Keys: ``id`` (str), ``label`` (str or ``None``),
        ``prompt_mode`` (str), ``agent_session`` (str),
        ``system_prompt`` (str or ``None``), ``stages`` (list[dict]),
        ``adversary`` (list[dict]), and ``debug`` (dict).
    """
    try:
        WorkflowSchema.model_validate(raw)
    except ValidationError as exc:
        details = "; ".join(
            f"{'.'.join(str(loc) for loc in e['loc'])}: {e['msg']}"
            for e in exc.errors()
        )
        raise ValueError(
            f"workflow schema validation failed: {details}"
        ) from exc

    meta = raw.get("metadata") or {}
    spec = raw.get("spec") or {}
    raw_stages = spec.get("stages") or []

    normalized_stages: list[dict[str, Any]] = []
    prior_stage_params: dict[str, dict[str, Any]] = {}
    # Local import: cases <-> workflows would be a circular top-level import.
    from .cases import load_case_file, resolve_case_params

    for i, s in enumerate(raw_stages):
        stage_id = str(s.get("id") or f"stage_{i + 1}")
        # stage_id becomes a path segment (runs/<id>/stages/<stage_id>/...), so it
        # must not carry traversal characters -- an unguarded id like
        # "../../../x" from workflow YAML would write artifacts outside runs/.
        if not _is_valid_name(stage_id):
            raise ValueError(
                f"invalid stage id {stage_id!r}: only letters, digits, '-', and '_' are allowed"
            )
        resolved_overrides, w = _resolve_stage_param_overrides(
            s, i, raw_stages, prior_stage_params
        )
        ns_list = _namespace_aliases_for_stage(s)
        stage_dict: dict[str, Any] = {
            "id": stage_id,
            "service": str(s.get("service") or ""),
            "case_name": str(s.get("case") or ""),
            "param_overrides": resolved_overrides,
            "namespaces": ns_list,
            "namespace_binding": {
                str(k): str(v) for k, v in (s.get("namespace_binding") or {}).items()
            },
            "agent_timeout_sec": int(s.get("agent_timeout_sec") or _DEFAULT_AGENT_TIMEOUT_SEC),
            "retries": int(s.get("retries") or 0),
            "_warnings": w,
        }
        normalized_stages.append(stage_dict)
        # Record this stage's EFFECTIVE params (case defaults + overrides) so a
        # later stage's ${stages.X.params.Y} resolves to the real value even when
        # X left Y at its case default -- not None (SS-7). Best-effort: on any case
        # load/validation failure fall back to overrides-only (the prior behavior);
        # the definitive case load + validation happens in resolve_workflow_rows.
        effective_params = dict(resolved_overrides)
        svc, cn = str(s.get("service") or ""), str(s.get("case") or "")
        if svc and cn:
            try:
                effective_params, _ = resolve_case_params(
                    load_case_file(resources_dir, svc, cn), resolved_overrides
                )
            except Exception:
                effective_params = dict(resolved_overrides)
        prior_stage_params[stage_id] = effective_params

    return {
        "id": str(meta.get("id") or ""),
        "label": meta.get("label"),
        "prompt_mode": str(spec.get("prompt_mode") or _DEFAULT_PROMPT_MODE),
        "agent_session": str(spec.get("agent_session") or _DEFAULT_AGENT_SESSION),
        "system_prompt": (str(spec.get("system_prompt") or "").strip() or None),
        "stages": normalized_stages,
        "adversary": list(spec.get("adversary") or []),
        "debug": {
            "namespace_overrides": dict(
                (spec.get("debug") or {}).get("namespace_overrides") or {}
            ),
        },
    }


def resolve_workflow_rows(
    workflow: dict[str, Any],
    *,
    resources_dir: Path,
) -> list[dict[str, Any]]:
    """Resolve a normalized workflow into an ordered list of workflow rows.

    Loads case files, normalizes cases, resolves adversary scenarios from
    disk, and assembles the full row dict for each stage. This is the
    single point of filesystem I/O for case and adversary resolution.

    Parameters
    ----------
    workflow:
        Normalized workflow dict from :func:`normalize_workflow`.
    resources_dir:
        Root resources directory.

    Raises
    ------
    RuntimeError
        When any case or adversary scenario cannot be loaded.

    Returns
    -------
    list[dict]
        Ordered list of workflow row dicts. See module docstring for the
        row shape.
    """
    from .cases import load_case_file, normalize_case
    from ..adversary.definitions import (
        resolve_adversary_scenario,
        collect_stage_operations,
        collect_stage_hint,
    )

    stages = workflow.get("stages") or []
    all_stage_ids = [str(s.get("id") or "") for s in stages]
    stage_service_map = {
        str(s.get("id") or ""): str(s.get("service") or "") for s in stages
    }

    # Resolve every adversary entry once, loading and normalizing its scenario
    # file. Each injection targets exactly one inject_at_stage, so the per-stage
    # collectors below distribute the deploy/lift units to the right rows.
    injections: list[dict[str, Any]] = []
    for adv in (workflow.get("adversary") or []):
        if not isinstance(adv, dict):
            continue
        injections.append(
            resolve_adversary_scenario(
                adv, stage_service_map, resources_dir=resources_dir
            )
        )

    rows: list[dict[str, Any]] = []
    for stage in stages:
        service = stage["service"]
        case_name = stage["case_name"]
        stage_id = stage["id"]
        param_overrides = stage.get("param_overrides") or {}

        case_data = load_case_file(resources_dir, service, case_name)
        normalized = normalize_case(case_data, service, case_name, param_overrides)

        deploy_units, lift_units = collect_stage_operations(injections, stage_id)
        hint = collect_stage_hint(injections, stage_id, all_stage_ids)
        stage_injections = [
            inj for inj in injections if inj.get("inject_at_stage") == stage_id
        ]

        # Namespace roles. Explicit per-stage namespaces win. Otherwise honour
        # the case's required_roles -- INCLUDING an explicit empty list, which
        # means "no roles; I manage my own literal namespaces." Binding a
        # "default" role there would set BENCH_NAMESPACE to a karma-* namespace
        # and break literal-namespace oracles (e.g. spark's bench_namespace()
        # default). Only a missing/None contract falls back to one default
        # namespace (so single-role cases like demo still work).
        _ns = stage.get("namespaces")
        _rr = (normalized.get("namespace_contract") or {}).get("required_roles")
        if _ns:
            _roles = _ns
        elif _rr is not None:
            _roles = _rr
        else:
            _roles = [_DEFAULT_NAMESPACE_ALIAS]

        row: dict[str, Any] = {
            "stage_id": stage_id,
            "service": service,
            "case_name": case_name,
            "case": normalized,
            "namespace_roles": _roles,
            "namespace_binding": stage.get("namespace_binding") or None,
            "adversary_deploy": deploy_units,
            "adversary_lift": lift_units,
            "adversary_hint": hint,
            "adversary_injections": stage_injections,
            "prompt_mode": workflow.get("prompt_mode") or _DEFAULT_PROMPT_MODE,
            "agent_timeout_sec": stage.get("agent_timeout_sec") or _DEFAULT_AGENT_TIMEOUT_SEC,
            "retries": int(stage.get("retries") or 0),
        }
        rows.append(row)

    return rows


def single_case_to_workflow(
    service: str,
    case_name: str,
    param_overrides: dict[str, Any] | None = None,
    *,
    prompt_mode: str = _DEFAULT_PROMPT_MODE,
    agent_timeout_sec: int = _DEFAULT_AGENT_TIMEOUT_SEC,
    namespace_roles: list[str] | None = None,
    retries: int = 0,
) -> dict[str, Any]:
    """Return a 1-stage workflow dict for a single-case run.

    Called by ``interfaces.http.jobs`` to convert a UI form submission
    into the same workflow representation used by the CLI path, ensuring
    both paths execute through an identical runtime stack.

    The generated stage ID is ``"stage_1"``. The workflow ID is derived
    from *service* and *case_name*.

    Parameters
    ----------
    service:
        Service name, e.g. ``"rabbitmq"``.
    case_name:
        Case name, e.g. ``"failover"``.
    param_overrides:
        Optional parameter overrides applied to the case.
    prompt_mode:
        One of ``"progressive"``, ``"concat_stateful"``,
        ``"concat_blind"``.
    agent_timeout_sec:
        Agent timeout in seconds for the single stage.
    namespace_roles:
        Explicit namespace roles; when ``None`` the case contract is used.
    retries:
        Number of retry attempts for the stage (clamped to ``>= 0``).
    """
    if prompt_mode not in _VALID_PROMPT_MODES:
        prompt_mode = _DEFAULT_PROMPT_MODE

    # None (no explicit override) is passed through so resolve_workflow_rows can
    # derive the roles from the case's namespace_contract.required_roles. Forcing
    # [default] here would mask multi-role cases (e.g. source/target).
    namespaces = namespace_roles
    workflow_id = f"{service}/{case_name}"

    return {
        "id": workflow_id,
        "label": None,
        "prompt_mode": prompt_mode,
        "stages": [
            {
                "id": "stage_1",
                "service": service,
                "case_name": case_name,
                "param_overrides": dict(param_overrides or {}),
                "namespaces": namespaces,
                "agent_timeout_sec": agent_timeout_sec,
                "retries": max(0, int(retries)),
                "_warnings": [],
            }
        ],
        "adversary": [],
    }


def get_all_stage_ids(workflow: dict[str, Any]) -> list[str]:
    """Return the ordered list of stage IDs from a normalized workflow dict."""
    return [str(s.get("id") or "") for s in (workflow.get("stages") or [])]

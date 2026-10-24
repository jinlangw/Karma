"""
Case loading, schema validation, parameter resolution, and config normalization.

A *case* is one benchmark task defined by a ``test.yaml`` file under the
configured resource root (the built-in root is ``cases/tests``), grouped as
``{service}/{case_name}/``. This module loads that file from disk, validates
its structure, resolves parameter overrides, and returns
a normalized case descriptor consumed by ``runtime.case``.

Only the contemporary case format is accepted. Files containing legacy
fields such as ``preOperationCommands`` or ``verificationCommands`` are
rejected at load time with a descriptive error. No dual-format branching
exists anywhere in this module or downstream in ``runtime.case``.

Schema validation is performed by pydantic models defined in this
module. ``load_case_file`` runs ``CaseSchema.model_validate`` before
returning, so no unvalidated dict ever reaches normalization code.

No runtime imports. All functions operate on plain dicts and ``Path``
objects.
"""

from __future__ import annotations

import re
from copy import deepcopy
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, ValidationError, field_validator, model_validator

_TEST_FILE_NAME = "test.yaml"
_VALID_ON_PROBE_FAIL = {"error", "skip"}


# ---------------------------------------------------------------------------
# Pydantic schema models
# ---------------------------------------------------------------------------

class _CommandItem(BaseModel):
    """A single command entry in a probe, apply, or verify block."""

    command: str
    trusted_stdin: Literal["stage_key"] | None = None
    sleep: int = 0
    namespace_role: str | None = None
    timeout_sec: int | None = None


class _PreconditionUnit(BaseModel):
    """One precondition unit with a name and an operation block."""

    name: str
    probe: list[_CommandItem] | _CommandItem | str
    apply: list[_CommandItem] | _CommandItem | str
    verify: list[_CommandItem] | _CommandItem | str
    on_probe_fail: Literal["error", "skip"] = "skip"


class _OracleVerify(BaseModel):
    """The verify block inside the oracle config."""

    commands: list[_CommandItem] | _CommandItem | str = []
    retries: int = 1
    interval_sec: float = 0.0


class _OracleConfig(BaseModel):
    """The oracle block at the top level of a test.yaml."""

    verify: _OracleVerify = _OracleVerify()
    script: str | None = None


class _ParamDefinition(BaseModel):
    """A single parameter definition: a default plus optional type and
    validation constraints.

    ``type`` is one of ``string``/``int``/``float``/``bool``/``enum``/
    ``duration``/``quantity`` (default ``string``). ``values`` lists the
    allowed choices for an ``enum``. ``min``/``max`` bound numeric values,
    ``pattern`` is a regex the (stringified) value must match, and
    ``required`` forces an override to be supplied. Unset constraints impose
    no restriction, so a bare ``{default: x}`` keeps its old behavior.
    """

    default: Any = None
    description: str = ""
    type: str | None = None
    values: list[Any] | None = None
    min: float | None = None
    max: float | None = None
    pattern: str | None = None
    required: bool = False


class _NamespaceContract(BaseModel):
    """Namespace role requirements for a case."""

    required_roles: list[str] = []
    optional_roles: list[str] = []


class CaseSchema(BaseModel):
    """Top-level schema for a contemporary ``test.yaml`` file.

    Validation fails immediately when a required field is missing, a
    field has the wrong type, or an unrecognized top-level key is
    present that is not a known contemporary field. The error message
    from pydantic identifies the exact field path and reason.

    ``extra='forbid'`` makes a mis-keyed top-level field a hard error rather
    than a silent drop: e.g. ``oracel:`` (a typo of ``oracle:``) would
    otherwise vanish, leaving the case with an empty oracle that passes
    unconditionally. Nested blocks (``oracle.verify`` etc.) keep the default
    ``extra='ignore'`` on purpose -- the oracle normalizer reads before/after
    hooks straight from the raw dict, so those keys must be allowed through.
    """

    model_config = ConfigDict(extra="forbid")

    prompt: str
    params: dict[str, _ParamDefinition] = {}
    preconditionUnits: list[_PreconditionUnit] = []
    oracle: _OracleConfig = _OracleConfig()
    namespace_contract: _NamespaceContract = _NamespaceContract()
    decoys: list[Any] = []
    metrics: list[str] = []
    tags: list[str] = []


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


def _normalize_command_item(raw: Any) -> dict[str, Any] | None:
    """Return a canonical command dict for *raw*, or ``None`` when invalid.

    Accepts a non-empty string or a dict containing at minimum a
    ``"command"`` key. Recognized dict keys: ``command``, ``sleep``,
    ``namespace_role`` / ``namespaceRole``, ``timeout_sec`` /
    ``timeoutSec``.
    """
    if isinstance(raw, str):
        raw = raw.strip()
        if not raw:
            return None
        return {"command": raw, "sleep": 0}
    if not isinstance(raw, dict):
        return None
    command = raw.get("command")
    if command is None:
        return None
    item: dict[str, Any] = {
        "command": command,
        "sleep": _coerce_int(raw.get("sleep", 0), default=0),
    }
    ns = raw.get("namespace_role") or raw.get("namespaceRole")
    if ns is not None:
        item["namespace_role"] = str(ns).strip()
    ts = raw.get("timeout_sec") or raw.get("timeoutSec")
    if ts is not None:
        item["timeout_sec"] = _coerce_int(ts, default=60)
    if raw.get("trusted_stdin") is not None:
        if raw["trusted_stdin"] != "stage_key":
            raise RuntimeError("trusted_stdin must be stage_key")
        item["trusted_stdin"] = "stage_key"
    return item


def _normalize_commands(raw: Any) -> list[dict[str, Any]]:
    """Return a list of canonical command dicts from *raw*.

    Accepts a single command string, a single command dict, or a list of
    either. Invalid and ``None`` entries are skipped silently.
    """
    if raw is None:
        return []
    if isinstance(raw, (str, dict)):
        raw = [raw]
    if not isinstance(raw, list):
        return []
    result = []
    for item in raw:
        normalized = _normalize_command_item(item)
        if normalized is not None:
            result.append(normalized)
    return result


def _normalize_operation_block(
    raw: Any,
    label: str,
    case_id: str,
    *,
    default_on_probe_fail: str = "skip",
) -> dict[str, Any]:
    """Return a canonical operation unit dict for *raw*.

    An operation unit has three sub-blocks: ``probe``, ``apply``, and
    ``verify``. Each must resolve to at least one command.

    Parameters
    ----------
    raw:
        Raw dict from the case YAML.
    label:
        Human-readable label used in error messages, e.g. ``"precondition[1]"``.
    case_id:
        Case identifier used in error messages.
    default_on_probe_fail:
        Default ``on_probe_fail`` value when not specified in *raw*.

    Raises
    ------
    ValueError
        When *raw* is not a dict, when any sub-block is missing commands,
        or when ``on_probe_fail`` is not a valid value.
    """
    if not isinstance(raw, dict):
        raise ValueError(f"case '{case_id}' {label} block must be an object")

    def _block_commands(value: Any) -> list[dict[str, Any]]:
        # A probe/apply/verify block may be a string, a command dict, a list,
        # or a structured block {"commands": [...], "retries": N, ...}. Unwrap
        # the structured form so its commands are extracted (the retries /
        # interval_sec fields are read separately below).
        if isinstance(value, dict) and "commands" in value:
            return _normalize_commands(value.get("commands"))
        return _normalize_commands(value)

    probe_commands = _block_commands(raw.get("probe"))
    apply_commands = _block_commands(raw.get("apply"))
    verify_commands = _block_commands(raw.get("verify"))

    if not probe_commands:
        raise ValueError(f"case '{case_id}' {label}.probe command(s) are required")
    if not apply_commands:
        raise ValueError(f"case '{case_id}' {label}.apply command(s) are required")
    if not verify_commands:
        raise ValueError(f"case '{case_id}' {label}.verify command(s) are required")

    probe_raw = raw.get("probe")
    on_probe_fail = default_on_probe_fail
    if isinstance(probe_raw, dict):
        v = probe_raw.get("on_probe_fail")
        if v is not None:
            on_probe_fail = str(v).strip().lower()
    if on_probe_fail not in _VALID_ON_PROBE_FAIL:
        raise ValueError(
            f"case '{case_id}' {label}.probe.on_probe_fail must be one of: "
            f"{', '.join(sorted(_VALID_ON_PROBE_FAIL))}"
        )

    # Verify confirms the apply established the target state, which usually
    # converges asynchronously (pods reaching Ready, a controller publishing
    # readyReplicas). Default verify to RETRY (~120s) so it waits for that
    # convergence instead of a single point-in-time check that loses the race on
    # a fresh/busy cluster. The common list-form verify lands here with vd={} and
    # gets these defaults; a structured verify block can still override them. A
    # verify that already holds passes on the first attempt, so this is free when
    # the state is ready and only adds waiting when it is not.
    vd = raw.get("verify") if isinstance(raw.get("verify"), dict) else {}
    retries = _coerce_int(vd.get("retries") if isinstance(vd, dict) else None, default=24)
    interval_sec = _coerce_float(
        (vd.get("interval_sec") or vd.get("intervalSec")) if isinstance(vd, dict) else None,
        default=5.0,
    )

    return {
        "id": f"{case_id}:{label}",
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

def _is_safe_segment(name: str) -> bool:
    """Return ``True`` when *name* is a single safe path component.

    Rejects empty, ``.``/``..``, and any value containing a path separator,
    so service/case names taken from URLs or request bodies cannot escape
    *resources_dir* via traversal.
    """
    return bool(name) and name not in (".", "..") and "/" not in name and "\\" not in name


def case_path(resources_dir: Path, service: str, case_name: str) -> Path:
    """Return the ``test.yaml`` path for *service*/*case_name*.

    Does not check whether the file exists.
    """
    return resources_dir / service / case_name / _TEST_FILE_NAME


_LEGACY_FIELDS: dict[str, str] = {
    "preOperationCommands": "preconditionUnits",
    "verificationCommands": "oracle.verify.commands",
}


def load_case_file(resources_dir: Path, service: str, case_name: str) -> dict[str, Any]:
    """Load and parse the ``test.yaml`` for *service*/*case_name*.

    Raises
    ------
    RuntimeError
        When the file is absent or cannot be parsed as a YAML object, or
        when the file contains a legacy field such as
        ``preOperationCommands`` or ``verificationCommands``, or when
        pydantic schema validation fails. The error message names the
        offending field path and the reason.
    """
    for segment, label in ((service, "service"), (case_name, "case")):
        if not _is_safe_segment(segment):
            raise RuntimeError(f"invalid {label} name: {segment!r}")
    path = case_path(resources_dir, service, case_name)
    if not path.exists():
        raise RuntimeError(f"case '{case_name}': test.yaml not found at {path}")
    try:
        data = yaml.safe_load(path.read_text()) or {}
    except Exception as exc:
        raise RuntimeError(
            f"case '{case_name}': failed to parse {path}: {exc}"
        ) from exc
    if not isinstance(data, dict):
        raise RuntimeError(f"case '{case_name}': {path} must be a YAML object")
    for legacy_field, replacement in _LEGACY_FIELDS.items():
        if legacy_field in data:
            raise RuntimeError(
                f"case '{case_name}': legacy field '{legacy_field}' is not supported. "
                f"Use '{replacement}' instead."
            )
    try:
        CaseSchema.model_validate(data)
    except ValidationError as exc:
        details = "; ".join(
            f"{'.'.join(str(loc) for loc in e['loc'])}: {e['msg']}"
            for e in exc.errors()
        )
        raise RuntimeError(
            f"case '{case_name}': schema validation failed: {details}"
        ) from exc
    return data


def _coerce_bool(value: Any) -> bool:
    """Parse a boolean from a bool/number/string, raising on garbage."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    raw = str(value).strip().lower()
    if raw in ("1", "true", "yes", "on"):
        return True
    if raw in ("0", "false", "no", "off"):
        return False
    raise ValueError(f"cannot parse bool from {value!r}")


def _coerce_param_value(name: str, spec: dict[str, Any], value: Any) -> Any:
    """Coerce and validate *value* for param *name* against its *spec*.

    Applies type coercion (string/int/float/bool/enum/duration/quantity),
    enum membership, numeric ``min``/``max`` bounds, and a regex ``pattern``.
    Returns ``None`` unchanged (an unset optional param). Raises
    ``ValueError`` on any type or constraint violation.
    """
    if value is None:
        return None

    # Coerce only when a type is explicitly declared; an untyped param keeps
    # its native value (so a bare ``{default: 3}`` stays the int 3).
    raw_type = spec.get("type")
    if raw_type is not None:
        param_type = str(raw_type).strip().lower()
        if param_type in ("string", "duration", "quantity"):
            value = str(value)
        elif param_type == "int":
            value = int(value)
        elif param_type in ("float", "number"):
            value = float(value)
        elif param_type == "bool":
            value = _coerce_bool(value)
        elif param_type == "enum":
            choices = spec.get("values")
            if not isinstance(choices, list) or not choices:
                raise ValueError(f"param {name}: enum requires a non-empty 'values' list")
            choice_set = {str(item) for item in choices}
            if str(value) not in choice_set:
                raise ValueError(
                    f"param {name}: value {value!r} not in {sorted(choice_set)}"
                )
            value = str(value)
        else:
            raise ValueError(f"param {name}: unsupported type {param_type!r}")

    min_value = spec.get("min")
    max_value = spec.get("max")
    if min_value is not None and isinstance(value, (int, float)) and value < min_value:
        raise ValueError(f"param {name}: value {value} < min {min_value}")
    if max_value is not None and isinstance(value, (int, float)) and value > max_value:
        raise ValueError(f"param {name}: value {value} > max {max_value}")

    pattern = spec.get("pattern")
    if pattern is not None:
        try:
            if not re.match(str(pattern), str(value)):
                raise ValueError(
                    f"param {name}: value {value!r} does not match pattern {pattern!r}"
                )
        except re.error as exc:
            raise ValueError(f"param {name}: invalid regex {pattern!r}: {exc}") from exc

    return value


def resolve_case_params(
    case_data: dict[str, Any],
    param_overrides: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], list[str]]:
    """Resolve, coerce, and validate the final parameter values for a case.

    Merges declared parameter defaults from *case_data* with
    *param_overrides* (overrides win), coercing and validating every value
    against its declared ``type``/``values``/``min``/``max``/``pattern`` and
    enforcing ``required``. Unrecognized override keys produce a warning
    rather than an error.

    Raises
    ------
    ValueError
        When a value fails type coercion or a constraint, or a ``required``
        param has no value.

    Returns
    -------
    tuple[dict, list[str]]
        ``(resolved_params, warnings)`` where *warnings* is a list of
        non-fatal diagnostic strings.
    """
    declared: dict[str, Any] = case_data.get("params") or {}
    overrides: dict[str, Any] = param_overrides or {}
    warnings: list[str] = []

    def _spec(param_def: Any) -> dict[str, Any]:
        return param_def if isinstance(param_def, dict) else {"default": param_def}

    resolved: dict[str, Any] = {}
    for key, param_def in declared.items():
        spec = _spec(param_def)
        if "default" in spec:
            resolved[key] = _coerce_param_value(key, spec, spec.get("default"))

    for key, value in overrides.items():
        if key not in declared:
            warnings.append(f"unrecognized param override '{key}' (not declared in case)")
            resolved[key] = value
        else:
            resolved[key] = _coerce_param_value(key, _spec(declared[key]), value)

    for key, param_def in declared.items():
        if _spec(param_def).get("required") and key not in resolved:
            raise ValueError(f"required param missing: {key}")

    return resolved, warnings


_PARAM_TOKEN_RE = re.compile(r"\{\{params\.([a-zA-Z0-9_]+)\}\}")
_FULL_PARAM_TOKEN_RE = re.compile(r"^\s*\{\{params\.([a-zA-Z0-9_]+)\}\}\s*$")


def _substitute_param_tokens(value: Any, params: dict[str, Any]) -> Any:
    """Recursively substitute ``{{params.key}}`` tokens in *value*.

    A string that is exactly one token returns the param's native value
    (preserving non-string types); tokens embedded in a larger string are
    replaced with the string form of the value. Tokens whose key is not in
    *params* are left untouched so partially-parameterized cases do not
    crash at load time.
    """
    if isinstance(value, str):
        full = _FULL_PARAM_TOKEN_RE.match(value)
        if full and full.group(1) in params:
            return params[full.group(1)]

        def _repl(m: re.Match) -> str:
            key = m.group(1)
            return str(params[key]) if key in params else m.group(0)

        return _PARAM_TOKEN_RE.sub(_repl, value)
    if isinstance(value, list):
        return [_substitute_param_tokens(item, params) for item in value]
    if isinstance(value, dict):
        return {k: _substitute_param_tokens(v, params) for k, v in value.items()}
    return value


def normalize_namespace_contract(case_data: dict[str, Any]) -> dict[str, Any]:
    """Return the normalized namespace contract from *case_data*.

    Returns
    -------
    dict
        Keys ``required_roles`` (list[str]) and ``optional_roles``
        (list[str]). Both lists are deduplicated with order preserved.
        An absent contract is represented as two empty lists.
    """
    raw = case_data.get("namespace_contract") or {}
    if not isinstance(raw, dict):
        raw = {}

    def _dedup(lst: Any) -> list[str]:
        seen: set[str] = set()
        result: list[str] = []
        for item in (lst or []):
            s = str(item).strip()
            if s and s not in seen:
                seen.add(s)
                result.append(s)
        return result

    return {
        "required_roles": _dedup(raw.get("required_roles")),
        "optional_roles": _dedup(raw.get("optional_roles")),
    }


def normalize_precondition_units(case_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the list of normalized precondition operation units from *case_data*.

    Reads from the ``preconditionUnits`` key only. Any file containing a
    legacy field such as ``preOperationCommands`` is rejected upstream by
    :func:`load_case_file` before this function is ever reached, so no
    format detection is performed here.

    Each unit has the canonical probe/apply/verify shape produced by
    :func:`_normalize_operation_block`. Returns an empty list when the
    case declares no preconditions.

    Raises
    ------
    RuntimeError
        When any unit is structurally invalid.
    """
    raw_units = case_data.get("preconditionUnits") or []
    if not isinstance(raw_units, list):
        return []

    result: list[dict[str, Any]] = []
    for i, unit in enumerate(raw_units):
        if not isinstance(unit, dict):
            raise RuntimeError(
                f"preconditionUnits[{i}] must be a dict, got {type(unit).__name__}"
            )
        name = unit.get("name") or f"unit_{i}"
        label = f"preconditionUnits[{i}] '{name}'"
        on_probe_fail = str(unit.get("on_probe_fail") or "skip").strip().lower()
        try:
            normalized = _normalize_operation_block(
                unit,
                label=label,
                case_id=name,
                default_on_probe_fail=on_probe_fail,
            )
            normalized["name"] = name
            result.append(normalized)
        except ValueError as exc:
            raise RuntimeError(str(exc)) from exc

    return result


def normalize_oracle_config(case_data: dict[str, Any]) -> dict[str, Any]:
    """Return the normalized oracle configuration from *case_data*.

    Returns
    -------
    dict
        Keys: ``verify_commands`` (list), ``before_commands`` (list),
        ``after_commands`` (list), ``after_failure_mode`` (``"warn"`` or
        ``"fail"``), ``script_path`` (str or ``None``).
    """
    raw = case_data.get("oracle") or {}
    if not isinstance(raw, dict):
        raw = {}

    # Pydantic's extra='ignore' drops before/after hooks from CaseSchema,
    # so we read them directly from the raw dict here.
    verify_block = raw.get("verify") or {}
    if not isinstance(verify_block, dict):
        verify_block = {}

    verify_commands = _normalize_commands(verify_block.get("commands"))
    before_commands = _normalize_commands(verify_block.get("before_commands"))
    after_commands = _normalize_commands(verify_block.get("after_commands"))

    raw_mode = str(verify_block.get("after_failure_mode") or "warn").strip().lower()
    after_failure_mode = raw_mode if raw_mode in ("warn", "fail") else "warn"

    script_path: str | None = None
    if isinstance(raw.get("script"), str):
        script_path = raw["script"].strip() or None

    # Case-authored convergence retries for the verify: an eventually-consistent
    # check (e.g. "all pods Ready") can author retries: N / interval_sec so the
    # oracle re-runs the verify on FAIL instead of losing the race once. Default
    # 1 (single check) keeps existing behavior for cases that don't ask for it.
    # (The precondition normalizer honors the same keys; the oracle side dropped
    # them silently -- M6.)
    retries = _coerce_int(verify_block.get("retries"), default=1)
    interval_sec = _coerce_float(
        verify_block.get("interval_sec") or verify_block.get("intervalSec"),
        default=2.0,
    )

    return {
        "verify_commands": verify_commands,
        "before_commands": before_commands,
        "after_commands": after_commands,
        "after_failure_mode": after_failure_mode,
        "script_path": script_path,
        "verify_retries": max(1, retries),
        "verify_interval_sec": max(0.0, interval_sec),
    }


def normalize_decoy_config(case_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the list of normalized decoy descriptors from *case_data*.

    Each descriptor has keys ``path`` (str) and ``namespace`` (str).
    Returns an empty list when the case declares no decoys.
    """
    raw = case_data.get("decoys") or []
    if not isinstance(raw, list):
        return []

    result: list[dict[str, Any]] = []
    for item in raw:
        if isinstance(item, dict):
            path = str(item.get("path") or "").strip()
            namespace = str(item.get("namespace") or "").strip()
            if path:
                result.append({"path": path, "namespace": namespace})
        elif isinstance(item, str):
            item = item.strip()
            if item:
                result.append({"path": item, "namespace": ""})

    return result


def decoy_manifest_namespace(resources_dir: Any, rel_path: str) -> str:
    """Return the first non-empty ``metadata.namespace`` in a decoy manifest.

    A decoy descriptor's ``namespace`` is the target the manifest is applied
    into (``kubectl apply -n``); resolving it from the manifest itself gives a
    descriptor left at ``""`` a concrete namespace instead of falling back to
    the default. Parses every document of the (possibly multi-doc) manifest;
    returns ``""`` when unreadable or when no document declares a namespace
    (Law 4).
    """
    try:
        import yaml

        with open(Path(resources_dir) / rel_path, encoding="utf-8") as fh:
            for doc in yaml.safe_load_all(fh):
                if isinstance(doc, dict):
                    ns = str(((doc.get("metadata") or {}).get("namespace")) or "").strip()
                    if ns:
                        return ns
    except Exception:
        pass
    return ""


def discover_case_decoys(
    resources_dir: Any, service: str, case_name: str
) -> list[dict[str, Any]]:
    """Return decoy descriptors discovered under the case's ``decoy/`` dir.

    Scans ``<resources_dir>/<service>/<case_name>/decoy/*.yaml`` and returns
    one descriptor per file (``path`` relative to *resources_dir*,
    ``namespace`` resolved from the manifest's own ``metadata.namespace`` so
    the decoy is planted into the namespace it declares). This auto-discovers
    on-disk decoy manifests; an explicit ``decoys:`` key in the case is also
    honored, though no shipped case declares one.
    """
    base = Path(resources_dir)
    decoy_dir = base / service / case_name / "decoy"
    if not decoy_dir.is_dir():
        return []
    return [
        {
            "path": str(p.relative_to(base)),
            "namespace": decoy_manifest_namespace(base, str(p.relative_to(base))),
        }
        for p in sorted(decoy_dir.glob("*.yaml"))
    ]


def normalize_case(
    case_data: dict[str, Any],
    service: str,
    case_name: str,
    param_overrides: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return the fully normalized case descriptor for *case_data*.

    Runs all sub-normalizations and returns a single flat dict that
    ``runtime.case`` consumes without further parsing.

    Raises
    ------
    RuntimeError
        When any structural error is detected during normalization.

    Returns
    -------
    dict
        Keys: ``service``, ``case_name``, ``params``,
        ``namespace_contract``, ``precondition_units``, ``oracle``,
        ``decoys``, ``metrics``, ``tags``, ``warnings``.
    """
    data = deepcopy(case_data)
    params, warnings = resolve_case_params(data, param_overrides)
    # Substitute {{params.key}} tokens throughout the case (commands, prompt,
    # decoys) with the resolved param values before sub-normalization, so the
    # units consumed by runtime.case carry concrete values rather than tokens.
    data = _substitute_param_tokens(data, params)
    namespace_contract = normalize_namespace_contract(data)
    precondition_units = normalize_precondition_units(data)
    oracle = normalize_oracle_config(data)
    # Every case MUST carry a real oracle: an oracle with no verify commands and
    # no script checks nothing, and "nothing checked" is scored as an
    # unconditional pass. Enforce this at the module level so the contract holds
    # wherever the case is loaded -- standalone or resolved inside a workflow --
    # rather than leaving the workflow parser to reach into each case (the oracle
    # is a property of the case, not the workflow). This is post-normalization on
    # purpose: it catches oracles that normalize to empty (e.g. commands: [""]),
    # not just a literally-absent block.
    if not oracle.get("verify_commands") and not oracle.get("script_path"):
        raise RuntimeError(
            f"case '{service}/{case_name}': oracle has no verify commands and no "
            f"script -- a case must define at least one oracle check (an empty "
            f"oracle would pass unconditionally)"
        )
    decoys = normalize_decoy_config(data)

    metrics = [str(m) for m in (data.get("metrics") or []) if m]
    tags = [str(t) for t in (data.get("tags") or []) if t]

    return {
        "service": service,
        "case_name": case_name,
        "prompt": data.get("prompt", ""),
        "params": params,
        "namespace_contract": namespace_contract,
        "precondition_units": precondition_units,
        "oracle": oracle,
        "decoys": decoys,
        "metrics": metrics,
        "tags": tags,
        "warnings": warnings,
    }

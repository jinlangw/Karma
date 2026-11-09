"""
Public runtime API for CLI and HTTP adapters.

This is the single entrypoint into the execution core. Neither adapter
implements orchestration logic; both call functions from this module.

Dependency rules:

- This module imports from ``runtime.case``, ``runtime.workflow``,
  ``definitions``, ``environments``, ``agents``, ``sandbox``, and
  ``protocol``.
- ``interfaces.*`` imports from this module; this module never imports
  from ``interfaces.*``.
"""

from __future__ import annotations

import threading
import uuid
from pathlib import Path
from typing import Any

import json

from ..definitions.workflows import resolve_workflow_rows, single_case_to_workflow
from ..environments.registry import get_environment
from ..agents.registry import resolve_agent
from ..protocol import generate_run_id, run_config_path
from .._warn import warn
from .workflow import run_workflow_loop

# Default system prompt (the harness contract) applied to every run's agents.
# The workflow's spec.system_prompt is APPENDED to this; a CLI --system-prompt
# replaces this base. docs/default-system-prompt.md is the single source of truth.
_DEFAULT_SYSTEM_PROMPT_PATH = Path(__file__).resolve().parents[2] / "docs" / "default-system-prompt.md"


def _default_system_prompt() -> str:
    """Return the base system prompt read from docs/default-system-prompt.md.

    Returns "" if the file can't be read; the agents then deliver no system
    prompt, which they handle gracefully (no hardcoded copy to drift from it).
    """
    try:
        return _DEFAULT_SYSTEM_PROMPT_PATH.read_text().strip()
    except OSError:
        return ""


# ---------------------------------------------------------------------------
# Run status registry
# ---------------------------------------------------------------------------

_active_runs: dict[str, dict[str, Any]] = {}
_runs_lock = threading.Lock()


def _register_run(run_id: str, meta: dict[str, Any]) -> None:
    """Register *meta* under *run_id* in the active runs table."""
    with _runs_lock:
        _active_runs[run_id] = meta


def _update_run(run_id: str, updates: dict[str, Any]) -> None:
    """Apply *updates* to the entry for *run_id*. No-op when not found."""
    with _runs_lock:
        if run_id in _active_runs:
            _active_runs[run_id].update(updates)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_workflow(
    workflow: dict[str, Any],
    *,
    runs_dir: Path,
    resources_dir: Path,
    agent_name: str | None = None,
    sandbox_mode: str = "local",
    environment_provider: str | None = None,
    environment_config: dict[str, Any] | None = None,
    on_stage_complete: Any | None = None,
    on_progress: Any | None = None,
    should_cancel: Any | None = None,
    max_attempts: int | None = None,
    run_id: str | None = None,
    stage_failure_mode: str = "terminate",
    final_sweep_mode: str = "auto",
    sandbox_options: dict[str, Any] | None = None,
    agent_session: str | None = None,
    system_prompt: str | None = None,
    prompt_mode_prologues: str | None = None,
    namespace_overrides: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Execute a workflow synchronously and return the final run result.

    Resolves workflow rows, initializes the environment, and drives the
    workflow loop via ``runtime.workflow``. Blocks until completion.

    Parameters
    ----------
    workflow:
        Normalized workflow dict from ``definitions.workflows``.
    runs_dir:
        Directory under which the run artifact directory is created.
    resources_dir:
        Root resources directory forwarded to row resolution.
    agent_name:
        Registered agent name, or ``None`` for solver/local runs.
    sandbox_mode:
        ``"local"`` or ``"docker"``.
    environment_provider:
        Provider name passed to ``environments.registry.get_environment``.
    environment_config:
        Provider-specific config dict.
    namespace_overrides:
        Optional debug-only mapping from workflow namespace identities to
        explicit physical Kubernetes namespaces.
    on_stage_complete:
        Optional callable invoked with the stage result dict after each
        stage. Used by the HTTP SSE path to stream progress.
    run_id:
        Explicit run ID. A timestamped ID is generated when ``None``.

    Returns
    -------
    dict
        Keys: ``run_id``, ``status`` (``"complete"``, ``"failed"``,
        ``"cancelled"``, or ``"error"``), ``stages`` (list[dict]),
        ``summary`` (dict). ``"error"`` is returned only when this call
        itself raises (row resolution, environment/agent setup).
    """
    effective_run_id = run_id or generate_run_id(str(workflow.get("id") or "workflow"))
    run_dir = runs_dir / effective_run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    # Record agent/sandbox (and case info) so the UI shows them. The HTTP path
    # writes a richer config.json before calling us; only write when absent so we
    # don't clobber it. This covers CLI run-case, which otherwise has no
    # config.json and displays the agent as "none".
    cfg_path = run_config_path(run_dir)
    if not cfg_path.exists():
        wf_id = str(workflow.get("id") or "")
        cfg: dict[str, Any] = {"agent": agent_name, "sandbox": sandbox_mode, "workflow_id": wf_id}
        if "/" in wf_id:
            svc, _, cs = wf_id.partition("/")
            cfg["service"], cfg["case_name"] = svc, cs
        # Persist the resolved stage + adversary definitions so the Results
        # detail can show every stage even for a multi-stage CLI workflow run.
        wf_stages = workflow.get("stages") or []
        cfg["stage_total"] = len(wf_stages)
        # Record every behavior-affecting knob so the run self-documents and the
        # rerun command can reproduce the exact launch configuration (not the
        # outcome -- the agent is stochastic). Effective values: an explicit
        # override wins, then the workflow's own value, then the default. The HTTP
        # writer (jobs.py) records the same set.
        cfg["prompt_mode"] = str(workflow.get("prompt_mode") or "progressive")
        cfg["agent_session"] = str(agent_session or workflow.get("agent_session") or "persistent")
        cfg["max_attempts"] = max_attempts
        cfg["stage_failure_mode"] = stage_failure_mode
        cfg["final_sweep_mode"] = final_sweep_mode
        if namespace_overrides:
            cfg["debug_namespace_overrides"] = dict(namespace_overrides)
        cfg["stages"] = [
            {
                "id": s.get("id"),
                "service": s.get("service"),
                "case_name": s.get("case_name"),
                "param_overrides": s.get("param_overrides") or {},
                "agent_timeout_sec": s.get("agent_timeout_sec"),
            }
            for s in wf_stages
        ]
        cfg["adversary"] = [
            {
                "scenario": a.get("scenario"),
                "inject_at_stage": a.get("inject_at_stage"),
                "lift_at_stage": a.get("lift_at_stage"),
                "param_overrides": a.get("param_overrides") or {},
            }
            for a in (workflow.get("adversary") or [])
        ]
        try:
            cfg_path.write_text(json.dumps(cfg, indent=2))
        except Exception:
            pass

    _register_run(effective_run_id, {"run_id": effective_run_id, "status": "running", "stages": []})

    try:
        rows = resolve_workflow_rows(workflow, resources_dir=resources_dir)
        active_namespace_overrides = namespace_overrides or {}
        known_namespace_roles = {
            str(role)
            for row in rows
            for role in (
                row.get("namespace_roles")
                if row.get("namespace_roles") is not None
                else ["default"]
            )
        }
        unknown_override_roles = sorted(set(active_namespace_overrides) - known_namespace_roles)
        if unknown_override_roles:
            raise ValueError(
                "debug namespace override references unknown workflow namespace "
                f"role(s): {', '.join(unknown_override_roles)}"
            )
        env = get_environment(environment_provider, config=environment_config)
        agent_meta = resolve_agent(agent_name, sandbox_mode=sandbox_mode)
        # Docker image provisioning: override the tag and/or build the image on
        # demand (old --agent-tag / --docker-image / --agent-build).
        opts = sandbox_options or {}
        image_override = opts.get("image_tag")
        if image_override:
            agent_meta["image_tag"] = image_override
        if opts.get("build_image") and sandbox_mode == "docker" and agent_meta.get("folder"):
            from ..sandbox import build_agent_image
            # image_tag/run_dir are keyword-only; capture the built tag so the
            # launch step runs the image we just built (per-agent to avoid clashes).
            tag = agent_meta.get("image_tag") or f"karma-agent-{agent_name}:latest"
            agent_meta["image_tag"] = build_agent_image(
                agent_meta, image_tag=tag, run_dir=run_dir
            )
        prompt_mode = str(workflow.get("prompt_mode") or "progressive")
        # Persistent-session mode keeps ONE agent conversation alive across all
        # stages (each stage resumes the same CLI/api session). Mint one stable
        # session id per run; per_stage mode leaves it None (fresh agent/stage).
        # Explicit override (CLI/UI) wins, then the workflow's own value, then the
        # default (persistent: one agent conversation from the first stage to the last).
        agent_session = str(agent_session or workflow.get("agent_session") or "persistent")
        session_id = str(uuid.uuid4()) if agent_session == "persistent" else None
        # System prompt delivered to every agent each stage = a base (the CLI
        # --system-prompt override, else the default harness contract read from
        # docs/default-system-prompt.md) with the workflow's spec.system_prompt
        # APPENDED to it.
        base_prompt = (system_prompt or _default_system_prompt()).rstrip()
        if not base_prompt:
            # The harness contract resolved to nothing: the default file is
            # missing/empty (e.g. docs/ wasn't deployed) and no --system-prompt
            # was supplied. Don't drop it silently -- agents would run without the
            # single-session/submit contract. Warn loudly (an intentionally-empty
            # spec.system_prompt is fine; an empty BASE is not).
            warn(
                "no base system prompt resolved -- the default harness-contract file "
                f"({_DEFAULT_SYSTEM_PROMPT_PATH}) is missing or empty and no --system-prompt "
                "was given. Agents will run WITHOUT the harness contract; deploy docs/ "
                "or pass --system-prompt."
            )
        append_prompt = (workflow.get("system_prompt") or "").strip()
        effective_system_prompt = (
            base_prompt + "\n\n" + append_prompt if append_prompt else base_prompt
        )

        # Mode-specific prologue prepended to each stage's assembled prompt so the
        # agent understands the prompt STRUCTURE (default file, or the
        # --prompt-mode-prologues override). Resolved once; the mode is workflow-level.
        from ..definitions.prompts import load_prompt_mode_prologues
        stage_prologue = load_prompt_mode_prologues(prompt_mode_prologues).get(prompt_mode, "")

        result = run_workflow_loop(
            rows,
            run_id=effective_run_id,
            run_dir=run_dir,
            resources_dir=resources_dir,
            agent_meta=agent_meta,
            sandbox_mode=sandbox_mode,
            environment=env,
            prompt_mode=prompt_mode,
            stage_prologue=stage_prologue,
            agent_session=agent_session,
            session_id=session_id,
            system_prompt=effective_system_prompt,
            on_stage_complete=on_stage_complete,
            on_progress=on_progress,
            should_cancel=should_cancel,
            max_attempts=max_attempts,
            stage_failure_mode=stage_failure_mode,
            final_sweep_mode=final_sweep_mode,
            sandbox_options=sandbox_options,
            namespace_overrides=active_namespace_overrides,
        )
        result["summary"] = {
            "total_stages": len(rows),
            "passed": sum(1 for s in result.get("stages", []) if s.get("status") == "pass"),
            "failed": sum(1 for s in result.get("stages", []) if s.get("status") in ("fail", "error", "timeout")),
        }
        _update_run(effective_run_id, result)
        return result

    except Exception as exc:
        error_result: dict[str, Any] = {
            "run_id": effective_run_id,
            "status": "error",
            "stages": [],
            "summary": {},
            "error": str(exc),
        }
        _update_run(effective_run_id, error_result)
        return error_result


def run_case(
    service: str,
    case_name: str,
    *,
    runs_dir: Path,
    resources_dir: Path,
    param_overrides: dict[str, Any] | None = None,
    agent_name: str | None = None,
    sandbox_mode: str = "local",
    environment_provider: str | None = None,
    environment_config: dict[str, Any] | None = None,
    namespace_roles: list[str] | None = None,
    agent_timeout_sec: int = 900,
    max_attempts: int | None = None,
    stage_failure_mode: str = "terminate",
    final_sweep_mode: str = "auto",
    sandbox_options: dict[str, Any] | None = None,
    run_id: str | None = None,
) -> dict[str, Any]:
    """Execute a single case as a 1-stage workflow and return the run result.

    Converts the request into a workflow via
    ``definitions.workflows.single_case_to_workflow`` and delegates to
    :func:`run_workflow`, ensuring both the CLI and HTTP paths use
    identical runtime code.

    Returns the same result dict as :func:`run_workflow`.
    """
    # --max-attempts is a total attempt cap; the loop runs retries + 1 attempts.
    retries = max(0, max_attempts - 1) if max_attempts else 0
    workflow = single_case_to_workflow(
        service,
        case_name,
        param_overrides,
        agent_timeout_sec=agent_timeout_sec,
        namespace_roles=namespace_roles,
        retries=retries,
    )
    return run_workflow(
        workflow,
        runs_dir=runs_dir,
        resources_dir=resources_dir,
        agent_name=agent_name,
        sandbox_mode=sandbox_mode,
        environment_provider=environment_provider,
        environment_config=environment_config,
        stage_failure_mode=stage_failure_mode,
        final_sweep_mode=final_sweep_mode,
        sandbox_options=sandbox_options,
        run_id=run_id,
    )


def submit_run(
    workflow: dict[str, Any],
    *,
    runs_dir: Path,
    resources_dir: Path,
    agent_name: str | None = None,
    sandbox_mode: str = "local",
    environment_provider: str | None = None,
    on_stage_complete: Any | None = None,
) -> str:
    """Submit a workflow run asynchronously and return the run ID immediately.

    Starts :func:`run_workflow` in a background thread. Progress can be
    polled via :func:`get_run_status`.

    Returns
    -------
    str
        Run ID that can be passed to :func:`get_run_status` and
        :func:`cleanup_run`.
    """
    effective_run_id = generate_run_id(str(workflow.get("id") or "workflow"))
    _register_run(effective_run_id, {"run_id": effective_run_id, "status": "running", "stages": []})

    def _run() -> None:
        run_workflow(
            workflow,
            runs_dir=runs_dir,
            resources_dir=resources_dir,
            agent_name=agent_name,
            sandbox_mode=sandbox_mode,
            environment_provider=environment_provider,
            on_stage_complete=on_stage_complete,
            run_id=effective_run_id,
        )

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    return effective_run_id


def get_run_status(run_id: str) -> dict[str, Any] | None:
    """Return the current status dict for *run_id*, or ``None`` when not found.

    The returned dict has the same shape as the result from
    :func:`run_workflow`, with ``status`` set to ``"running"`` while the
    run is still in progress.
    """
    with _runs_lock:
        entry = _active_runs.get(run_id)
    return dict(entry) if entry else None


def cleanup_run(run_id: str, *, runs_dir: Path) -> None:
    """Remove *run_id* from the active runs table.

    Safe to call on a run that has already been cleaned up or never
    registered.
    """
    with _runs_lock:
        _active_runs.pop(run_id, None)

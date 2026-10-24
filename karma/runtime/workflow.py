"""
Workflow loop, stage advance, state publication, and final sweeps.

:func:`run_workflow_loop` is the outermost execution loop. It iterates
over workflow rows, calls ``runtime.case.run_stage`` for each stage,
manages retries and fail-fast decisions, publishes workflow state after
each stage, and runs final sweeps on completion.

Final sweeps:

*Regression sweep*
    Re-runs the oracle for all completed stages to detect regressions
    introduced by later stages. By default (``final_sweep_mode="auto"``)
    executed only when the workflow completes successfully with more than
    one stage; ``"off"`` disables it and ``"full"`` sweeps whenever at
    least one stage passed.

*Adversary cleanup sweep*
    Lifts any adversary injections whose ``lift_at_stage`` never ran due
    to an early workflow exit, ensuring no adversarial conditions are left
    in the cluster.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from .case import run_stage, _apply_namespace_binding, _bind_namespace_identities
from ..definitions.prompts import render_stage_prompt
from ..oracle import run_regression_sweep
from ..adversary import collect_pending_lift_units
from .. import protocol
from .._warn import warn


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _write_workflow_state(run_dir: Path, state: dict[str, Any]) -> None:
    """Write *state* to the workflow state file atomically.

    Writes to a ``.tmp`` file then renames to avoid partial reads by the
    HTTP SSE path.
    """
    path = protocol.workflow_state_path(run_dir)
    tmp = path.with_suffix(".tmp")
    try:
        tmp.write_text(json.dumps(state, indent=2))
        tmp.rename(path)
    except Exception as exc:
        warn(f"failed to write workflow state: {exc}")


def _should_retry(stage_result: dict[str, Any], retries_remaining: int) -> bool:
    """Return ``True`` when the stage should be retried.

    Retry is permitted on ``"error"``, ``"timeout"``, and oracle ``"fail"``
    when attempts remain. (The old monolith retried oracle failures via
    ``oracle_failed_retryable``; restoring that so ``max_attempts`` gives the
    agent another shot at a fresh stage.) ``"cancelled"`` is never retried.
    """
    if retries_remaining <= 0:
        return False
    return stage_result.get("status") in ("error", "timeout", "fail")


def _run_final_regression_sweep(
    rows: list[dict[str, Any]],
    stage_results: list[dict[str, Any]],
    *,
    run_dir: Path,
    environment: Any,
    namespace_overrides: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Re-run the oracle for all completed stages and return a regression summary.

    A regression is a stage whose oracle passed during the run but fails
    when re-evaluated after later stages may have altered cluster state.

    Namespace cleanup is deferred to the end of the workflow (see
    ``run_stage(defer_cleanup=True)``), so each stage's namespaces are still
    live here. The bindings and namespace/param env are recomputed from the
    rows the same way the stage built them, so the re-run oracle commands see
    the same ``$BENCH_NS_*``/``$BENCH_PARAM_*`` context they did originally.

    Returns
    -------
    dict
        Map of ``stage_id`` to regression verdict dict.
    """
    from .case import _param_env_vars

    passed_ids = {r.get("stage_id") for r in stage_results if r.get("status") == "pass"}
    completed_rows = [row for row in rows if row.get("stage_id") in passed_ids]
    if len(completed_rows) <= 1:
        return {}

    oracle_configs: list[tuple[str, dict[str, Any]]] = []
    role_bindings_map: dict[str, dict[str, str]] = {}
    env_vars_map: dict[str, dict[str, str]] = {}
    for row in completed_rows:
        stage_id = row["stage_id"]
        case = row.get("case") or {}
        roles = row.get("namespace_roles")
        if roles is None:
            roles = ["default"]
        _, identity_bindings = _bind_namespace_identities(
            environment, roles, run_dir.name, namespace_overrides
        )
        bindings = _apply_namespace_binding(
            identity_bindings, row.get("namespace_binding")
        )
        oracle_configs.append((stage_id, case.get("oracle") or {}))
        role_bindings_map[stage_id] = bindings
        env_vars_map[stage_id] = {
            **environment.build_namespace_env_vars(bindings),
            **_param_env_vars(case.get("params")),
        }

    return run_regression_sweep(
        oracle_configs,
        role_bindings_map=role_bindings_map,
        env_vars_map=env_vars_map,
        run_dir=run_dir,
    )


def _run_adversary_cleanup_sweep(
    all_injections: list[dict[str, Any]],
    *,
    deployed_scenario_ids: set[str],
    completed_stage_ids: set[str],
    environment: Any,
    run_dir: Path,
    role_bindings: dict[str, str] | None = None,
    env_vars: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Lift pending adversary injections and return a cleanup summary.

    Runs with the workflow's namespace bindings and env so the lift commands
    target the right namespaces (they reference ``$BENCH_NS_*``); namespace
    teardown is deferred until after this sweep.

    Returns
    -------
    dict
        Keys: ``lifted`` (list of scenario IDs that were lifted),
        ``errors`` (list of error strings for failed lifts).
    """
    pending = collect_pending_lift_units(
        all_injections,
        deployed_scenario_ids=deployed_scenario_ids,
        completed_stage_ids=completed_stage_ids,
    )
    if not pending:
        return {"lifted": [], "errors": []}

    lifted_ids: list[str] = []
    errors: list[str] = []
    adv_log = run_dir / "adversary_cleanup.log"
    for unit in pending:
        from ..adversary.runtime import lift as adv_lift
        result = adv_lift(
            [unit],
            role_bindings=role_bindings or {},
            log_path=adv_log,
            env_vars=env_vars,
        )
        if result.get("ok"):
            lifted_ids.extend(result.get("lifted_ids") or [])
        else:
            errors.append(f"cleanup lift failed: {result.get('output', '')[:200]}")
    return {"lifted": lifted_ids, "errors": errors}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_workflow_loop(
    rows: list[dict[str, Any]],
    *,
    run_id: str,
    run_dir: Path,
    resources_dir: Path,
    agent_meta: dict[str, Any],
    sandbox_mode: str,
    environment: Any,
    prompt_mode: str,
    stage_prologue: str = "",
    agent_session: str = "persistent",
    session_id: str | None = None,
    system_prompt: str | None = None,
    on_stage_complete: Any | None = None,
    on_progress: Any | None = None,
    should_cancel: Any | None = None,
    max_attempts: int | None = None,
    stage_failure_mode: str = "terminate",
    final_sweep_mode: str = "auto",
    sandbox_options: dict[str, Any] | None = None,
    namespace_overrides: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Drive the workflow execution loop and return the final run result.

    Iterates over *rows* in order, calling ``runtime.case.run_stage`` for
    each. Handles per-stage retries and fail-fast decisions. Publishes
    workflow state to disk after each stage so that the HTTP SSE path can
    stream progress. Runs final sweeps after the loop completes.

    Parameters
    ----------
    rows:
        Ordered workflow row list from
        ``definitions.workflows.resolve_workflow_rows``.
    run_id:
        Unique identifier for this run.
    run_dir:
        Root directory for all run artifacts.
    resources_dir:
        Root resources directory forwarded to ``run_stage``.
    agent_meta:
        Agent launch metadata from ``agents.registry.resolve_agent``.
    sandbox_mode:
        ``"local"`` or ``"docker"``.
    environment:
        Initialized environment provider from ``environments.registry``.
    prompt_mode:
        One of the prompt modes defined in ``definitions.prompts``.
    on_stage_complete:
        Optional callable invoked with the stage result dict after each
        stage (including retries). Used by the HTTP SSE path to push
        progress events to the UI.
    stage_failure_mode:
        ``"terminate"`` (default) stops the workflow at the first stage that
        does not pass (fail-fast). ``"continue"`` runs the remaining stages
        anyway; the overall status is still ``"failed"``.
    final_sweep_mode:
        Controls the final regression sweep. ``"auto"`` (default) sweeps when
        the workflow completed with more than one passed stage; ``"off"``
        never sweeps; ``"full"`` sweeps whenever at least one stage passed
        (even on a failed workflow).
    namespace_overrides:
        Optional debug-only mapping from workflow namespace identities to
        borrowed physical Kubernetes namespaces.

    Returns
    -------
    dict
        Keys: ``run_id``, ``status`` (``"complete"``, ``"failed"``, or
        ``"cancelled"``), ``stages`` (list[dict]),
        ``regression_sweep`` (dict or ``None``),
        ``adversary_cleanup`` (dict or ``None``),
        ``duration_sec`` (float).
    """
    start_time = time.monotonic()
    stage_results: list[dict[str, Any]] = []

    # Pre-render every stage's prompt from the workflow definition, statically
    # (no runtime env; unresolved ${ENV} tokens stay literal). Concat modes
    # deliver the FULL workflow -- future stages included -- so the agent sees
    # the whole plan; run_stage re-renders each stage's own slot with runtime
    # env as it executes. Built once from the definition, so there is no
    # accumulated runtime history to duplicate (retires the concat prompt bug).
    def _static_render(r: dict[str, Any]) -> str:
        try:
            return render_stage_prompt(r.get("case") or {}, r, {"id": run_dir.name})
        except Exception:
            return ""
    stage_prompts: list[str] = [_static_render(r) for r in rows]

    completed_stage_ids: set[str] = set()
    deployed_scenario_ids: set[str] = set()
    # Namespaces the stages create (mongodb, rabbitmq, ...), accumulated across
    # stages via each stage's `created_sink`. The deferred teardown deletes
    # exactly this recorded set -- never a re-diff of the live namespace list,
    # which would sweep up a concurrent run's namespaces on a shared cluster (SS-2).
    ns_created: set[str] = set()

    all_injections = [
        inj
        for row in rows
        for inj in (row.get("adversary_injections") or [])
    ]

    workflow_status = "complete"

    # Compute the full namespace binding up front so the deferred teardown in
    # the `finally` below can ALWAYS run -- even if a stage callback
    # (should_cancel/on_progress) or a stage/sweep raises mid-run -- so the
    # workflow's namespaces are never orphaned (SR8). bind_namespace_roles only
    # derives deterministic names; creation happens per stage and
    # cleanup_namespaces is delete-by-name (idempotent).
    # `[]` (literal-namespace cases) contributes no role namespaces; only a
    # missing/None contract implies the single default role.
    all_roles = sorted({
        role for row in rows
        for role in (row.get("namespace_roles") if row.get("namespace_roles") is not None else ["default"])
    })
    full_bindings: dict[str, str] = {}
    generated_bindings: dict[str, str] = {}
    full_env: dict[str, str] = {}
    if environment is not None and all_roles:
        try:
            generated_bindings, full_bindings = _bind_namespace_identities(
                environment, all_roles, run_dir.name, namespace_overrides
            )
            full_env = environment.build_namespace_env_vars(full_bindings)
        except Exception:
            full_bindings, generated_bindings, full_env = {}, {}, {}

    regression_sweep = None
    adversary_cleanup = None
    try:
        for idx, row in enumerate(rows):
            if should_cancel is not None and should_cancel():
                workflow_status = "cancelled"
                break
            stage_id = row["stage_id"]
            # Workflow-level max_attempts (stage-agnostic) overrides any per-stage
            # retries when set, so one Run Config knob applies to every stage.
            retries = (max(0, max_attempts - 1) if max_attempts else row.get("retries", 0))
            stage_result: dict[str, Any] = {}
            # Per-stage progress sink: tag each fine-grained message with this stage.
            stage_progress = None
            if on_progress is not None:
                stage_progress = (lambda sid: lambda msg: on_progress(sid, msg))(stage_id)

            for attempt in range(retries + 1):
                if on_progress is not None:
                    on_progress(stage_id, f"▶ stage {stage_id}"
                                + (f" (attempt {attempt + 1})" if attempt else ""))
                stage_result = run_stage(
                    row,
                    run_dir=run_dir,
                    resources_dir=resources_dir,
                    agent_meta=agent_meta,
                    sandbox_mode=sandbox_mode,
                    environment=environment,
                    prior_stage_ids=list(completed_stage_ids),
                    stage_prompts=stage_prompts,
                    prompt_mode=prompt_mode,
                    agent_session=agent_session,
                    session_id=session_id,
                    system_prompt=system_prompt,
                    stage_index=idx,
                    prologue=stage_prologue,
                    namespace_overrides=namespace_overrides,
                    defer_cleanup=True,
                    created_sink=ns_created,
                    sandbox_options=sandbox_options,
                    on_progress=stage_progress,
                    should_cancel=should_cancel,
                )

                if on_stage_complete is not None:
                    try:
                        on_stage_complete(stage_result)
                    except Exception:
                        pass

                if not _should_retry(stage_result, retries - attempt):
                    break

            stage_results.append(stage_result)

            for inj in (row.get("adversary_injections") or []):
                if inj.get("id"):
                    deployed_scenario_ids.add(inj["id"])

            if stage_result.get("status") == "pass":
                completed_stage_ids.add(stage_id)
            elif stage_result.get("status") == "cancelled":
                workflow_status = "cancelled"
                break
            else:
                workflow_status = "failed"
                if stage_failure_mode != "continue":
                    break
                # "continue": record the failure but keep running later stages.

            _write_workflow_state(run_dir, {
                "run_id": run_id,
                "status": "running",
                "completed_stages": list(completed_stage_ids),
                "stage_results": stage_results,
            })

        if final_sweep_mode == "off":
            run_sweep = False
        elif final_sweep_mode == "full":
            run_sweep = len(completed_stage_ids) >= 1
        else:  # "auto" / "inherit"
            run_sweep = workflow_status == "complete" and len(completed_stage_ids) > 1
        regression_sweep = None
        if run_sweep:
            # A sweep failure is diagnostic only; it must not crash the run result.
            try:
                regression_sweep = _run_final_regression_sweep(
                    rows, stage_results, run_dir=run_dir, environment=environment,
                    namespace_overrides=namespace_overrides,
                )
            except Exception as exc:
                regression_sweep = None
                warn(f"regression sweep failed: {exc}")

        adversary_cleanup = None
        if deployed_scenario_ids:
            adversary_cleanup = _run_adversary_cleanup_sweep(
                all_injections,
                deployed_scenario_ids=deployed_scenario_ids,
                completed_stage_ids=completed_stage_ids,
                environment=environment,
                run_dir=run_dir,
                role_bindings=full_bindings,
                env_vars=full_env,
            )

    finally:
        # Deferred namespace teardown: runs on EVERY exit path -- normal,
        # break, or a raised exception -- so namespaces are never orphaned (SR8).
        if generated_bindings and environment is not None:
            try:
                environment.cleanup_namespaces(generated_bindings, run_dir=run_dir)
            except Exception as exc:
                warn(f"failed to delete workflow namespaces: {exc}")
        if environment is not None and hasattr(environment, "cleanup_created_namespaces"):
            try:
                environment.cleanup_created_namespaces(
                    ns_created, run_dir=run_dir
                )
            except Exception:
                pass

    result = {
        "run_id": run_id,
        "status": workflow_status,
        "stages": stage_results,
        "regression_sweep": regression_sweep,
        "adversary_cleanup": adversary_cleanup,
        "duration_sec": time.monotonic() - start_time,
    }

    try:
        protocol.run_meta_path(run_dir).write_text(json.dumps(result, indent=2))
    except Exception as exc:
        warn(f"failed to write run metadata: {exc}")

    _write_workflow_state(run_dir, {
        "run_id": run_id,
        "status": workflow_status,
        "completed_stages": list(completed_stage_ids),
        "stage_results": stage_results,
    })

    return result

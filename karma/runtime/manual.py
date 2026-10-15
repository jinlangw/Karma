"""
Interactive manual-operator run mode.

``run_stage`` runs a whole stage in one synchronous call: it sets the
scenario up, launches an *agent*, waits for the agent's ``submit.txt``,
then verifies and tears down. The old framework also supported a *manual*
mode with no agent at all -- a human operator sets the scenario up, does
the task by hand against the cluster, then asks for verification. That
mode was dropped in the refactor; this module restores it.

The lifecycle is split across three calls because a human acts between
them, so the cluster context (proxy, namespaces, environment) must survive
between HTTP requests:

1. :func:`start_manual_run` -- create the run, launch the proxy, create
   namespaces, run preconditions, plant decoys, and write the prompt and
   credential bundle. Setup runs on a background thread so the caller can
   poll setup phase; the session ends at ``ready`` (or ``setup_failed``).
2. :func:`submit_manual_run` -- the operator is done; collect evidence and
   run the oracle, yielding ``passed`` or ``failed``. Re-runnable so a
   failed attempt can be retried.
3. :func:`cleanup_manual_run` -- tear down the proxy and namespaces.

A live session is held in memory keyed by run id. The building blocks are
the same ones ``runtime.case`` uses, referenced as module attributes so
tests can substitute fakes (no cluster required).
"""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any

from ..transport.k8s.backend import launch_proxy, write_agent_bundle
from ..environments.registry import get_environment
from ..oracle import run_oracle
from ..stage_context import stage_env, freeze_stage
from ..evidence import collect_evidence
from .. import protocol
from ..definitions.cases import load_case_file, normalize_case, discover_case_decoys
from .case import _run_operation_units, _param_env_vars, _namespaces_created_since


_MANUAL_STAGE_ID = "manual"

_sessions: dict[str, dict[str, Any]] = {}
_lock = threading.Lock()

# Keys prefixed with "_" hold non-serializable live objects and are never
# returned to clients.
_SERIALIZABLE_SKIP = lambda k: k.startswith("_")


def _register(run_id: str, session: dict[str, Any]) -> None:
    """Store *session* under *run_id* in the live manual-session table."""
    with _lock:
        _sessions[run_id] = session


def _update(run_id: str, updates: dict[str, Any]) -> None:
    """Apply *updates* to the session for *run_id*. No-op when not found."""
    with _lock:
        if run_id in _sessions:
            _sessions[run_id].update(updates)


def _public_view(session: dict[str, Any]) -> dict[str, Any]:
    """Return the client-facing subset of *session* (drops live objects)."""
    return {k: v for k, v in session.items() if not _SERIALIZABLE_SKIP(k)}


def get_manual_status(run_id: str) -> dict[str, Any] | None:
    """Return the public status of a manual run, or ``None`` when unknown."""
    with _lock:
        session = _sessions.get(run_id)
        return _public_view(session) if session else None


def _record_ns_created(run_id: str, environment: Any, ns_baseline: set) -> None:
    """Store the namespaces this manual setup created on the session (SW-1).

    The delta from *ns_baseline* is exactly the literal namespaces the case's
    preconditions/decoys create (mongodb/cockroachdb/spark), which the per-role
    cleanup does not cover; cleanup_manual_run deletes this recorded set. Mirrors
    the automated path in runtime.case.
    """
    created = _namespaces_created_since(environment, ns_baseline)
    with _lock:
        s = _sessions.get(run_id)
        if s is not None:
            s["_ns_created"] = created


def _do_setup(run_id: str) -> None:
    """Run setup steps for the session, updating phase as it progresses."""
    with _lock:
        session = _sessions.get(run_id)
    if session is None:
        return

    run_dir: Path = session["_run_dir"]
    resources_dir: Path = session["_resources_dir"]
    case: dict[str, Any] = session["_case"]
    ns_roles: list[str] = session["_namespace_roles"]
    service: str = session["service"]
    case_name: str = session["case_name"]

    proxy_handle = None
    try:
        stage_dir = protocol.ensure_stage_dir(run_dir, _MANUAL_STAGE_ID)

        proxy_handle = launch_proxy(run_dir=stage_dir)
        environment = get_environment(session.get("_environment_provider"))
        role_bindings = environment.bind_namespace_roles(ns_roles, run_dir.name)
        environment.ensure_namespaces(role_bindings, run_dir=stage_dir)
        # SW-1: all namespaces present now (best-effort; the helper never raises).
        # The delta after setup is the literal namespaces the case creates, which
        # cleanup must delete -- exactly as the automated path records them.
        ns_baseline = _namespaces_created_since(environment, set())
        # Record the live objects on the session immediately so that a failure
        # in a later setup step (or a cleanup call) can still tear the
        # namespaces and proxy down -- otherwise they would be orphaned.
        with _lock:
            s0 = _sessions.get(run_id)
            if s0 is not None:
                s0["_proxy"] = proxy_handle
                s0["_env"] = environment
                s0["_role_bindings"] = role_bindings
                s0["_stage_dir"] = stage_dir

        param_env = _param_env_vars(case.get("params"))
        command_env = {**environment.build_namespace_env_vars(role_bindings), **param_env,
                       **stage_env(run_dir, _MANUAL_STAGE_ID)}

        _update(run_id, {"phase": "precondition"})
        precond_result = _run_operation_units(
            case.get("precondition_units") or [],
            role_bindings=role_bindings,
            log_path=protocol.stage_precondition_log_path(run_dir, _MANUAL_STAGE_ID),
            env_vars=command_env,
            label="precondition",
        )
        # SW-1: record now, before the ok-check's raise, so a precondition-failure
        # teardown still deletes the literal namespaces the preconditions created.
        _record_ns_created(run_id, environment, ns_baseline)
        if not precond_result["ok"]:
            # Raise rather than return so the except handler below tears down
            # the proxy and the namespaces created above.
            _update(run_id, {"phase": "precondition"})
            raise RuntimeError("precondition units failed")

        _update(run_id, {"phase": "decoy"})
        decoy_configs = list(case.get("decoys") or [])
        decoy_configs += discover_case_decoys(resources_dir, service, case_name)
        if decoy_configs:
            environment.plant_decoys(
                decoy_configs, role_bindings,
                resources_dir=resources_dir, run_dir=stage_dir,
            )
        # SW-1: re-record to also capture any namespaces decoy planting created.
        _record_ns_created(run_id, environment, ns_baseline)

        env_vars = {
            **environment.build_env_vars(role_bindings, proxy_port=proxy_handle.port),
            **param_env,
            **stage_env(run_dir, _MANUAL_STAGE_ID),
        }
        kubeconfig = write_agent_bundle(
            proxy_handle, run_dir=run_dir, namespace_env_vars=env_vars,
        )

        _update(run_id, {"phase": "prompt"})
        prompt = _render_prompt(case, run_dir, ns_roles, env_vars)
        protocol.stage_prompt_path(run_dir, _MANUAL_STAGE_ID).write_text(prompt)

        freeze_stage(run_dir, _MANUAL_STAGE_ID)
        with _lock:
            s = _sessions.get(run_id)
            if s is not None:
                s["_proxy"] = proxy_handle
                s["_env"] = environment
                s["_role_bindings"] = role_bindings
                s["_env_vars"] = env_vars
                s["_stage_dir"] = stage_dir
                s.update({
                    "status": "ready",
                    "phase": "ready",
                    "prompt_path": str(protocol.stage_prompt_path(run_dir, _MANUAL_STAGE_ID)),
                    "kubeconfig_path": str(kubeconfig),
                    "namespace_bindings": role_bindings,
                })
    except Exception as exc:
        _update(run_id, {"status": "setup_failed", "error": str(exc)})
        if proxy_handle is not None:
            try:
                proxy_handle.teardown()
            except Exception:
                pass
        # Tear down any namespaces created before the failure so they are not
        # orphaned in the cluster.
        with _lock:
            s_err = _sessions.get(run_id) or {}
            env_err = s_err.get("_env")
            rb_err = s_err.get("_role_bindings")
            sd_err = s_err.get("_stage_dir")
        if env_err is not None and rb_err:
            try:
                env_err.cleanup_namespaces(rb_err, run_dir=sd_err)
            except Exception:
                pass
        # SW-1: also delete the literal namespaces the partial setup created
        # (not covered by the per-role cleanup; the only path for required_roles:[]).
        ns_created_err = s_err.get("_ns_created")
        if env_err is not None and ns_created_err and hasattr(env_err, "cleanup_created_namespaces"):
            try:
                env_err.cleanup_created_namespaces(ns_created_err, run_dir=sd_err)
            except Exception:
                pass


def _render_prompt(
    case: dict[str, Any], run_dir: Path, ns_roles: list[str], env_vars: dict[str, str]
) -> str:
    """Render the operator prompt, falling back to the raw case prompt."""
    try:
        from ..definitions.prompts import render_stage_prompt, assemble_agent_prompt

        row = {"stage_id": _MANUAL_STAGE_ID, "namespace_roles": ns_roles, "adversary_hint": None}
        rendered = render_stage_prompt(case, row, {"id": run_dir.name}, variables=env_vars)
        return assemble_agent_prompt([rendered], 0, "progressive")
    except Exception:
        return str(case.get("prompt", ""))


def start_manual_run(
    service: str,
    case_name: str,
    *,
    runs_dir: Path,
    resources_dir: Path,
    param_overrides: dict[str, Any] | None = None,
    namespace_roles: list[str] | None = None,
    environment_provider: str | None = None,
) -> str:
    """Begin a manual run and return its run id immediately.

    Loads and normalizes the case, then runs setup on a background thread.
    The caller polls :func:`get_manual_status` until the status leaves
    ``setup_running`` (it becomes ``ready`` or ``setup_failed``).

    Raises
    ------
    RuntimeError
        When the case file is missing or invalid (surfaced synchronously
        so the caller gets an immediate 400/404).
    """
    case_data = load_case_file(resources_dir, service, case_name)
    case = normalize_case(case_data, service, case_name, param_overrides)

    run_id = protocol.generate_run_id(f"{service}-{case_name}-manual")
    run_dir = runs_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    # Use `is None`, not `or`: an explicit required_roles: [] (a case that manages
    # its own literal namespaces -- mongodb/cockroachdb/spark) is falsy, so the
    # old `or ["default"]` collapsed it to ["default"], re-bound a karma-* namespace
    # and set BENCH_NAMESPACE, breaking those cases in manual mode. The run/workflow
    # paths already guard with `is None`; manual mode was the gap (Law-3).
    ns_roles = namespace_roles
    if ns_roles is None:
        ns_roles = case.get("namespace_contract", {}).get("required_roles")
    if ns_roles is None:
        ns_roles = ["default"]

    _register(run_id, {
        "run_id": run_id,
        "service": service,
        "case_name": case_name,
        "status": "setup_running",
        "phase": "starting",
        "attempts": 0,
        "error": None,
        "created_at": time.time(),
        "_run_dir": run_dir,
        "_resources_dir": resources_dir,
        "_case": case,
        "_namespace_roles": ns_roles,
        "_environment_provider": environment_provider,
    })

    threading.Thread(target=_do_setup, args=(run_id,), daemon=True).start()
    return run_id


def submit_manual_run(run_id: str) -> dict[str, Any]:
    """Verify a ready manual run and return its updated status.

    Collects evidence and runs the oracle against the operator's work,
    setting the status to ``passed`` or ``failed``. Re-runnable: a failed
    attempt can be submitted again after more work.

    Raises
    ------
    RuntimeError
        When the run is unknown or not in the ``ready``/``failed`` state.
    """
    with _lock:
        session = _sessions.get(run_id)
        if session is None:
            raise RuntimeError(f"unknown manual run: {run_id}")
        if session.get("status") not in ("ready", "failed"):
            raise RuntimeError(
                f"manual run {run_id} is not ready to submit (status="
                f"{session.get('status')})"
            )
        run_dir: Path = session["_run_dir"]
        case = session["_case"]
        role_bindings = session.get("_role_bindings") or {}
        env_vars = session.get("_env_vars") or {}

    with _lock:
        s = _sessions.get(run_id)
        if s is not None:
            s["status"] = "verifying"
            s["attempts"] = s.get("attempts", 0) + 1

    try:
        collect_evidence(
            run_dir=run_dir, stage_id=_MANUAL_STAGE_ID,
            case=case, role_bindings=role_bindings,
        )
        oracle_result = run_oracle(
            case.get("oracle") or {},
            role_bindings=role_bindings,
            run_dir=run_dir,
            stage_id=_MANUAL_STAGE_ID,
            env_vars=env_vars,
        )
        verdict = oracle_result.get("verdict")
        status = "passed" if verdict == "pass" else "failed"
        _update(run_id, {"status": status, "oracle_verdict": verdict})
    except Exception as exc:
        _update(run_id, {"status": "failed", "error": str(exc)})

    return get_manual_status(run_id)  # type: ignore[return-value]


def cleanup_manual_run(run_id: str) -> dict[str, Any]:
    """Tear down a manual run's proxy and namespaces and drop the session.

    Safe to call in any state. Returns a final status dict. Never raises on
    teardown errors; they are recorded but cleanup always completes.
    """
    with _lock:
        session = _sessions.pop(run_id, None)
    if session is None:
        return {"run_id": run_id, "status": "unknown"}

    proxy = session.get("_proxy")
    env = session.get("_env")
    role_bindings = session.get("_role_bindings")
    stage_dir = session.get("_stage_dir")

    if proxy is not None:
        try:
            proxy.teardown()
        except Exception:
            pass
    if env is not None and role_bindings:
        try:
            env.cleanup_namespaces(role_bindings, run_dir=stage_dir)
        except Exception:
            pass
    # SW-1: delete the literal namespaces the case's preconditions created
    # (mongodb/cockroachdb/spark) -- not covered by the per-role cleanup above,
    # and skipped entirely for required_roles:[] cases where role_bindings is {}.
    ns_created = session.get("_ns_created")
    if env is not None and ns_created and hasattr(env, "cleanup_created_namespaces"):
        try:
            env.cleanup_created_namespaces(ns_created, run_dir=stage_dir)
        except Exception:
            pass

    view = _public_view(session)
    view["status"] = "cleaned"
    return view


def deploy_manual_adversary(
    run_id: str, scenario: str, *, param_overrides: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Inject an adversary scenario into a live manual run.

    Resolves the scenario against the run's service (treating the manual
    stage as the inject point), then runs its deploy unit with the
    session's namespace bindings and env. The resolved injection is tracked
    on the session so :func:`lift_manual_adversary` can later run its lift
    unit. This is the operator-driven fault injection the UI surfaces.

    Raises
    ------
    RuntimeError
        When the run is unknown/not ready or the scenario cannot resolve.
    """
    from ..adversary import resolve_adversary_scenario, deploy as adversary_deploy

    with _lock:
        session = _sessions.get(run_id)
        if session is None:
            raise RuntimeError(f"unknown manual run: {run_id}")
        if session.get("status") not in ("ready", "passed", "failed"):
            raise RuntimeError(f"manual run {run_id} is not ready for adversary injection")
        service = session["service"]
        resources_dir: Path = session["_resources_dir"]
        run_dir: Path = session["_run_dir"]
        role_bindings = session.get("_role_bindings") or {}
        env_vars = session.get("_env_vars") or {}

    injection = resolve_adversary_scenario(
        {
            "scenario": scenario,
            "inject_at_stage": _MANUAL_STAGE_ID,
            "param_overrides": param_overrides or {},
        },
        {_MANUAL_STAGE_ID: service},
        resources_dir=resources_dir,
    )
    result = adversary_deploy(
        [injection["deploy_unit"]],
        role_bindings=role_bindings,
        log_path=protocol.stage_adversary_log_path(run_dir, _MANUAL_STAGE_ID),
        env_vars=env_vars,
    )
    with _lock:
        s = _sessions.get(run_id)
        if s is not None:
            s.setdefault("_injections", {})[scenario] = injection
            active = s.setdefault("active_adversary", [])
            if scenario not in active:
                active.append(scenario)
    return {"scenario": scenario, "deploy": result}


def lift_manual_adversary(run_id: str, scenario: str) -> dict[str, Any]:
    """Lift a previously deployed adversary scenario from a manual run.

    Raises
    ------
    RuntimeError
        When the run or the deployed scenario is unknown, or the scenario
        declared no lift unit.
    """
    from ..adversary import lift as adversary_lift

    with _lock:
        session = _sessions.get(run_id)
        if session is None:
            raise RuntimeError(f"unknown manual run: {run_id}")
        injection = (session.get("_injections") or {}).get(scenario)
        if injection is None:
            raise RuntimeError(f"scenario '{scenario}' is not deployed on run {run_id}")
        if injection.get("lift_unit") is None:
            raise RuntimeError(f"scenario '{scenario}' declares no lift unit")
        run_dir: Path = session["_run_dir"]
        role_bindings = session.get("_role_bindings") or {}
        env_vars = session.get("_env_vars") or {}

    result = adversary_lift(
        [injection["lift_unit"]],
        role_bindings=role_bindings,
        log_path=protocol.stage_adversary_log_path(run_dir, _MANUAL_STAGE_ID),
        env_vars=env_vars,
    )
    with _lock:
        s = _sessions.get(run_id)
        if s is not None:
            active = s.get("active_adversary") or []
            if scenario in active:
                active.remove(scenario)
    return {"scenario": scenario, "lift": result}

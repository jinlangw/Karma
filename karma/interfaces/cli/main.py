"""
CLI parsing, request normalization, and result output.

Defines all CLI subcommands and delegates execution to ``runtime.service``
and the ``judge`` package. No orchestration logic lives here.

Entrypoint::

    python orchestrator.py [args...]
    python -m karma.interfaces.cli.main [args...]

Subcommands:

``run-workflow``
    Run a workflow YAML file end to end.
``run-case``
    Run a single case directly without a workflow file.
``run-batch``
    Run many cases sequentially (selected by --all / --service / --case).
``manual``
    Set a case up, hand the namespace to a human operator to act on by
    hand, then verify on demand and tear down.
``judge``
    Run the judge on an existing run directory.
``info``
    Print the registry of available agents.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .profiles import load_profile, merge_profile
from ...runtime.service import run_workflow, run_case
from ...agents.registry import list_agents

# Bundled example rubric used when `--rubric` is given with no path.
_DEFAULT_RUBRIC_PATH = str(
    Path(__file__).resolve().parents[3] / "docs" / "example-rubric.yaml"
)
# Bundled example regression-adjudication prompt; the --regression-prompt default.
_DEFAULT_REGRESSION_PROMPT_PATH = str(
    Path(__file__).resolve().parents[3] / "docs" / "example-regression-prompt.md"
)
# Default agent system prompt (harness contract); the --system-prompt default.
_DEFAULT_SYSTEM_PROMPT_PATH = str(
    Path(__file__).resolve().parents[3] / "docs" / "default-system-prompt.md"
)
from ...definitions.workflows import load_workflow_file, normalize_workflow


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def _add_docker_args(p: argparse.ArgumentParser) -> None:
    """Add the docker-sandbox provisioning flags shared by run subcommands."""
    p.add_argument("--agent-build", action="store_true",
                   help="Build the agent's Docker image before running.")
    p.add_argument("--agent-tag", default=None, help="Override the agent image tag.")
    p.add_argument("--docker-image", default=None,
                   help="Docker image to run as the agent (alias of --agent-tag).")
    p.add_argument("--agent-cleanup", action="store_true",
                   help="Remove the agent image after the run.")
    p.add_argument("--agent-cmd", default=None,
                   help="Per-run agent launch command: replaces the entrypoint "
                        "(local) or the image's default command (docker).")
    p.add_argument("--source-kubeconfig", default=None,
                   help="Source kubeconfig (accepted for compatibility; the proxy "
                        "authenticates upstream so it is not required).")
    p.add_argument("--agent-auth-path", default=None,
                   help="Host path to agent credentials to mount into the container.")
    p.add_argument("--agent-auth-dest", default=None,
                   help="Container path to mount the agent credentials at.")


def _add_run_extra_args(p: argparse.ArgumentParser) -> None:
    """Add the cleanup-timeout and llm-env-file flags shared by run subcommands."""
    p.add_argument("--cleanup-timeout", type=int, default=None,
                   help="Namespace force-delete timeout (seconds).")
    p.add_argument("--setup-timeout-mode", choices=["fixed", "auto"], default=None,
                   help="How --setup-timeout is applied: 'fixed' is a hard cap; "
                        "'auto' (default) floors it at the per-case computed budget.")
    p.add_argument("--llm-env-file", default=None,
                   help="Load KEY=VALUE lines from this file into the environment.")


def _add_inline_judge_args(p: argparse.ArgumentParser) -> None:
    """Add judge-LLM controls for the inline post-run judge on run subcommands.

    These mirror the standalone ``judge`` subcommand's flags but are
    judge-prefixed so they do not collide with a run's own ``--timeout`` /
    ``--model``. They take effect when the run requests judging (``--judge`` or
    ``--judge-mode``); otherwise the judge falls back to ``KARMA_JUDGE_*`` env.
    """
    p.add_argument("--judge-model", default=None, help="Judge LLM model.")
    p.add_argument("--judge-base-url", default=None,
                   help="OpenAI-compatible base URL for the judge LLM.")
    p.add_argument("--judge-api-key", default=None,
                   help="API key for the judge LLM (else from the environment).")
    p.add_argument("--judge-timeout", type=int, default=None,
                   help="Per-request judge LLM timeout in seconds.")
    p.add_argument("--judge-max-retries", type=int, default=None,
                   help="Judge LLM retry attempts on transient errors.")
    p.add_argument("--judge-exclude-outcome", action="store_true",
                   help="Hide the oracle verdict from the judge prompt (reduce bias).")


def _inline_judge_kwargs(args: argparse.Namespace) -> dict[str, Any]:
    """Collect the inline judge-LLM overrides into run_judge(_batch) kwargs."""
    return {
        "judge_model": getattr(args, "judge_model", None),
        "judge_base_url": getattr(args, "judge_base_url", None),
        "judge_api_key": getattr(args, "judge_api_key", None),
        "judge_timeout_sec": getattr(args, "judge_timeout", None),
        "judge_max_retries": getattr(args, "judge_max_retries", None),
        "include_outcome": not getattr(args, "judge_exclude_outcome", False),
    }


def _load_env_file(path: str | None) -> None:
    """Load KEY=VALUE lines from *path* into the process environment."""
    import os
    if not path:
        return
    try:
        for line in Path(path).read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            os.environ[key.strip()] = value.strip().strip('"').strip("'")
    except Exception as exc:
        print(f"could not load --llm-env-file {path}: {exc}", file=sys.stderr)


def _environment_config(args: argparse.Namespace) -> dict[str, Any] | None:
    """Build the environment provider config from CLI flags (cleanup timeout)."""
    ct = getattr(args, "cleanup_timeout", None)
    return {"force_delete_timeout_sec": ct} if ct else None


def _build_sandbox_options(args: argparse.Namespace) -> dict[str, Any] | None:
    """Build the sandbox_options dict from the docker provisioning flags."""
    opts: dict[str, Any] = {}
    if getattr(args, "agent_build", False):
        opts["build_image"] = True
    tag = getattr(args, "agent_tag", None) or getattr(args, "docker_image", None)
    if tag:
        opts["image_tag"] = tag
    if getattr(args, "source_kubeconfig", None):
        opts["source_kubeconfig"] = args.source_kubeconfig
    ap, ad = getattr(args, "agent_auth_path", None), getattr(args, "agent_auth_dest", None)
    if ap and ad:
        opts["extra_mounts"] = [(Path(ap), str(ad))]
    if getattr(args, "agent_cmd", None):
        opts["agent_cmd"] = args.agent_cmd
    return opts or None


def _build_parser() -> argparse.ArgumentParser:
    """Return the top-level argument parser with all subcommands registered."""
    # No explicit prog: argparse derives it from argv[0], so help/usage text
    # reflects however the CLI was invoked (e.g. `orchestrator.py`).
    parser = argparse.ArgumentParser(
        description="KARMA Kubernetes microservice agent benchmark framework.",
    )
    sub = parser.add_subparsers(dest="command")

    wf = sub.add_parser("run-workflow", help="Run a workflow YAML file.")
    wf.add_argument("workflow", help="Path to the workflow YAML file.")
    wf.add_argument("--agent", default=None)
    wf.add_argument("--sandbox", default="local", choices=["local", "docker"])
    wf.add_argument("--runs-dir", default="runs")
    wf.add_argument("--resources-dir", default="cases")
    wf.add_argument("--profile", default=None)
    wf.add_argument("--dry-run", action="store_true",
                    help="Resolve rows and print without running.")
    wf.add_argument("--debug", action="store_true",
                    help="Use spec.debug settings, including any explicit namespace overrides.")
    wf.add_argument("--judge", action="store_true",
                    help="Run the LLM judge on every stage after the run completes.")
    wf.add_argument("--max-attempts", type=int, default=None,
                    help="Workflow-level retry cap: re-run each stage up to N times "
                         "on oracle fail/error/timeout (stage-agnostic; default 1).")
    wf.add_argument("--agent-session", choices=["per_stage", "persistent"], default=None,
                    help="persistent (default): ONE agent conversation resumed across "
                         "every stage; per_stage: a fresh agent each stage. Overrides "
                         "the workflow's spec.agent_session.")
    wf.add_argument("--system-prompt", default=_DEFAULT_SYSTEM_PROMPT_PATH, metavar="FILE",
                    help="Base system prompt sent to every agent each stage (defaults "
                         "to docs/default-system-prompt.md, the harness contract). The "
                         "workflow's spec.system_prompt is appended to it.")
    wf.add_argument("--prompt-mode-prologues", default=None, metavar="FILE",
                    help="YAML file of per-mode prologues prepended to the assembled "
                         "prompt (keys: progressive, concat_stateful, concat_blind). "
                         "Defaults to docs/prompt-mode-prologues.yaml when omitted.")
    wf.add_argument("--stage-failure-mode", choices=["terminate", "continue"],
                    default="terminate",
                    help="terminate (fail-fast) or continue past a failed stage.")
    wf.add_argument("--final-sweep-mode", choices=["auto", "off", "full"],
                    default="auto", help="Control the final regression sweep.")
    wf.add_argument("--setup-timeout", type=int, default=None,
                    help="Override the precondition timeout (seconds).")
    wf.add_argument("--verify-timeout", type=int, default=None,
                    help="Override the oracle/verify timeout (seconds).")
    _add_docker_args(wf)
    _add_run_extra_args(wf)
    _add_inline_judge_args(wf)
    wf.add_argument("--output", default="text", choices=["text", "json"])

    rc = sub.add_parser("run-case", help="Run a single case.")
    rc.add_argument("service")
    rc.add_argument("case")
    rc.add_argument("--agent", default=None)
    rc.add_argument("--sandbox", default="local", choices=["local", "docker"])
    rc.add_argument("--runs-dir", default="runs")
    rc.add_argument("--resources-dir", default="cases")
    rc.add_argument("--param", action="append", default=[], metavar="KEY=VALUE")
    rc.add_argument("--timeout", type=int, default=900)
    rc.add_argument("--max-attempts", type=int, default=None,
                    help="Total attempt cap (the stage runs retries + 1 times).")
    rc.add_argument("--setup-timeout", type=int, default=None,
                    help="Override the precondition timeout (seconds).")
    rc.add_argument("--verify-timeout", type=int, default=None,
                    help="Override the oracle/verify timeout (seconds).")
    rc.add_argument("--judge", action="store_true",
                    help="Run the LLM judge on every stage after the run completes.")
    _add_docker_args(rc)
    _add_run_extra_args(rc)
    _add_inline_judge_args(rc)
    rc.add_argument("--profile", default=None)
    rc.add_argument("--output", default="text", choices=["text", "json"])

    rb = sub.add_parser("run-batch", help="Run many cases sequentially.")
    rb.add_argument("--all", action="store_true", help="Run every case under cases/.")
    rb.add_argument("--service", default=None, help="Run all cases in this service.")
    rb.add_argument("--case", action="append", default=[], metavar="SERVICE/CASE",
                    help="Run a specific case (repeatable).")
    rb.add_argument("--agent", default=None)
    rb.add_argument("--sandbox", default="local", choices=["local", "docker"])
    rb.add_argument("--runs-dir", default="runs")
    rb.add_argument("--resources-dir", default="cases")
    rb.add_argument("--param", action="append", default=[], metavar="KEY=VALUE")
    rb.add_argument("--timeout", type=int, default=900)
    rb.add_argument("--max-attempts", type=int, default=None)
    rb.add_argument("--setup-timeout", type=int, default=None)
    rb.add_argument("--verify-timeout", type=int, default=None)
    rb.add_argument("--results-json", default=None,
                    help="Write per-case results to this JSON file.")
    rb.add_argument("--judge-mode", choices=["off", "post-run", "post-batch"],
                    default="off",
                    help="Judge each run (post-run) or all runs after (post-batch).")
    _add_run_extra_args(rb)
    _add_inline_judge_args(rb)
    rb.add_argument("--profile", default=None)
    rb.add_argument("--output", default="text", choices=["text", "json"])

    mn = sub.add_parser(
        "manual",
        help="Set up a case for hands-on operation, then verify and clean up.",
    )
    mn.add_argument("service")
    mn.add_argument("case")
    mn.add_argument("--param", action="append", default=[], metavar="KEY=VALUE")
    mn.add_argument("--runs-dir", default="runs")
    mn.add_argument("--resources-dir", default="cases")
    mn.add_argument("--profile", default=None)

    jg = sub.add_parser("judge", help="Run the judge on an existing run directory.")
    jg.add_argument("run_dir")
    jg.add_argument("--stage", default=None)
    jg.add_argument("--model", default=None)
    jg.add_argument("--base-url", default=None,
                    help="OpenAI-compatible base URL for the judge LLM.")
    jg.add_argument("--api-key", default=None,
                    help="API key for the judge LLM (else from the environment).")
    jg.add_argument("--timeout", type=int, default=None,
                    help="Per-request judge LLM timeout in seconds.")
    jg.add_argument("--max-retries", type=int, default=None,
                    help="Judge LLM retry attempts on transient errors.")
    jg.add_argument("--batch", action="store_true",
                    help="Treat run_dir as a batch dir and judge every run under it.")
    jg.add_argument("--rubric", nargs="?", const=_DEFAULT_RUBRIC_PATH, default=None,
                    metavar="FILE",
                    help="Score each oracle-passing stage 0-1 against a rubric file "
                         "(YAML/JSON: weighted items summing to 1.0) "
                         "instead of flat full marks. Bare --rubric uses the bundled "
                         "docs/example-rubric.yaml.")
    jg.add_argument("--regression-prompt", default=_DEFAULT_REGRESSION_PROMPT_PATH,
                    metavar="FILE",
                    help="Prompt template for the LLM that adjudicates each "
                         "regression-sweep failure (real regression vs false "
                         "positive). Placeholders: $stage_id, $regression_output, "
                         "$stage_prompts. Defaults to docs/example-regression-prompt.md.")
    jg.add_argument("--fail-open", dest="fail_open", action="store_true", default=True,
                    help="Do not fail the command if the judge errors (default).")
    jg.add_argument("--fail-closed", dest="fail_open", action="store_false",
                    help="Exit non-zero if the judge errors.")
    jg.add_argument("--exclude-outcome", action="store_true",
                    help="Hide the oracle verdict from the judge prompt (reduce bias).")
    jg.add_argument("--llm-env-file", default=None,
                    help="Load KEY=VALUE lines from this file into the environment.")
    jg.add_argument("--dry-run", action="store_true")
    jg.add_argument("--output", default="text", choices=["text", "json"])

    inf = sub.add_parser("info", help="Print registry info.")
    inf.add_argument("--agents", action="store_true")

    return parser


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_param_overrides(param_args: list[str]) -> dict[str, Any]:
    """Parse ``KEY=VALUE`` strings into a parameter overrides dict.

    Values that are valid JSON are decoded as their native Python type;
    all others are kept as strings.

    Raises
    ------
    ValueError
        When any entry is not in ``KEY=VALUE`` format.
    """
    result: dict[str, Any] = {}
    for item in param_args:
        if "=" not in item:
            raise ValueError(
                f"invalid --param format (expected KEY=VALUE): {item!r}"
            )
        key, _, raw_value = item.partition("=")
        if raw_value.startswith("str:"):
            # Explicit string escape: --param version=str:1.10 keeps "1.10"
            # verbatim. Use it for version tags / digests / anything that looks
            # numeric or boolean but must stay a string.
            value: Any = raw_value[len("str:"):]
        else:
            try:
                value = json.loads(raw_value)
            except Exception:
                value = raw_value
            else:
                # Guard the silent-mangle case: json turns the version tag "1.10"
                # into the float 1.1 (and back into "1.1"). If a decoded float
                # doesn't round-trip to the original text, the user meant a
                # string -> keep it literal.
                if isinstance(value, float) and str(value) != raw_value.strip():
                    value = raw_value.strip()
        result[key.strip()] = value
    return result


def _maybe_inline_judge(
    result: dict[str, Any], runs_dir: Path, output_format: str,
    judge_kwargs: dict[str, Any] | None = None,
) -> None:
    """Run the judge on every stage of a just-completed run and print it.

    Restores the old inline post-run judging: ``run-case``/``run-workflow``
    with ``--judge`` score the run immediately instead of requiring a
    separate ``judge`` invocation. *judge_kwargs* carries the inline
    judge-LLM overrides (``--judge-model`` etc.); when absent the judge falls
    back to ``KARMA_JUDGE_*`` env.
    """
    from ...judge.engine import run_judge_batch

    run_id = result.get("run_id")
    if not run_id:
        return
    try:
        batch = run_judge_batch(runs_dir / str(run_id), **(judge_kwargs or {}))
    except Exception as exc:
        print(f"inline judge failed: {exc}", file=sys.stderr)
        return
    if output_format == "json":
        print(json.dumps(batch, indent=2))
    else:
        print("judge:")
        for sid, res in batch.items():
            print(f"  stage {sid}: {res.get('verdict')} (score {res.get('score')})")


def _print_result(result: dict[str, Any], output_format: str) -> None:
    """Print *result* to stdout in *output_format* (``"text"`` or ``"json"``).

    Two result shapes flow through here: a *run* result (run-case/run-workflow,
    with ``run_id``/``status``/``stages``) and a *judge* result (the ``judge``
    subcommand / score_run, with ``score``/``summary``/``stage_scores`` and none
    of the run keys). Branch on the shape so a judge result no longer degrades to
    ``run ?: unknown (0.0s)``.
    """
    if output_format == "json":
        print(json.dumps(result, indent=2))
        return
    if "score" in result:  # judge result
        summary = result.get("summary")
        if isinstance(summary, str) and summary:
            print(f"judge: {summary}")
        elif result.get("stage_id"):  # single-stage rubric judge (--stage)
            print(f"judge stage {result['stage_id']}: {result.get('verdict', '?')} "
                  f"(score {result.get('score')})")
        else:
            print(f"judge: score {result.get('score')}/{result.get('score_max', 100.0)}")
        for st in result.get("stage_scores") or []:
            print(f"  stage {st.get('stage_id', '?')}: score {st.get('score')}")
        return
    status = result.get("status", "unknown")
    run_id = result.get("run_id", "?")
    duration = result.get("duration_sec", 0.0)
    print(f"run {run_id}: {status} ({duration:.1f}s)")
    for stage in result.get("stages") or []:
        sid = stage.get("stage_id", "?")
        st = stage.get("status", "?")
        verdict = stage.get("oracle_verdict", "?")
        print(f"  stage {sid}: {st} (oracle: {verdict})")


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------

def _apply_timeout_overrides(args: argparse.Namespace) -> None:
    """Map the per-phase timeout flags onto the settings the runtime reads.

    ``--setup-timeout`` -> precondition timeout, ``--verify-timeout`` ->
    oracle timeout. Scoped to this process (the settings singleton).
    """
    from ...settings import settings as _settings
    if getattr(args, "setup_timeout", None):
        _settings.precondition_timeout_sec = args.setup_timeout
    if getattr(args, "setup_timeout_mode", None):
        _settings.setup_timeout_mode = args.setup_timeout_mode
    if getattr(args, "verify_timeout", None):
        _settings.oracle_timeout_sec = args.verify_timeout


def _read_system_prompt_arg(args: argparse.Namespace) -> str | None:
    """Read the --system-prompt file (defaults to docs/default-system-prompt.md).

    Returns the file's text, or None if the path is missing/unreadable. The
    service then reads the default file itself; if THAT is also missing the base
    prompt is empty and run_workflow warns (there is no in-code fallback).
    """
    path = getattr(args, "system_prompt", None)
    if path and Path(path).exists():
        try:
            return Path(path).read_text()
        except OSError:
            return None
    return None


def _cmd_run_workflow(args: argparse.Namespace) -> None:
    """Handle the ``run-workflow`` subcommand."""
    profile = load_profile(args.profile) if args.profile else {}
    merged = merge_profile(vars(args), profile)
    resources_dir = Path(merged.get("resources_dir", "cases"))
    runs_dir = Path(merged.get("runs_dir", "runs"))
    _apply_timeout_overrides(args)
    _load_env_file(getattr(args, "llm_env_file", None))

    raw = load_workflow_file(Path(args.workflow))
    workflow = normalize_workflow(raw, resources_dir=resources_dir)
    debug_namespace_overrides = None
    if args.debug:
        debug_namespace_overrides = (
            workflow.get("debug", {}).get("namespace_overrides") or {}
        )
        if not debug_namespace_overrides:
            raise ValueError(
                "--debug was specified, but this workflow has no "
                "spec.debug.namespace_overrides"
            )

    if args.dry_run:
        print(json.dumps(workflow, indent=2, default=str))
        return

    # Detailed live progress to stderr (stdout stays clean for the result).
    def _progress(stage_id: str, message: str) -> None:
        print(f"  {message}", file=sys.stderr, flush=True)

    result = run_workflow(
        workflow,
        runs_dir=runs_dir,
        resources_dir=resources_dir,
        agent_name=merged.get("agent"),
        sandbox_mode=merged.get("sandbox", "local"),
        environment_config=_environment_config(args),
        on_progress=_progress,
        max_attempts=args.max_attempts,
        stage_failure_mode=args.stage_failure_mode,
        final_sweep_mode=args.final_sweep_mode,
        sandbox_options=_build_sandbox_options(args),
        agent_session=args.agent_session,
        system_prompt=_read_system_prompt_arg(args),
        prompt_mode_prologues=getattr(args, "prompt_mode_prologues", None),
        namespace_overrides=debug_namespace_overrides,
    )
    _print_result(result, args.output)
    if getattr(args, "judge", False):
        _maybe_inline_judge(result, runs_dir, args.output, _inline_judge_kwargs(args))
    _maybe_cleanup_image(args)


def _maybe_cleanup_image(args: argparse.Namespace) -> None:
    """Remove the agent Docker image after the run when --agent-cleanup is set."""
    if not getattr(args, "agent_cleanup", False):
        return
    tag = (getattr(args, "agent_tag", None) or getattr(args, "docker_image", None)
           or (f"karma-agent-{args.agent}:latest" if getattr(args, "agent", None) else None))
    if not tag:
        return
    import subprocess
    try:
        subprocess.run(["docker", "rmi", "-f", tag], capture_output=True, text=True)
    except Exception as exc:
        print(f"image cleanup failed: {exc}", file=sys.stderr)


def _cmd_run_case(args: argparse.Namespace) -> None:
    """Handle the ``run-case`` subcommand."""
    profile = load_profile(args.profile) if args.profile else {}
    merged = merge_profile(vars(args), profile)
    param_overrides = _parse_param_overrides(args.param)
    resources_dir = Path(merged.get("resources_dir", "cases"))
    runs_dir = Path(merged.get("runs_dir", "runs"))
    _apply_timeout_overrides(args)
    _load_env_file(getattr(args, "llm_env_file", None))

    result = run_case(
        args.service,
        args.case,
        runs_dir=runs_dir,
        resources_dir=resources_dir,
        param_overrides=param_overrides,
        agent_name=merged.get("agent"),
        sandbox_mode=merged.get("sandbox", "local"),
        environment_config=_environment_config(args),
        agent_timeout_sec=args.timeout,
        max_attempts=args.max_attempts,
        sandbox_options=_build_sandbox_options(args),
    )
    _print_result(result, args.output)
    if getattr(args, "judge", False):
        _maybe_inline_judge(result, runs_dir, args.output, _inline_judge_kwargs(args))
    _maybe_cleanup_image(args)


def _select_batch_cases(args: argparse.Namespace, resources_dir: Path) -> list[tuple[str, str]]:
    """Return the (service, case) pairs selected by --all / --service / --case."""
    all_cases = sorted(
        (p.parent.parent.name, p.parent.name)
        for p in resources_dir.glob("*/*/test.yaml")
    )
    if args.case:
        wanted = {tuple(c.split("/", 1)) for c in args.case if "/" in c}
        return [c for c in all_cases if c in wanted]
    if args.service:
        return [c for c in all_cases if c[0] == args.service]
    if args.all:
        return all_cases
    return []


def _cmd_run_batch(args: argparse.Namespace) -> None:
    """Handle the ``run-batch`` subcommand: run many cases sequentially.

    Selects cases via --all / --service / --case, runs each through the same
    ``run_case`` path, aggregates results, optionally writes them to JSON, and
    optionally judges per-run or after the whole batch.
    """
    profile = load_profile(args.profile) if args.profile else {}
    merged = merge_profile(vars(args), profile)
    resources_dir = Path(merged.get("resources_dir", "cases"))
    runs_dir = Path(merged.get("runs_dir", "runs"))
    _apply_timeout_overrides(args)
    _load_env_file(getattr(args, "llm_env_file", None))

    cases = _select_batch_cases(args, resources_dir)
    if not cases:
        print("no cases selected (use --all, --service NAME, or --case SVC/CASE)",
              file=sys.stderr)
        sys.exit(1)
    param_overrides = _parse_param_overrides(args.param)

    results: list[dict[str, Any]] = []
    for service, case in cases:
        result = run_case(
            service, case,
            runs_dir=runs_dir, resources_dir=resources_dir,
            param_overrides=param_overrides,
            agent_name=merged.get("agent"),
            sandbox_mode=merged.get("sandbox", "local"),
            environment_config=_environment_config(args),
            agent_timeout_sec=args.timeout,
            max_attempts=args.max_attempts,
        )
        results.append({
            "service": service, "case": case,
            "run_id": result.get("run_id"), "status": result.get("status"),
            "summary": result.get("summary"),
        })
        _print_result(result, "text")
        if args.judge_mode == "post-run":
            _maybe_inline_judge(result, runs_dir, "text", _inline_judge_kwargs(args))

    if args.judge_mode == "post-batch":
        print("--- post-batch judging ---")
        for entry in results:
            _maybe_inline_judge(
                {"run_id": entry["run_id"]}, runs_dir, "text", _inline_judge_kwargs(args)
            )

    if args.results_json:
        Path(args.results_json).write_text(json.dumps(results, indent=2))
        print(f"results written to {args.results_json}")

    passed = sum(1 for r in results if r["status"] == "complete")
    if args.output == "json":
        print(json.dumps({"total": len(results), "complete": passed, "results": results}, indent=2))
    else:
        print(f"batch: {passed}/{len(results)} complete")


def _cmd_manual(args: argparse.Namespace) -> None:
    """Handle the ``manual`` subcommand.

    Sets the scenario up (proxy, namespaces, preconditions, decoys, bundle),
    pauses for a human operator to do the task by hand against the printed
    namespace, then verifies on demand (re-runnable) and tears down. Drives
    the same ``runtime.manual`` lifecycle the HTTP API exposes -- the whole
    session lives in this one process, so the in-memory state survives.
    """
    import time
    from ...runtime import manual

    profile = load_profile(args.profile) if args.profile else {}
    merged = merge_profile(vars(args), profile)
    param_overrides = _parse_param_overrides(args.param)
    resources_dir = Path(merged.get("resources_dir", "cases"))
    runs_dir = Path(merged.get("runs_dir", "runs"))

    run_id = manual.start_manual_run(
        args.service,
        args.case,
        runs_dir=runs_dir,
        resources_dir=resources_dir,
        param_overrides=param_overrides,
    )
    print(f"manual run {run_id}: setting up scenario...")

    status = manual.get_manual_status(run_id) or {}
    while status.get("status") == "setup_running":
        time.sleep(1.5)
        status = manual.get_manual_status(run_id) or {}

    if status.get("status") == "setup_failed":
        print(f"setup failed: {status.get('error')}", file=sys.stderr)
        manual.cleanup_manual_run(run_id)
        sys.exit(1)

    print("\nready -- operate the cluster by hand, then verify:")
    for role, ns in (status.get("namespace_bindings") or {}).items():
        print(f"  namespace[{role}] = {ns}")
    if status.get("kubeconfig_path"):
        print(f"  export KUBECONFIG={status['kubeconfig_path']}")
    if status.get("prompt_path"):
        print(f"  task prompt: {status['prompt_path']}")

    try:
        while True:
            choice = input("\n[Enter] verify  /  q then Enter to quit: ").strip().lower()
            if choice == "q":
                break
            result = manual.submit_manual_run(run_id)
            print(
                f"  {result.get('status')} "
                f"(oracle: {result.get('oracle_verdict')}, "
                f"attempt {result.get('attempts')})"
            )
            if result.get("status") == "passed":
                break
    finally:
        manual.cleanup_manual_run(run_id)
        print("cleaned up.")


def _cmd_judge(args: argparse.Namespace) -> None:
    """Handle the ``judge`` subcommand."""
    from ...judge.engine import run_judge, run_judge_batch

    run_dir = Path(args.run_dir)
    if not run_dir.exists():
        raise RuntimeError(f"run directory not found: {run_dir}")

    _load_env_file(getattr(args, "llm_env_file", None))
    rubric = None
    if getattr(args, "rubric", None):
        from ...judge.rubric import load_rubric_file
        rubric = load_rubric_file(args.rubric)
    # Regression-adjudication prompt: read the template file (defaults to the
    # bundled example); None falls back to score_run's built-in default.
    regression_prompt = None
    rp_path = getattr(args, "regression_prompt", None)
    if rp_path and Path(rp_path).exists():
        regression_prompt = Path(rp_path).read_text()
    judge_kwargs = {
        "judge_model": args.model,
        "judge_base_url": args.base_url,
        "judge_api_key": args.api_key,
        "judge_timeout_sec": args.timeout,
        "judge_max_retries": args.max_retries,
        "include_outcome": not getattr(args, "exclude_outcome", False),
    }
    # score_run / judge_batch_dir take the run-level scorer's kwargs (no
    # include_outcome, which is a rubric-judge-only knob) plus the regression prompt.
    score_kwargs = {k: v for k, v in judge_kwargs.items() if k != "include_outcome"}
    score_kwargs["regression_prompt"] = regression_prompt
    try:
        if args.batch:
            # Cross-run batch: score every run under run_dir and average.
            from ...judge.batch import judge_batch_dir
            result = judge_batch_dir(run_dir, rubric=rubric, dry_run=args.dry_run, **score_kwargs)
        elif args.stage:
            # Per-stage rubric judge (inspection of a single stage).
            result = run_judge(run_dir, args.stage, rubric=rubric, dry_run=args.dry_run, **judge_kwargs)
        else:
            # Default: run-level score -- objective stage-pass fraction (or per-stage
            # rubric scores when --rubric is given), plus regression adjudication.
            from ...judge.run_score import score_run
            result = score_run(run_dir, rubric=rubric, dry_run=args.dry_run, **score_kwargs)
    except Exception as exc:
        if args.fail_open:
            print(f"judge error (continuing, --fail-open): {exc}", file=sys.stderr)
            return
        print(f"judge error: {exc}", file=sys.stderr)
        sys.exit(1)
    _print_result(result, args.output)


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> None:
    """Parse *argv* and dispatch to the appropriate subcommand handler.

    Exits with code 1 on error and code 0 on success.
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    if args.command == "info":
        print("agents:", ", ".join(list_agents()))
        sys.exit(0)

    try:
        if args.command == "run-workflow":
            _cmd_run_workflow(args)
        elif args.command == "run-case":
            _cmd_run_case(args)
        elif args.command == "run-batch":
            _cmd_run_batch(args)
        elif args.command == "manual":
            _cmd_manual(args)
        elif args.command == "judge":
            _cmd_judge(args)
        else:
            parser.print_help()
            sys.exit(1)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)

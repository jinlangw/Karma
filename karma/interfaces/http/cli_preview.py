"""
CLI command preview generation for the HTTP interface.

The old UI's "Generate CLI" panels turned a form into a copy-pasteable
orchestrator command. That generator targeted the old CLI flags; this
rebuilds it against the *current* ``orchestrator.py`` surface
(``run-case``, ``run-workflow``, ``judge``) so the preview always matches
what the installed CLI actually accepts.

Pure string assembly with shell-safe quoting -- no execution, no
filesystem access -- so it is cheap to call on every keystroke.
"""

from __future__ import annotations

import shlex
from typing import Any

from ...agents.registry import list_agents

# Tokens kept on the first preview line: "python orchestrator.py <subcommand>".
_CMD_HEAD_TOKENS = 3


def get_cli_options() -> dict[str, Any]:
    """Return the choices and defaults the command builder renders from."""
    return {
        "choices": {
            "agents": list_agents(),
            "sandbox": ["local", "docker"],
            "output": ["text", "json"],
            "command": ["case", "workflow", "judge"],
        },
        "defaults": {
            "agent": "",
            "sandbox": "local",
            "timeout": 900,
            "runs_dir": "runs",
            "resources_dir": "cases/tests",
            "output": "text",
            "dry_run": False,
            "model": "",
            "profile": "",
        },
    }


def _clean(value: Any) -> str:
    """Return *value* as a stripped string, or ``""`` when it is ``None``."""
    return "" if value is None else str(value).strip()


def _tokens_to_multi_line(tokens: list[str]) -> str:
    """Render *tokens* as a backslash-continued multi-line command.

    The subcommand and its positional arguments stay on the first line;
    each subsequent ``--flag value`` pair gets its own indented line, so a
    long command stays readable when copied into a terminal.
    """
    quoted = [shlex.quote(t) for t in tokens]
    if len(quoted) <= _CMD_HEAD_TOKENS:
        return " ".join(quoted)
    # Keep "python orchestrator.py <subcommand> <positionals...>" on line one.
    head_len = _CMD_HEAD_TOKENS
    while head_len < len(quoted) and not quoted[head_len].startswith("--"):
        head_len += 1
    lines = [" ".join(quoted[:head_len])]
    i = head_len
    while i < len(quoted):
        cur = quoted[i]
        if cur.startswith("--") and i + 1 < len(quoted) and not quoted[i + 1].startswith("--"):
            lines.append(f"  {cur} {quoted[i + 1]}")
            i += 2
        else:
            lines.append(f"  {cur}")
            i += 1
    return " \\\n".join(lines)


def _workflow_flags(flags: dict[str, Any]) -> list[str]:
    """run-workflow behavior knobs, emitted only when set to a non-default so the
    command reproduces the launch configuration without needless clutter."""
    tokens: list[str] = []
    ma = flags.get("max_attempts")
    if ma not in (None, "", 1, "1"):
        tokens += ["--max-attempts", str(ma)]
    ses = _clean(flags.get("agent_session"))
    if ses and ses != "persistent":
        tokens += ["--agent-session", ses]
    sfm = _clean(flags.get("stage_failure_mode"))
    if sfm and sfm != "terminate":
        tokens += ["--stage-failure-mode", sfm]
    fsm = _clean(flags.get("final_sweep_mode"))
    if fsm and fsm != "auto":
        tokens += ["--final-sweep-mode", fsm]
    return tokens


def _common_flags(flags: dict[str, Any], defaults: dict[str, Any]) -> list[str]:
    """Return the flag tokens shared by run-case and run-workflow."""
    tokens: list[str] = []
    agent = _clean(flags.get("agent"))
    if agent:
        tokens += ["--agent", agent]
    sandbox = _clean(flags.get("sandbox")) or defaults["sandbox"]
    if sandbox != defaults["sandbox"]:
        tokens += ["--sandbox", sandbox]
    runs_dir = _clean(flags.get("runs_dir"))
    if runs_dir and runs_dir != defaults["runs_dir"]:
        tokens += ["--runs-dir", runs_dir]
    resources_dir = _clean(flags.get("resources_dir"))
    if resources_dir and resources_dir != defaults["resources_dir"]:
        tokens += ["--resources-dir", resources_dir]
    profile = _clean(flags.get("profile"))
    if profile:
        tokens += ["--profile", profile]
    output = _clean(flags.get("output"))
    if output and output != defaults["output"]:
        tokens += ["--output", output]
    return tokens


def build_preview(payload: dict[str, Any]) -> dict[str, Any]:
    """Build a CLI command preview from a builder *payload*.

    The payload has a ``command`` (``"case"``, ``"workflow"``, or
    ``"judge"``), a ``target`` block identifying what to run, and a
    ``flags`` block of optional settings. Validation errors and advisory
    warnings are returned rather than raised so the UI can show them inline.

    Returns
    -------
    dict
        ``ok`` (bool), ``errors`` (list[str]), ``warnings`` (list[str]),
        ``command_one_line`` (str), ``command_multi_line`` (str),
        ``tokens`` (list[str]).
    """
    options = get_cli_options()
    defaults = options["defaults"]
    choices = options["choices"]
    errors: list[str] = []
    warnings: list[str] = []

    command = _clean(payload.get("command")) or "case"
    target = payload.get("target") or {}
    flags = payload.get("flags") or {}

    tokens: list[str] = ["python", "orchestrator.py"]

    sandbox = _clean(flags.get("sandbox")) or defaults["sandbox"]
    if sandbox not in choices["sandbox"]:
        errors.append(f"sandbox must be one of: {', '.join(choices['sandbox'])}")
    agent = _clean(flags.get("agent"))
    if agent and choices["agents"] and agent not in choices["agents"]:
        errors.append(f"agent must be one of: {', '.join(choices['agents'])}")
    if sandbox == "docker" and not agent:
        errors.append("--agent is required when --sandbox docker")
    if sandbox == "local" and not agent:
        warnings.append("No agent selected, so this runs locally without launching one.")

    if command == "case":
        service = _clean(target.get("service"))
        case = _clean(target.get("case"))
        if not service or not case:
            errors.append("case command requires target.service and target.case")
        tokens += ["run-case", service, case]
        tokens += _common_flags(flags, defaults)
        for k, v in (flags.get("params") or {}).items():
            tokens += ["--param", f"{k}={v}"]
        timeout = flags.get("timeout")
        if timeout not in (None, "", defaults["timeout"]):
            tokens += ["--timeout", str(timeout)]

    elif command == "workflow":
        path = _clean(target.get("path"))
        if not path:
            errors.append("workflow command requires target.path")
        tokens += ["run-workflow", path]
        tokens += _common_flags(flags, defaults)
        tokens += _workflow_flags(flags)
        if flags.get("dry_run"):
            tokens.append("--dry-run")

    elif command == "judge":
        run_dir = _clean(target.get("run_dir"))
        if not run_dir:
            errors.append("judge command requires target.run_dir")
        tokens += ["judge", run_dir]
        stage = _clean(flags.get("stage"))
        if stage:
            tokens += ["--stage", stage]
        model = _clean(flags.get("model"))
        if model:
            tokens += ["--model", model]
        if flags.get("dry_run"):
            tokens.append("--dry-run")
        output = _clean(flags.get("output"))
        if output and output != defaults["output"]:
            tokens += ["--output", output]

    else:
        errors.append(f"command must be one of: {', '.join(choices['command'])}")

    return {
        "ok": not errors,
        "errors": errors,
        "warnings": warnings,
        "command_one_line": shlex.join(tokens),
        "command_multi_line": _tokens_to_multi_line(tokens),
        "tokens": tokens,
    }

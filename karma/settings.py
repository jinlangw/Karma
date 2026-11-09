"""
karma/settings.py — runtime configuration loaded from environment variables.

All KARMA_ prefixed variables are read at import time via ``Settings.from_env()``.
Callers import the module-level ``settings`` singleton; tests can replace it with
a fresh ``Settings.from_env()`` call against a patched environment.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_RESOURCES_DIR = Path("cases/tests")


def top_level_adversaries_dir(resources_dir: Path) -> Path:
    """Return the top-level adversary directory for a resource root.

    The built-in corpus lives below the cwd-relative ``cases/tests`` root while
    its adversaries stay at the repository root. Caller-supplied resource
    roots retain the existing sibling-directory convention.
    """
    resources_root = Path(resources_dir)
    builtin_root = DEFAULT_RESOURCES_DIR.resolve()
    if resources_root.resolve() == builtin_root:
        return builtin_root.parent.parent / "adversaries"
    return resources_root.parent / "adversaries"


@dataclass
class Settings:
    """Flat bag of every tuneable runtime parameter.

    All fields have sensible defaults so a local dev environment works
    without setting any environment variable.
    """

    # Filesystem roots
    resources_dir: Path = field(default_factory=lambda: DEFAULT_RESOURCES_DIR)
    runs_dir: Path = field(default_factory=lambda: Path("runs"))

    # HTTP server
    host: str = "127.0.0.1"
    port: int = 8080

    # NOTE: judge model/api-key/base-url and the agent model are intentionally
    # NOT configured here. The judge resolves them per call from KARMA_JUDGE_*
    # env (see judge/client.py) and mirrors the run's agent (judge/agent_defaults
    # .py); each agent resolves its own model from its own env in entrypoint.sh
    # (e.g. KARMA_CLAUDE_AGENT_MODEL). Keeping duplicate defaults here only
    # misleads, since nothing reads them.

    # Execution limits
    command_timeout_sec: int = 120
    precondition_timeout_sec: int = 600
    # How precondition_timeout_sec is applied: "fixed" uses it as a hard cap;
    # "auto" uses max(precondition_timeout_sec, per-case computed budget) so a
    # legitimately slow precondition is not killed by a too-small literal.
    setup_timeout_mode: str = "auto"
    oracle_timeout_sec: int = 120
    # Absolute upper bound (seconds) on a single agent attempt. The per-stage
    # agent_timeout_sec is treated as an IDLE budget that resets while the agent
    # keeps producing output, so a still-working agent is never cut off by the
    # clock; this cap only stops a runaway agent that loops while still emitting.
    agent_hard_cap_sec: int = 3600

    # Logging
    log_level: str = "INFO"

    @classmethod
    def from_env(cls) -> "Settings":
        """Construct a Settings instance by reading KARMA_* environment variables.

        Each field maps to an env var with the KARMA_ prefix and the field
        name uppercased (e.g. ``runs_dir`` → ``KARMA_RUNS_DIR``).
        """
        def _path(key: str, default: str) -> Path:
            return Path(os.environ.get(key, default))

        def _int(key: str, default: int) -> int:
            try:
                return int(os.environ[key])
            except (KeyError, ValueError):
                return default

        def _str(key: str, default: str) -> str:
            return os.environ.get(key, default)

        return cls(
            resources_dir=_path("KARMA_RESOURCES_DIR", str(DEFAULT_RESOURCES_DIR)),
            runs_dir=_path("KARMA_RUNS_DIR", "runs"),
            host=_str("KARMA_HOST", "127.0.0.1"),
            port=_int("KARMA_PORT", 8080),
            command_timeout_sec=_int("KARMA_COMMAND_TIMEOUT_SEC", 120),
            precondition_timeout_sec=_int("KARMA_PRECONDITION_TIMEOUT_SEC", 600),
            setup_timeout_mode=_str("KARMA_SETUP_TIMEOUT_MODE", "auto"),
            oracle_timeout_sec=_int("KARMA_ORACLE_TIMEOUT_SEC", 120),
            agent_hard_cap_sec=_int("KARMA_AGENT_HARD_CAP_SEC", 3600),
            log_level=_str("KARMA_LOG_LEVEL", "INFO"),
        )


# Module-level singleton used by production code.
settings: Settings = Settings.from_env()

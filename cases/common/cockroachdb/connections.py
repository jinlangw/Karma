"""Shared fixed-query connection checks for CockroachDB cases."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from subprocess import CompletedProcess


_READINESS_SQL = "SELECT 1;"


def select_sql_readiness_flag(
    candidates: Iterable[str],
    sql: Callable[[str, str], CompletedProcess[str]],
    *,
    unavailable_message: str,
) -> str:
    """Return the first caller-selected connection flag that passes ``SELECT 1``."""
    for flag in candidates:
        if sql(_READINESS_SQL, flag).returncode == 0:
            return flag
    raise RuntimeError(unavailable_message)

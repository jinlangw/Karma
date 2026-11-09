"""Stable public stage identity and ephemeral private input for trusted commands.

Keys live only in the orchestrator process. Opted-in setup/oracle commands receive
JSON through stdin; agent launches/bundles never receive it. This prevents routine
artifact/env disclosure, not same-user process debugging in an unrestricted local
sandbox. Restarting the orchestrator loses keys and grading fails closed.
"""
from __future__ import annotations

import base64
import json
import secrets
import threading
from pathlib import Path

_records: dict[tuple[str, str], dict] = {}
_lock = threading.Lock()


def stage_env(run_dir: Path, stage_id: str) -> dict[str, str]:
    return {"BENCH_RUN_ID": run_dir.name, "BENCH_STAGE_ID": stage_id}


def trusted_input(entry: dict, env: dict[str, str], *, create: bool = False) -> str:
    """Return private JSON only for an explicit trusted_stdin: stage_key command."""
    if entry.get("trusted_stdin") != "stage_key":
        raise ValueError("unsupported trusted command input")
    identity = (env["BENCH_RUN_ID"], env["BENCH_STAGE_ID"])
    with _lock:
        if identity not in _records:
            if not create:
                raise RuntimeError("private stage key unavailable; cannot validate baseline")
            _records[identity] = {"key": base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),
                                  "frozen": False}
        return json.dumps(_records[identity])


def freeze_stage(run_dir: Path, stage_id: str) -> None:
    """Subsequent setup/agent retries must retain the first solver's baseline."""
    with _lock:
        record = _records.get((run_dir.name, stage_id))
        if record is not None:
            record["frozen"] = True

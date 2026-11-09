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

StageIdentity = tuple[Path, str]

_records: dict[StageIdentity, dict] = {}
_lock = threading.Lock()


def stage_env(run_dir: Path, stage_id: str) -> dict[str, str]:
    return {"BENCH_RUN_ID": run_dir.name, "BENCH_STAGE_ID": stage_id}


def trusted_input(entry: dict, stage: StageIdentity | None, *, create: bool = False) -> str:
    """Return private JSON only for an explicit trusted_stdin: stage_key command."""
    if entry.get("trusted_stdin") != "stage_key":
        raise ValueError("unsupported trusted command input")
    if stage is None:
        raise RuntimeError("private stage key unavailable; missing stage identity")
    identity = _stage_identity(*stage)
    with _lock:
        if identity not in _records:
            if not create:
                raise RuntimeError("private stage key unavailable; cannot validate baseline")
            _records[identity] = {"key": base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),
                                  "frozen": False}
        return json.dumps(_records[identity])


def _stage_identity(run_dir: Path, stage_id: str) -> StageIdentity:
    return run_dir.resolve(), stage_id


def freeze_stage(run_dir: Path, stage_id: str) -> None:
    """Subsequent setup/agent retries must retain the first solver's baseline."""
    identity = _stage_identity(run_dir, stage_id)
    with _lock:
        record = _records.get(identity)
        if record is not None:
            record["frozen"] = True

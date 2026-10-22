#!/usr/bin/env python3
"""Oracle for ray/job_submission.

Runs the fixed job script inside the ray-client pod and verifies it connects to
the cluster, exits 0, and prints the expected output.
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

NAMESPACE = "ray"
CLIENT = "ray-client"
JOB_PATH = "/opt/job.py"
# Param-aware: a workflow can override expected_output. Read it from the env
# (default = the standalone value "pong") so the oracle checks whichever string
# the workflow told the agent to make the job print.
EXPECTED_OUTPUT = os.environ.get("BENCH_PARAM_EXPECTED_OUTPUT", "pong") or "pong"

# The job does a Ray Client connect (ray.init(address="ray://...")). On a freshly
# (re)created client pod or a cold head the client-server gRPC channel can take a
# while to become reachable, surfacing as a transient "ray client connection
# timeout" before the job ever runs. Retry the whole connect+run a few times so a
# correct fix is not failed by that race. This does NOT weaken the check: every
# attempt still requires the job to exit 0 AND print EXPECTED_OUTPUT.
#
# Ray's own client connect retries internally for ~60s before raising, so we bound
# each attempt with a per-exec timeout and keep the total well under the oracle's
# 150s budget: ATTEMPTS * (PER_ATTEMPT_TIMEOUT + BACKOFF) must stay < 150.
CONNECT_ATTEMPTS = 3
PER_ATTEMPT_TIMEOUT_SEC = 40
CONNECT_BACKOFF_SEC = 5
# Substrings that mark a transient cluster-not-ready connect failure (vs a real
# job/script defect, which we must still report on the final attempt).
TRANSIENT_MARKERS = (
    "ray client connection timeout",
    "Ray Client connection timed out",
    "connection refused",
    "failed to connect",
    "timed out",
)


def _attempt_job() -> tuple[bool, str, list[str]]:
    """Run the job once (bounded); return (passed, detail, output_lines)."""
    try:
        proc = subprocess.run(
            ["kubectl", "-n", NAMESPACE, "exec", CLIENT, "--", "python", JOB_PATH],
            text=True,
            capture_output=True,
            timeout=PER_ATTEMPT_TIMEOUT_SEC,
        )
    except subprocess.TimeoutExpired:
        return False, "ray client connection timeout (exec exceeded attempt budget)", []
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip() or f"exit {proc.returncode}"
        return False, detail, []
    output_lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    if EXPECTED_OUTPUT not in output_lines:
        return False, f"output {output_lines!r}", output_lines
    return True, "", output_lines


def check_job() -> int:
    """Execute the job script in ray-client and check its exit code + output.

    Retries a transient Ray Client connect timeout (cluster/client still warming
    up) a few times; a non-transient failure or a wrong/missing output is reported
    immediately and is never papered over.
    """
    last_detail = "no attempt made"
    for attempt in range(1, CONNECT_ATTEMPTS + 1):
        passed, detail, _ = _attempt_job()
        if passed:
            print(f"job script printed {EXPECTED_OUTPUT!r}")
            return 0
        last_detail = detail
        transient = any(m.lower() in detail.lower() for m in TRANSIENT_MARKERS)
        if not transient or attempt == CONNECT_ATTEMPTS:
            break
        last_line = detail.splitlines()[-1] if detail else detail
        print(
            f"ray-client connect not ready (attempt {attempt}/{CONNECT_ATTEMPTS}): "
            f"{last_line!r}; retrying"
        )
        time.sleep(CONNECT_BACKOFF_SEC)
    print(f"job script failed in {CLIENT}: {last_detail}")
    return 1


def main() -> int:
    """Run the job_submission verification check."""
    rc = check_job()
    if rc != 0:
        return rc
    print("ray job_submission verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

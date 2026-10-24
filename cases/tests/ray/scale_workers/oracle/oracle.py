#!/usr/bin/env python3
"""Oracle for ray/scale_workers.

Verifies the head is ready, the worker deployment is both specced and ready at
the target replica count, and that EXPECTED_WORKERS raylets belonging to the
worker pods (scoped by pod IP — O41, never the unscoped ray.nodes() tally the
throwaway ray-client inflates) are alive in the cluster.
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

from cases.common.ray.oracle_lib import (  # noqa: E402
    deployment_ready_replicas,
    deployment_spec_replicas,
    ray_worker_raylet_count,
    wait_ready_replicas,
)

NAMESPACE = "ray"
HEAD = "ray-head"
WORKER = "ray-worker"
# Param-aware: a workflow can override target_worker_replicas (e.g. a scale
# sweep 1 -> 3 -> 5). Read this stage's live target from the env (default = the
# standalone value 3) so the oracle verifies whatever this stage scaled to,
# not a baked-in count. A non-solving agent still fails — the criterion is
# unchanged, only WHICH count it checks is redirected.
EXPECTED_WORKERS = int(os.environ.get("BENCH_PARAM_TARGET_WORKER_REPLICAS", "3") or "3")

CONNECTIVITY_TOTAL_TIMEOUT_SEC = 60
CONNECTIVITY_ATTEMPT_TIMEOUT_SEC = 12


def check_head() -> int:
    """Confirm the head deployment has at least one ready replica."""
    ready = deployment_ready_replicas(NAMESPACE, HEAD)
    if ready < 1:
        print(f"deployment/{HEAD} ready replicas {ready}, expected at least 1")
        return 1
    print(f"deployment/{HEAD} ready replicas {ready}")
    return 0


def check_worker_spec() -> int:
    """Confirm the worker deployment is specced at the target replica count."""
    replicas = deployment_spec_replicas(NAMESPACE, WORKER)
    if replicas != EXPECTED_WORKERS:
        print(f"deployment/{WORKER} spec replicas {replicas}, expected {EXPECTED_WORKERS}")
        return 1
    print(f"deployment/{WORKER} spec replicas {replicas}")
    return 0


def check_worker_ready_replicas() -> int:
    """Confirm the worker Deployment reaches EXPECTED_WORKERS ready replicas.

    O41: the raylet tally alone can be inflated by non-worker raylets, so pair
    it with the graded workload's own readyReplicas — polled to a bounded
    deadline (O13/O14) so the post-scale rejoin window can't false-fail.
    """
    reached, last = wait_ready_replicas(
        NAMESPACE, WORKER, EXPECTED_WORKERS, timeout_sec=CONNECTIVITY_TOTAL_TIMEOUT_SEC
    )
    if not reached:
        print(f"deployment/{WORKER} ready replicas {last}, expected at least {EXPECTED_WORKERS}")
        return 1
    print(f"deployment/{WORKER} ready replicas {last}")
    return 0


def check_worker_raylets() -> int:
    """Confirm EXPECTED_WORKERS raylets from the WORKER pods joined the head.

    O41: ray.nodes() also lists the head raylet and the throwaway ray-client
    raylet the precondition registers, so an unscoped `alive >= 1 + N` tally
    passes one worker short (head+client+N-1). Count only alive raylets whose
    NodeManagerAddress is one of the worker Deployment's own pod IPs, polled
    to convergence (O13). Not a loosening: a worker that never joins leaves
    the scoped count short and still fails.
    """
    deadline = time.time() + CONNECTIVITY_TOTAL_TIMEOUT_SEC
    last_count = 0
    last_error = ""
    while time.time() < deadline:
        try:
            last_count = ray_worker_raylet_count(
                NAMESPACE, HEAD, WORKER, timeout_sec=CONNECTIVITY_ATTEMPT_TIMEOUT_SEC
            )
        except Exception as exc:  # noqa: BLE001
            last_error = str(exc)
            time.sleep(3)
            continue
        last_error = ""
        if last_count >= EXPECTED_WORKERS:
            print(f"ray reports {last_count} live worker raylets ({EXPECTED_WORKERS} required)")
            return 0
        time.sleep(3)
    if last_error:
        print(f"ray worker raylet probe failed: {last_error}")
        return 1
    print(f"ray reports {last_count} live worker raylets, expected at least {EXPECTED_WORKERS}")
    return 1


def main() -> int:
    """Run every scale_workers verification check in order."""
    for fn in (check_head, check_worker_spec, check_worker_ready_replicas, check_worker_raylets):
        rc = fn()
        if rc != 0:
            return rc
    print("ray scale_workers verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

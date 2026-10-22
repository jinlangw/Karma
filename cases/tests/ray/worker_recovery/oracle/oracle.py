#!/usr/bin/env python3
"""Oracle for ray/worker_recovery.

Verifies the head is ready, the worker deployment recovered to the promised
ready replica count, and that EXPECTED_WORKERS raylets belonging to the worker
pods (scoped by pod IP — O41, never the unscoped ray.nodes() tally the
throwaway ray-client inflates) are alive in the cluster.
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

from cases.common.ray.oracle_lib import (  # noqa: E402
    bench_namespace,
    deployment_ready_replicas,
    ray_worker_raylet_count,
    wait_ready_replicas,
)

NAMESPACE = bench_namespace()
HEAD = "ray-head"
WORKER = "ray-worker"
# Param-first, never live-derived (O2 exception / O41): the worker count IS the
# graded outcome here — the prompt promises the deployment recovers to this many
# ready workers. Deriving it from the live spec.replicas would let an agent that
# scales to 1 (instead of fixing the crash-looping command) "recover" trivially.
# A workflow overrides via the expected_workers param; standalone default is 2.
EXPECTED_WORKERS = int(os.environ.get("BENCH_PARAM_EXPECTED_WORKERS", "2") or "2")

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


def check_worker_ready_replicas() -> int:
    """Confirm the worker Deployment recovers to EXPECTED_WORKERS ready replicas.

    O41: the raylet tally alone can be inflated by non-worker raylets, so pair
    it with the graded workload's own readyReplicas — polled to a bounded
    deadline (O13/O14) so the post-fix rollout window can't false-fail.
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
    """Confirm EXPECTED_WORKERS raylets from the WORKER pods rejoined the head.

    O41: ray.nodes() also lists the head raylet and the throwaway ray-client
    raylet the precondition registers, so an unscoped `alive >= 1 + N` tally
    passes one worker short (head+client+N-1). Count only alive raylets whose
    NodeManagerAddress is one of the worker Deployment's own pod IPs, polled
    to convergence (O13). Not a loosening: a worker that never recovers leaves
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
    """Run every worker_recovery verification check in order."""
    for fn in (check_head, check_worker_ready_replicas, check_worker_raylets):
        rc = fn()
        if rc != 0:
            return rc
    print("ray worker_recovery verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

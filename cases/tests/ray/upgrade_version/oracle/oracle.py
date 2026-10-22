#!/usr/bin/env python3
"""Oracle for ray/upgrade_version.

Verifies both the head and worker deployments run the target Ray image, remain
ready, and that the inherited worker count is still fully live — counted from
raylets belonging to the worker pods (scoped by pod IP — O41, never the
unscoped ray.nodes() tally an auxiliary client raylet inflates).
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

from cases.common.ray.oracle_lib import (  # noqa: E402
    deployment_image,
    deployment_ready_replicas,
    ray_worker_raylet_count,
    resolve_expected_workers,
    wait_ready_replicas,
)

NAMESPACE = "ray"
HEAD = "ray-head"
WORKER = "ray-worker"
# Param-aware: a workflow can override to_image (the target upgrade image).
# Read it from the env (default = the standalone value) so the oracle verifies
# whatever version this stage upgraded to, not a baked-in tag.
EXPECTED_IMAGE = os.environ.get("BENCH_PARAM_TO_IMAGE", "rayproject/ray:2.9.0") or "rayproject/ray:2.9.0"
# Live/param-aware worker count: an upgrade does NOT change the worker count, so
# adapt to whatever topology this stage inherits (param override -> live worker
# spec -> the standalone default 2). A cluster previously scaled to N workers
# must still report all N ready/live after the upgrade.
EXPECTED_WORKERS = resolve_expected_workers(NAMESPACE, WORKER, default=2)

CONNECTIVITY_TOTAL_TIMEOUT_SEC = 60
CONNECTIVITY_ATTEMPT_TIMEOUT_SEC = 12


def check_head_image() -> int:
    """Confirm the head deployment runs the target image."""
    image = deployment_image(NAMESPACE, HEAD)
    if image != EXPECTED_IMAGE:
        print(f"deployment/{HEAD} image {image}, expected {EXPECTED_IMAGE}")
        return 1
    print(f"deployment/{HEAD} image {image}")
    return 0


def check_worker_image() -> int:
    """Confirm the worker deployment runs the target image."""
    image = deployment_image(NAMESPACE, WORKER)
    if image != EXPECTED_IMAGE:
        print(f"deployment/{WORKER} image {image}, expected {EXPECTED_IMAGE}")
        return 1
    print(f"deployment/{WORKER} image {image}")
    return 0


def check_head_ready() -> int:
    """Confirm the head deployment has at least one ready replica."""
    ready = deployment_ready_replicas(NAMESPACE, HEAD)
    if ready < 1:
        print(f"deployment/{HEAD} ready replicas {ready}, expected at least 1")
        return 1
    print(f"deployment/{HEAD} ready replicas {ready}")
    return 0


def check_worker_ready_replicas() -> int:
    """Confirm the worker Deployment returns to EXPECTED_WORKERS ready replicas.

    O41: the raylet tally alone can be inflated by non-worker raylets, so pair
    it with the graded workload's own readyReplicas — polled to a bounded
    deadline (O13/O14) so the post-upgrade rollout window can't false-fail.
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

    O41: ray.nodes() also lists the head raylet and any auxiliary client raylet,
    so an unscoped `alive >= 1 + N` tally passes one worker short. Count only
    alive raylets whose NodeManagerAddress is one of the worker Deployment's
    own pod IPs, polled to convergence (O13) across the post-upgrade rejoin
    window. Not a loosening: a worker that never rejoins leaves the scoped
    count short and still fails. check_worker_image keeps the upgraded-image
    assertion.
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
    """Run every upgrade_version verification check in order."""
    for fn in (
        check_head_image,
        check_worker_image,
        check_head_ready,
        check_worker_ready_replicas,
        check_worker_raylets,
    ):
        rc = fn()
        if rc != 0:
            return rc
    print("ray upgrade_version verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

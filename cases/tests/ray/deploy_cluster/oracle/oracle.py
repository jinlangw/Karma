#!/usr/bin/env python3
"""Oracle for ray/deploy_cluster.

Verifies the Ray head Service exposes the GCS port, the head and worker
deployments are ready, and that EXPECTED_WORKERS raylets belonging to the
worker pods (scoped by pod IP — O41, never the unscoped ray.nodes() tally an
auxiliary client raylet inflates) are alive in the cluster.
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
    service_ports,
    wait_ready_replicas,
)

NAMESPACE = bench_namespace()
HEAD = "ray-head"
WORKER = "ray-worker"
# Param-aware: a workflow can override worker_replicas (deploy a cluster with
# 1/2/3/5 workers). Read the requested count from the env (default = the
# standalone value 2) so the oracle verifies the size the workflow asked for.
EXPECTED_WORKERS = int(os.environ.get("BENCH_PARAM_WORKER_REPLICAS", "2") or "2")

CONNECTIVITY_TOTAL_TIMEOUT_SEC = 60
CONNECTIVITY_ATTEMPT_TIMEOUT_SEC = 12


def check_service() -> int:
    """Confirm the head Service exposes the GCS port 6379."""
    ports = service_ports(NAMESPACE, HEAD)
    if 6379 not in ports:
        print(f"service/{HEAD} does not expose port 6379")
        return 1
    print(f"service/{HEAD} exposes port 6379")
    return 0


def check_head() -> int:
    """Confirm the head deployment has at least one ready replica."""
    ready = deployment_ready_replicas(NAMESPACE, HEAD)
    if ready < 1:
        print(f"deployment/{HEAD} ready replicas {ready}, expected at least 1")
        return 1
    print(f"deployment/{HEAD} ready replicas {ready}")
    return 0


def check_worker_ready_replicas() -> int:
    """Confirm the worker Deployment reaches EXPECTED_WORKERS ready replicas.

    O41: the raylet tally alone can be inflated by non-worker raylets, so pair
    it with the graded workload's own readyReplicas — polled to a bounded
    deadline (O13/O14) so the fresh-deploy convergence window can't false-fail.
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

    O41: ray.nodes() also lists the head raylet and any auxiliary client raylet,
    so an unscoped `alive >= 1 + N` tally passes one worker short. Count only
    alive raylets whose NodeManagerAddress is one of the worker Deployment's
    own pod IPs, polled to convergence (O13). Not a loosening: a worker that
    never joins leaves the scoped count short and still fails.
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
    """Run every deploy_cluster verification check in order."""
    for fn in (check_service, check_head, check_worker_ready_replicas, check_worker_raylets):
        rc = fn()
        if rc != 0:
            return rc
    print("ray deploy_cluster verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

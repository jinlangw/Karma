#!/usr/bin/env python3
"""Oracle for ray/teardown_cluster.

Verifies the namespace still exists while the ray-head deployment, ray-worker
deployment, and ray-head Service have all been removed.
"""
from __future__ import annotations

import sys
from pathlib import Path

from cases.common.ray.oracle_lib import namespace_exists, resource_missing  # noqa: E402

NAMESPACE = "ray"
HEAD = "ray-head"
WORKER = "ray-worker"


def check_namespace() -> int:
    """Confirm the ray namespace was preserved."""
    if not namespace_exists(NAMESPACE):
        print(f"namespace/{NAMESPACE} is missing")
        return 1
    print(f"namespace/{NAMESPACE} still exists")
    return 0


def check_head_missing() -> int:
    """Confirm the head deployment was deleted."""
    if not resource_missing(NAMESPACE, "deployment", HEAD):
        print(f"deployment/{HEAD} still exists")
        return 1
    print(f"deployment/{HEAD} is absent")
    return 0


def check_worker_missing() -> int:
    """Confirm the worker deployment was deleted."""
    if not resource_missing(NAMESPACE, "deployment", WORKER):
        print(f"deployment/{WORKER} still exists")
        return 1
    print(f"deployment/{WORKER} is absent")
    return 0


def check_service_missing() -> int:
    """Confirm the head Service was deleted."""
    if not resource_missing(NAMESPACE, "service", HEAD):
        print(f"service/{HEAD} still exists")
        return 1
    print(f"service/{HEAD} is absent")
    return 0


def main() -> int:
    """Run every teardown_cluster verification check in order."""
    for fn in (check_namespace, check_head_missing, check_worker_missing, check_service_missing):
        rc = fn()
        if rc != 0:
            return rc
    print("ray teardown_cluster verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

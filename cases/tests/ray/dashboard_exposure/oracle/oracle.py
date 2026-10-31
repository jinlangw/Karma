#!/usr/bin/env python3
"""Oracle for ray/dashboard_exposure.

Verifies the ray-head Service exposes the dashboard port and that the dashboard
endpoint returns HTTP 200 from inside the cluster.
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

from cases.common.ray.oracle_lib import bench_namespace, curl_dashboard_status, service_ports  # noqa: E402

NAMESPACE = bench_namespace()
HEAD = "ray-head"
CURL_POD = "curl-test"
# Param-aware: a workflow can override dashboard_port. Read it from the env
# (default = the standalone value 8265) so the oracle checks whichever port the
# workflow asked the agent to expose.
EXPECTED_PORT = int(os.environ.get("BENCH_PARAM_DASHBOARD_PORT", "8265") or "8265")

# The dashboard HTTP endpoint is slow to warm up (the head's dashboard process
# starts asynchronously after the agent's change, and an inherited head may have
# just restarted). A single-shot curl flakes during that window (Pattern 5), so
# re-evaluate within a bounded budget. This does NOT weaken the check: every
# attempt still requires HTTP 200; only a transient pre-200 state is retried.
HTTP_TOTAL_TIMEOUT_SEC = 90
HTTP_RETRY_INTERVAL_SEC = 5


def check_service_port() -> int:
    """Confirm the head Service exposes the dashboard port."""
    ports = service_ports(NAMESPACE, HEAD)
    if EXPECTED_PORT not in ports:
        print(f"service/{HEAD} does not expose port {EXPECTED_PORT}")
        return 1
    print(f"service/{HEAD} exposes port {EXPECTED_PORT}")
    return 0


def check_http() -> int:
    """Confirm the dashboard endpoint returns HTTP 200.

    Retries within a bounded budget so a slow dashboard warm-up (or a head pod
    that just restarted) does not fail a correct fix; a genuinely unexposed or
    broken dashboard still fails after the budget.
    """
    deadline = time.time() + HTTP_TOTAL_TIMEOUT_SEC
    last_detail = "no attempt made"
    while True:
        try:
            status = curl_dashboard_status(NAMESPACE, CURL_POD, HEAD, EXPECTED_PORT)
        except Exception as exc:  # noqa: BLE001
            last_detail = str(exc)
            status = ""
        if status == "200":
            print("dashboard endpoint returned HTTP 200")
            return 0
        last_detail = f"HTTP status {status}" if status else last_detail
        if time.time() >= deadline:
            break
        time.sleep(HTTP_RETRY_INTERVAL_SEC)
    print(f"dashboard HTTP check failed: {last_detail}, expected 200")
    return 1


def main() -> int:
    """Run every dashboard_exposure verification check in order."""
    for fn in (check_service_port, check_http):
        rc = fn()
        if rc != 0:
            return rc
    print("ray dashboard_exposure verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

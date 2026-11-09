#!/usr/bin/env python3
"""Oracle for nginx-ingress/class_only_upgrade.

Curls the case's private gateway (class-demo/ingress-gateway, which forwards
to private controller instance #2) from the in-cluster curl pod and passes
when the expected body is served for the target host. All state lives in the
case's private namespaces (C16): class-demo + class-ingress-nginx(-2).
"""
import os
import subprocess
import sys
import time

# Param-aware: a workflow can override host/expected_body/curl_pod_name via
# param_overrides; read BENCH_PARAM_* (default = the standalone value) so the
# oracle checks the host this stage was asked to serve on the live cluster.
# Pass criterion unchanged.
HOST = os.environ.get("BENCH_PARAM_HOST") or "class.example.com"
EXPECTED_BODY = os.environ.get("BENCH_PARAM_EXPECTED_BODY") or "hello"
CURL_POD = os.environ.get("BENCH_PARAM_CURL_POD_NAME") or "curl-test"

# Reachability is transient-prone: once the agent assigns the IngressClass the
# selected controller reloads asynchronously and the gateway Service may still be
# warming up. A single curl races that, so re-evaluate within a bounded window
# and pass as soon as the body matches. This does not loosen the criterion -- a
# host that never serves the expected body still fails after the deadline.
# O21 arithmetic: worst case = last attempt starts just under DEADLINE_SEC
# (110s) + one bounded exec (30s) = 140s < the oracle command's timeout_sec
# (150s), so the harness can never kill the loop before it prints a verdict.
DEADLINE_SEC = 110
INTERVAL_SEC = 3


def run(cmd, timeout=30):
    """Run a command bounded (O17); a hang counts as a failed attempt."""
    try:
        return subprocess.run(cmd, text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, 124, "", "timed out")


def main():
    # curl is bounded too (O17): a hung connect/read against a reloading
    # controller counts as a failed attempt the loop retries.
    cmd = [
        "kubectl",
        "-n",
        "class-demo",
        "exec",
        CURL_POD,
        "--",
        "curl",
        "-sS",
        "--connect-timeout",
        "5",
        "--max-time",
        "15",
        "-H",
        f"Host: {HOST}",
        "http://ingress-gateway.class-demo.svc.cluster.local/",
    ]
    deadline = time.monotonic() + DEADLINE_SEC
    last_err = "no response"
    while True:
        result = run(cmd)
        if result.returncode != 0:
            last_err = result.stderr.strip() or "ingress request failed"
        else:
            body = result.stdout.strip()
            if body == EXPECTED_BODY:
                return 0
            last_err = f"unexpected response body: {body}"
        if time.monotonic() >= deadline:
            break
        time.sleep(INTERVAL_SEC)

    print(f"Ingress request failed: {last_err}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())

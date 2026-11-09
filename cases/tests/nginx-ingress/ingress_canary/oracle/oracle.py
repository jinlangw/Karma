#!/usr/bin/env python3
import os
import subprocess
import sys
import time

# Param-aware: a workflow can override host/header/body values via
# param_overrides; read BENCH_PARAM_* (default = the standalone value) so the
# oracle verifies the header-based routing this stage configured on the live,
# accumulated cluster. Pass criterion (stable without header, canary with
# header) is unchanged.
HOST = os.environ.get("BENCH_PARAM_HOST") or "canary.example.com"
HEADER_NAME = os.environ.get("BENCH_PARAM_HEADER_NAME") or "X-Canary"
HEADER_VALUE = os.environ.get("BENCH_PARAM_HEADER_VALUE") or "always"
STABLE_BODY = os.environ.get("BENCH_PARAM_STABLE_BODY") or "stable"
CANARY_BODY = os.environ.get("BENCH_PARAM_CANARY_BODY") or "canary"

# Reachability is transient-prone: ingress-nginx applies the canary annotations
# asynchronously (config reload) and in a workflow the controller may be warming
# up or reloading right when the oracle runs. A single pass races that, so
# re-evaluate both routes within a bounded window and pass as soon as BOTH match
# in the same cycle. This does not loosen the criterion -- mis-routed traffic
# that never settles still fails after the deadline.
# O-deadline: keep the loop window strictly below the oracle timeout_sec (150s)
# with headroom for the final pair of (possibly slow) execs + output, so the
# harness can never kill the loop before it prints a verdict.
DEADLINE_SEC = 110
INTERVAL_SEC = 3


def run(cmd, timeout=30):
    """Run a command bounded (O17); a hang counts as a failed attempt."""
    try:
        return subprocess.run(cmd, text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, 124, "", "timed out")


def require_body(label, cmd, expected, quiet=False):
    result = run(cmd)
    if result.returncode != 0:
        if not quiet:
            print(f"{label} request failed", file=sys.stderr)
            if result.stderr:
                print(result.stderr.strip(), file=sys.stderr)
        return False
    body = result.stdout.strip()
    if body != expected:
        if not quiet:
            print(f"{label} unexpected body: {body}", file=sys.stderr)
        return False
    return True


def main():
    # curl is bounded too (O17): a hung connect/read against a reloading
    # controller counts as a failed attempt the loop retries.
    base = [
        "kubectl",
        "-n",
        "demo",
        "exec",
        "curl-test",
        "--",
        "curl",
        "-sS",
        "--connect-timeout",
        "5",
        "--max-time",
        "15",
        "-H",
        f"Host: {HOST}",
    ]

    checks = [
        (
            "stable root",
            base + ["http://ingress-nginx-controller.ingress-nginx.svc/"],
            STABLE_BODY,
        ),
        (
            "canary root",
            base
            + [
                "-H",
                f"{HEADER_NAME}: {HEADER_VALUE}",
                "http://ingress-nginx-controller.ingress-nginx.svc/",
            ],
            CANARY_BODY,
        ),
    ]

    deadline = time.monotonic() + DEADLINE_SEC
    while True:
        # Suppress per-check diagnostics until the final attempt so a transient
        # early miss does not spam stderr; the last cycle reports real failures.
        last = time.monotonic() >= deadline
        ok = True
        for label, cmd, expected in checks:
            if not require_body(label, cmd, expected, quiet=not last):
                ok = False
        if ok:
            return 0
        if last:
            return 1
        time.sleep(INTERVAL_SEC)


if __name__ == "__main__":
    sys.exit(main())

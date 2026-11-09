#!/usr/bin/env python3
import os
import subprocess
import sys
import time


REQUEST_COUNT = 20
MIN_429 = 4
# O40: a burst through a warming / reloading controller can complete
# successfully (returncode 0) yet carry transient 502/504s from a not-yet-ready
# replica -- an exec-only retry never re-polls those, so the first transient
# gateway code hard-failed a correct setup. Re-evaluate the FULL snapshot (both
# bursts, including the /health 200-check) within ONE shared bounded window and
# pass on the first clean cycle; fail only when the wrong codes persist at the
# deadline (a *stable* wrong status). Not a loosening: a genuinely unlimited
# /api returns all-200 on every cycle and still fails at the deadline.
# O-deadline (O21): the window is SHARED across both probes, and every exec is
# bounded (BURST_TIMEOUT_SEC), so the worst case is the window plus one final
# double-burst cycle (~110 + 2x60s) -- keep the oracle command's timeout_sec
# in test.yaml above that (240s) so the harness never kills the loop before
# it prints a verdict.
PROBE_DEADLINE_SEC = 110
PROBE_INTERVAL_SEC = 3
# Per-burst exec bound (O17): 20 curls each capped at --max-time 15 could in
# the pathological case outrun the shared window; bound the exec itself and
# treat a timeout as a failed (retryable) attempt.
BURST_TIMEOUT_SEC = 60
# Param-aware: a workflow can override host/api_path/health_path via
# param_overrides; read BENCH_PARAM_* (default = the standalone value) so the
# oracle exercises the routes this stage configured on the live cluster. The
# rate-limit pass criterion (>= MIN_429 429s on api, only 200s on health) is
# unchanged.
HOST = os.environ.get("BENCH_PARAM_HOST") or "rate.example.com"
API_PATH = os.environ.get("BENCH_PARAM_API_PATH") or "/api"
HEALTH_PATH = os.environ.get("BENCH_PARAM_HEALTH_PATH") or "/health"
SERVICE_URL = "http://ingress-nginx-controller.ingress-nginx.svc"


def run(cmd, timeout=BURST_TIMEOUT_SEC):
    """Run a command bounded (O17); a hang counts as a failed attempt."""
    try:
        return subprocess.run(cmd, text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, 124, "", "timed out")


def burst(path):
    # Fire the requests as a FAST BURST (no inter-request sleep) -- excess traffic
    # relative to ANY finite limit, so the probe is workflow-agnostic. The old
    # version paced at a hardcoded ~2 rps (sleep 0.5); that only generated 429s
    # when limit_rps < 2, so a workflow overriding limit_rps=2 (the leaky bucket
    # refills exactly as fast as the probe sends) saw zero 429s and could never
    # pass -- even though rate limiting WAS correctly configured. A burst trips
    # the limit regardless of its value; an UNlimited path still returns all 200.
    # Every curl is bounded (O17); a timed-out request prints 000, which counts
    # as a wrong (retryable) code.
    loop = " ".join(str(i) for i in range(1, REQUEST_COUNT + 1))
    shell_cmd = (
        "for i in "
        + loop
        + "; do curl -s -o /dev/null --connect-timeout 5 --max-time 15"
        + " -w '%{http_code}\\n' -H 'Host: "
        + HOST
        + "' "
        + SERVICE_URL
        + path
        + "; done"
    )
    cmd = ["kubectl", "-n", "demo", "exec", "curl-test", "--", "sh", "-c", shell_cmd]
    result = run(cmd)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "burst command failed")
    codes = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    return codes


def evaluate():
    """One full snapshot: burst /api and /health; return failure strings (O28)."""
    errors = []
    try:
        api_codes = burst(API_PATH)
    except RuntimeError as exc:
        errors.append(f"API test failed: {exc}")
        api_codes = None
    try:
        health_codes = burst(HEALTH_PATH)
    except RuntimeError as exc:
        errors.append(f"Health test failed: {exc}")
        health_codes = None

    if api_codes is not None:
        api_200 = api_codes.count("200")
        # ingress-nginx returns 503 (not always 429) when a request is dropped by
        # the rate limiter, depending on controller version/config (O22). Count
        # BOTH as a rate-limited response so a correct limit that surfaces as 503
        # still passes; the /health-stays-200 + /api-still-serves-some-200 checks
        # keep the limit scoped to /api.
        api_limited = api_codes.count("429") + api_codes.count("503")
        api_other = [code for code in api_codes if code not in ("200", "429", "503")]
        if api_limited < MIN_429:
            errors.append(
                f"/api returned too few rate-limited (429/503) responses "
                f"({api_limited}/{REQUEST_COUNT}): {api_codes}"
            )
        if api_200 < 1:
            errors.append(f"/api did not return any 200 responses: {api_codes}")
        if api_other:
            errors.append(f"/api returned unexpected codes: {api_other}")

    if health_codes is not None:
        health_other = [code for code in health_codes if code != "200"]
        if health_other:
            errors.append(f"/health returned non-200 codes: {health_other}")

    return errors


def main():
    # One shared convergence window for the whole snapshot (O40/O13): pass on
    # the first cycle where both bursts are clean; fail with the last cycle's
    # accumulated errors only once the deadline has passed.
    deadline = time.monotonic() + PROBE_DEADLINE_SEC
    while True:
        last = time.monotonic() >= deadline
        errors = evaluate()
        if not errors:
            return 0
        if last:
            for error in errors:
                print(error, file=sys.stderr)
            return 1
        print(f"snapshot not converged, retrying: {errors[0]}", file=sys.stderr)
        time.sleep(PROBE_INTERVAL_SEC)


if __name__ == "__main__":
    sys.exit(main())

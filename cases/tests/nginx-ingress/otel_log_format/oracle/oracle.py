#!/usr/bin/env python3
import os
import re
import subprocess
import sys
import time

# Param-aware: a workflow can override host/path via param_overrides; read
# BENCH_PARAM_* (default = the standalone value) so the oracle generates and
# matches the access-log line for the path this stage was asked to trace on the
# live cluster. The OTel/log-format pass criterion is unchanged.
HOST = os.environ.get("BENCH_PARAM_HOST") or "otel.example.com"
PATH = os.environ.get("BENCH_PARAM_PATH") or "/otel-check"


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
    request_cmd = [
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
        f"http://ingress-nginx-controller.ingress-nginx.svc{PATH}",
    ]
    logs_cmd = [
        "kubectl",
        "-n",
        "ingress-nginx",
        "logs",
        "deploy/ingress-nginx-controller",
        "--tail=200",
    ]
    collector_cmd = [
        "kubectl",
        "-n",
        "otel",
        "logs",
        "deploy/otel-collector",
        "--since=120s",
    ]
    trace_re = re.compile(r"otel_trace_id=([0-9a-f]{32})")
    span_re = re.compile(r"otel_span_id=([0-9a-f]{16})")

    # The request must reach a real backend (non-empty response), but the exact
    # body text is NOT part of this case's criterion — it verifies the OTel log
    # FORMAT, not the upstream's payload. Standalone the echo backend returns
    # "hello"; in a workflow the persistence invariant means this stage inherits
    # whatever backend a prior stage left (e.g. "otel-echo-ok"), and the
    # precondition correctly skips redeploying it. Asserting a fixed string here
    # would falsely fail that valid inherited state. The OTel trace/span/collector
    # checks below are the unchanged, authoritative pass criterion.
    #
    # Tracing is inherently asynchronous: the ingress may not sample every
    # request, and a span only reaches the collector after an OTLP batch export
    # (several seconds behind the request). A single request + a fixed 4s sleep +
    # one collector read therefore races both sampling and export latency. So
    # drive a small burst of requests and re-check for up to ~45s, accumulating
    # every trace_id the access log emitted for PATH and passing as soon as ANY
    # of them surfaces in the collector. This does not loosen the criterion — a
    # span that never reaches the collector (mis-configured export) still fails
    # after the deadline.
    seen_traces = set()
    reached_backend = False
    request_failure = None
    deadline = time.monotonic() + 45

    while True:
        result = run(request_cmd)
        if result.returncode != 0:
            request_failure = result.stderr.strip() or "curl failed"
        elif result.stdout.strip():
            reached_backend = True

        time.sleep(2)

        logs = run(logs_cmd)
        if logs.returncode == 0:
            for line in logs.stdout.splitlines():
                if PATH not in line:
                    continue
                trace_match = trace_re.search(line)
                span_match = span_re.search(line)
                if trace_match and span_match:
                    seen_traces.add(trace_match.group(1).lower())

        if seen_traces:
            collector_logs = run(collector_cmd)
            if collector_logs.returncode == 0:
                blob = collector_logs.stdout.lower()
                if any(tid in blob for tid in seen_traces):
                    return 0

        if time.monotonic() >= deadline:
            break
        time.sleep(3)

    if not reached_backend:
        if request_failure:
            print("Failed to send request through ingress", file=sys.stderr)
            print(request_failure, file=sys.stderr)
        else:
            print("Empty response body — request did not reach a backend", file=sys.stderr)
        return 1
    if not seen_traces:
        print("Missing otel_trace_id or otel_span_id in access logs", file=sys.stderr)
        return 1

    print("Trace ID not found in otel-collector logs", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())

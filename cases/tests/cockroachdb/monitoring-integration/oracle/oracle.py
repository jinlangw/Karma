#!/usr/bin/env python3
# Verify Prometheus has an active target scraping CockroachDB metrics and the
# metrics endpoint is reachable. The metrics path (BENCH_PARAM_METRICS_PATH) and
# port (BENCH_PARAM_METRICS_PORT) come from the case params, so a workflow that
# overrides them is honored instead of a hardcoded value. Standalone (default
# params) this behaves identically.
import json
import os
import subprocess
import sys
from urllib.parse import urlparse


METRICS_PATH = os.environ.get("BENCH_PARAM_METRICS_PATH", "/_status/vars")
METRICS_PORT = os.environ.get("BENCH_PARAM_METRICS_PORT", "8080")


def run(cmd):
    return subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def fetch_metrics(host, port, path):
    """Fetch the CockroachDB metrics endpoint, scheme-adaptively.

    Standalone the cluster is `--insecure` and serves :8080 over plain HTTP. But
    in a workflow this stage can inherit a SECURE cluster (e.g. after
    certificate-rotation / generate-cert), which serves :8080 over HTTPS only and
    307-redirects a plain-HTTP request to https (whose body has no metrics). Try
    HTTPS first with -k (self-signed) and -L (follow redirects), then fall back to
    HTTP, and return whichever yields real metrics output. Workflow-agnostic.
    """
    for scheme, extra in (("https", ["-k", "-L"]), ("http", [])):
        cmd = [
            "kubectl", "-n", "cockroachdb", "exec", "curl-test", "--",
            "curl", "-fsS", "--connect-timeout", "5", "--max-time", "20",
            *extra, f"{scheme}://{host}:{port}{path}",
        ]
        result = run(cmd)
        if result.returncode == 0 and "sys_uptime" in result.stdout:
            return result, ""
    # Neither scheme produced metrics; surface the last attempt's error.
    return None, (result.stderr.strip() or "Metrics endpoint unreachable")


def parse_targets(payload):
    data = payload.get("data", {})
    return data.get("activeTargets", [])


def _crdb_pod_selector():
    """Return the live `crdb-cluster` StatefulSet's pod selector string (§3.1).

    Falls back to the canonical app.kubernetes.io/name=cockroachdb label when the
    StatefulSet can't be read, so the oracle still works against an inherited
    agent-built cluster (whose labels the deploy oracle now mandates).
    """
    sts = run(["kubectl", "-n", "cockroachdb", "get", "statefulset",
               "crdb-cluster", "-o", "json"])
    if sts.returncode == 0:
        try:
            match = (json.loads(sts.stdout).get("spec", {})
                     .get("selector", {}).get("matchLabels")) or {}
        except json.JSONDecodeError:
            match = {}
        if match:
            return ",".join(f"{k}={v}" for k, v in match.items())
    return "app.kubernetes.io/name=cockroachdb"


def load_pod_ips():
    cmd = [
        "kubectl",
        "-n",
        "cockroachdb",
        "get",
        "pods",
        "-l",
        _crdb_pod_selector(),
        "-o",
        "json",
    ]
    result = run(cmd)
    if result.returncode != 0:
        return None, result.stderr.strip()
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None, "Failed to parse pod list"
    ips = []
    for item in data.get("items", []):
        ip = item.get("status", {}).get("podIP")
        if ip:
            ips.append(ip)
    # Last resort: select by the StatefulSet's stable pod-name prefix.
    if not ips:
        res = run(["kubectl", "-n", "cockroachdb", "get", "pods", "-o", "json"])
        if res.returncode == 0:
            try:
                items = json.loads(res.stdout).get("items", [])
            except json.JSONDecodeError:
                items = []
            for item in items:
                name = item.get("metadata", {}).get("name", "")
                ip = item.get("status", {}).get("podIP")
                if name.startswith("crdb-cluster-") and ip:
                    ips.append(ip)
    return ips, ""


def evaluate():
    """One full snapshot of the targets + metrics checks; returns error list (O28)."""
    errors = []

    pod_ips, pod_err = load_pod_ips()
    if pod_ips is None:
        errors.append(pod_err or "Failed to load pod IPs")
        pod_ips = []

    cmd = [
        "kubectl",
        "-n",
        "cockroachdb",
        "exec",
        "curl-test",
        "--",
        "curl",
        "-fsS",
        "--connect-timeout",
        "5",
        "--max-time",
        "20",
        "http://prometheus.monitoring.svc:9090/api/v1/targets",
    ]
    result = run(cmd)
    if result.returncode != 0:
        errors.append(f"Failed to query Prometheus targets: {result.stderr.strip()}")
    else:
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            errors.append("Failed to parse Prometheus targets")
            payload = {}

        targets = parse_targets(payload)
        target_ok = False
        for target in targets:
            if target.get("health") != "up":
                continue
            scrape_url = target.get("scrapeUrl", "")
            parsed = urlparse(scrape_url)
            if parsed.path != METRICS_PATH:
                continue
            if str(parsed.port) != str(METRICS_PORT):
                continue
            if parsed.hostname in pod_ips:
                target_ok = True
                break

        if not target_ok:
            errors.append(
                f"No active Prometheus target scraping {METRICS_PATH} on port {METRICS_PORT}"
            )

    result, fetch_err = fetch_metrics("crdb-cluster-public", METRICS_PORT, METRICS_PATH)
    if result is None:
        errors.append(f"Metrics endpoint unreachable: {fetch_err}")
    elif "sys_uptime" not in result.stdout:
        errors.append("Metrics output missing sys_uptime")

    return errors


def main():
    # Prometheus discovers and health-marks a just-configured scrape target
    # ASYNCHRONOUSLY (its scrape interval + config reload lag), so a single-shot
    # targets query can see the agent's correct config with the target not yet
    # "up" -- an O23/O13 false fail. Re-evaluate the targets + metrics checks
    # for up to ~90s and pass on the first clean snapshot; a target that never
    # comes up keeps failing after the deadline. The loop fits under the raised
    # oracle timeout_sec (O21).
    import time
    deadline = time.monotonic() + 90
    errors = evaluate()
    while errors and time.monotonic() < deadline:
        time.sleep(8)
        errors = evaluate()

    if errors:
        print("Monitoring integration verification failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print("Monitoring integration configured successfully")
    return 0


if __name__ == "__main__":
    sys.exit(main())

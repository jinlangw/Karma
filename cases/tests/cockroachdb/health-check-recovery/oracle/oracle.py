#!/usr/bin/env python3
import json
import os
import subprocess
import sys


def run(cmd):
    return subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def crdb_pods():
    """Return the cluster's pods, robust to how the cluster was labelled (§3.1).

    Resolve by the live `crdb-cluster` StatefulSet's own selector first; fall
    back to the canonical app.kubernetes.io/name=cockroachdb label, then to the
    crdb-cluster-* pod-name prefix. This makes a downstream oracle survive a
    workflow whose earlier (agent-built) deploy stage chose different labels.
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
            sel = ",".join(f"{k}={v}" for k, v in match.items())
            res = run(["kubectl", "-n", "cockroachdb", "get", "pods",
                       "-l", sel, "-o", "json"])
            if res.returncode == 0:
                try:
                    items = json.loads(res.stdout).get("items", [])
                except json.JSONDecodeError:
                    items = []
                if items:
                    return items
    res = run(["kubectl", "-n", "cockroachdb", "get", "pods",
               "-l", "app.kubernetes.io/name=cockroachdb", "-o", "json"])
    if res.returncode == 0:
        try:
            items = json.loads(res.stdout).get("items", [])
        except json.JSONDecodeError:
            items = []
        if items:
            return items
    res = run(["kubectl", "-n", "cockroachdb", "get", "pods", "-o", "json"])
    if res.returncode != 0:
        return []
    try:
        items = json.loads(res.stdout).get("items", [])
    except json.JSONDecodeError:
        return []
    return [p for p in items
            if p.get("metadata", {}).get("name", "").startswith("crdb-cluster-")]


_EXPECTED_NODES = None


def expected_nodes():
    """Resolve how many live nodes the cluster should have.

    This stage RECOVERS an inherited cluster; it does not change topology, so the
    expected count adapts to whatever was inherited: an explicit param override
    (BENCH_PARAM_EXPECTED_NODES / _REPLICA_COUNT) wins, else the live
    StatefulSet's DESIRED size (spec.replicas), else the old hardcoded 3. Using
    the desired size (not readyReplicas) keeps the check honest — if a node fails
    to recover, live_nodes < spec.replicas still fails. Cached.
    """
    global _EXPECTED_NODES
    if _EXPECTED_NODES is not None:
        return _EXPECTED_NODES
    override = (
        os.environ.get("BENCH_PARAM_EXPECTED_NODES")
        or os.environ.get("BENCH_PARAM_REPLICA_COUNT")
    )
    if override and override.strip().isdigit():
        _EXPECTED_NODES = int(override)
        return _EXPECTED_NODES
    result = run([
        "kubectl", "-n", "cockroachdb", "get", "statefulset", "crdb-cluster",
        "-o", "jsonpath={.spec.replicas}",
    ])
    if result.returncode == 0 and result.stdout.strip().isdigit():
        live = int(result.stdout.strip())
        if live > 0:
            _EXPECTED_NODES = live
            return _EXPECTED_NODES
    _EXPECTED_NODES = 3
    return _EXPECTED_NODES


_CONN_FLAG = None


def conn_flag():
    """Return the right cockroach SQL connection flag for the live cluster.

    Standalone this case runs against an INSECURE cluster (`--insecure`). But in
    a workflow this stage can inherit a SECURE cluster left running by a prior
    stage (e.g. certificate-rotation), whose precondition probe sees pods already
    Running and skips its own insecure redeploy. A hardcoded `--insecure` then
    fails with an SSL authentication error. Detect the mode once by checking for
    the mounted certs dir and connect accordingly so the same oracle works in
    both contexts. Mirrors cockroachdb/cluster-settings/oracle/oracle.py.
    """
    global _CONN_FLAG
    if _CONN_FLAG is not None:
        return _CONN_FLAG
    probe = run([
        "kubectl", "-n", "cockroachdb", "--request-timeout=15s", "exec",
        "crdb-cluster-0", "--", "ls", "/cockroach/cockroach-certs/ca.crt",
    ])
    if probe.returncode == 0:
        _CONN_FLAG = "--certs-dir=/cockroach/cockroach-certs"
    else:
        _CONN_FLAG = "--insecure"
    return _CONN_FLAG


def parse_tsv(output):
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if not lines:
        return [], []
    header = lines[0].split("\t")
    rows = [line.split("\t") for line in lines[1:]]
    return header, rows


def to_bool(value):
    return str(value).strip().lower() in ("true", "t", "1", "yes")


def evaluate():
    """One full snapshot of the health-check-recovery checks; returns error list."""
    errors = []

    # Check all pods are present, Running AND Ready (resolved robustly to the
    # build's labels). This case's planted fault breaks pod-1's HTTP health
    # listener (--http-addr=127.0.0.1), i.e. the readiness path itself -- so
    # per O39 the oracle MUST grade the faulted signal directly: with the
    # fault in place pod-1's Ready condition can never stabilize True, while
    # phase stays Running and gRPC is_live + SQL keep working (an idle agent
    # used to pass). O15's "don't gate on pod-Ready" exemption does not apply
    # when the fault IS the health path; the convergence loop below absorbs
    # the legitimate post-recovery Ready lag.
    try:
        for pod in crdb_pods():
            name = pod["metadata"]["name"]
            phase = pod["status"].get("phase", "Unknown")
            if phase != "Running":
                errors.append(f"Pod {name} is not Running (phase: {phase})")
            conditions = pod["status"].get("conditions") or []
            ready = any(c.get("type") == "Ready" and c.get("status") == "True"
                        for c in conditions)
            if not ready:
                errors.append(f"Pod {name} is not Ready (health endpoint not serving)")
    except (KeyError, TypeError):
        errors.append("Failed to parse pod status")

    # Check all nodes are live
    cmd = [
        "kubectl",
        "-n",
        "cockroachdb",
        "exec",
        "crdb-cluster-0",
        "--",
        "./cockroach",
        "node",
        "status",
        conn_flag(),
        "--format=tsv",
    ]
    result = run(cmd)
    if result.returncode != 0:
        errors.append(result.stderr.strip() or "Failed to read node status")
    else:
        header, rows = parse_tsv(result.stdout)
        if not header:
            errors.append("Empty node status output")
        else:
            cols = {name: idx for idx, name in enumerate(header)}
            live_idx = cols.get("is_live")
            if live_idx is None:
                errors.append("Missing is_live column in node status output")
            else:
                live_nodes = 0
                for row in rows:
                    if len(row) <= live_idx:
                        continue
                    if to_bool(row[live_idx]):
                        live_nodes += 1
                if live_nodes != expected_nodes():
                    errors.append(f"Expected {expected_nodes()} live nodes, found {live_nodes}")

    # Verify SQL readiness
    cmd = [
        "kubectl",
        "-n",
        "cockroachdb",
        "exec",
        "crdb-cluster-0",
        "--",
        "./cockroach",
        "sql",
        conn_flag(),
        "-e",
        "SELECT 1;",
    ]
    result = run(cmd)
    if result.returncode != 0:
        errors.append(result.stderr.strip() or "SQL query failed")

    return errors


def main():
    # Health recovery restarts nodes one at a time; a just-restarted node takes a
    # short while to become Ready and report is_live again. A single snapshot can
    # race that convergence and see e.g. "2 live nodes" on a cluster healthily
    # finishing recovery (the same case passes at the prior stages). Re-evaluate
    # for up to ~150s and pass on the first clean snapshot (sized generously
    # because the Ready condition -- now graded directly per O39 -- lags
    # functional recovery under load, O15). This does not loosen the check --
    # with the fault unfixed pod-1 never turns Ready, so the oracle still
    # fails after the deadline. The 150s deadline fits the 240s oracle budget
    # with headroom (O21).
    import time
    deadline = time.monotonic() + 150
    errors = evaluate()
    while errors and time.monotonic() < deadline:
        time.sleep(7)
        errors = evaluate()

    if errors:
        print("Health check recovery verification failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print("All pods recovered and healthy")
    return 0


if __name__ == "__main__":
    sys.exit(main())

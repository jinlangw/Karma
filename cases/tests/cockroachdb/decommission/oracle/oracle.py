#!/usr/bin/env python3
# Verify the cluster was safely decommissioned to 3 nodes with the seeded data
# preserved. The seeded table name comes from the case param
# (BENCH_PARAM_SEED_TABLE_NAME), so a workflow that overrides it is honored
# instead of a hardcoded value. Standalone (default param) this behaves
# identically.
import json
import os
import subprocess
import sys


NAMESPACE = "cockroachdb"
POD = "crdb-cluster-0"
SQL_HOST = "crdb-cluster-0.crdb-cluster.cockroachdb.svc.cluster.local"
SEED_TABLE = os.environ.get("BENCH_PARAM_SEED_TABLE_NAME", "bench.decom_data")

# Final node count the cluster must be decommissioned down to. This is the TASK
# OUTCOME (the agent reduces a 5-node cluster to this many), so it must NOT be
# read from the live cluster — that would make the count check vacuous. It comes
# from an explicit param override (a workflow that seeds/targets a different size
# is honored) and otherwise defaults to the old hardcoded 3. Standalone this
# behaves identically.
TARGET_NODES = int(
    os.environ.get("BENCH_PARAM_TARGET_NODES")
    or os.environ.get("BENCH_PARAM_EXPECTED_NODES")
    or "3"
)
# The pods expected to be removed are every ordinal at/above the target. With a
# 5-node start and target 3 this is crdb-cluster-{3,4}, matching the old check;
# a larger source (param override) extends the set generically.
SOURCE_NODES = int(
    os.environ.get("BENCH_PARAM_SOURCE_NODES")
    or os.environ.get("BENCH_PARAM_SEED_NODE_COUNT")
    or "5"
)
TARGET_PODS = [f"crdb-cluster-{i}" for i in range(TARGET_NODES, SOURCE_NODES)]


def run(cmd):
    return subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


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
        "kubectl", "-n", NAMESPACE, "--request-timeout=15s", "exec", POD, "--",
        "ls", "/cockroach/cockroach-certs/ca.crt",
    ])
    if probe.returncode == 0:
        _CONN_FLAG = "--certs-dir=/cockroach/cockroach-certs"
    else:
        _CONN_FLAG = "--insecure"
    return _CONN_FLAG


def exec_sql(sql, fmt=None):
    cmd = [
        "kubectl",
        "-n",
        NAMESPACE,
        "exec",
        POD,
        "--",
        "./cockroach",
        "sql",
        conn_flag(),
        f"--host={SQL_HOST}",
    ]
    if fmt:
        cmd.append(f"--format={fmt}")
    cmd += ["-e", sql]
    return run(cmd)


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
    """One full snapshot of the decommission checks; returns error list."""
    errors = []

    cmd = ["kubectl", "-n", NAMESPACE, "get", "statefulset", "crdb-cluster", "-o", "json"]
    result = run(cmd)
    if result.returncode == 0:
        try:
            sts = json.loads(result.stdout)
            replicas = sts.get("spec", {}).get("replicas", 0)
            if replicas != TARGET_NODES:
                errors.append(f"StatefulSet should have {TARGET_NODES} replicas, got {replicas}")
            # We do NOT gate on status.readyReplicas (the k8s pod-Ready tally):
            # after a decommission a surviving node restarting can lag its
            # readiness probe while already serving SQL (O-funcready). The
            # functional signal -- TARGET_NODES nodes is_live and serving, the
            # data query below -- is graded directly, so a readyReplicas gate
            # would only add a laggy false-fail without strengthening anything.
        except json.JSONDecodeError:
            errors.append("Failed to parse StatefulSet JSON")
    else:
        errors.append(result.stderr.strip() or "Failed to get StatefulSet")

    cmd = [
        "kubectl",
        "-n",
        NAMESPACE,
        "exec",
        POD,
        "--",
        "./cockroach",
        "node",
        "status",
        conn_flag(),
        "--decommission",
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
            addr_idx = cols.get("address")
            live_idx = cols.get("is_live")
            membership_idx = cols.get("membership")
            decom_idx = cols.get("is_decommissioned")
            decom_ing_idx = cols.get("is_decommissioning")
            if addr_idx is None or live_idx is None or (
                membership_idx is None and decom_idx is None and decom_ing_idx is None
            ):
                errors.append(
                    "Missing expected columns in node status output "
                    "(need address, is_live, and one of membership, is_decommissioned, "
                    "is_decommissioning)"
                )
            else:
                live_active = 0
                target_states = {}
                for row in rows:
                    max_idx = max(
                        addr_idx,
                        live_idx,
                        membership_idx if membership_idx is not None else -1,
                        decom_idx if decom_idx is not None else -1,
                        decom_ing_idx if decom_ing_idx is not None else -1,
                    )
                    if len(row) <= max_idx:
                        continue
                    address = row[addr_idx]
                    is_live = to_bool(row[live_idx])
                    if membership_idx is not None:
                        membership = row[membership_idx].strip().lower()
                        is_decommissioned = membership == "decommissioned"
                    elif decom_idx is not None:
                        is_decommissioned = to_bool(row[decom_idx])
                    else:
                        is_decommissioned = to_bool(row[decom_ing_idx])
                    if is_live and not is_decommissioned:
                        live_active += 1
                    for pod in TARGET_PODS:
                        if pod in address:
                            target_states[pod] = is_decommissioned
                if live_active != TARGET_NODES:
                    errors.append(f"Expected {TARGET_NODES} live nodes, found {live_active}")
                for pod in TARGET_PODS:
                    if pod not in target_states:
                        errors.append(f"Missing node status for {pod}")
                    elif not target_states[pod]:
                        errors.append(f"{pod} is not decommissioned")

    result = exec_sql(f"SELECT count(*) FROM {SEED_TABLE};", fmt="tsv")
    if result.returncode != 0:
        errors.append(result.stderr.strip() or f"Failed to query {SEED_TABLE}")
    else:
        header, rows = parse_tsv(result.stdout)
        if not rows:
            errors.append("No rows returned for data check")
        else:
            try:
                count = int(rows[0][0])
                if count < 3:
                    errors.append(f"Expected at least 3 rows, got {count}")
            except ValueError:
                errors.append("Failed to parse row count")

    return errors


def main():
    # Decommission removes nodes and reshuffles replicas; the StatefulSet's
    # readyReplicas and the removed nodes' membership (is_decommissioning ->
    # decommissioned) settle a beat after the operation reports done, and a
    # surviving node briefly restarting during the scale-down can dip is_live. A
    # single snapshot can race that convergence on a cluster healthily finishing
    # its decommission (the same case passes at the prior stages). Every assertion
    # here already encodes the POST-decommission expectation -- the reduced
    # TARGET_NODES live count and each removed node confirmed decommissioned -- so
    # re-evaluating only waits for that asserted state to settle; it never flips
    # an assertion. A node that genuinely fails to decommission never reports
    # decommissioned, and a lost survivor never returns to live, so the oracle
    # still fails after the deadline.
    import time
    deadline = time.monotonic() + 70
    errors = evaluate()
    while errors and time.monotonic() < deadline:
        time.sleep(7)
        errors = evaluate()

    if errors:
        print("Decommission verification failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print("Decommission verification passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

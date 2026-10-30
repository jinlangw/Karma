#!/usr/bin/env python3
"""Oracle for spark/spark_multi_tenant.

Verifies the multi-tenant Spark environment is healthy after the agent's fixes:
  - both tenant SparkPi jobs (spark-pi-team-a, spark-pi-team-b) completed and
    report a Pi value near 3.14,
  - the Team A RoleBinding subject namespace was corrected to "spark-team-a",
  - the History Server deployment references the real PVC "spark-history-pvc",
    reads its event logs from the correct log directory, and is running.
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

COMMON = Path(__file__).resolve().parents[2] / "common"
sys.path.insert(0, str(COMMON))

from oracle_lib import (  # noqa: E402
    bench_ns,
    deployment_env,
    deployment_pvc_claim,
    deployment_ready_replicas,
    job_logs,
    job_succeeded,
    kubectl_json,
)

DEPLOYMENT_NAME = os.environ.get("BENCH_PARAM_DEPLOYMENT_NAME", "spark-history-server")
PVC_NAME = os.environ.get("BENCH_PARAM_PVC_NAME", "spark-history-pvc")
LOG_DIR = os.environ.get("BENCH_PARAM_LOG_DIR", "/mnt/spark-logs")

TEAM_A_NS = bench_ns("spark_team_a", "spark-team-a")
TEAM_B_NS = bench_ns("spark_team_b", "spark-team-b")
HISTORY_NS = bench_ns("spark_history", "spark-history")

TENANTS = (
    (TEAM_A_NS, "spark-pi-team-a"),
    (TEAM_B_NS, "spark-pi-team-b"),
)


def fail(message: str) -> int:
    print(f"spark_multi_tenant oracle failed: {message}")
    return 1


def check_tenant_jobs() -> int:
    for namespace, job_name in TENANTS:
        if not job_succeeded(namespace, job_name):
            return fail(f"job/{job_name} did not complete successfully in {namespace}")
        logs = job_logs(namespace, job_name)
        match = re.search(r"Pi is roughly ([0-9.]+)", logs)
        if not match:
            return fail(f"job/{job_name} logs do not contain a Pi result in {namespace}")
        try:
            pi_value = float(match.group(1))
        except ValueError:
            return fail(f"job/{job_name} emitted an unparsable Pi result in {namespace}")
        if not 3.0 <= pi_value <= 3.3:
            return fail(f"job/{job_name} Pi value {pi_value} is outside expected range in {namespace}")
    return 0


def check_team_a_rolebinding() -> int:
    binding = kubectl_json(TEAM_A_NS, ["get", "rolebinding", "spark-role-binding"])
    subjects = binding.get("subjects", []) or []
    if not subjects:
        return fail("rolebinding/spark-role-binding has no subjects in spark-team-a")
    # O-multi: a RoleBinding's `subjects` is a list that can legitimately hold
    # more than one entry (a valid fix may add/reorder subjects). The contract is
    # that the Team A spark ServiceAccount is bound IN spark-team-a, so assert the
    # required namespace is PRESENT AMONG the ServiceAccount subjects, not that it
    # equals subjects[0] (which would false-fail a correct multi-subject binding).
    sa_namespaces = [
        str(s.get("namespace") or "")
        for s in subjects
        if str(s.get("kind") or "") == "ServiceAccount"
    ]
    if TEAM_A_NS not in sa_namespaces:
        return fail(
            "rolebinding/spark-role-binding has no ServiceAccount subject in "
            f"namespace {TEAM_A_NS!r} (subject namespaces={sa_namespaces!r})"
        )
    return 0


def check_history_server() -> int:
    claim = deployment_pvc_claim(HISTORY_NS, DEPLOYMENT_NAME, "spark-logs")
    if claim != PVC_NAME:
        return fail(
            f"deployment/{DEPLOYMENT_NAME} spark-logs claimName={claim!r}, expected {PVC_NAME!r}"
        )

    history_opts = deployment_env(HISTORY_NS, DEPLOYMENT_NAME, "SPARK_HISTORY_OPTS")
    if f"spark.history.fs.logDirectory={LOG_DIR}" not in history_opts:
        return fail(
            f"deployment/{DEPLOYMENT_NAME} log directory is not set to {LOG_DIR!r} (got {history_opts!r})"
        )

    ready = deployment_ready_replicas(HISTORY_NS, DEPLOYMENT_NAME)
    if ready < 1:
        return fail(f"deployment/{DEPLOYMENT_NAME} readyReplicas={ready}, expected >= 1")
    return 0


def main() -> int:
    for check in (check_tenant_jobs, check_team_a_rolebinding, check_history_server):
        rc = check()
        if rc != 0:
            return rc
    print("spark_multi_tenant verified: tenant jobs completed, RBAC and History Server fixed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

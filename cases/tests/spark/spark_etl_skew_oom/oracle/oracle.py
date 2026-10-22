#!/usr/bin/env python3
"""Oracle for spark/spark_etl_skew_oom.

Verifies the data-skew OOM in Stage 3 was diagnosed and remediated:
  - the etl-job Job completed successfully, and
  - at least one valid fix is in place: executor memory was raised above the
    failing 256m baseline, the worker deployment was scaled out / given more
    memory, or Adaptive Query Execution (skew handling) was enabled on the job.
"""
from __future__ import annotations

import sys
from pathlib import Path

from cases.common.spark.oracle_lib import (  # noqa: E402
    bench_namespace,
    deployment_env,
    deployment_spec_replicas,
    job,
    job_logs,
    job_succeeded,
)

NAMESPACE = bench_namespace("spark-etl")
JOB_NAME = "etl-job"
WORKER_DEPLOYMENT = "spark-worker"


def fail(message: str) -> int:
    print(f"spark_etl_skew_oom oracle failed: {message}")
    return 1


def job_command_text() -> str:
    payload = job(NAMESPACE, JOB_NAME)
    containers = payload.get("spec", {}).get("template", {}).get("spec", {}).get("containers", []) or []
    if not containers:
        return ""
    return " ".join(str(part) for part in (containers[0].get("command") or []))


def fix_applied() -> bool:
    """True if any of the documented remediations is detectable in cluster state.

    Law 5 guard: none of these branches may match the SHIPPED broken baseline
    (etl-job.yaml carries `--driver-memory 256m` + `spark.executor.memory=256m`
    and no AQE flags), so an untouched cluster can never count as remediated.
    """
    command = job_command_text().lower()

    # Primary fix: the failing 256m memory settings are gone from the job
    # command — raised (e.g. 1g) or removed entirely (spark's defaults are
    # ~1g). O22: accept every equivalent valid form; either one unblocks the
    # job. The shipped baseline carries these markers, so this is False
    # pre-agent.
    mem_fault_markers = (
        "spark.executor.memory=256m",
        "--executor-memory 256m",
        "spark.driver.memory=256m",
        "--driver-memory 256m",
    )
    if not any(marker in command for marker in mem_fault_markers):
        return True

    # Also acceptable alongside: AQE / skew-join handling enabled on the job.
    if "spark.sql.adaptive.enabled=true" in command or "skewjoin.enabled=true" in command:
        return True

    # Option A: workers scaled out and/or given more memory.
    try:
        if deployment_spec_replicas(NAMESPACE, WORKER_DEPLOYMENT) > 1:
            return True
        worker_memory = deployment_env(NAMESPACE, WORKER_DEPLOYMENT, "SPARK_WORKER_MEMORY")
        if worker_memory and worker_memory not in ("1G", "1g"):
            return True
    except Exception:
        pass
    return False


def main() -> int:
    if not job_succeeded(NAMESPACE, JOB_NAME):
        return fail(f"job/{JOB_NAME} did not complete successfully")

    logs = job_logs(NAMESPACE, JOB_NAME)
    if "spark_etl_pipeline_verified" not in logs:
        return fail(f"job/{JOB_NAME} logs do not confirm pipeline completion")

    if not fix_applied():
        return fail(
            "no remediation detected (expected raised executor memory, scaled/upsized "
            "workers, or enabled AQE skew handling)"
        )

    print("spark_etl_skew_oom verified: Stage 3 OOM remediated and ETL job completed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Oracle for spark/spark_data_skew.

Verifies the data-skew benchmark was fixed and at least one optimization ran:
  - the baseline job (spark-skew-baseline) completed successfully after the
    planted configuration bug was fixed, and
  - at least one optimization strategy job (broadcast or AQE) was applied and
    also completed successfully.
"""
from __future__ import annotations

import sys
from pathlib import Path

from cases.common.spark.oracle_lib import bench_namespace, run  # noqa: E402

NAMESPACE = bench_namespace("spark-skew")
BASELINE_JOB = "spark-skew-baseline"
OPTIMIZATION_JOBS = ("spark-skew-broadcast", "spark-skew-aqe")


def fail(message: str) -> int:
    print(f"spark_data_skew oracle failed: {message}")
    return 1


def job_exists(name: str) -> bool:
    proc = run(["kubectl", "-n", NAMESPACE, "get", "job", name], check=False)
    return proc.returncode == 0


def job_completed(name: str) -> bool:
    """True when the Job reports >= 1 succeeded completion."""
    proc = run(
        ["kubectl", "-n", NAMESPACE, "get", "job", name, "-o", "jsonpath={.status.succeeded}"],
        check=False,
    )
    if proc.returncode != 0:
        return False
    raw = (proc.stdout or "").strip()
    try:
        return int(raw or "0") >= 1
    except ValueError:
        return False


def main() -> int:
    if not job_exists(BASELINE_JOB):
        return fail(f"baseline job/{BASELINE_JOB} does not exist")
    if not job_completed(BASELINE_JOB):
        return fail(f"baseline job/{BASELINE_JOB} did not complete successfully")

    applied = [name for name in OPTIMIZATION_JOBS if job_exists(name)]
    if not applied:
        return fail("no optimization strategy applied (expected broadcast or aqe job)")

    completed = [name for name in applied if job_completed(name)]
    if not completed:
        return fail(
            f"optimization job(s) {applied} applied but none completed successfully"
        )

    print(
        f"spark_data_skew verified: baseline + {', '.join(completed)} completed successfully"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

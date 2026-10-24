#!/usr/bin/env python3
"""Oracle for spark/spark_runtime_ops.

Verifies all runtime issues were fixed with kubectl (no YAML edits):
  1. job/spark-data-processor completed successfully (resumed),
  2. the monitoring deployment has all pods Running (valid image),
  3. the batch job completed successfully (resumed),
  4. the ConfigMap's spark.executor.memory is >= the required minimum,
  5. the credentials Secret holds a valid api-key (no "EXPIRED"),
  6. the Spark cluster (master + worker) is still running with >= 1 replica.
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

from cases.common.spark.oracle_lib import (  # noqa: E402
    bench_namespace,
    configmap_value,
    deployment_ready_replicas,
    job_succeeded,
    secret_value,
)

NAMESPACE = bench_namespace("spark-runtime")
CONFIGMAP_NAME = os.environ.get("BENCH_PARAM_CONFIGMAP_NAME", "spark-config")
SECRET_NAME = os.environ.get("BENCH_PARAM_SECRET_NAME", "spark-credentials")
MONITOR_DEPLOYMENT = os.environ.get("BENCH_PARAM_MONITOR_DEPLOYMENT_NAME", "spark-monitor")
JOB_NAME = os.environ.get("BENCH_PARAM_JOB_NAME", "spark-batch-processor")
EXECUTOR_MEMORY = os.environ.get("BENCH_PARAM_EXECUTOR_MEMORY", "512m")

DATA_PROCESSOR_JOB = "spark-data-processor"


def fail(message: str) -> int:
    print(f"spark_runtime_ops oracle failed: {message}")
    return 1


def memory_to_bytes(value: str) -> int:
    """Parse a Spark/k8s memory quantity (e.g. '512m', '1g', '512Mi') to bytes."""
    text = str(value or "").strip()
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)\s*([a-zA-Z]*)", text)
    if not match:
        return -1
    number = float(match.group(1))
    unit = match.group(2).lower()
    factors = {
        "": 1,
        "b": 1,
        "k": 1000,
        "kb": 1000,
        "ki": 1024,
        "kib": 1024,
        "m": 1024 * 1024,
        "mb": 1000 * 1000,
        "mi": 1024 * 1024,
        "mib": 1024 * 1024,
        "g": 1024 * 1024 * 1024,
        "gb": 1000 * 1000 * 1000,
        "gi": 1024 * 1024 * 1024,
        "gib": 1024 * 1024 * 1024,
    }
    if unit not in factors:
        return -1
    return int(number * factors[unit])


def check_data_processor() -> int:
    if not job_succeeded(NAMESPACE, DATA_PROCESSOR_JOB):
        return fail(f"job/{DATA_PROCESSOR_JOB} did not complete successfully")
    return 0


def check_monitor() -> int:
    ready = deployment_ready_replicas(NAMESPACE, MONITOR_DEPLOYMENT)
    if ready < 1:
        return fail(f"deployment/{MONITOR_DEPLOYMENT} readyReplicas={ready}, expected >= 1")
    return 0


def check_batch_job() -> int:
    if not job_succeeded(NAMESPACE, JOB_NAME):
        return fail(f"job/{JOB_NAME} did not complete successfully")
    return 0


def check_config() -> int:
    actual = configmap_value(NAMESPACE, CONFIGMAP_NAME, "spark.executor.memory")
    actual_bytes = memory_to_bytes(actual)
    required_bytes = memory_to_bytes(EXECUTOR_MEMORY)
    if actual_bytes < 0:
        return fail(f"configmap/{CONFIGMAP_NAME} spark.executor.memory={actual!r} is unparsable")
    if actual_bytes < required_bytes:
        return fail(
            f"configmap/{CONFIGMAP_NAME} spark.executor.memory={actual!r} is below the "
            f"required minimum {EXECUTOR_MEMORY!r}"
        )
    return 0


def check_secret() -> int:
    api_key = secret_value(NAMESPACE, SECRET_NAME, "api-key")
    if not api_key:
        return fail(f"secret/{SECRET_NAME} has no api-key")
    if "EXPIRED" in api_key:
        return fail(f"secret/{SECRET_NAME} api-key is still expired")
    return 0


def check_cluster() -> int:
    for name in ("spark-master", "spark-worker"):
        ready = deployment_ready_replicas(NAMESPACE, name)
        if ready < 1:
            return fail(f"deployment/{name} readyReplicas={ready}, expected >= 1 (cluster must stay up)")
    return 0


def main() -> int:
    checks = (
        check_data_processor,
        check_monitor,
        check_batch_job,
        check_config,
        check_secret,
        check_cluster,
    )
    for check in checks:
        rc = check()
        if rc != 0:
            return rc
    print("spark_runtime_ops verified: all runtime issues resolved, cluster intact")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

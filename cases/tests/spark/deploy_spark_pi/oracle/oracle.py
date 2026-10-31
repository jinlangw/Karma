#!/usr/bin/env python3
"""Oracle for spark/deploy_spark_pi.

Verifies the four planted bugs are fixed and the SparkPi Job completed:
  1. image no longer carries the "-nonexistent" suffix,
  2. serviceAccountName is "spark-pi" (not "spark-nonexistent"),
  3. the Job container requests a valid memory format (e.g. "512Mi"),
  4. the spark-pi-role Role grants the "pods" resource,
and the Job succeeded with a Pi value near 3.14 in its logs.
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

from cases.common.spark.oracle_lib import (  # noqa: E402
    bench_namespace,
    job,
    job_logs,
    job_succeeded,
    kubectl_json,
)

NAMESPACE = bench_namespace("spark-pi")
JOB_NAME = "spark-pi"
ROLE_NAME = "spark-pi-role"
EXPECTED_SERVICE_ACCOUNT = "spark-pi"
EXPECTED_IMAGE = os.environ.get("BENCH_PARAM_SPARK_IMAGE", "apache/spark:3.5.3")


def fail(message: str) -> int:
    print(f"deploy_spark_pi oracle failed: {message}")
    return 1


def check_job_spec() -> int:
    payload = job(NAMESPACE, JOB_NAME)
    spec = payload.get("spec", {}).get("template", {}).get("spec", {}) or {}

    service_account = str(spec.get("serviceAccountName") or "")
    if service_account != EXPECTED_SERVICE_ACCOUNT:
        return fail(
            f"job/{JOB_NAME} serviceAccountName={service_account!r}, expected {EXPECTED_SERVICE_ACCOUNT!r}"
        )

    containers = spec.get("containers", []) or []
    if not containers:
        return fail(f"job/{JOB_NAME} has no containers")
    image = str(containers[0].get("image") or "")
    if "-nonexistent" in image or image != EXPECTED_IMAGE:
        return fail(f"job/{JOB_NAME} image={image!r}, expected {EXPECTED_IMAGE!r}")

    requests = (containers[0].get("resources", {}) or {}).get("requests", {}) or {}
    memory = str(requests.get("memory") or "")
    if memory and not re.search(r"[0-9]+(Mi|Gi|M|G|Ki)$", memory):
        return fail(f"job/{JOB_NAME} memory request {memory!r} is not a valid quantity")
    return 0


def check_role_pods() -> int:
    role = kubectl_json(NAMESPACE, ["get", "role", ROLE_NAME])
    for rule in role.get("rules", []) or []:
        if "pods" in (rule.get("resources") or []):
            return 0
    return fail(f"role/{ROLE_NAME} does not grant the 'pods' resource")


def check_job_status() -> int:
    if not job_succeeded(NAMESPACE, JOB_NAME):
        return fail(f"job/{JOB_NAME} did not complete successfully")
    return 0


def check_logs() -> int:
    logs = job_logs(NAMESPACE, JOB_NAME)
    match = re.search(r"Pi is roughly ([0-9.]+)", logs)
    if not match:
        return fail(f"job/{JOB_NAME} logs do not contain a Pi result")
    try:
        pi_value = float(match.group(1))
    except ValueError:
        return fail(f"job/{JOB_NAME} emitted an unparsable Pi result")
    if not 3.0 <= pi_value <= 3.3:
        return fail(f"job/{JOB_NAME} Pi value {pi_value} is outside expected range")
    return 0


def main() -> int:
    for check in (check_job_spec, check_role_pods, check_job_status, check_logs):
        rc = check()
        if rc != 0:
            return rc
    print(f"deploy_spark_pi verified: job/{JOB_NAME} fixed and completed successfully")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

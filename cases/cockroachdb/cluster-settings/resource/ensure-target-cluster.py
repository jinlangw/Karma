#!/usr/bin/env python3
"""Reuse a queryable target, or recover/create only that CockroachDB cluster."""
import os
from pathlib import Path
import subprocess
import sys
import time


NAMESPACE = os.environ["BENCH_NAMESPACE"]
CLUSTER_NAME = os.environ["BENCH_PARAM_CLUSTER_NAME"]
POD = f"{CLUSTER_NAME}-0"
HOST = f"{POD}.{CLUSTER_NAME}.{NAMESPACE}.svc.cluster.local"
LABEL = f"app.kubernetes.io/name=cockroachdb,app.kubernetes.io/instance={CLUSTER_NAME}"
RESOURCES = Path(__file__).resolve().parent


def kubectl(*args, timeout=30, input_text=None):
    command = ["kubectl", "-n", NAMESPACE, f"--request-timeout={max(1, int(timeout))}s", *args]
    try:
        return subprocess.run(
            command, input=input_text, capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(command, 124, "", f"timed out after {timeout}s")


def require(result):
    if result.stdout:
        print(result.stdout, end="", flush=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "kubectl command failed")


def cluster_exists():
    return kubectl("get", "statefulset", CLUSTER_NAME, timeout=10).returncode == 0


def sql_ready(deadline):
    for flag in ("--certs-dir=/cockroach/cockroach-certs", "--insecure"):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        result = kubectl(
            "exec", POD, "--", "./cockroach", "sql", flag,
            f"--host={HOST}", "-e", "SELECT 1;", timeout=min(10, remaining),
        )
        if result.returncode == 0:
            return True
    return False


def wait_for_sql(seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if sql_ready(deadline):
            return True
        time.sleep(max(0, min(4, deadline - time.monotonic())))
    return False


def apply_manifest(name, variables):
    # Explicit envsubst allowlists preserve Kubernetes $(POD_NAME) and
    # $(POD_NAMESPACE) expansion in the container command.
    rendered = subprocess.run(
        ["envsubst", variables], input=(RESOURCES / name).read_text(),
        capture_output=True, text=True, check=True, timeout=10,
    )
    require(kubectl("apply", "-f", "-", input_text=rendered.stdout, timeout=120))


def bootstrap():
    apply_manifest("rbac.yaml", "$BENCH_NAMESPACE $BENCH_PARAM_CLUSTER_NAME")
    apply_manifest("services.yaml", "$BENCH_PARAM_CLUSTER_NAME")
    apply_manifest("statefulset.yaml", "$BENCH_PARAM_CLUSTER_NAME")

    # Wait for the controller to create pods before kubectl wait: it returns
    # immediately with an error if its selector matches no resources yet.
    deadline = time.monotonic() + 60
    while True:
        pods = kubectl("get", "pods", "-l", LABEL, "-o", "name", timeout=10)
        if pods.returncode == 0 and pods.stdout.strip():
            break
        if time.monotonic() >= deadline:
            raise RuntimeError("target cluster pods were not created")
        time.sleep(2)
    require(kubectl(
        "wait", "--for=jsonpath={.status.phase}=Running", "pod", "-l", LABEL,
        "--timeout=300s", timeout=330,
    ))

    # Reused storage may already be initialized; a successful SQL read is also
    # sufficient. Fresh clusters need init before their readiness probes pass.
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        if sql_ready(deadline):
            break
        initialized = kubectl(
            "exec", POD, "--", "./cockroach", "init", "--insecure",
            f"--host={HOST}", timeout=min(15, max(1, deadline - time.monotonic())),
        )
        if initialized.returncode == 0:
            print(initialized.stdout, end="", flush=True)
            break
        time.sleep(3)
    else:
        raise RuntimeError("target cluster could not be initialized")

    require(kubectl(
        "wait", "--for=condition=ready", "pod", "-l", LABEL,
        "--timeout=600s", timeout=640,
    ))


def recover_or_create():
    if cluster_exists():
        # Recheck before touching an inherited cluster: it may have become
        # queryable between the probe timeout and apply.
        if wait_for_sql(10):
            return
        print("Restarting only the target cluster's pods", flush=True)
        require(kubectl(
            "delete", "pods", "-l", LABEL, "--grace-period=0", "--force",
            "--ignore-not-found=true", "--wait=false", timeout=60,
        ))
        if wait_for_sql(60):
            return

    # A missing or still-unhealthy target gets a fresh default insecure cluster.
    # Remove only its StatefulSet, labeled pods and PVCs. The framework owns
    # the namespace, and other clusters/workflow resources stay untouched.
    print("Recreating only the target cluster's workload and data", flush=True)
    require(kubectl(
        "delete", "statefulset", CLUSTER_NAME, "--cascade=orphan",
        "--ignore-not-found=true", "--timeout=60s", timeout=75,
    ))
    require(kubectl(
        "delete", "pods", "-l", LABEL, "--grace-period=0", "--force",
        "--ignore-not-found=true", "--timeout=60s", timeout=75,
    ))
    require(kubectl(
        "delete", "pvc", "-l", LABEL, "--ignore-not-found=true",
        "--timeout=120s", timeout=135,
    ))
    bootstrap()


def main():
    mode = sys.argv[1] if len(sys.argv) == 2 else ""
    if mode == "probe":
        return 0 if cluster_exists() and wait_for_sql(180) else 1
    if mode == "apply":
        recover_or_create()
        return 0
    if mode == "verify":
        return 0 if wait_for_sql(120) else 1
    print(f"usage: {sys.argv[0]} {{probe|apply|verify}}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, subprocess.CalledProcessError) as error:
        print(f"Target cluster setup failed: {error}", file=sys.stderr)
        sys.exit(1)

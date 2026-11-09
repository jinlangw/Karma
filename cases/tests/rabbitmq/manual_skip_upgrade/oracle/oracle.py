import json
import re
import subprocess
import sys
import os
import argparse

NAMESPACE = os.environ.get("BENCH_NAMESPACE", "rabbitmq")


def run(cmd, timeout_sec=30):
    try:
        return subprocess.check_output(
            cmd,
            stderr=subprocess.STDOUT,
            timeout=timeout_sec,
        ).decode()
    except subprocess.TimeoutExpired as exc:
        out = (exc.output or b"").decode(errors="replace").strip()
        msg = f"command timed out after {timeout_sec}s: {' '.join(cmd)}"
        if out:
            msg += f"\n{out}"
        raise subprocess.CalledProcessError(124, cmd, output=msg.encode()) from exc


def run_json(cmd):
    return json.loads(run(cmd, timeout_sec=30))


def _resolve_expected_nodes():
    """Cluster size to enforce: param override -> the case contract's 3.

    The prompt promises a 3-node cluster, so the node count IS a graded
    outcome: param-first (BENCH_PARAM_EXPECTED_NODES / BENCH_PARAM_TARGET_NODES),
    else the contract default 3 -- NEVER derived from readyReplicas or
    spec.replicas (O2 exception: live derivation lets a downscaled/broken
    cluster shrink its own expectation, masking e.g. a scale_down_cluster
    adversary). A workflow that legitimately resizes the cluster must say so
    via the param override.
    """
    for key in ("BENCH_PARAM_EXPECTED_NODES", "BENCH_PARAM_TARGET_NODES"):
        val = os.environ.get(key)
        if val is not None and str(val).strip():
            try:
                return int(val)
            except ValueError:
                pass
    return 3


def get_pod_version(pod):
    out = run([
        "kubectl", "-n", NAMESPACE, "exec", pod, "--",
        "rabbitmqctl", "status"
    ], timeout_sec=60)
    match = re.search(r"RabbitMQ\s*version\s*[:=]\s*([0-9]+\.[0-9]+\.[0-9]+)", out)
    if match:
        return match.group(1)
    match = re.search(r'\"RabbitMQ\"\s*,\s*\"([0-9]+\.[0-9]+\.[0-9]+)\"', out)
    if match:
        return match.group(1)
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--namespace", default=os.environ.get("BENCH_NAMESPACE", "rabbitmq"))
    parser.add_argument(
        "--cluster-prefix",
        default=os.environ.get("BENCH_PARAM_CLUSTER_PREFIX", "rabbitmq"),
    )
    parser.add_argument(
        "--to-version",
        default=os.environ.get("BENCH_PARAM_TO_VERSION", "4.1"),
    )
    args = parser.parse_args()

    global NAMESPACE
    NAMESPACE = args.namespace
    cluster_prefix = args.cluster_prefix
    errors = []
    expected_nodes = _resolve_expected_nodes()

    try:
        pods = run_json([
            "kubectl", "-n", NAMESPACE, "get", "pods", "-l", f"app={cluster_prefix}", "-o", "json"
        ])
    except subprocess.CalledProcessError as exc:
        print(f"Failed to list RabbitMQ pods: {exc.output.decode().strip()}")
        sys.exit(1)

    ready_pods = []
    for item in pods.get("items", []):
        name = item.get("metadata", {}).get("name", "unknown")
        phase = item.get("status", {}).get("phase")
        statuses = item.get("status", {}).get("containerStatuses", [])
        if phase != "Running" or not statuses or not all(s.get("ready") for s in statuses):
            errors.append(f"Pod not ready: {name}")
        else:
            ready_pods.append(name)

    if len(ready_pods) < expected_nodes:
        errors.append(f"Expected {expected_nodes} RabbitMQ pods ready, got {len(ready_pods)}")

    if ready_pods:
        try:
            cluster_out = run([
                "kubectl", "-n", NAMESPACE, "exec", ready_pods[0], "--",
                "rabbitmqctl", "cluster_status"
            ], timeout_sec=60)
            running = re.findall(r"rabbit@[^\s,\]\}]+", cluster_out)
            if len(set(running)) < expected_nodes:
                errors.append(f"Cluster does not report {expected_nodes} running nodes")
        except subprocess.CalledProcessError as exc:
            errors.append(f"Failed to read cluster status: {exc.output.decode().strip()}")

    # Version check (accept exact version or patch releases within the requested family)
    requested = args.to_version.strip()
    family_prefix = requested if requested.endswith(".") else f"{requested}."
    for pod in ready_pods:
        try:
            version = get_pod_version(pod)
        except subprocess.CalledProcessError as exc:
            errors.append(f"Failed to read RabbitMQ version on {pod}: {exc.output.decode().strip()}")
            continue
        if not version:
            errors.append(f"Unable to parse RabbitMQ version on {pod}")
            continue
        if not (version == requested or version.startswith(family_prefix)):
            errors.append(
                f"Pod {pod} not running target version/family {requested} (got {version})"
            )

    # Data check
    if ready_pods:
        try:
            queues = run([
                "kubectl", "-n", NAMESPACE, "exec", ready_pods[0], "--",
                "rabbitmqctl", "-q", "list_queues", "-p", "/app", "name", "messages"
            ], timeout_sec=60)
            found = False
            for line in queues.splitlines():
                parts = line.strip().split()
                if len(parts) >= 2 and parts[0] == "app-queue":
                    found = True
                    try:
                        messages = int(parts[1])
                    except ValueError:
                        messages = 0
                    if messages < 1:
                        errors.append("app-queue has no messages")
                    break
            if not found:
                errors.append("app-queue not found in /app")
        except subprocess.CalledProcessError as exc:
            errors.append(f"Failed to list queues in /app: {exc.output.decode().strip()}")

    if errors:
        print("Manual skip upgrade verification failed:")
        for err in errors:
            print(f"  - {err}")
        sys.exit(1)

    print("Manual skip upgrade verified.")


if __name__ == "__main__":
    main()

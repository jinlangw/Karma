import json
import re
import subprocess
import sys
import os

NAMESPACE = os.environ.get("BENCH_NAMESPACE", "rabbitmq")
CLUSTER_PREFIX = os.environ.get("BENCH_PARAM_CLUSTER_PREFIX", "rabbitmq")


def run(cmd):
    # Bound every kubectl/exec call so a hung pod or unresponsive broker fails
    # the check fast instead of blocking until the outer oracle timeout.
    return subprocess.run(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        check=True, timeout=60,
    ).stdout.decode()


def run_json(cmd):
    return json.loads(run(cmd))


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


def main():
    errors = []
    expected_nodes = _resolve_expected_nodes()

    try:
        pods = run_json([
            "kubectl", "-n", NAMESPACE, "get", "pods", "-l", f"app={CLUSTER_PREFIX}", "-o", "json"
        ])
    except subprocess.CalledProcessError as exc:
        print(f"Failed to list RabbitMQ pods: {exc.output.decode().strip()}")
        sys.exit(1)

    ready = []
    for item in pods.get("items", []):
        name = item.get("metadata", {}).get("name", "unknown")
        phase = item.get("status", {}).get("phase")
        statuses = item.get("status", {}).get("containerStatuses", [])
        if phase != "Running" or not statuses or not all(s.get("ready") for s in statuses):
            errors.append(f"Pod not ready: {name}")
        else:
            ready.append(name)

    if len(ready) != expected_nodes:
        errors.append(f"Expected {expected_nodes} RabbitMQ pods ready, got {len(ready)}")

    if ready:
        try:
            cluster_out = run([
                "kubectl", "-n", NAMESPACE, "exec", ready[0], "--",
                "rabbitmqctl", "cluster_status"
            ])
            running = re.findall(r"rabbit@[^\s,\]\}]+", cluster_out)
            if len(set(running)) < expected_nodes:
                errors.append(f"Cluster does not report {expected_nodes} running nodes")
        except subprocess.CalledProcessError as exc:
            errors.append(f"Failed to read cluster status: {exc.output.decode().strip()}")

    if ready:
        try:
            queues = run([
                "kubectl", "-n", NAMESPACE, "exec", ready[0], "--",
                "rabbitmqctl", "-q", "list_queues", "-p", "/app", "name", "messages"
            ])
            found = False
            for line in queues.splitlines():
                parts = line.strip().split()
                if len(parts) >= 2 and parts[0] == "app-backup":
                    found = True
                    try:
                        messages = int(parts[1])
                    except ValueError:
                        messages = 0
                    if messages < 20:
                        errors.append("app-backup does not have expected messages (>=20)")
                    break
            if not found:
                errors.append("app-backup queue not found in /app")
        except subprocess.CalledProcessError as exc:
            errors.append(f"Failed to list queues in /app: {exc.output.decode().strip()}")

    if errors:
        print("RabbitMQ backup/restore verification failed:")
        for err in errors:
            print(f"  - {err}")
        sys.exit(1)

    print("RabbitMQ backup/restore verified.")


if __name__ == "__main__":
    main()

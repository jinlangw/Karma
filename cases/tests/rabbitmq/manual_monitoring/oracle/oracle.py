import json
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


def curl_from_curl_test(url):
    return run([
        "kubectl", "-n", NAMESPACE, "exec", "oracle-client", "--",
        "curl", "-s", "--connect-timeout", "5", "--max-time", "25", url
    ])


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


def evaluate():
    """One full snapshot of the monitoring checks; returns the error list."""
    errors = []
    expected_nodes = _resolve_expected_nodes()

    try:
        pods = run_json([
            "kubectl", "-n", NAMESPACE, "get", "pods", "-l", f"app={CLUSTER_PREFIX}", "-o", "json"
        ])
    except subprocess.CalledProcessError as exc:
        errors.append(f"Failed to list RabbitMQ pods: {exc.output.decode().strip()}")
        pods = {"items": []}

    ready_pods = 0
    pod_names = []
    for item in pods.get("items", []):
        name = item.get("metadata", {}).get("name", "unknown")
        pod_names.append(name)
        phase = item.get("status", {}).get("phase")
        statuses = item.get("status", {}).get("containerStatuses", [])
        if phase != "Running" or not statuses or not all(s.get("ready") for s in statuses):
            errors.append(f"Pod not ready: {name}")
        else:
            ready_pods += 1

    if ready_pods < expected_nodes:
        errors.append(f"Expected {expected_nodes} RabbitMQ pods ready, got {ready_pods}")

    for name in pod_names:
        try:
            out = curl_from_curl_test(
                f"http://{name}.{CLUSTER_PREFIX}-headless.{NAMESPACE}.svc.cluster.local:15692/metrics"
            )
            if "rabbitmq_" not in out:
                errors.append(f"RabbitMQ metrics missing on {name}")
        except subprocess.CalledProcessError as exc:
            errors.append(f"Failed to fetch metrics from {name}: {exc.output.decode().strip()}")

    try:
        targets_raw = curl_from_curl_test(
            f"http://prometheus.{NAMESPACE}.svc.cluster.local:8000/api/v1/targets"
        )
        targets = json.loads(targets_raw)
        if targets.get("status") != "success":
            errors.append("Prometheus targets query failed")
            targets = {}
    except Exception as exc:
        errors.append(f"Failed to query Prometheus targets: {exc}")
        targets = {}

    rabbit_targets = []
    for target in targets.get("data", {}).get("activeTargets", []):
        if target.get("labels", {}).get("job") == "rabbitmq":
            rabbit_targets.append(target)

    if len(rabbit_targets) < expected_nodes:
        errors.append(f"Expected {expected_nodes} RabbitMQ targets in Prometheus, got {len(rabbit_targets)}")
    else:
        down = [t for t in rabbit_targets if t.get("health") != "up"]
        if down:
            errors.append(f"Prometheus has {len(down)} RabbitMQ targets not UP")

    try:
        query_raw = curl_from_curl_test(
            f"http://prometheus.{NAMESPACE}.svc.cluster.local:8000/api/v1/query?query=up%7Bjob%3D%22rabbitmq%22%7D"
        )
        query = json.loads(query_raw)
        if query.get("status") != "success":
            errors.append("Prometheus query up{job=\"rabbitmq\"} failed")
        else:
            results = query.get("data", {}).get("result", [])
            if len(results) < expected_nodes:
                errors.append(f"Expected {expected_nodes} up{{job=\"rabbitmq\"}} samples, got {len(results)}")
            for sample in results:
                value = sample.get("value", [None, "0"])[1]
                if value not in ("1", "1.0"):
                    errors.append("up{job=\"rabbitmq\"} has non-1 value")
                    break
    except Exception as exc:
        errors.append(f"Failed to query up{{job=\"rabbitmq\"}}: {exc}")

    return errors


def main():
    # Monitoring converges asynchronously after the agent's change: rabbitmq must
    # reload to expose the prometheus plugin's /metrics endpoint (the port refuses
    # connections until it does), and Prometheus only marks the targets UP after
    # its next scrape interval. A single snapshot can run before that convergence
    # and report unreachable metrics / targets-not-UP on a correctly-configured
    # cluster. Re-evaluate for up to ~120s and pass on the first clean snapshot. A
    # genuinely mis-configured monitoring setup never comes UP, so the oracle
    # still fails after the deadline.
    import time
    deadline = time.monotonic() + 120
    errors = evaluate()
    while errors and time.monotonic() < deadline:
        time.sleep(8)
        errors = evaluate()

    if errors:
        print("RabbitMQ monitoring verification failed:")
        for err in errors:
            print(f"  - {err}")
        sys.exit(1)

    print("RabbitMQ monitoring verified.")


if __name__ == "__main__":
    main()

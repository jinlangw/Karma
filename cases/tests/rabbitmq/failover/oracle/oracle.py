import base64
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


_MGMT_BASE = None


def mgmt_base():
    """Resolve the live management-API base URL (scheme + port).

    Standalone the management plugin is plain HTTP on 15672. A prior workflow
    stage may have enabled TLS (HTTPS on 15671); a hardcoded http://:15672 then
    fails. Probe https://:15671 first (with -k), fall back to http://:15672.
    Auth is NOT bypassed -- only the transport scheme adapts.
    """
    global _MGMT_BASE
    if _MGMT_BASE is not None:
        return _MGMT_BASE
    candidates = [f"http://{CLUSTER_PREFIX}:15672", f"https://{CLUSTER_PREFIX}:15671"]
    for base in candidates:
        try:
            out = run([
                "kubectl", "-n", NAMESPACE, "exec", "oracle-client", "--",
                "/bin/sh", "-c",
                f"curl -sk --connect-timeout 5 --max-time 15 -o /dev/null -w '%{{http_code}}' {base}/api/overview",
            ]).strip()
            if out and out[:1].isdigit() and out != "000":
                _MGMT_BASE = base
                return _MGMT_BASE
        except subprocess.CalledProcessError:
            continue
    _MGMT_BASE = candidates[-1]
    return _MGMT_BASE


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
            admin_secret = run_json([
                "kubectl", "-n", NAMESPACE, "get", "secret", f"{CLUSTER_PREFIX}-admin", "-o", "json"
            ])
            admin_user = base64.b64decode(
                admin_secret["data"]["username"]
            ).decode().strip()
            admin_pass = base64.b64decode(
                admin_secret["data"]["password"]
            ).decode().strip()
            nodes_raw = run([
                "kubectl", "-n", NAMESPACE, "exec", "oracle-client", "--",
                "/bin/sh", "-c",
                f"curl -sk --connect-timeout 5 --max-time 25 -u {admin_user}:{admin_pass} {mgmt_base()}/api/nodes"
            ])
            try:
                nodes = json.loads(nodes_raw)
            except json.JSONDecodeError:
                nodes = []
            if not isinstance(nodes, list):
                errors.append("Failed to query management API for nodes")
            else:
                if len(nodes) < expected_nodes:
                    errors.append(f"Cluster does not report {expected_nodes} running nodes")
                names = {n.get("name") for n in nodes if isinstance(n, dict)}
                expected_node_names = [
                    f"rabbit@{pod}.{CLUSTER_PREFIX}-headless.{NAMESPACE}.svc.cluster.local"
                    for pod in ready_pods
                ]
                for node in expected_node_names:
                    if node not in names:
                        errors.append(f"Cluster missing running node: {node}")
        except (subprocess.CalledProcessError, KeyError) as exc:
            detail = exc.output.decode().strip() if isinstance(exc, subprocess.CalledProcessError) else str(exc)
            errors.append(f"Failed to read cluster membership: {detail}")

    # Erlang cookie consistency check
    try:
        secret = run_json([
            "kubectl", "-n", NAMESPACE, "get", "secret", f"{CLUSTER_PREFIX}-cookie-perpod", "-o", "json"
        ])
        data = secret.get("data", {})
        cookies = {}
        for key, value in data.items():
            try:
                cookies[key] = base64.b64decode(value).decode().strip()
            except Exception:
                cookies[key] = None
        # Derive the per-pod cookie keys from the FIXED expected node count
        # (param-first, contract default 3 -- see _resolve_expected_nodes), so
        # a cluster a fault shrank cannot shrink the cookie check either.
        expected_keys = [f"{CLUSTER_PREFIX}-{i}" for i in range(expected_nodes)]
        missing = [k for k in expected_keys if k not in cookies]
        if missing:
            errors.append(f"Missing cookie keys in secret: {', '.join(missing)}")
        else:
            values = [cookies[k] for k in expected_keys]
            if any(v is None or v == "" for v in values):
                errors.append("Erlang cookie values are empty or unreadable")
            elif len(set(values)) != 1:
                errors.append("Erlang cookie values are not consistent across nodes")
    except subprocess.CalledProcessError as exc:
        errors.append(f"Failed to read cookie secret: {exc.output.decode().strip()}")

    if errors:
        print("RabbitMQ failover verification failed:")
        for err in errors:
            print(f"  - {err}")
        sys.exit(1)

    print("RabbitMQ failover verified.")


if __name__ == "__main__":
    main()

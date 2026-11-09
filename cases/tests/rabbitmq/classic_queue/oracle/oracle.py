import base64
import json
import subprocess
import sys
import os
import time

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


def get_secret_value(name, key):
    data = run_json([
        "kubectl", "-n", NAMESPACE, "get", "secret", name, "-o", "json"
    ])
    raw = data.get("data", {}).get(key)
    if not raw:
        raise ValueError(f"Missing secret data: {name}/{key}")
    return base64.b64decode(raw).decode().strip()


_MGMT_BASE = None


def mgmt_base():
    """Resolve the live management-API base URL (scheme + port).

    Standalone this cluster serves the management plugin over plain HTTP on
    15672. A prior workflow stage may have enabled TLS on the management
    listener (HTTPS on 15671); a hardcoded http://:15672 then fails. Probe the
    live cluster: try https://:15671 first (with -k), fall back to
    http://:15672. Auth is NOT bypassed -- only the transport scheme adapts.
    """
    global _MGMT_BASE
    if _MGMT_BASE is not None:
        return _MGMT_BASE
    # Prefer the plain mgmt port (the RabbitMQ default). Only fall back to the
    # TLS port when http is unavailable -- this both matches a non-TLS cluster
    # (stage runs before any mgmt-TLS stage) and a later TLS-only one, and avoids
    # a slow TLS listener that answers the probe but then drags every query past
    # its deadline (curl exit 28). Auth is unchanged; only the transport adapts.
    candidates = [f"http://{CLUSTER_PREFIX}:15672", f"https://{CLUSTER_PREFIX}:15671"]
    # The agent typically restarts the broker to apply config; the management
    # plugin can still be coming up when the oracle runs. Poll the candidates
    # until one answers (any HTTP code, incl. 401) rather than giving up on the
    # first probe and falling back to a base that is not serving yet -- which
    # would fail every API query below. Bounded so a truly-down API still fails.
    deadline = time.time() + 60
    while True:
        for base in candidates:
            try:
                out = subprocess.run(
                    [
                        "kubectl", "-n", NAMESPACE, "exec", "oracle-client", "--",
                        "curl", "-sk", "--connect-timeout", "5", "--max-time", "15",
                        "-o", "/dev/null", "-w", "%{http_code}",
                        f"{base}/api/overview",
                    ],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                    timeout=25,
                ).stdout.strip()
                if out and out[:1].isdigit() and out != "000":
                    _MGMT_BASE = base
                    return _MGMT_BASE
            except Exception:
                continue
        if time.time() >= deadline:
            break
        time.sleep(3)
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


def curl_api(path, user, password):
    return run([
        "kubectl", "-n", NAMESPACE, "exec", "oracle-client", "--",
        "curl", "-sk", "--connect-timeout", "5", "--max-time", "25",
        "-u", f"{user}:{password}",
        f"{mgmt_base()}{path}",
    ])


def main():
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
    for item in pods.get("items", []):
        name = item.get("metadata", {}).get("name", "unknown")
        phase = item.get("status", {}).get("phase")
        statuses = item.get("status", {}).get("containerStatuses", [])
        if phase != "Running" or not statuses or not all(s.get("ready") for s in statuses):
            errors.append(f"Pod not ready: {name}")
        else:
            ready_pods += 1

    if ready_pods < expected_nodes:
        errors.append(f"Expected {expected_nodes} RabbitMQ pods ready, got {ready_pods}")

    try:
        dep = run_json([
            "kubectl", "-n", NAMESPACE, "get", "deployment", "app-producer", "-o", "json"
        ])
        ready_repl = dep.get("status", {}).get("readyReplicas", 0)
        if ready_repl < 1:
            errors.append("app-producer is not Ready")
    except subprocess.CalledProcessError as exc:
        errors.append(f"Failed to read app-producer deployment: {exc.output.decode().strip()}")

    try:
        admin_user = get_secret_value(f"{CLUSTER_PREFIX}-admin", "username")
        admin_pass = get_secret_value(f"{CLUSTER_PREFIX}-admin", "password")
    except Exception as exc:
        errors.append(f"Failed to read admin credentials: {exc}")
        admin_user = None
        admin_pass = None

    if admin_user and admin_pass:
        try:
            raw_nodes = curl_api("/api/nodes", admin_user, admin_pass)
            nodes = json.loads(raw_nodes)
            if len(nodes) < expected_nodes:
                errors.append(f"Expected {expected_nodes} nodes in cluster, got {len(nodes)}")
        except Exception as exc:
            errors.append(
                f"Failed to query cluster nodes via management API "
                f"(base={mgmt_base()}): {exc}: {locals().get('raw_nodes', '')[:120]!r}"
            )

        try:
            policies = json.loads(curl_api("/api/policies/%2Fapp", admin_user, admin_pass))
            for policy in policies:
                definition = policy.get("definition", {})
                if definition.get("queue-type") == "quorum":
                    errors.append("Quorum queue policy still present on /app")
                    break
        except Exception:
            errors.append("Failed to query policies for /app")

        try:
            perms = json.loads(curl_api("/api/permissions/%2Fapp/app-user", admin_user, admin_pass))
            configure = perms.get("configure", "")
            if not configure:
                errors.append("app-user configure permission for /app is empty")
        except Exception:
            errors.append("Failed to query app-user permissions for /app")

        try:
            queue_info = json.loads(curl_api("/api/queues/%2Fapp/app-queue", admin_user, admin_pass))
            messages = queue_info.get("messages", 0)
            if messages < 1:
                errors.append("app-queue has no messages")
        except Exception:
            errors.append("Failed to query app-queue state")

    try:
        queue_out = run([
            "kubectl", "-n", NAMESPACE, "exec", f"{CLUSTER_PREFIX}-0", "--",
            "rabbitmqctl", "-q", "list_queues", "-p", "/app", "name", "type"
        ])
        found = False
        for line in queue_out.splitlines():
            parts = line.strip().split()
            if len(parts) >= 2 and parts[0] == "app-queue":
                found = True
                if parts[1] != "classic":
                    errors.append("app-queue is not a classic queue")
                break
        if not found:
            errors.append("app-queue not found in /app")
    except subprocess.CalledProcessError as exc:
        errors.append(f"Failed to list queues in /app: {exc.output.decode().strip()}")

    if errors:
        print("Classic queue verification failed:")
        for err in errors:
            print(f"  - {err}")
        sys.exit(1)

    print("Classic queue verified.")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
import os
import subprocess
import sys
import time

# O13: ingress-nginx picks up a renewed TLS Secret asynchronously (config /
# cert reload), so a single-shot serving-cert check races the controller's
# reload right after the agent's fix. Re-evaluate the HTTPS probe within a
# bounded window (the pattern of the create_ingress sibling) and pass on the
# first clean response; a cert that never becomes valid still fails at the
# deadline. O21: keep the window strictly below the oracle timeout_sec (150s
# in test.yaml) with headroom for a final bounded exec + output.
DEADLINE_SEC = 110
INTERVAL_SEC = 3


def run(cmd, timeout=30):
    """Run a command bounded (O17); a hang counts as a failed attempt."""
    try:
        return subprocess.run(cmd, text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, 124, "", "timed out")


def cluster_key():
    # Per-cluster file key (Law 4 run isolation): parallel campaigns against
    # two clusters share this host's /tmp, so the precondition keys its env /
    # cert artifacts by the KUBECONFIG basename. Preconditions, this oracle,
    # and the delete_tls_secret adversary all run under the same KUBECONFIG,
    # so producer and consumer derive the same key.
    return os.path.basename(os.environ.get("KUBECONFIG") or "default")


def load_ingress_env():
    # Read the precondition-written endpoint file: the cluster-keyed path
    # first, the legacy shared path as a last resort (older artifacts).
    env = {}
    for path in (f"/tmp/ingress_env.{cluster_key()}", "/tmp/ingress_env"):
        if not os.path.exists(path):
            continue
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("export "):
                    line = line[len("export "):]
                if "=" not in line:
                    continue
                key, value = line.split("=", 1)
                env[key.strip()] = value.strip()
        return env
    return env


def derive_node_ip():
    # Discover a node InternalIP from the live cluster. The live cluster is
    # the AUTHORITATIVE source (Law 4): a host-shared env file written by a
    # parallel campaign against another cluster must never steer this oracle.
    cmd = [
        "kubectl",
        "get",
        "nodes",
        "-o",
        "jsonpath={.items[*].status.addresses[?(@.type==\"InternalIP\")].address}",
    ]
    result = run(cmd)
    if result.returncode != 0:
        return None
    # jsonpath over all nodes returns a space-separated list; take the first.
    addresses = result.stdout.split()
    return addresses[0] if addresses else None


def derive_https_node_port():
    # Discover the ingress-nginx controller Service's https (443) nodePort from
    # the live cluster, mirroring how the precondition computes INGRESS_HTTPS_PORT.
    cmd = [
        "kubectl",
        "get",
        "svc",
        "ingress-nginx-controller",
        "-n",
        "ingress-nginx",
        "-o",
        "jsonpath={.spec.ports[?(@.port==443)].nodePort}",
    ]
    result = run(cmd)
    if result.returncode != 0:
        return None
    port = result.stdout.strip()
    return port or None


def main():
    # Param-aware: a workflow can override host/expected_body via
    # param_overrides; read BENCH_PARAM_* (default = the standalone value) so
    # the oracle validates HTTPS against whichever host this stage targets on
    # the live cluster. Pass criterion (valid cert, body matches) is unchanged.
    host = os.environ.get("BENCH_PARAM_HOST") or "demo.example.com"
    expected_body = os.environ.get("BENCH_PARAM_EXPECTED_BODY") or "hello"

    # Resolve the ingress endpoint: SELF-DERIVE from the live cluster FIRST
    # (Law 4 -- the cluster this oracle's KUBECONFIG points at is the ground
    # truth), and only fall back to the precondition-written env file / env
    # vars when the live derivation fails.
    node_ip = derive_node_ip()
    node_port = derive_https_node_port()
    if not node_ip or not node_port:
        env = load_ingress_env()
        node_ip = node_ip or env.get("INGRESS_NODE_IP") or os.environ.get("INGRESS_NODE_IP")
        node_port = (node_port or env.get("INGRESS_HTTPS_PORT")
                     or os.environ.get("INGRESS_HTTPS_PORT"))
    if not node_ip or not node_port:
        print(
            "Could not determine INGRESS_NODE_IP / INGRESS_HTTPS_PORT "
            "(live derivation failed and no ingress_env fallback)",
            file=sys.stderr,
        )
        return 1

    resolve = f"{host}:{node_port}:{node_ip}"
    url = f"https://{host}:{node_port}/"

    cmd = [
        "kubectl",
        "-n",
        "demo",
        "exec",
        "curl-test",
        "--",
        "curl",
        "-sS",
        "--connect-timeout",
        "5",
        "--max-time",
        "15",
        "--cacert",
        "/tmp/tls/ca.crt",
        "--resolve",
        resolve,
        url,
    ]

    deadline = time.monotonic() + DEADLINE_SEC
    last_err = "no response"
    while True:
        result = run(cmd)
        if result.returncode == 0:
            body = result.stdout.strip()
            if body == expected_body:
                return 0
            last_err = f"unexpected body: {body}"
        elif result.returncode == 60 and "certificate has expired" in result.stderr:
            # The graded fault: keep polling -- the controller reloads a
            # renewed Secret asynchronously; still-expired at the deadline is
            # a stable (real) failure.
            last_err = "certificate is still expired"
        else:
            last_err = result.stderr.strip() or "HTTPS request failed"
        if time.monotonic() >= deadline:
            break
        time.sleep(INTERVAL_SEC)

    print(f"HTTPS check failed: {last_err}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())

import base64
import datetime as dt
import json
import subprocess
import sys
import os
import argparse

NAMESPACE = os.environ.get("BENCH_NAMESPACE", "rabbitmq")
CLUSTER_PREFIX = os.environ.get("BENCH_PARAM_CLUSTER_PREFIX", "rabbitmq")


def run(cmd, input_data=None):
    # Bound every kubectl/exec/openssl call so a hung pod or unresponsive broker
    # fails the check fast instead of blocking until the outer oracle timeout.
    return subprocess.check_output(
        cmd, stderr=subprocess.STDOUT, input=input_data, timeout=60
    ).decode()


def run_json(cmd):
    return json.loads(run(cmd))


def decode_secret(name, key):
    data = run_json([
        "kubectl", "-n", NAMESPACE, "get", "secret", name, "-o", "json"
    ])
    return base64.b64decode(data["data"][key])


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


def openssl_fingerprint(pem_bytes):
    out = run(["openssl", "x509", "-noout", "-fingerprint", "-sha256"], input_data=pem_bytes)
    return out.strip().split("=")[-1]


def openssl_enddate(pem_bytes):
    out = run(["openssl", "x509", "-noout", "-enddate"], input_data=pem_bytes)
    # format: notAfter=Jan 27 01:21:20 2026 GMT
    value = out.strip().split("=", 1)[1]
    return dt.datetime.strptime(value, "%b %d %H:%M:%S %Y %Z")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--namespace", default=os.environ.get("BENCH_NAMESPACE", "rabbitmq"))
    parser.add_argument(
        "--min-rotated-leaf-validity-days",
        type=int,
        default=int(os.environ.get("BENCH_PARAM_MIN_ROTATED_LEAF_VALIDITY_DAYS", "300")),
    )
    args = parser.parse_args()

    global NAMESPACE, CLUSTER_PREFIX
    NAMESPACE = args.namespace
    CLUSTER_PREFIX = os.environ.get("BENCH_PARAM_CLUSTER_PREFIX", CLUSTER_PREFIX)
    errors = []
    expected_nodes = _resolve_expected_nodes()

    # pods ready
    pods = run_json([
        "kubectl", "-n", NAMESPACE, "get", "pods", "-l", f"app={CLUSTER_PREFIX}", "-o", "json"
    ])
    ready = []
    for item in pods.get("items", []):
        name = item.get("metadata", {}).get("name", "unknown")
        phase = item.get("status", {}).get("phase")
        statuses = item.get("status", {}).get("containerStatuses", [])
        if phase != "Running" or not statuses or not all(s.get("ready") for s in statuses):
            errors.append(f"Pod not ready: {name}")
        else:
            ready.append(name)
    if len(ready) < expected_nodes:
        errors.append(f"Expected {expected_nodes} RabbitMQ pods ready, got {len(ready)}")

    # cluster status
    if ready:
        try:
            out = run([
                "kubectl", "-n", NAMESPACE, "exec", ready[0], "--",
                "rabbitmqctl", "cluster_status"
            ])
            if out.count("Running Nodes") == 0:
                errors.append("Unable to read cluster status")
            else:
                # Derive expected node names from the LIVE cluster size rather
                # than a hardcoded 0..2, so a scaled cluster is fully checked.
                missing = [
                    i for i in range(expected_nodes)
                    if f"rabbit@{CLUSTER_PREFIX}-{i}" not in out
                ]
                if missing:
                    errors.append(f"Cluster does not report {expected_nodes} running nodes")
        except subprocess.CalledProcessError as exc:
            errors.append(f"Failed to read cluster status: {exc.output.decode().strip()}")

    # old fingerprints
    old_cm = run_json([
        "kubectl", "-n", NAMESPACE, "get", "configmap", f"{CLUSTER_PREFIX}-tls-old", "-o", "json"
    ])
    old_ca_fp = old_cm.get("data", {}).get("ca_fingerprint_sha256")
    old_leaf_fp = old_cm.get("data", {}).get("leaf_fingerprint_sha256")
    if not old_ca_fp or not old_leaf_fp:
        errors.append("Missing old TLS fingerprints")

    # current certs
    ca_pem = decode_secret(f"{CLUSTER_PREFIX}-tls", "ca.crt")
    leaf_pem = decode_secret(f"{CLUSTER_PREFIX}-tls", "tls.crt")
    new_ca_fp = openssl_fingerprint(ca_pem)
    new_leaf_fp = openssl_fingerprint(leaf_pem)

    if old_ca_fp and new_ca_fp != old_ca_fp:
        errors.append("CA fingerprint changed")
    if old_leaf_fp and new_leaf_fp == old_leaf_fp:
        errors.append("Leaf certificate was not rotated")

    # validity check: configurable minimum remaining days
    not_after = openssl_enddate(leaf_pem)
    if (not_after - dt.datetime.utcnow()).days < args.min_rotated_leaf_validity_days:
        errors.append(
            "New leaf certificate validity is too short "
            f"(min_days={args.min_rotated_leaf_validity_days})"
        )

    # ensure live TLS uses new leaf. Right after the agent rotates the cert the
    # broker reloads its TLS listener, which can be briefly unresponsive, and on
    # a loaded node the handshake is slow -- `openssl s_client` then HANGS, and
    # the un-bounded run() (timeout=60) would raise TimeoutExpired and crash the
    # whole oracle. Bound each attempt with `timeout 15` and retry, treating a
    # hang/failure as "not converged yet" rather than fatal. Run s_client from the
    # broker pod (the curl-only oracle-client image ships no openssl); the pod can
    # reach its own TLS service on 5671.
    import time
    s_client_cmd = (
        f"echo | timeout 15 openssl s_client -connect "
        f"{CLUSTER_PREFIX}.{NAMESPACE}.svc.cluster.local:5671 -servername {CLUSTER_PREFIX} "
        f"2>/dev/null | openssl x509 -noout -fingerprint -sha256"
    )
    live_fp = None
    for _attempt in range(8):
        try:
            out = run([
                "kubectl", "-n", NAMESPACE, "exec", f"{CLUSTER_PREFIX}-0", "--",
                "/bin/sh", "-c", s_client_cmd,
            ])
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            out = ""
        fp = out.strip().split("=")[-1] if out and out.strip() else ""
        if fp:
            live_fp = fp
            break
        time.sleep(5)
    if live_fp is None:
        errors.append("Failed to check live TLS certificate (s_client unreachable after retries)")
    elif live_fp != new_leaf_fp:
        errors.append("Live TLS certificate does not match rotated leaf")

    if errors:
        print("Manual TLS rotation verification failed:")
        for err in errors:
            print(f"  - {err}")
        sys.exit(1)

    print("Manual TLS rotation verified.")


if __name__ == "__main__":
    main()

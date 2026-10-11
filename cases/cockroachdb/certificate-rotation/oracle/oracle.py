#!/usr/bin/env python3
# Verify the TLS certs were rotated (secure SQL works, node/CA fingerprints,
# ~1y validity). The cluster name is configurable through the case params; its
# TLS Secret and baseline ConfigMap use names derived from that cluster name.
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone


CLUSTER_NAME = os.environ.get("BENCH_PARAM_CLUSTER_NAME", "crdb-cluster")
CERT_SECRET = f"{CLUSTER_NAME}-certs"
OLD_CERT_CM = f"{CLUSTER_NAME}-old-cert"
NAMESPACE = os.environ.get("BENCH_NAMESPACE")
NODE_NAME = f"{CLUSTER_NAME}-0"


def run(cmd, timeout=30):
    """Run a command with a hard timeout (O17); a timeout becomes a failed result."""
    try:
        return subprocess.run(
            cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        # TimeoutExpired may expose captured output as bytes even when
        # subprocess.run was called with text=True.
        if isinstance(stdout, bytes):
            stdout = stdout.decode(errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode(errors="replace")
        return subprocess.CompletedProcess(
            cmd, 124, stdout, stderr + "\n[command timed out]"
        )


def served_leaf_fingerprint(node_name):
    """SHA-256 fingerprint of a target cluster node's served leaf cert (O37).

    Read via a live TLS handshake from the openssl-toolbox pod (the crdb image
    does not ship openssl, O12) against the node's HTTP port 8080 -- a secure
    CockroachDB node serves its node cert there. The s_client is bounded both
    in-pod by a 15-second timeout and on the exec (O17). Returns (fingerprint, error).
    """
    cmd = [
        "kubectl", "-n", NAMESPACE, "exec", "openssl-toolbox", "--",
        "sh", "-c",
        "timeout 15 openssl s_client -connect "
        f"{node_name}.{CLUSTER_NAME}.{NAMESPACE}.svc.cluster.local:8080 "
        "-showcerts </dev/null 2>/dev/null | "
        "openssl x509 -noout -fingerprint -sha256",
    ]
    result = run(cmd, timeout=30)
    if result.returncode != 0 or "=" not in result.stdout:
        return "", (result.stderr.strip() or result.stdout.strip() or "TLS handshake failed")
    return result.stdout.strip().split("=", 1)[-1].upper().replace(":", ""), ""


def statefulset_replicas():
    """Return the target StatefulSet's desired replica count, or an error."""
    result = run([
        "kubectl", "-n", NAMESPACE, "get", "statefulset", CLUSTER_NAME,
        "-o", "jsonpath={.spec.replicas}",
    ])
    if result.returncode != 0:
        return 0, result.stderr.strip() or "unable to read StatefulSet replicas"
    try:
        replicas = int(result.stdout.strip())
    except ValueError:
        return 0, f"invalid StatefulSet replica count: {result.stdout.strip()!r}"
    if replicas < 1:
        return 0, f"target StatefulSet has invalid replica count: {replicas}"
    return replicas, ""


def target_pod_names():
    """Return names of pods belonging to the selected cluster."""
    result = run([
        "kubectl", "-n", NAMESPACE, "get", "pods",
        "-l", f"app.kubernetes.io/instance={CLUSTER_NAME}",
        "-o", "name",
    ])
    if result.returncode != 0:
        return [], result.stderr.strip() or "unable to list target cluster pods"
    return sorted(
        line.split("/", 1)[-1]
        for line in result.stdout.splitlines()
        if line.strip()
    ), ""


def main():
    errors = []
    if not NAMESPACE:
        print("Certificate rotation verification failed: BENCH_NAMESPACE is not set", file=sys.stderr)
        return 1

    secure_cmd = [
        "kubectl",
        "-n",
        NAMESPACE,
        "exec",
        NODE_NAME,
        "--",
        "./cockroach",
        "sql",
        "--certs-dir=/cockroach/cockroach-certs",
        "-e",
        "SELECT 1;",
    ]
    secure_result = run(secure_cmd)
    if secure_result.returncode != 0:
        errors.append("TLS connection failed after certificate rotation")
        errors.append(f"Error: {secure_result.stderr.strip()}")

    old_fp_cmd = [
        "kubectl",
        "-n",
        NAMESPACE,
        "get",
        "configmap",
        OLD_CERT_CM,
        "-o",
        "jsonpath={.data.fingerprint}",
    ]
    old_fp_result = run(old_fp_cmd)
    old_fp = ""
    if old_fp_result.returncode != 0:
        errors.append(f"Missing {OLD_CERT_CM} ConfigMap")
        errors.append(f"Error: {old_fp_result.stderr.strip()}")
    else:
        old_fp = old_fp_result.stdout.strip().upper().replace(":", "")

    old_na_cmd = [
        "kubectl",
        "-n",
        NAMESPACE,
        "get",
        "configmap",
        OLD_CERT_CM,
        "-o",
        "jsonpath={.data.not_after}",
    ]
    old_na_result = run(old_na_cmd)
    old_not_after = None
    if old_na_result.returncode != 0:
        errors.append(f"Missing not_after in {OLD_CERT_CM} ConfigMap")
        errors.append(f"Error: {old_na_result.stderr.strip()}")
    else:
        raw = old_na_result.stdout.strip()
        if raw.endswith(" GMT"):
            raw = raw[:-4]
        try:
            old_not_after = datetime.strptime(raw, "%b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
        except ValueError:
            errors.append(f"Unable to parse old not_after: {old_na_result.stdout.strip()}")

    new_fp_cmd = [
        "/bin/sh",
        "-c",
        f"kubectl -n {NAMESPACE} get secret {CERT_SECRET} "
        "-o jsonpath='{.data.node\\.crt}' | base64 -d | "
        "openssl x509 -noout -fingerprint -sha256",
    ]
    new_fp_result = run(new_fp_cmd)
    new_fp = ""
    if new_fp_result.returncode != 0:
        errors.append("Failed to read new node cert fingerprint")
        errors.append(f"Error: {new_fp_result.stderr.strip()}")
    else:
        new_fp = new_fp_result.stdout.strip().split("=", 1)[-1].upper().replace(":", "")
        if old_fp and new_fp == old_fp:
            errors.append("Node certificate fingerprint did not change")

    # O37: the Secret bytes alone do not prove the rotation took effect -- the
    # SQL check above also succeeds against the OLD served cert (same CA), so
    # "updated the Secret but never restarted the nodes" would score as done.
    # Require every expected StatefulSet pod to present the Secret's new
    # node.crt in a live TLS handshake. Pods may still be settling from the
    # agent's restart, so poll to a bounded deadline.
    if new_fp:
        expected_replicas, replica_error = statefulset_replicas()
        if replica_error:
            errors.append(f"Unable to determine target cluster size: {replica_error}")
        else:
            deadline = time.monotonic() + 90
            pending_pods = {}
            discovery_error = ""
            while time.monotonic() < deadline:
                pod_names, pod_error = target_pod_names()
                if pod_error:
                    discovery_error = pod_error
                    pending_pods = {}
                elif len(pod_names) != expected_replicas:
                    discovery_error = (
                        f"Expected {expected_replicas} pods for {CLUSTER_NAME}, "
                        f"found {len(pod_names)}"
                    )
                    pending_pods = {}
                else:
                    discovery_error = ""
                    pending_pods = {}
                    for node_name in pod_names:
                        served_fp, served_err = served_leaf_fingerprint(node_name)
                        if served_fp != new_fp:
                            pending_pods[node_name] = (
                                served_err
                                or (
                                    f"served fingerprint {served_fp[:16]}... does not match "
                                    f"Secret fingerprint {new_fp[:16]}..."
                                )
                            )
                    if not pending_pods:
                        break
                time.sleep(6)

            if discovery_error:
                errors.append(f"Unable to inspect every target cluster pod: {discovery_error}")
            for node_name, reason in sorted(pending_pods.items()):
                errors.append(
                    f"Node {node_name} is not serving the rotated certificate: {reason}"
                )

    new_na_cmd = [
        "/bin/sh",
        "-c",
        f"kubectl -n {NAMESPACE} get secret {CERT_SECRET} "
        "-o jsonpath='{.data.node\\.crt}' | base64 -d | "
        "openssl x509 -noout -enddate",
    ]
    ca_old_cmd = [
        "kubectl",
        "-n",
        NAMESPACE,
        "get",
        "configmap",
        OLD_CERT_CM,
        "-o",
        "jsonpath={.data.ca_fingerprint}",
    ]
    ca_old_result = run(ca_old_cmd)
    ca_old_fp = ""
    if ca_old_result.returncode != 0:
        errors.append(f"Missing ca_fingerprint in {OLD_CERT_CM} ConfigMap")
        errors.append(f"Error: {ca_old_result.stderr.strip()}")
    else:
        ca_old_fp = ca_old_result.stdout.strip().upper().replace(":", "")

    ca_new_cmd = [
        "/bin/sh",
        "-c",
        f"kubectl -n {NAMESPACE} get secret {CERT_SECRET} "
        "-o jsonpath='{.data.ca\\.crt}' | base64 -d | "
        "openssl x509 -noout -fingerprint -sha256",
    ]
    ca_new_result = run(ca_new_cmd)
    if ca_new_result.returncode != 0:
        errors.append("Failed to read new CA fingerprint")
        errors.append(f"Error: {ca_new_result.stderr.strip()}")
    else:
        ca_new_fp = ca_new_result.stdout.strip().split("=", 1)[-1].upper().replace(":", "")
        if ca_old_fp and ca_new_fp != ca_old_fp:
            errors.append("CA fingerprint changed; expected same CA")
    new_na_result = run(new_na_cmd)
    if new_na_result.returncode != 0:
        errors.append("Failed to read new node cert expiration")
        errors.append(f"Error: {new_na_result.stderr.strip()}")
    else:
        raw = new_na_result.stdout.strip().replace("notAfter=", "")
        if raw.endswith(" GMT"):
            raw = raw[:-4]
        try:
            new_not_after = datetime.strptime(raw, "%b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
            # "About 1 year" means a 300-400 day window from now, not just a
            # minimum lifetime. An absolute window avoids depending on the old
            # certificate's expiration when this case is composed in a workflow.
            remaining = new_not_after - datetime.now(timezone.utc)
            if remaining < timedelta(days=300):
                errors.append(
                    f"New certificate validity too short ({remaining.days} days from now)"
                )
            elif remaining > timedelta(days=400):
                errors.append(
                    f"New certificate validity too long ({remaining.days} days from now)"
                )
        except ValueError:
            errors.append(f"Unable to parse new not_after: {new_na_result.stdout.strip()}")

    if errors:
        print("Certificate rotation verification failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print("Certificates rotated successfully")
    return 0


if __name__ == "__main__":
    sys.exit(main())

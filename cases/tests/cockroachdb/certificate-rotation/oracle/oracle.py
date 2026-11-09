#!/usr/bin/env python3
# Verify the TLS certs were rotated (secure SQL works, node/CA fingerprints,
# ~1y validity). The cert secret name (BENCH_PARAM_CERT_SECRET_NAME) and the
# pre-rotation fingerprint ConfigMap name (BENCH_PARAM_OLD_CERT_CONFIGMAP_NAME)
# come from the case params, so a workflow that overrides them is honored
# instead of a hardcoded value. Standalone (default params) this behaves
# identically.
import os
import subprocess
import sys
import time
from datetime import datetime, timezone


CERT_SECRET = os.environ.get("BENCH_PARAM_CERT_SECRET_NAME", "crdb-cluster-certs")
OLD_CERT_CM = os.environ.get("BENCH_PARAM_OLD_CERT_CONFIGMAP_NAME", "crdb-old-cert")


def run(cmd, timeout=30):
    """Run a command with a hard timeout (O17); a timeout becomes a failed result."""
    try:
        return subprocess.run(
            cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(
            cmd, 124, exc.stdout or "", (exc.stderr or "") + "\n[command timed out]"
        )


def served_leaf_fingerprint():
    """SHA-256 fingerprint of the leaf cert crdb-cluster-0 actually SERVES (O37).

    Read via a live TLS handshake from the openssl-toolbox pod (the crdb image
    does not ship openssl, O12) against pod-0's HTTP port 8080 -- a secure
    CockroachDB node serves its node cert there. The s_client is bounded both
    in-pod (`timeout 15`) and on the exec (O17). Returns (fingerprint, error).
    """
    cmd = [
        "kubectl", "-n", "cockroachdb", "exec", "openssl-toolbox", "--",
        "sh", "-c",
        "timeout 15 openssl s_client -connect "
        "crdb-cluster-0.crdb-cluster.cockroachdb.svc.cluster.local:8080 "
        "-showcerts </dev/null 2>/dev/null | "
        "openssl x509 -noout -fingerprint -sha256",
    ]
    result = run(cmd, timeout=30)
    if result.returncode != 0 or "=" not in result.stdout:
        return "", (result.stderr.strip() or result.stdout.strip() or "TLS handshake failed")
    return result.stdout.strip().split("=", 1)[-1].upper().replace(":", ""), ""


def main():
    errors = []

    secure_cmd = [
        "kubectl",
        "-n",
        "cockroachdb",
        "exec",
        "crdb-cluster-0",
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
        "cockroachdb",
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
        "cockroachdb",
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
        f"kubectl -n cockroachdb get secret {CERT_SECRET} "
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
    # Require the leaf cert pod-0 actually presents in the TLS handshake to
    # equal the Secret's new node.crt. The pods may still be settling from the
    # agent's restart, so poll to a bounded deadline (~90s, kept under the
    # oracle timeout_sec per O21); a node never reloaded keeps serving the old
    # leaf and still fails after the deadline.
    if new_fp:
        deadline = time.monotonic() + 90
        served_fp, served_err = served_leaf_fingerprint()
        while served_fp != new_fp and time.monotonic() < deadline:
            time.sleep(6)
            served_fp, served_err = served_leaf_fingerprint()
        if served_fp != new_fp:
            if served_fp:
                errors.append(
                    "Served certificate does not match rotated node.crt "
                    f"(served {served_fp[:16]}..., secret {new_fp[:16]}...)"
                )
            else:
                errors.append(f"Unable to read served certificate: {served_err}")

    new_na_cmd = [
        "/bin/sh",
        "-c",
        f"kubectl -n cockroachdb get secret {CERT_SECRET} "
        "-o jsonpath='{.data.node\\.crt}' | base64 -d | "
        "openssl x509 -noout -enddate",
    ]
    ca_old_cmd = [
        "kubectl",
        "-n",
        "cockroachdb",
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
        f"kubectl -n cockroachdb get secret {CERT_SECRET} "
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
            # "about 1 year" per the prompt: require the NEW cert valid for at
            # least ~10 months FROM NOW (absolute), NOT merely outliving the OLD
            # cert. Standalone the old leaf is deliberately 2 days (gen-old-certs.sh)
            # so a relative check happened to work; but when this case is chained
            # after a stage that installed multi-year certs (e.g. generate-cert),
            # the inherited old cert is long-lived, so "new must outlive old by
            # 300d" wrongly failed a correct ~1-year rotation. The forward-looking
            # floor still rejects a too-short cert in both standalone and composed.
            days_from_now = (new_not_after - datetime.now(timezone.utc)).days
            if days_from_now < 300:
                errors.append(f"New certificate validity too short ({days_from_now} days from now)")
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

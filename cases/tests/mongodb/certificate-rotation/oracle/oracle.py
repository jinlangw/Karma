#!/usr/bin/env python3
import argparse
import base64
import datetime
import json
import os
import subprocess
import sys
import time


NAMESPACE = os.environ.get("BENCH_NAMESPACE", "mongodb")
CLUSTER_PREFIX = os.environ.get("BENCH_PARAM_CLUSTER_PREFIX", "mongo-rs")
SERVICE_NAME = os.environ.get("BENCH_PARAM_SERVICE_NAME", "mongo")
OPENSSL_POD = os.environ.get("BENCH_PARAM_OPENSSL_POD_NAME", "openssl-toolbox")
TLS_CA_SECRET = os.environ.get("BENCH_PARAM_TLS_CA_SECRET_NAME", "mongodb-tls-ca")
TLS_CERT_SECRET = os.environ.get("BENCH_PARAM_TLS_CERT_SECRET_NAME", "mongodb-tls-cert")
OLD_CONFIGMAP = os.environ.get("BENCH_PARAM_OLD_TLS_CONFIGMAP_NAME", "mongodb-tls-old")
MIN_VALID_DAYS = int(os.environ.get("BENCH_PARAM_TARGET_VALIDITY_MIN_DAYS", "300"))
MAX_VALID_DAYS = int(os.environ.get("BENCH_PARAM_TARGET_VALIDITY_MAX_DAYS", "400"))
TLS_URI = "mongodb://localhost:27017/?directConnection=true"


def run(cmd, input_data=None, text=True, timeout=30):
    """Run a command bounded (O17): a hung kubectl/mongosh/s_client exec
    becomes a failed attempt instead of an uncaught TimeoutExpired that would
    crash the whole oracle at its deadline."""
    try:
        return subprocess.run(
            cmd,
            input=input_data,
            text=text,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        out, err = ("", "timed out") if text else (b"", b"timed out")
        return subprocess.CompletedProcess(cmd, 124, out, err)


def fail(prefix, errors):
    if errors:
        print(prefix, file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1
    return 0


def get_configmap_value(name, key, errors):
    res = run([
        "kubectl", "-n", NAMESPACE, "get", "configmap", name, "-o", f"jsonpath={{.data.{key}}}"
    ])
    if res.returncode != 0:
        errors.append(f"Failed to read configmap {name}: {res.stderr.strip() or res.stdout.strip()}")
        return None
    return (res.stdout or "").strip()


def get_secret_bytes(secret_name, key, errors):
    res = run([
        "kubectl", "-n", NAMESPACE, "get", "secret", secret_name, "-o", "json"
    ])
    if res.returncode != 0:
        errors.append(f"Failed to read secret {secret_name}: {res.stderr.strip() or res.stdout.strip()}")
        return None
    try:
        data = json.loads(res.stdout).get("data", {})
        val = data.get(key)
    except Exception:
        errors.append(f"Failed to parse secret {secret_name} JSON")
        return None
    if not val:
        errors.append(f"Secret {secret_name} missing key {key}")
        return None
    try:
        return base64.b64decode(val)
    except Exception:
        errors.append(f"Failed to decode secret {secret_name}.{key}")
        return None


def openssl_fingerprint_from_pem(pem_bytes, label, errors):
    res = run(
        [
            "kubectl", "-n", NAMESPACE, "exec", "-i", OPENSSL_POD, "--",
            "openssl", "x509", "-noout", "-fingerprint", "-sha256",
        ],
        input_data=pem_bytes,
        text=False,
    )
    if res.returncode != 0:
        errors.append(f"{label} fingerprint failed: {res.stderr.decode().strip() or res.stdout.decode().strip()}")
        return None
    out = res.stdout.decode().strip()
    if "=" not in out:
        errors.append(f"Unable to parse {label} fingerprint output")
        return None
    return out.split("=", 1)[1].strip()


def openssl_not_after_from_pem(pem_bytes, label, errors):
    res = run(
        [
            "kubectl", "-n", NAMESPACE, "exec", "-i", OPENSSL_POD, "--",
            "openssl", "x509", "-noout", "-enddate",
        ],
        input_data=pem_bytes,
        text=False,
    )
    if res.returncode != 0:
        errors.append(f"{label} enddate failed: {res.stderr.decode().strip() or res.stdout.decode().strip()}")
        return None
    out = res.stdout.decode().strip()
    if not out.lower().startswith("notafter="):
        errors.append(f"Unable to parse {label} notAfter output")
        return None
    return out.split("=", 1)[1].strip()


def parse_not_after(not_after, errors):
    try:
        return datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
    except Exception:
        errors.append(f"Unable to parse notAfter value: {not_after}")
        return None


def check_fingerprints():
    errors = []
    old_server_fp = get_configmap_value(OLD_CONFIGMAP, "server_fingerprint_sha256", errors)
    old_ca_fp = get_configmap_value(OLD_CONFIGMAP, "ca_fingerprint_sha256", errors)

    server_pem = get_secret_bytes(TLS_CERT_SECRET, "server.pem", errors)
    ca_pem = get_secret_bytes(TLS_CA_SECRET, "ca.crt", errors)

    if server_pem is None or ca_pem is None:
        return fail("Certificate rotation fingerprint check failed:", errors)

    cur_server_fp = openssl_fingerprint_from_pem(server_pem, "server", errors)
    cur_ca_fp = openssl_fingerprint_from_pem(ca_pem, "ca", errors)

    if old_server_fp and cur_server_fp and old_server_fp == cur_server_fp:
        errors.append("server certificate fingerprint did not change")
    if old_ca_fp and cur_ca_fp and old_ca_fp != cur_ca_fp:
        errors.append("CA fingerprint changed; CA trust must remain unchanged")

    return fail("Certificate rotation fingerprint check failed:", errors)


def check_validity():
    errors = []
    server_pem = get_secret_bytes(TLS_CERT_SECRET, "server.pem", errors)
    if server_pem is None:
        return fail("Certificate rotation validity check failed:", errors)

    not_after = openssl_not_after_from_pem(server_pem, "server", errors)
    if not_after:
        expires_at = parse_not_after(not_after, errors)
        if expires_at:
            now = datetime.datetime.now(datetime.timezone.utc)
            days_left = (expires_at - now).days
            if days_left < MIN_VALID_DAYS:
                errors.append(f"rotated certificate validity too short: {days_left} days")
            if days_left > MAX_VALID_DAYS:
                errors.append(f"rotated certificate validity too long: {days_left} days")

    return fail("Certificate rotation validity check failed:", errors)


def check_tls():
    errors = []

    tls = run([
        "kubectl", "-n", NAMESPACE, "exec", f"{CLUSTER_PREFIX}-0", "--", "mongosh", "--quiet", TLS_URI,
        "--tls", "--tlsAllowInvalidHostnames", "--tlsCAFile", "/etc/mongo-ca/ca.crt", "--eval", "db.hello().ok",
    ])
    if tls.returncode != 0:
        errors.append(f"TLS connection failed: {tls.stderr.strip() or tls.stdout.strip()}")

    # Deliberate negative probe (O32): the plain connect MUST fail. Cap server
    # selection at 5s so the expected failure resolves fast instead of burning
    # the default 30s window against the closed TLS listener (O21).
    plain = run([
        "kubectl", "-n", NAMESPACE, "exec", f"{CLUSTER_PREFIX}-0", "--", "mongosh", "--quiet",
        TLS_URI + "&serverSelectionTimeoutMS=5000",
        "--eval", "db.hello().ok",
    ])
    if plain.returncode == 0:
        errors.append("insecure connection unexpectedly succeeded")

    return fail("Certificate rotation TLS check failed:", errors)


def _sts_replicas():
    """Member count to check served certs on: the live spec.replicas, else 3."""
    res = run(["kubectl", "-n", NAMESPACE, "get", "sts", CLUSTER_PREFIX,
               "-o", "jsonpath={.spec.replicas}"])
    raw = (res.stdout or "").strip()
    if res.returncode == 0 and raw.isdigit() and int(raw) > 0:
        return int(raw)
    return 3


def _served_leaf_fingerprint(idx):
    """SHA-256 fingerprint of the leaf cert member `idx` presents in a live
    TLS handshake, read via the case's openssl-toolbox. Bounded twice (O17):
    `timeout 15` around s_client inside the toolbox plus a subprocess cap.
    Returns None when the handshake/read fails (caller retries transport)."""
    host = f"{CLUSTER_PREFIX}-{idx}.{SERVICE_NAME}.{NAMESPACE}.svc.cluster.local"
    res = run(
        [
            "kubectl", "-n", NAMESPACE, "exec", OPENSSL_POD, "--", "/bin/sh", "-c",
            f"timeout 15 openssl s_client -connect {host}:27017 -showcerts </dev/null 2>/dev/null"
            " | openssl x509 -noout -fingerprint -sha256",
        ],
        timeout=25,
    )
    out = (res.stdout or "").strip()
    if res.returncode != 0 or "=" not in out:
        return None
    return out.split("=", 1)[1].strip()


def check_served_cert():
    """O37: grade the certificate each member actually SERVES, not just the
    stored Secret bytes -- an agent that updates the Secret but never reloads
    mongod leaves the old leaf live in the handshake and must fail. Checked on
    EVERY member (O31); the leaf presented by each handshake must equal the
    certificate in the rotated server.pem. Only the transport read is retried
    (O18); a stable mismatch fails on every attempt."""
    errors = []
    server_pem = get_secret_bytes(TLS_CERT_SECRET, "server.pem", errors)
    if server_pem is None:
        return fail("Certificate rotation served-cert check failed:", errors)
    want_fp = openssl_fingerprint_from_pem(server_pem, "server", errors)
    if want_fp is None:
        return fail("Certificate rotation served-cert check failed:", errors)

    for idx in range(_sts_replicas()):
        got_fp = None
        for _attempt in range(2):
            got_fp = _served_leaf_fingerprint(idx)
            if got_fp is not None:
                break
            time.sleep(5)
        if got_fp is None:
            errors.append(f"could not read the served certificate from {CLUSTER_PREFIX}-{idx}")
        elif got_fp != want_fp:
            errors.append(
                f"{CLUSTER_PREFIX}-{idx} serves leaf {got_fp}, expected the rotated "
                f"server.pem cert {want_fp} -- the Secret was updated but this member "
                f"was never reloaded"
            )

    return fail("Certificate rotation served-cert check failed:", errors)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", default="all", choices=["all", "fingerprints", "validity", "tls", "served_cert"])
    args = parser.parse_args()

    if args.check == "fingerprints":
        return check_fingerprints()
    if args.check == "validity":
        return check_validity()
    if args.check == "tls":
        return check_tls()
    if args.check == "served_cert":
        return check_served_cert()

    for fn in (check_fingerprints, check_validity, check_tls, check_served_cert):
        rc = fn()
        if rc != 0:
            return rc
    print("Certificate rotation verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())

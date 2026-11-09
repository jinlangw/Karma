#!/usr/bin/env python3
import argparse
import os
import subprocess
import sys


NAMESPACE = os.environ.get("BENCH_NAMESPACE", "mongodb")
CLUSTER_PREFIX = os.environ.get("BENCH_PARAM_CLUSTER_PREFIX", "mongo-rs")
POD = f"{CLUSTER_PREFIX}-0"
APP_DB = os.environ.get("BENCH_PARAM_APP_DATABASE", "app")
APP_COLLECTION = os.environ.get("BENCH_PARAM_APP_COLLECTION", "test")
SEED_DOCS = int(os.environ.get("BENCH_PARAM_SEED_DOCS", "3"))
TLS_URI = "mongodb://localhost:27017/?directConnection=true"


def run(cmd, timeout=30):
    """Run a command bounded (O17): a hung kubectl/mongosh exec becomes a
    failed attempt instead of an uncaught TimeoutExpired that would crash the
    whole oracle at its deadline."""
    try:
        return subprocess.run(cmd, text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, 124, "", "timed out")


def fail(prefix, errors):
    if errors:
        print(prefix, file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1
    return 0


def check_plain_blocked():
    # Deliberate negative probe (O32): the plain connect MUST fail. Cap server
    # selection at 5s so the expected failure resolves fast instead of burning
    # the full bounded-exec window against the closed TLS listener (O21).
    errors = []
    plain = run([
        "kubectl", "-n", NAMESPACE, "exec", POD, "--", "mongosh", "--quiet",
        "mongodb://localhost:27017/?directConnection=true&serverSelectionTimeoutMS=5000",
        "--eval", "db.adminCommand({ping:1})"
    ])
    if plain.returncode == 0:
        errors.append("plain connection succeeded; TLS is not required")
    return fail("TLS setup plain-blocked check failed:", errors)


def tls_base_cmd(eval_str):
    # The task sets up mutual TLS (the prompt has the agent mount a client cert at
    # /etc/tls/client.pem), so mongod requires the client to present it -- connect
    # with both the CA and the client certificate or the server closes the socket.
    return [
        "kubectl", "-n", NAMESPACE, "exec", POD, "--", "mongosh", "--quiet", TLS_URI,
        "--tls", "--tlsAllowInvalidHostnames", "--tlsCAFile", "/etc/tls/ca.crt",
        "--tlsCertificateKeyFile", "/etc/tls/client.pem", "--eval", eval_str,
    ]


def check_tls_ok():
    errors = []
    ping = run(tls_base_cmd("db.adminCommand({ping:1}).ok"))
    if ping.returncode != 0:
        errors.append(f"TLS ping failed: {ping.stderr.strip() or ping.stdout.strip()}")

    status = run(tls_base_cmd("rs.status().ok"))
    if status.returncode != 0:
        errors.append(f"TLS rs.status failed: {status.stderr.strip() or status.stdout.strip()}")
    elif (status.stdout or "").strip() != "1":
        errors.append(f"TLS rs.status unexpected: {(status.stdout or '').strip()}")

    return fail("TLS setup tls-ok check failed:", errors)


def check_data():
    errors = []
    count = run(
        tls_base_cmd(
            f'db.getMongo().setReadPref("secondaryPreferred");'
            f'db.getSiblingDB("{APP_DB}").{APP_COLLECTION}.countDocuments({{}})'
        )
    )
    if count.returncode != 0:
        errors.append(f"TLS data count failed: {count.stderr.strip() or count.stdout.strip()}")
    else:
        raw = (count.stdout or "").strip()
        if not raw.isdigit() or int(raw) < SEED_DOCS:
            errors.append(f"expected >= {SEED_DOCS} docs in {APP_DB}.{APP_COLLECTION}, got {raw}")

    return fail("TLS setup data check failed:", errors)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", default="all", choices=["all", "plain_blocked", "tls_ok", "data"])
    args = parser.parse_args()

    if args.check == "plain_blocked":
        return check_plain_blocked()
    if args.check == "tls_ok":
        return check_tls_ok()
    if args.check == "data":
        return check_data()

    for fn in (check_plain_blocked, check_tls_ok, check_data):
        rc = fn()
        if rc != 0:
            return rc
    print("MongoDB TLS setup verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())

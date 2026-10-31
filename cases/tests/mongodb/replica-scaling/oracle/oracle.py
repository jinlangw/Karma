#!/usr/bin/env python3
import argparse
import base64
import json
import os
import subprocess
import sys
import time


NAMESPACE = os.environ.get("BENCH_NAMESPACE", "mongodb")
CLUSTER_PREFIX = os.environ.get("BENCH_PARAM_CLUSTER_PREFIX", "mongodb-replica")
HEADLESS_SERVICE = os.environ.get("BENCH_PARAM_HEADLESS_SERVICE_NAME", "mongodb-replica-svc")
REPLICA_SET_NAME = os.environ.get("BENCH_PARAM_REPLICA_SET_NAME", CLUSTER_PREFIX)
TARGET_REPLICAS = int(os.environ.get("BENCH_PARAM_TARGET_REPLICAS", "5"))
ADMIN_SECRET = os.environ.get("BENCH_PARAM_ADMIN_SECRET_NAME", "admin-user-password")
ADMIN_USERNAME = os.environ.get("BENCH_PARAM_ADMIN_USERNAME", "admin-user")
APP_DATABASE = os.environ.get("BENCH_PARAM_APP_DATABASE", "testdb")
APP_COLLECTION = os.environ.get("BENCH_PARAM_APP_COLLECTION", "data")
SEED_DOCS = int(os.environ.get("BENCH_PARAM_SEED_DOCS", "3"))


def run(cmd, timeout=30):
    """Run a command bounded (O17): a hung kubectl/mongosh exec becomes a
    failed attempt instead of an uncaught TimeoutExpired that would crash the
    whole oracle at its deadline."""
    try:
        return subprocess.run(cmd, text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, 124, "", "timed out")


_TLS_FLAGS_CACHE = None


def _mongo_tls_flags(probe_pod=None):
    """mongosh transport flags that adapt to the cluster's LIVE TLS mode.

    The environment PERSISTS across workflow stages, so an earlier stage
    (mongodb/tls-setup or mongodb/certificate-rotation) may have turned TLS on,
    after which a plain mongosh connection is refused. Detect TLS by probing the
    running mongo pod for a CA cert mounted at the paths the TLS stages use; if
    present, connect with --tls --tlsCAFile (and a client cert for mutual TLS
    when one is mounted), else connect plain. Standalone (no CA mounted) this
    returns [] -> identical plain behaviour. It only adds transport flags; every
    real check still runs and still fails when its condition is unmet.
    """
    global _TLS_FLAGS_CACHE
    if _TLS_FLAGS_CACHE is not None:
        return list(_TLS_FLAGS_CACHE)
    flags = []
    pod = probe_pod or f"{CLUSTER_PREFIX}-0"
    ca_path = None
    for cand in (
        "/etc/tls/ca.crt",
        "/etc/mongo-ca/ca.crt",
        "/etc/mongodb/tls/ca.crt",
        "/etc/ssl/mongodb/ca.crt",
    ):
        probe = run(["kubectl", "-n", NAMESPACE, "exec", pod, "--", "/bin/sh", "-c", "test -f " + cand])
        if probe.returncode == 0:
            ca_path = cand
            break
    if ca_path:
        flags = ["--tls", "--tlsAllowInvalidHostnames", "--tlsAllowInvalidCertificates", "--tlsCAFile", ca_path]
        for client_pem in ("/etc/tls/client.pem", "/etc/mongo-ca/client.pem"):
            cprobe = run(["kubectl", "-n", NAMESPACE, "exec", pod, "--", "/bin/sh", "-c", "test -f " + client_pem])
            if cprobe.returncode == 0:
                flags += ["--tlsCertificateKeyFile", client_pem]
                break
    _TLS_FLAGS_CACHE = flags
    return list(flags)

def fail(prefix, errors):
    if errors:
        print(prefix, file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1
    return 0


def get_secret(secret_name, key, errors):
    res = run(
        [
            "kubectl",
            "-n",
            NAMESPACE,
            "get",
            "secret",
            secret_name,
            "-o",
            f"jsonpath={{.data.{key}}}",
        ]
    )
    if res.returncode != 0:
        detail = res.stderr.strip() or res.stdout.strip() or f"exit {res.returncode}"
        errors.append(f"Failed to read secret {secret_name}: {detail}")
        return None
    raw = (res.stdout or "").strip()
    if not raw:
        errors.append(f"Secret {secret_name}.{key} is empty")
        return None
    try:
        return base64.b64decode(raw).decode("utf-8")
    except Exception:
        errors.append(f"Failed to decode secret {secret_name}.{key}")
        return None


def mongo_eval(pod, uri, script):
    return run(
        [
            "kubectl",
            "-n",
            NAMESPACE,
            "exec",
            pod,
            "--",
            "mongosh",
            "--quiet",
            *_mongo_tls_flags(),
            uri,
            "--eval",
            script,
        ]
    )


def mongo_json(pod, uri, script, label, errors):
    res = mongo_eval(pod, uri, script)
    if res.returncode != 0:
        detail = res.stderr.strip() or res.stdout.strip() or f"exit {res.returncode}"
        errors.append(f"{label} failed on {pod}: {detail}")
        return None
    raw = (res.stdout or "").strip()
    if not raw:
        errors.append(f"{label} returned empty output on {pod}")
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        errors.append(f"Unable to parse {label} JSON output on {pod}")
        return None


def find_primary(uri, errors):
    for idx in range(TARGET_REPLICAS):
        pod = f"{CLUSTER_PREFIX}-{idx}"
        res = mongo_eval(pod, uri, "db.hello().isWritablePrimary")
        if res.returncode == 0 and "true" in (res.stdout or ""):
            return pod
    errors.append("Unable to locate primary pod")
    return f"{CLUSTER_PREFIX}-0"


def _workload_attempt():
    errors = []
    res = run(["kubectl", "-n", NAMESPACE, "get", "sts", CLUSTER_PREFIX, "-o", "json"])
    if res.returncode != 0:
        detail = res.stderr.strip() or res.stdout.strip() or f"exit {res.returncode}"
        errors.append(f"Failed to read statefulset {CLUSTER_PREFIX}: {detail}")
        return errors
    try:
        sts = json.loads(res.stdout)
    except json.JSONDecodeError:
        errors.append("Failed to parse statefulset JSON")
        return errors

    spec_replicas = sts.get("spec", {}).get("replicas")
    ready_replicas = sts.get("status", {}).get("readyReplicas", 0)
    if spec_replicas != TARGET_REPLICAS:
        errors.append(f"StatefulSet replicas expected {TARGET_REPLICAS}, got {spec_replicas}")
    if ready_replicas != TARGET_REPLICAS:
        errors.append(f"Ready replicas expected {TARGET_REPLICAS}, got {ready_replicas}")

    pods = run(["kubectl", "-n", NAMESPACE, "get", "pods", "-l", f"app={CLUSTER_PREFIX}", "-o", "json"])
    if pods.returncode != 0:
        detail = pods.stderr.strip() or pods.stdout.strip() or f"exit {pods.returncode}"
        errors.append(f"Failed to read pods: {detail}")
        return errors
    try:
        pod_obj = json.loads(pods.stdout)
    except json.JSONDecodeError:
        errors.append("Failed to parse pod JSON")
        return errors

    items = pod_obj.get("items", [])
    if len(items) != TARGET_REPLICAS:
        errors.append(f"Expected {TARGET_REPLICAS} pods, got {len(items)}")

    return errors


def check_workload():
    # O-flap-restart: scaling adds a new mongod pod that joins via
    # STARTUP2/RECOVERING, so readyReplicas and the pod count read short until it
    # is Ready. Poll to convergence (~120s, 5s between attempts); assertions
    # unchanged.
    deadline = time.monotonic() + 120
    errors = []
    while True:
        errors = _workload_attempt()
        if not errors:
            break
        if time.monotonic() >= deadline:
            break
        time.sleep(5)
    return fail("MongoDB replica-scaling workload check failed:", errors)


def _topology_attempt():
    errors = []
    admin_pw = get_secret(ADMIN_SECRET, "password", errors)
    if errors:
        return errors
    # directConnection skips SDAM topology monitoring, which a localhost
    # connection would start and which fails under a persisted requireTLS mode.
    uri = f"mongodb://{ADMIN_USERNAME}:{admin_pw}@localhost:27017/admin?directConnection=true"
    primary = find_primary(uri, errors)

    conf = mongo_json(primary, uri, "JSON.stringify(rs.conf())", "rs.conf()", errors)
    if isinstance(conf, dict):
        members = conf.get("members", [])
        if len(members) != TARGET_REPLICAS:
            errors.append(f"Expected {TARGET_REPLICAS} members in rs.conf(), got {len(members)}")
        hosts = {m.get("host") for m in members if m.get("host")}
        expected_hosts = {
            f"{CLUSTER_PREFIX}-{i}.{HEADLESS_SERVICE}.{NAMESPACE}.svc.cluster.local:27017"
            for i in range(TARGET_REPLICAS)
        }
        if hosts != expected_hosts:
            errors.append("Replica set hosts do not match scaled membership")

    status = mongo_json(primary, uri, "JSON.stringify(rs.status())", "rs.status()", errors)
    if isinstance(status, dict):
        if status.get("set") != REPLICA_SET_NAME:
            errors.append(f"Replica set name expected {REPLICA_SET_NAME}, got {status.get('set')}")
        members = status.get("members", [])
        p = sum(1 for m in members if m.get("stateStr") == "PRIMARY")
        s = sum(1 for m in members if m.get("stateStr") == "SECONDARY")
        if p != 1:
            errors.append(f"Expected 1 PRIMARY, got {p}")
        if s != TARGET_REPLICAS - 1:
            errors.append(f"Expected {TARGET_REPLICAS - 1} SECONDARY, got {s}")

    return errors


def check_topology():
    # O-flap-restart: the newly-scaled-in member sits in a STARTUP2/RECOVERING
    # rejoin window, reading the SECONDARY tally short. Poll to convergence
    # (~120s, 5s between attempts); assertion not loosened.
    deadline = time.monotonic() + 120
    errors = []
    while True:
        errors = _topology_attempt()
        if not errors:
            break
        if time.monotonic() >= deadline:
            break
        time.sleep(5)
    return fail("MongoDB replica-scaling topology check failed:", errors)


def check_data():
    errors = []
    admin_pw = get_secret(ADMIN_SECRET, "password", errors)
    if errors:
        return fail("MongoDB replica-scaling data check failed:", errors)
    # directConnection skips SDAM topology monitoring (see check_topology).
    uri = f"mongodb://{ADMIN_USERNAME}:{admin_pw}@localhost:27017/admin?directConnection=true"
    primary = find_primary(uri, errors)

    res = mongo_eval(
        primary,
        uri,
        f"db.getSiblingDB('{APP_DATABASE}').{APP_COLLECTION}.countDocuments({{}})",
    )
    if res.returncode != 0:
        detail = res.stderr.strip() or res.stdout.strip() or f"exit {res.returncode}"
        errors.append(f"Failed to read {APP_DATABASE}.{APP_COLLECTION}: {detail}")
    else:
        raw = (res.stdout or "").strip()
        if not raw.isdigit() or int(raw) < SEED_DOCS:
            errors.append(f"Expected >= {SEED_DOCS} docs in {APP_DATABASE}.{APP_COLLECTION}, got {raw}")

    return fail("MongoDB replica-scaling data check failed:", errors)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", default="all", choices=["all", "workload", "topology", "data"])
    args = parser.parse_args()

    if args.check == "workload":
        return check_workload()
    if args.check == "topology":
        return check_topology()
    if args.check == "data":
        return check_data()

    for fn in (check_workload, check_topology, check_data):
        rc = fn()
        if rc != 0:
            return rc
    print("MongoDB replica scaling verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())

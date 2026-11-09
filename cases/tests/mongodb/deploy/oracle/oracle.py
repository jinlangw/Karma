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
ADMIN_SECRET = os.environ.get("BENCH_PARAM_ADMIN_SECRET_NAME", "admin-user-password")
APP_SECRET = os.environ.get("BENCH_PARAM_APP_SECRET_NAME", "app-user-password")
ADMIN_USER = os.environ.get("BENCH_PARAM_ADMIN_USERNAME", "admin-user")
APP_USER = os.environ.get("BENCH_PARAM_APP_USERNAME", "app-user")
APP_DATABASE = os.environ.get("BENCH_PARAM_APP_DATABASE", "appdb")
POD_PREFIX = f"{CLUSTER_PREFIX}-"


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

def _resolve_expected_replicas():
    """Topology size to enforce: param-first, defaulting to 3 (O2 exception).

    The member count IS this case's graded outcome -- the prompt promises a
    3-member replica set -- so it is never derived from the live cluster
    (live-deriving would mask a failed or partial deployment). An explicit
    ``expected_replicas``/``target_replicas`` param override wins, else 3.
    """
    for key in ("BENCH_PARAM_EXPECTED_REPLICAS", "BENCH_PARAM_TARGET_REPLICAS"):
        val = os.environ.get(key)
        if val is not None and str(val).strip():
            try:
                return int(val)
            except ValueError:
                pass
    return 3


EXPECTED_REPLICAS = _resolve_expected_replicas()


def fail(prefix, errors):
    if errors:
        print(prefix, file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1
    return 0


def get_secret_value(secret_name, key, errors):
    result = run(
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
    if result.returncode != 0:
        errors.append(f"Failed to read secret {secret_name}: {result.stderr.strip()}")
        return None
    encoded = (result.stdout or "").strip()
    if not encoded:
        errors.append(f"Secret {secret_name}.{key} is empty")
        return None
    try:
        return base64.b64decode(encoded).decode("utf-8")
    except Exception:
        errors.append(f"Failed to decode secret {secret_name}.{key}")
        return None


def run_mongo(pod, uri, eval_str):
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
            eval_str,
        ]
    )


def load_json(pod, uri, eval_str, label, errors):
    result = run_mongo(pod, uri, eval_str)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        errors.append(f"{label} failed on {pod}: {detail}")
        return None
    raw = (result.stdout or "").strip()
    if not raw:
        errors.append(f"{label} returned empty output on {pod}")
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        errors.append(f"Unable to parse {label} JSON output on {pod}")
        return None


def find_primary(admin_uri, errors):
    for idx in range(EXPECTED_REPLICAS):
        pod = f"{POD_PREFIX}{idx}"
        result = run_mongo(pod, admin_uri, "db.hello().isWritablePrimary")
        if result.returncode == 0 and "true" in (result.stdout or ""):
            return pod
    errors.append("Unable to locate primary pod")
    return f"{POD_PREFIX}0"


def check_service():
    errors = []
    result = run(["kubectl", "-n", NAMESPACE, "get", "svc", HEADLESS_SERVICE])
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        errors.append(f"Headless service missing: {detail}")
    return fail("MongoDB deploy service check failed:", errors)


def _workload_attempt():
    errors = []
    sts_result = run(
        ["kubectl", "-n", NAMESPACE, "get", "sts", CLUSTER_PREFIX, "-o", "json"]
    )
    if sts_result.returncode != 0:
        detail = sts_result.stderr.strip() or sts_result.stdout.strip() or f"exit {sts_result.returncode}"
        errors.append(f"Failed to read statefulset {CLUSTER_PREFIX}: {detail}")
        return errors
    try:
        sts = json.loads(sts_result.stdout)
    except json.JSONDecodeError:
        errors.append("Failed to parse statefulset JSON")
        return errors

    spec_replicas = sts.get("spec", {}).get("replicas")
    ready_replicas = sts.get("status", {}).get("readyReplicas")
    if spec_replicas != EXPECTED_REPLICAS:
        errors.append(f"StatefulSet replicas expected {EXPECTED_REPLICAS}, got {spec_replicas}")
    if ready_replicas != EXPECTED_REPLICAS:
        errors.append(f"Ready replicas expected {EXPECTED_REPLICAS}, got {ready_replicas}")

    pods_result = run(
        [
            "kubectl",
            "-n",
            NAMESPACE,
            "get",
            "pods",
            "-l",
            f"app={CLUSTER_PREFIX}",
            "-o",
            "json",
        ]
    )
    if pods_result.returncode != 0:
        detail = pods_result.stderr.strip() or pods_result.stdout.strip() or f"exit {pods_result.returncode}"
        errors.append(f"Failed to read pods: {detail}")
        return errors
    try:
        pods = json.loads(pods_result.stdout)
    except json.JSONDecodeError:
        errors.append("Failed to parse pods JSON")
        return errors

    items = pods.get("items", [])
    if len(items) != EXPECTED_REPLICAS:
        errors.append(f"Expected {EXPECTED_REPLICAS} pods, got {len(items)}")
    for pod in items:
        name = pod.get("metadata", {}).get("name", "unknown")
        conditions = pod.get("status", {}).get("conditions", [])
        ready = next((c for c in conditions if c.get("type") == "Ready"), {})
        if ready.get("status") != "True":
            errors.append(f"Pod {name} is not Ready")

    return errors


def check_workload():
    # O-flap-restart: a freshly-deployed StatefulSet brings pods Ready staggered,
    # so readyReplicas/Ready and the pod count read short during formation. Poll
    # to convergence (~120s, 5s between attempts); assertions unchanged.
    deadline = time.monotonic() + 120
    errors = []
    while True:
        errors = _workload_attempt()
        if not errors:
            break
        if time.monotonic() >= deadline:
            break
        time.sleep(5)
    return fail("MongoDB deploy workload check failed:", errors)


def _topology_attempt():
    errors = []
    admin_pw = get_secret_value(ADMIN_SECRET, "password", errors)
    if errors:
        return errors
    # directConnection skips SDAM topology monitoring, which a localhost
    # connection would start and which fails under a persisted requireTLS mode.
    admin_uri = f"mongodb://{ADMIN_USER}:{admin_pw}@localhost:27017/admin?directConnection=true"
    primary_pod = find_primary(admin_uri, errors)
    status = load_json(primary_pod, admin_uri, "JSON.stringify(rs.status())", "rs.status()", errors)
    if isinstance(status, dict):
        set_name = status.get("set")
        if set_name != REPLICA_SET_NAME:
            errors.append(f"Replica set name expected {REPLICA_SET_NAME}, got {set_name}")
        members = status.get("members", [])
        primary = sum(1 for m in members if m.get("stateStr") == "PRIMARY")
        secondary = sum(1 for m in members if m.get("stateStr") == "SECONDARY")
        if primary != 1:
            errors.append(f"Expected 1 PRIMARY, got {primary}")
        if secondary != EXPECTED_REPLICAS - 1:
            errors.append(f"Expected {EXPECTED_REPLICAS - 1} SECONDARY, got {secondary}")
    else:
        errors.append("Unable to read replica set status")
    return errors


def check_topology():
    # O-flap-restart: members join via STARTUP2/RECOVERING during set formation,
    # reading the PRIMARY/SECONDARY tally short. Poll to convergence (~120s, 5s
    # between attempts); assertion not loosened.
    deadline = time.monotonic() + 120
    errors = []
    while True:
        errors = _topology_attempt()
        if not errors:
            break
        if time.monotonic() >= deadline:
            break
        time.sleep(5)
    return fail("MongoDB deploy topology check failed:", errors)


def check_auth():
    errors = []
    admin_pw = get_secret_value(ADMIN_SECRET, "password", errors)
    app_pw = get_secret_value(APP_SECRET, "password", errors)
    if errors:
        return fail("MongoDB deploy auth check failed:", errors)

    # directConnection skips SDAM topology monitoring (see check_topology).
    admin_uri = f"mongodb://{ADMIN_USER}:{admin_pw}@localhost:27017/admin?directConnection=true"
    primary_pod = find_primary(admin_uri, errors)

    unauth = run(
        [
            "kubectl",
            "-n",
            NAMESPACE,
            "exec",
            primary_pod,
            "--",
            "mongosh",
            "--quiet",
            *_mongo_tls_flags(),
            "--eval",
            f"db.getSiblingDB('{APP_DATABASE}').records.countDocuments({{}})",
        ]
    )
    if unauth.returncode == 0:
        errors.append("Unauthenticated access succeeded (auth may be disabled)")

    admin_status = load_json(
        primary_pod,
        admin_uri,
        "JSON.stringify(db.runCommand({connectionStatus:1}))",
        "admin connectionStatus",
        errors,
    )
    if isinstance(admin_status, dict):
        auth_users = admin_status.get("authInfo", {}).get("authenticatedUsers", [])
        names = [u.get("user") for u in auth_users]
        if ADMIN_USER not in names:
            errors.append(f"Admin auth user {ADMIN_USER} not present in connection status")

    # The app user is validly defined in EITHER its own db (authSource=appdb) or
    # in admin (authSource=admin) with a role on appdb -- both grant appdb access.
    # Accept whichever the agent chose; only fail if neither authenticates.
    app_status = None
    for _auth_db in (APP_DATABASE, "admin"):
        # directConnection skips SDAM topology monitoring (see check_topology).
        uri = f"mongodb://{APP_USER}:{app_pw}@localhost:27017/{APP_DATABASE}?authSource={_auth_db}&directConnection=true"
        st = load_json(
            primary_pod, uri,
            "JSON.stringify(db.runCommand({connectionStatus:1}))",
            "app connectionStatus", [],
        )
        if isinstance(st, dict):
            app_status = st
            break
    if app_status is None:
        errors.append(
            "app connectionStatus failed: app user could not authenticate "
            "(tried authSource=appdb and authSource=admin)"
        )
    else:
        auth_users = app_status.get("authInfo", {}).get("authenticatedUsers", [])
        names = [u.get("user") for u in auth_users]
        if APP_USER not in names:
            errors.append(f"App auth user {APP_USER} not present in connection status")

    return fail("MongoDB deploy auth check failed:", errors)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        default="all",
        choices=["all", "service", "workload", "topology", "auth"],
    )
    args = parser.parse_args()

    if args.check == "service":
        return check_service()
    if args.check == "workload":
        return check_workload()
    if args.check == "topology":
        return check_topology()
    if args.check == "auth":
        return check_auth()

    checks = [check_service, check_workload, check_topology, check_auth]
    rc = 0
    for fn in checks:
        rc = fn()
        if rc != 0:
            return rc
    print("MongoDB deploy verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())

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
ADMIN_SECRET = os.environ.get("BENCH_PARAM_ADMIN_SECRET_NAME", "admin-user-password")
HEALTH_SECRET = os.environ.get("BENCH_PARAM_HEALTH_SECRET_NAME", "health-user-password")
OVERRIDE_CONFIGMAP = os.environ.get("BENCH_PARAM_HEALTH_OVERRIDES_CONFIGMAP_NAME", "health-overrides")
ADMIN_USER = os.environ.get("BENCH_PARAM_ADMIN_USERNAME", "admin-user")
HEALTH_USER = os.environ.get("BENCH_PARAM_HEALTH_USERNAME", "health-user")
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
    res = run(["kubectl", "-n", NAMESPACE, "get", "secret", secret_name, "-o", f"jsonpath={{.data.{key}}}"])
    if res.returncode != 0:
        errors.append(f"failed to read secret {secret_name}: {res.stderr.strip() or res.stdout.strip()}")
        return None
    raw = (res.stdout or "").strip()
    if not raw:
        errors.append(f"secret {secret_name}.{key} empty")
        return None
    try:
        return base64.b64decode(raw).decode("utf-8")
    except Exception:
        errors.append(f"failed to decode secret {secret_name}.{key}")
        return None


def run_mongo(pod, uri, eval_str):
    return run(["kubectl", "-n", NAMESPACE, "exec", pod, "--", "mongosh", "--quiet", *_mongo_tls_flags(), uri, "--eval", eval_str])


def load_json(pod, uri, eval_str, label, errors):
    res = run_mongo(pod, uri, eval_str)
    if res.returncode != 0:
        errors.append(f"{label} failed on {pod}: {res.stderr.strip() or res.stdout.strip()}")
        return None
    raw = (res.stdout or "").strip()
    if not raw:
        errors.append(f"{label} returned empty output on {pod}")
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        errors.append(f"unable to parse {label} JSON output on {pod}")
        return None


def _find_primary(admin_uri, errors):
    for i in range(EXPECTED_REPLICAS):
        pod = f"{POD_PREFIX}{i}"
        res = run_mongo(pod, admin_uri, "db.hello().isWritablePrimary")
        if res.returncode == 0 and "true" in (res.stdout or ""):
            return pod
    errors.append("unable to locate primary pod")
    return f"{POD_PREFIX}0"


def _workload_attempt():
    """One snapshot of readyReplicas + per-pod Ready. Restart-volatile (fixing
    the readiness probe rolls the StatefulSet), so polled to convergence by
    check_workload. Assertions unchanged."""
    errors = []
    sts_res = run(["kubectl", "-n", NAMESPACE, "get", "sts", CLUSTER_PREFIX, "-o", "json"])
    if sts_res.returncode != 0:
        errors.append(f"failed to read statefulset: {sts_res.stderr.strip() or sts_res.stdout.strip()}")
        return errors
    try:
        sts = json.loads(sts_res.stdout)
    except json.JSONDecodeError:
        errors.append("failed to parse statefulset JSON")
        return errors

    if sts.get("spec", {}).get("replicas") != EXPECTED_REPLICAS:
        errors.append("statefulset replicas mismatch")
    if sts.get("status", {}).get("readyReplicas") != EXPECTED_REPLICAS:
        errors.append("ready replicas mismatch")

    pods_res = run(["kubectl", "-n", NAMESPACE, "get", "pods", "-l", f"app={CLUSTER_PREFIX}", "-o", "json"])
    if pods_res.returncode != 0:
        errors.append(f"failed to read pods: {pods_res.stderr.strip() or pods_res.stdout.strip()}")
        return errors
    try:
        pods = json.loads(pods_res.stdout)
    except json.JSONDecodeError:
        errors.append("failed to parse pods JSON")
        return errors

    items = pods.get("items", [])
    if len(items) != EXPECTED_REPLICAS:
        errors.append(f"expected {EXPECTED_REPLICAS} pods, got {len(items)}")
    for pod in items:
        name = pod.get("metadata", {}).get("name", "unknown")
        ready = next((c for c in pod.get("status", {}).get("conditions", []) if c.get("type") == "Ready"), {})
        if ready.get("status") != "True":
            errors.append(f"pod {name} is not Ready")
    return errors


def check_workload():
    # O-flap-restart: fixing the readiness/liveness probe rolls the StatefulSet,
    # so readyReplicas and per-pod Ready read short while the last pod recreates.
    # Poll to convergence (~120s, 5s between attempts); assertions unchanged.
    deadline = time.monotonic() + 120
    errors = []
    while True:
        errors = _workload_attempt()
        if not errors:
            break
        if time.monotonic() >= deadline:
            break
        time.sleep(5)
    return fail("Health-check recovery workload check failed:", errors)


def _topology_attempt():
    """One snapshot of the replica-set topology. Restart-volatile after the
    probe roll, so polled to convergence by check_topology. Assertion unchanged
    (1 PRIMARY, EXPECTED_REPLICAS-1 SECONDARY, members == EXPECTED_REPLICAS)."""
    errors = []
    admin_pw = get_secret_value(ADMIN_SECRET, "password", errors)
    if errors:
        return errors
    # directConnection skips SDAM topology monitoring, which a localhost
    # connection would start and which fails under a persisted requireTLS mode.
    admin_uri = f"mongodb://{ADMIN_USER}:{admin_pw}@localhost:27017/admin?directConnection=true"
    primary = _find_primary(admin_uri, errors)
    status = load_json(primary, admin_uri, "JSON.stringify(rs.status())", "rs.status()", errors)
    if isinstance(status, dict):
        members = status.get("members", [])
        p = sum(1 for m in members if m.get("stateStr") == "PRIMARY")
        s = sum(1 for m in members if m.get("stateStr") == "SECONDARY")
        if len(members) != EXPECTED_REPLICAS:
            errors.append(f"replica set members expected {EXPECTED_REPLICAS}, got {len(members)}")
        if p != 1:
            errors.append(f"expected 1 PRIMARY, got {p}")
        if s != EXPECTED_REPLICAS - 1:
            errors.append(f"expected {EXPECTED_REPLICAS - 1} SECONDARY, got {s}")
    else:
        errors.append("unable to read replica set status")
    return errors


def check_topology():
    # O-flap-restart: the probe-fix roll leaves the last-restarted member in a
    # STARTUP2/RECOVERING rejoin window, reading the SECONDARY tally short. Poll
    # to convergence (~120s, 5s between attempts); assertion not loosened.
    deadline = time.monotonic() + 120
    errors = []
    while True:
        errors = _topology_attempt()
        if not errors:
            break
        if time.monotonic() >= deadline:
            break
        time.sleep(5)
    return fail("Health-check recovery topology check failed:", errors)


def check_health_auth():
    errors = []
    health_pw = get_secret_value(HEALTH_SECRET, "password", errors)
    if errors:
        return fail("Health-check recovery health-auth check failed:", errors)

    cm_res = run(["kubectl", "-n", NAMESPACE, "get", "configmap", OVERRIDE_CONFIGMAP, "-o", "json"])
    if cm_res.returncode != 0:
        errors.append(f"failed to read configmap {OVERRIDE_CONFIGMAP}: {cm_res.stderr.strip() or cm_res.stdout.strip()}")
    else:
        try:
            cm = json.loads(cm_res.stdout)
            data = cm.get("data", {})
            key = f"{CLUSTER_PREFIX}-1"
            if key in data and data.get(key) not in (None, "", health_pw):
                errors.append(f"stale override still present for {key}")
        except json.JSONDecodeError:
            errors.append(f"failed to parse configmap {OVERRIDE_CONFIGMAP} JSON")

    # directConnection skips SDAM topology monitoring (see check_topology).
    uri = f"mongodb://{HEALTH_USER}:{health_pw}@localhost:27017/admin?directConnection=true"
    for i in range(EXPECTED_REPLICAS):
        pod = f"{POD_PREFIX}{i}"
        res = run_mongo(pod, uri, "db.hello().ok")
        if res.returncode != 0:
            errors.append(f"health user auth failed on {pod}: {res.stderr.strip() or res.stdout.strip()}")
            continue
        if (res.stdout or "").strip() != "1":
            errors.append(f"health check did not succeed on {pod}: {(res.stdout or '').strip()}")

    return fail("Health-check recovery health-auth check failed:", errors)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", default="all", choices=["all", "workload", "topology", "health_auth"])
    args = parser.parse_args()

    if args.check == "workload":
        return check_workload()
    if args.check == "topology":
        return check_topology()
    if args.check == "health_auth":
        return check_health_auth()

    for fn in (check_health_auth, check_workload, check_topology):
        rc = fn()
        if rc != 0:
            return rc
    print("Health-check recovery verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())

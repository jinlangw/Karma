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
ADMIN_USER = os.environ.get("BENCH_PARAM_ADMIN_USERNAME", "admin-user")
HEALTH_USER = os.environ.get("BENCH_PARAM_HEALTH_USERNAME", "health-user")
TUNED_READINESS_INITIAL_DELAY = int(os.environ.get("BENCH_PARAM_TUNED_READINESS_INITIAL_DELAY", "20"))
TUNED_READINESS_TIMEOUT = int(os.environ.get("BENCH_PARAM_TUNED_READINESS_TIMEOUT", "5"))
TUNED_READINESS_FAILURE_THRESHOLD = int(os.environ.get("BENCH_PARAM_TUNED_READINESS_FAILURE_THRESHOLD", "6"))
TUNED_LIVENESS_INITIAL_DELAY = int(os.environ.get("BENCH_PARAM_TUNED_LIVENESS_INITIAL_DELAY", "120"))
TUNED_LIVENESS_TIMEOUT = int(os.environ.get("BENCH_PARAM_TUNED_LIVENESS_TIMEOUT", "5"))
TUNED_LIVENESS_FAILURE_THRESHOLD = int(os.environ.get("BENCH_PARAM_TUNED_LIVENESS_FAILURE_THRESHOLD", "10"))
# The faulty baseline the precondition injects. The task only asks to "tune the
# probes so the replica set becomes stable" -- it never dictates exact values --
# so the oracle accepts any probe that is strictly MORE TOLERANT than the faulty
# baseline (and the cluster-stability checks below prove the chosen values work),
# rather than demanding the exact TUNED_* numbers.
FAULTY_READINESS_INITIAL_DELAY = int(os.environ.get("BENCH_PARAM_FAULTY_READINESS_INITIAL_DELAY", "5"))
FAULTY_READINESS_TIMEOUT = int(os.environ.get("BENCH_PARAM_FAULTY_READINESS_TIMEOUT", "1"))
FAULTY_READINESS_FAILURE_THRESHOLD = int(os.environ.get("BENCH_PARAM_FAULTY_READINESS_FAILURE_THRESHOLD", "2"))
FAULTY_LIVENESS_INITIAL_DELAY = int(os.environ.get("BENCH_PARAM_FAULTY_LIVENESS_INITIAL_DELAY", "15"))
FAULTY_LIVENESS_TIMEOUT = int(os.environ.get("BENCH_PARAM_FAULTY_LIVENESS_TIMEOUT", "1"))
FAULTY_LIVENESS_FAILURE_THRESHOLD = int(os.environ.get("BENCH_PARAM_FAULTY_LIVENESS_FAILURE_THRESHOLD", "2"))
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
    """Topology size to enforce, resolved fresh on every call (O2).

    The environment PERSISTS across workflow stages, so an earlier
    replica-scaling stage may have grown the replica set past the standalone
    default of 3. Resolve the expected count from (in priority order): an
    explicit ``expected_replicas``/``target_replicas`` param override, else
    the LIVE StatefulSet's desired ``spec.replicas`` (ignored while the STS is
    being deleted; transient ``status.readyReplicas`` is only a last-resort
    fallback when the spec carries no count -- a mid-rollout ready count would
    grade against a shrunken snapshot), else the standalone default of 3.
    """
    for key in ("BENCH_PARAM_EXPECTED_REPLICAS", "BENCH_PARAM_TARGET_REPLICAS"):
        val = os.environ.get(key)
        if val is not None and str(val).strip():
            try:
                return int(val)
            except ValueError:
                pass
    res = run(["kubectl", "-n", NAMESPACE, "get", "sts", CLUSTER_PREFIX, "-o", "json"])
    if res.returncode == 0:
        try:
            sts = json.loads(res.stdout)
            status = sts.get("status", {}) or {}
            spec = sts.get("spec", {}) or {}
            deleting = bool((sts.get("metadata", {}) or {}).get("deletionTimestamp"))
            live = spec.get("replicas") if not deleting else None
            if not isinstance(live, int) or live <= 0:
                live = status.get("readyReplicas")
            if isinstance(live, int) and live > 0:
                return live
        except (json.JSONDecodeError, AttributeError):
            pass
    return 3


def expected_replicas():
    """Per-call accessor for the expected-replica count (O2): re-resolves on
    every use, so convergence-loop attempts track the live desired size
    instead of a value frozen at import time."""
    return _resolve_expected_replicas()


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


def get_sts(errors):
    res = run(["kubectl", "-n", NAMESPACE, "get", "sts", CLUSTER_PREFIX, "-o", "json"])
    if res.returncode != 0:
        errors.append(f"failed to read statefulset {CLUSTER_PREFIX}: {res.stderr.strip() or res.stdout.strip()}")
        return {}
    try:
        return json.loads(res.stdout)
    except json.JSONDecodeError:
        errors.append("failed to parse statefulset JSON")
        return {}


def _workload_attempt():
    errors = []
    sts = get_sts(errors)
    if sts:
        spec_replicas = sts.get("spec", {}).get("replicas")
        ready_replicas = sts.get("status", {}).get("readyReplicas")
        if spec_replicas != expected_replicas():
            errors.append(f"statefulset replicas expected {expected_replicas()}, got {spec_replicas}")
        if ready_replicas != expected_replicas():
            errors.append(f"ready replicas expected {expected_replicas()}, got {ready_replicas}")

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
    if len(items) != expected_replicas():
        errors.append(f"expected {expected_replicas()} pods, got {len(items)}")
    for pod in items:
        name = pod.get("metadata", {}).get("name", "unknown")
        conditions = pod.get("status", {}).get("conditions", [])
        ready = next((c for c in conditions if c.get("type") == "Ready"), {})
        if ready.get("status") != "True":
            errors.append(f"pod {name} is not Ready")

    return errors


def check_workload():
    # O-flap-restart: tuning the probes rolls the StatefulSet, so readyReplicas
    # and per-pod Ready read short while the last pod recreates. Poll to
    # convergence (~120s, 5s between attempts); assertions unchanged.
    deadline = time.monotonic() + 120
    errors = []
    while True:
        errors = _workload_attempt()
        if not errors:
            break
        if time.monotonic() >= deadline:
            break
        time.sleep(5)
    return fail("Readiness probe tuning workload check failed:", errors)


def check_probes():
    errors = []
    sts = get_sts(errors)
    containers = sts.get("spec", {}).get("template", {}).get("spec", {}).get("containers", []) if sts else []
    if not containers:
        errors.append("statefulset has no containers")
        return fail("Readiness probe tuning probe check failed:", errors)

    c = containers[0]
    readiness = c.get("readinessProbe", {})
    liveness = c.get("livenessProbe", {})

    # O1/O22: grade only the fields the planted fault genuinely breaks. The
    # instability comes from the 1s probe timeoutSeconds (a loaded mongod ping
    # exceeds it) and the failureThreshold of 2 (two slow pings evict a healthy
    # member); those must exceed the faulty baseline. initialDelaySeconds only
    # delays the FIRST probe -- the faulty 5/15s values are workable once
    # timeout/threshold are sane, and the prompt never asks to raise them, so
    # demanding all six fields strictly greater failed valid solutions. The
    # workload/topology stability checks below prove the chosen values work.
    def _more_tolerant(probe, field, faulty, label):
        val = probe.get(field)
        if not isinstance(val, int) or val <= faulty:
            errors.append(
                f"{label} {field} ({val}) must be increased above the faulty baseline ({faulty})"
            )

    _more_tolerant(readiness, "timeoutSeconds", FAULTY_READINESS_TIMEOUT, "readiness")
    _more_tolerant(readiness, "failureThreshold", FAULTY_READINESS_FAILURE_THRESHOLD, "readiness")
    _more_tolerant(liveness, "timeoutSeconds", FAULTY_LIVENESS_TIMEOUT, "liveness")
    _more_tolerant(liveness, "failureThreshold", FAULTY_LIVENESS_FAILURE_THRESHOLD, "liveness")

    return fail("Readiness probe tuning probe check failed:", errors)


def _find_primary(admin_uri, errors):
    for i in range(expected_replicas()):
        pod = f"{POD_PREFIX}{i}"
        res = run_mongo(pod, admin_uri, "db.hello().isWritablePrimary")
        if res.returncode == 0 and "true" in (res.stdout or ""):
            return pod
    errors.append("unable to locate primary pod")
    return f"{POD_PREFIX}0"


def _topology_attempt():
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
        primary_n = sum(1 for m in members if m.get("stateStr") == "PRIMARY")
        secondary_n = sum(1 for m in members if m.get("stateStr") == "SECONDARY")
        if len(members) != expected_replicas():
            errors.append(f"replica set members expected {expected_replicas()}, got {len(members)}")
        if primary_n != 1:
            errors.append(f"expected 1 PRIMARY, got {primary_n}")
        if secondary_n != expected_replicas() - 1:
            errors.append(f"expected {expected_replicas() - 1} SECONDARY, got {secondary_n}")
    else:
        errors.append("unable to read replica set status")
    return errors


def check_topology():
    # O-flap-restart: the probe-tune roll leaves the last-restarted member in a
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
    return fail("Readiness probe tuning topology check failed:", errors)


def check_health_auth():
    errors = []
    health_pw = get_secret_value(HEALTH_SECRET, "password", errors)
    if errors:
        return fail("Readiness probe tuning health-auth check failed:", errors)

    # directConnection skips SDAM topology monitoring (see check_topology).
    uri = f"mongodb://{HEALTH_USER}:{health_pw}@localhost:27017/admin?directConnection=true"
    for i in range(expected_replicas()):
        pod = f"{POD_PREFIX}{i}"
        res = run_mongo(pod, uri, "db.hello().ok")
        if res.returncode != 0:
            errors.append(f"health user auth failed on {pod}: {res.stderr.strip() or res.stdout.strip()}")
            continue
        if (res.stdout or "").strip() != "1":
            errors.append(f"health user ping failed on {pod}: {(res.stdout or '').strip()}")

    return fail("Readiness probe tuning health-auth check failed:", errors)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", default="all", choices=["all", "workload", "probes", "topology", "health_auth"])
    args = parser.parse_args()

    if args.check == "workload":
        return check_workload()
    if args.check == "probes":
        return check_probes()
    if args.check == "topology":
        return check_topology()
    if args.check == "health_auth":
        return check_health_auth()

    for fn in (check_probes, check_workload, check_topology, check_health_auth):
        rc = fn()
        if rc != 0:
            return rc
    print("Readiness probe tuning verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())

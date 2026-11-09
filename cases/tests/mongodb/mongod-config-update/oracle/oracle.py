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
ADMIN_USER = os.environ.get("BENCH_PARAM_ADMIN_USERNAME", "admin-user")
SEED_DB = os.environ.get("BENCH_PARAM_SEED_DATABASE", "testdb")
SEED_COLLECTION = os.environ.get("BENCH_PARAM_SEED_COLLECTION", "data")
# Prompt asks for a change RELATIVE to the CURRENT (pre-agent) setting:
# "increase verbosity by one level" -> pre_verbosity + 1; "set the slow-operation
# threshold to 2x the current value" -> pre_slowms * 2. The pre-agent values are
# RECORDED per stage by the mongo_config_prevalue_record precondition into the
# ConfigMap below, so the oracle grades the RELATIVE delta against THIS stage's
# actual starting value (O5) -- NOT a fixed seeded baseline. A relative-change
# case scheduled more than once in a sweep legitimately advances the value again
# each run; grading against the recorded pre-value keeps the check correct on
# every instance with no compounding. journalCompressor is an ABSOLUTE per-stage
# target from the prompt/param and is graded unchanged.
PREVALUE_CONFIGMAP = os.environ.get("BENCH_PARAM_PREVALUE_CONFIGMAP", "mongod-config-prevalue")
TARGET_COMPRESSOR = os.environ.get("BENCH_PARAM_TARGET_JOURNAL_COMPRESSOR", "zlib")
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


def _find_primary(admin_uri, errors):
    for i in range(expected_replicas()):
        pod = f"{POD_PREFIX}{i}"
        res = run_mongo(pod, admin_uri, "db.hello().isWritablePrimary")
        if res.returncode == 0 and "true" in (res.stdout or ""):
            return pod
    errors.append("unable to locate primary pod")
    return f"{POD_PREFIX}0"


def _workload_attempt():
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

    if sts.get("spec", {}).get("replicas") != expected_replicas():
        errors.append("statefulset replicas mismatch")
    if sts.get("status", {}).get("readyReplicas") != expected_replicas():
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
    if len(items) != expected_replicas():
        errors.append(f"expected {expected_replicas()} pods, got {len(items)}")
    for pod in items:
        name = pod.get("metadata", {}).get("name", "unknown")
        ready = next((c for c in pod.get("status", {}).get("conditions", []) if c.get("type") == "Ready"), {})
        if ready.get("status") != "True":
            errors.append(f"pod {name} is not Ready")

    return errors


def check_workload():
    # O-flap-restart: applying the mongod config change across all members rolls
    # the StatefulSet, so readyReplicas and per-pod Ready read short while the
    # last pod recreates. Poll to convergence (~120s, 5s); assertions unchanged.
    deadline = time.monotonic() + 120
    errors = []
    while True:
        errors = _workload_attempt()
        if not errors:
            break
        if time.monotonic() >= deadline:
            break
        time.sleep(5)
    return fail("Mongod config update workload check failed:", errors)


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
        p = sum(1 for m in members if m.get("stateStr") == "PRIMARY")
        s = sum(1 for m in members if m.get("stateStr") == "SECONDARY")
        if len(members) != expected_replicas():
            errors.append(f"replica set members expected {expected_replicas()}, got {len(members)}")
        if p != 1:
            errors.append(f"expected 1 PRIMARY, got {p}")
        if s != expected_replicas() - 1:
            errors.append(f"expected {expected_replicas() - 1} SECONDARY, got {s}")
    else:
        errors.append("unable to read replica set status")
    return errors


def check_topology():
    # O-flap-restart: the config-update roll leaves the last-restarted member in
    # a STARTUP2/RECOVERING rejoin window, reading the SECONDARY tally short.
    # Poll to convergence (~120s, 5s); assertion not loosened.
    deadline = time.monotonic() + 120
    errors = []
    while True:
        errors = _topology_attempt()
        if not errors:
            break
        if time.monotonic() >= deadline:
            break
        time.sleep(5)
    return fail("Mongod config update topology check failed:", errors)


def _parse_int(value, label, errors):
    try:
        return int(value)
    except (TypeError, ValueError):
        errors.append(f"unable to parse {label}: {value}")
        return None


def _read_prevalue(errors):
    """Read the pre-agent verbosity + slowms recorded by the
    mongo_config_prevalue_record precondition (O5) from the mongod-config-prevalue
    ConfigMap. The oracle grades the RELATIVE change against THIS stage's recorded
    starting value: expected verbosity == pre_verbosity + 1 and expected
    slowOpThresholdMs == pre_slowms * 2. Returns (pre_verbosity, pre_slowms);
    either is None (with an error appended) when the record is missing/unreadable.
    """
    def _cfg(key):
        res = run(["kubectl", "-n", NAMESPACE, "get", "configmap", PREVALUE_CONFIGMAP,
                   "-o", f"jsonpath={{.data.{key}}}"])
        if res.returncode != 0:
            errors.append(
                f"failed to read recorded pre-value {PREVALUE_CONFIGMAP}.{key}: "
                f"{res.stderr.strip() or res.stdout.strip()}")
            return None
        raw = (res.stdout or "").strip()
        if not raw:
            errors.append(f"recorded pre-value {PREVALUE_CONFIGMAP}.{key} empty")
            return None
        return _parse_int(raw, f"pre-value {key}", errors)

    return _cfg("verbosity"), _cfg("slowms")


def _slow_ms(pod, uri, cmdline, errors):
    parsed = cmdline.get("parsed", {}) if isinstance(cmdline, dict) else {}
    val = parsed.get("operationProfiling", {}).get("slowOpThresholdMs")
    if val is not None:
        return _parse_int(val, "slowOpThresholdMs", errors)
    prof = load_json(pod, uri, "JSON.stringify(db.getProfilingStatus())", "getProfilingStatus", errors)
    if isinstance(prof, dict) and "slowms" in prof:
        return _parse_int(prof.get("slowms"), "slowOpThresholdMs", errors)
    errors.append("slowOpThresholdMs missing")
    return None


def _verbosity(pod, uri, cmdline, errors):
    """Dual-source verbosity read (O38), mirroring _slow_ms's order exactly:
    the start-up config (getCmdLineOpts) first, else the live runtime value
    (getParameter logLevel) -- so a valid runtime `setParameter` solution is
    graded the same way as a persisted mongod.conf one."""
    parsed = cmdline.get("parsed", {}) if isinstance(cmdline, dict) else {}
    val = parsed.get("systemLog", {}).get("verbosity")
    if val is not None:
        return _parse_int(val, "systemLog.verbosity", errors)
    param = load_json(pod, uri, "JSON.stringify(db.adminCommand({getParameter:1, logLevel:1}))", "getParameter logLevel", errors)
    if isinstance(param, dict) and "logLevel" in param:
        return _parse_int(param.get("logLevel"), "systemLog.verbosity", errors)
    errors.append("systemLog.verbosity missing")
    return None


def check_runtime():
    errors = []
    admin_pw = get_secret_value(ADMIN_SECRET, "password", errors)
    if errors:
        return fail("Mongod config update runtime check failed:", errors)
    # O5: grade the RELATIVE delta against THIS stage's recorded pre-agent value
    # (verbosity + 1, slowOpThresholdMs * 2), read from the mongod-config-prevalue
    # ConfigMap the precondition wrote before the agent ran -- not a fixed baseline.
    pre_verbosity, pre_slow_ms = _read_prevalue(errors)
    if errors or pre_verbosity is None or pre_slow_ms is None:
        return fail("Mongod config update runtime check failed:", errors)
    target_log_level = pre_verbosity + 1
    target_slow_ms = pre_slow_ms * 2
    # directConnection skips SDAM topology monitoring (see check_topology); the
    # per-member getCmdLineOpts read below is a single-member localhost read.
    admin_uri = f"mongodb://{ADMIN_USER}:{admin_pw}@localhost:27017/admin?directConnection=true"

    for i in range(expected_replicas()):
        pod = f"{POD_PREFIX}{i}"
        cmdline = load_json(pod, admin_uri, "JSON.stringify(db.adminCommand({getCmdLineOpts:1}))", "getCmdLineOpts", errors)
        if isinstance(cmdline, dict):
            parsed = cmdline.get("parsed", {})
            cfg_level = _verbosity(pod, admin_uri, cmdline, errors)
            if cfg_level is not None and cfg_level != target_log_level:
                errors.append(f"systemLog.verbosity on {pod} expected {target_log_level} (recorded pre-value {pre_verbosity} + 1), got {cfg_level}")
            slow_ms = _slow_ms(pod, admin_uri, cmdline, errors)
            if slow_ms is not None and slow_ms != target_slow_ms:
                errors.append(f"slowOpThresholdMs on {pod} expected {target_slow_ms} (recorded pre-value {pre_slow_ms} x 2), got {slow_ms}")
            compressor = (
                parsed
                .get("storage", {})
                .get("wiredTiger", {})
                .get("engineConfig", {})
                .get("journalCompressor")
            )
            if compressor != TARGET_COMPRESSOR:
                errors.append(f"journalCompressor on {pod} expected {TARGET_COMPRESSOR}, got {compressor}")

    return fail("Mongod config update runtime check failed:", errors)


def check_data():
    errors = []
    admin_pw = get_secret_value(ADMIN_SECRET, "password", errors)
    if errors:
        return fail("Mongod config update data check failed:", errors)
    # directConnection skips SDAM topology monitoring (see check_topology).
    admin_uri = f"mongodb://{ADMIN_USER}:{admin_pw}@localhost:27017/admin?directConnection=true"
    primary = _find_primary(admin_uri, errors)
    count_res = run_mongo(primary, admin_uri, f"db.getSiblingDB('{SEED_DB}').{SEED_COLLECTION}.countDocuments({{}})")
    if count_res.returncode != 0:
        errors.append(f"data count failed: {count_res.stderr.strip() or count_res.stdout.strip()}")
    else:
        raw = (count_res.stdout or "").strip()
        if not raw.isdigit() or int(raw) < 1:
            errors.append(f"expected >=1 docs in {SEED_DB}.{SEED_COLLECTION}, got {raw}")

    return fail("Mongod config update data check failed:", errors)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", default="all", choices=["all", "workload", "topology", "runtime", "data"])
    args = parser.parse_args()

    if args.check == "workload":
        return check_workload()
    if args.check == "topology":
        return check_topology()
    if args.check == "runtime":
        return check_runtime()
    if args.check == "data":
        return check_data()

    # O14: run the CONVERGED gates first. check_workload/check_topology poll the
    # post-roll cluster to convergence; the single-pass check_runtime must only
    # run once the roll has settled, else it reads a mid-roll member and
    # false-fails a correct config application.
    for fn in (check_workload, check_topology, check_runtime, check_data):
        rc = fn()
        if rc != 0:
            return rc
    print("Mongod config update verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())

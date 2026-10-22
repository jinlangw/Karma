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
LABEL_KEY = os.environ.get("BENCH_PARAM_TEMPLATE_LABEL_KEY", "monitoring")
LABEL_VALUE = os.environ.get("BENCH_PARAM_TEMPLATE_LABEL_VALUE", "enabled")
MIN_REQUEST_MEM_MIB = int(os.environ.get("BENCH_PARAM_MIN_REQUEST_MEMORY_MI", "512"))
MIN_LIMIT_MEM_MIB = int(os.environ.get("BENCH_PARAM_MIN_LIMIT_MEMORY_MI", "1024"))
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


def _parse_bytes(value):
    """Normalize a Kubernetes memory quantity to BYTES (O36).

    Accepts every legal spelling: binary suffixes (Ki/Mi/Gi/Ti/Pi/Ei), decimal
    suffixes (k/M/G/T/P/E), milli (m), scientific notation, and a bare number
    -- which in Kubernetes is BYTES (the old parser read a bare `536870912` as
    536870912 *MiB* and rejected `512M`/`1Ki` outright). Suffixes are
    case-sensitive per the k8s quantity grammar (`M` = mega, `m` = milli).
    Returns None when unparsable so the caller reports it.
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    multipliers = (
        ("Ki", 1024), ("Mi", 1024 ** 2), ("Gi", 1024 ** 3),
        ("Ti", 1024 ** 4), ("Pi", 1024 ** 5), ("Ei", 1024 ** 6),
        ("k", 1000), ("M", 1000 ** 2), ("G", 1000 ** 3),
        ("T", 1000 ** 4), ("P", 1000 ** 5), ("E", 1000 ** 6),
        ("m", 1e-3),
    )
    for suffix, mult in multipliers:
        if text.endswith(suffix):
            try:
                return int(float(text[: -len(suffix)]) * mult)
            except ValueError:
                return None
    try:
        return int(float(text))  # bare quantity = bytes
    except ValueError:
        return None


def _find_primary(admin_uri, errors):
    for i in range(expected_replicas()):
        pod = f"{POD_PREFIX}{i}"
        res = run_mongo(pod, admin_uri, "db.hello().isWritablePrimary")
        if res.returncode == 0 and "true" in (res.stdout or ""):
            return pod
    errors.append("unable to locate primary pod")
    return f"{POD_PREFIX}0"


def _load_sts(errors):
    res = run(["kubectl", "-n", NAMESPACE, "get", "sts", CLUSTER_PREFIX, "-o", "json"])
    if res.returncode != 0:
        errors.append(f"failed to read statefulset {CLUSTER_PREFIX}: {res.stderr.strip() or res.stdout.strip()}")
        return {}
    try:
        return json.loads(res.stdout)
    except json.JSONDecodeError:
        errors.append("failed to parse statefulset JSON")
        return {}


def check_template():
    errors = []
    sts = _load_sts(errors)
    if not sts:
        return fail("StatefulSet customization template check failed:", errors)

    template = sts.get("spec", {}).get("template", {})
    labels = template.get("metadata", {}).get("labels", {})
    if labels.get(LABEL_KEY) != LABEL_VALUE:
        errors.append(f"template label {LABEL_KEY} expected {LABEL_VALUE}, got {labels.get(LABEL_KEY)}")

    containers = template.get("spec", {}).get("containers", [])
    if not containers:
        errors.append("statefulset has no containers")
    else:
        resources = containers[0].get("resources", {})
        # O36: compare semantically, in bytes -- `512Mi` == `536870912` ==
        # `537M`-ish spellings are all legal; a genuinely small value still
        # differs after normalization.
        req_mem = _parse_bytes(resources.get("requests", {}).get("memory"))
        lim_mem = _parse_bytes(resources.get("limits", {}).get("memory"))
        if req_mem is None or req_mem < MIN_REQUEST_MEM_MIB * 1024 ** 2:
            errors.append(f"requests.memory below minimum {MIN_REQUEST_MEM_MIB}Mi")
        if lim_mem is None or lim_mem < MIN_LIMIT_MEM_MIB * 1024 ** 2:
            errors.append(f"limits.memory below minimum {MIN_LIMIT_MEM_MIB}Mi")

    return fail("StatefulSet customization template check failed:", errors)


def _workload_attempt():
    """One snapshot of the StatefulSet readyReplicas + per-pod Ready tally.
    Returns the error list (empty on a clean read). The readyReplicas count and
    the per-pod Ready conditions are restart-volatile (the last-rolled pod reads
    non-Ready for seconds), so this is polled to convergence by check_workload."""
    errors = []
    sts = _load_sts(errors)
    if sts:
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
    # O-flap-restart: the template edit (label + resources) rolls the
    # StatefulSet, so readyReplicas and the per-pod Ready tally read short while
    # the last pod recreates. Poll to convergence (~120s, 5s between attempts);
    # the spec.replicas == EXPECTED and pod-count assertions are unchanged, so a
    # genuinely missing/unready member still fails every attempt.
    deadline = time.monotonic() + 120
    errors = []
    while True:
        errors = _workload_attempt()
        if not errors:
            break
        if time.monotonic() >= deadline:
            break
        time.sleep(5)
    return fail("StatefulSet customization workload check failed:", errors)


def _topology_attempt():
    """One snapshot of the replica-set topology. Returns the error list (empty
    on a clean read). The graded assertion is UNCHANGED -- exactly 1 PRIMARY,
    expected_replicas()-1 SECONDARY, members == expected_replicas() -- so a genuinely
    degraded set fails every attempt."""
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
    # O-flap-restart: the agent's task (template label + resource edit) forces a
    # rolling restart of the StatefulSet, so the last-restarted member spends
    # seconds in a STARTUP2/RECOVERING rejoin window during which the
    # PRIMARY/SECONDARY tally reads short. Poll the topology to convergence
    # (~120s deadline, 5s between attempts) and pass on the first clean snapshot;
    # the assertion is not loosened, so a truly degraded set fails every attempt.
    deadline = time.monotonic() + 120
    errors = []
    while True:
        errors = _topology_attempt()
        if not errors:
            break
        if time.monotonic() >= deadline:
            break
        time.sleep(5)
    return fail("StatefulSet customization topology check failed:", errors)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", default="all", choices=["all", "template", "workload", "topology"])
    args = parser.parse_args()

    if args.check == "template":
        return check_template()
    if args.check == "workload":
        return check_workload()
    if args.check == "topology":
        return check_topology()

    for fn in (check_template, check_workload, check_topology):
        rc = fn()
        if rc != 0:
            return rc
    print("StatefulSet customization verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())

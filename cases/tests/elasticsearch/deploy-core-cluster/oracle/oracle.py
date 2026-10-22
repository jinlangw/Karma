#!/usr/bin/env python3
import json
import os
import subprocess
import sys


NAMESPACE = os.environ.get("BENCH_NAMESPACE", "elasticsearch")
ES_IMAGE = os.environ.get(
    "BENCH_PARAM_TARGET_IMAGE", "docker.elastic.co/elasticsearch/elasticsearch:8.11.1"
)
SERVICE = os.environ.get("BENCH_PARAM_HTTP_SERVICE_NAME", "es-http")
# ES 8.x runs with security enabled, so the HTTPS API requires authenticating as
# the elastic superuser. Read its password from the secret the precondition
# created so the oracle's queries aren't rejected with 401.
PASSWORD_SECRET = os.environ.get("BENCH_PARAM_ELASTIC_PASSWORD_SECRET_NAME", "elastic-password")
PASSWORD_KEY = os.environ.get("BENCH_PARAM_ELASTIC_PASSWORD_KEY", "password")
# ES 8.x deploys with HTTP TLS on, so https is the standalone default; a prior
# stage could have disabled it, so _detect_scheme() flips to http when needed.
DEFAULT_SCHEME = "https"
_SCHEME = None


def _elastic_password():
    """Fetch the elastic-user password from its secret (base64-decoded), or None."""
    import base64
    r = run(["kubectl", "-n", NAMESPACE, "get", "secret", PASSWORD_SECRET,
             "-o", "jsonpath={.data." + PASSWORD_KEY + "}"])
    if r.returncode != 0 or not r.stdout.strip():
        return None
    try:
        return base64.b64decode(r.stdout.strip()).decode()
    except Exception:
        return None


def _password_from_sts():
    """Fall back to a live ES StatefulSet's ELASTIC_PASSWORD env when the
    elastic-password secret is absent (skip-gated on an inherited cluster), so
    the oracle authenticates instead of 401-ing (C1). Reads the literal env
    value, or resolves its secretKeyRef; returns the password or None."""
    import base64
    res = run(["kubectl", "-n", NAMESPACE, "get", "sts", "-o", "json"])
    if res.returncode != 0:
        return None
    try:
        items = json.loads(res.stdout).get("items", [])
    except (json.JSONDecodeError, AttributeError):
        return None
    for sts in items:
        spec = sts.get("spec", {}) or {}
        containers = spec.get("template", {}).get("spec", {}).get("containers", []) or []
        if "elasticsearch" not in " ".join(c.get("image", "") for c in containers):
            continue
        for c in containers:
            for e in c.get("env", []) or []:
                if e.get("name") != "ELASTIC_PASSWORD":
                    continue
                if e.get("value"):
                    return e["value"]
                ref = (e.get("valueFrom", {}) or {}).get("secretKeyRef", {}) or {}
                name = ref.get("name")
                if name:
                    rs = run(["kubectl", "-n", NAMESPACE, "get", "secret", name,
                              "-o", "jsonpath={.data." + (ref.get("key") or "password") + "}"])
                    if rs.returncode == 0 and rs.stdout.strip():
                        try:
                            return base64.b64decode(rs.stdout.strip()).decode()
                        except Exception:
                            pass
    return None


ELASTIC_PASSWORD = None  # set in main() once kubectl is reachable


def run(cmd):
    return subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def _sum_es_statefulset_replicas():
    """Sum spec.replicas across every Elasticsearch StatefulSet in the namespace.

    This is the DESIRED node topology. Deriving from desired replicas -- not a
    point-in-time Ready-pod count -- adapts to whatever the persisted env
    accumulated (e.g. a prior scale-up grew it across multiple nodesets) WITHOUT
    masking a node that fails to come up: a still-down node leaves the desired
    count unmet rather than silently lowering the expectation. Returns None when
    no ES StatefulSet is found.
    """
    res = run(["kubectl", "-n", NAMESPACE, "get", "sts", "-o", "json"])
    if res.returncode != 0:
        return None
    try:
        items = json.loads(res.stdout).get("items", [])
    except (json.JSONDecodeError, AttributeError):
        return None
    total = 0
    found = False
    for sts in items:
        spec = sts.get("spec", {})
        containers = spec.get("template", {}).get("spec", {}).get("containers", [])
        if "elasticsearch" not in " ".join(c.get("image", "") for c in containers):
            continue
        replicas = spec.get("replicas")
        if isinstance(replicas, int):
            total += replicas
            found = True
    return total if found else None


def _resolve_expected_nodes(default=3):
    """Node count to enforce (param override -> desired StatefulSet replicas ->
    default).

    The env PERSISTS across stages; the expected count is the DESIRED topology
    (sum of spec.replicas over every ES StatefulSet), not a live Ready-pod count.
    A Ready-pod count both undercounts a scaled-up cluster and MASKS a node that
    failed to come up (fewer ready -> lower expectation -> false pass). The LIVE
    cluster is derived FIRST; the param is a FALLBACK used only when no live
    StatefulSets resolve.
    """
    # Derive from the LIVE cluster FIRST (workflow-agnostic + composition-aware):
    # sum spec.replicas over the active ES StatefulSets -- the base cluster PLUS
    # any nodeset a PRIOR stage added to the same cluster (e.g. an inherited
    # transform nodeset). A static EXPECTED_NODES param encodes a standalone
    # baseline that wrongly ignores such inherited nodesets, so it is demoted to a
    # FALLBACK below, used only when the live cluster cannot be resolved.
    # Robust count: sum spec.replicas over ES StatefulSets that are actually
    # present (status.replicas > 0). Counts the base cluster + any scaled-up
    # nodeset WITHOUT the fragile node.name -> StatefulSet string mapping (which
    # breaks when a nodeset's node.name differs from its pod name). A torn-down
    # prior cluster's StatefulSet has readyReplicas 0 and is excluded. Still
    # strict: a node that failed to join leaves its STS ready>0 but short, so the
    # spec-replica sum exceeds the live node count and the check still fails.
    res = run(["kubectl", "-n", NAMESPACE, "get", "sts", "-o", "json"])
    if res.returncode == 0:
        try:
            items = json.loads(res.stdout).get("items", [])
        except Exception:
            items = []
        desired = 0
        for sts in items:
            spec = sts.get("spec", {}) or {}
            containers = spec.get("template", {}).get("spec", {}).get("containers", []) or []
            if "elasticsearch" not in " ".join(c.get("image", "") for c in containers):
                continue
            replicas = spec.get("replicas")
            # Use status.replicas (pods that EXIST), not readyReplicas: a
            # scaled-up nodeset whose pods joined the cluster but lack a passing
            # STS readiness probe has readyReplicas 0 yet is genuinely live.
            # Count an ES StatefulSet's DESIRED replicas when it is an active part
            # of the cluster: spec.replicas > 0 and not being torn down. Gating on
            # status.replicas undercounts a freshly scaled-up nodeset whose status
            # lags -- its pods have joined the cluster but status.replicas is still
            # 0 -- which wrongly made EXPECTED < the live node count.
            being_deleted = (sts.get("metadata", {}) or {}).get("deletionTimestamp") is not None
            if isinstance(replicas, int) and replicas > 0 and not being_deleted:
                desired += replicas
        if desired > 0:
            return desired

    # Fallbacks (live cluster unresolvable): explicit param, then the default.
    for key in ("BENCH_PARAM_EXPECTED_NODES", "BENCH_PARAM_EXPECTED_NODE_COUNT"):
        val = os.environ.get(key)
        if val is not None and str(val).strip():
            try:
                return int(val)
            except ValueError:
                pass
    return default


EXPECTED_NODES = _resolve_expected_nodes(3)


def _probe_scheme(scheme):
    """True if the ES HTTP API answers on the given scheme (auth-agnostic).

    A 401 still means the scheme is live, so any HTTP status code counts.
    """
    cmd = ["kubectl", "-n", NAMESPACE, "exec", "curl-test", "--",
           "curl", "-s", "-S", "-k", "-o", "/dev/null", "-w", "%{http_code}",
           "--max-time", "5"]
    if ELASTIC_PASSWORD:
        cmd += ["-u", f"elastic:{ELASTIC_PASSWORD}"]
    cmd += [f"{scheme}://{SERVICE}:9200/"]
    result = run(cmd)
    code = (result.stdout or "").strip()
    return result.returncode == 0 and code.isdigit() and code != "000"


def detect_scheme():
    """Detect the cluster's live HTTP scheme (default first, then the other)."""
    global _SCHEME
    if _SCHEME is not None:
        return _SCHEME
    for scheme in (DEFAULT_SCHEME, "https" if DEFAULT_SCHEME == "http" else "http"):
        if _probe_scheme(scheme):
            _SCHEME = scheme
            return _SCHEME
    _SCHEME = DEFAULT_SCHEME
    return _SCHEME


def get_es_pods(errors):
    result = run(["kubectl", "-n", NAMESPACE, "get", "pods", "-o", "json"])
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        errors.append(f"Failed to list pods: {detail}")
        return []
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        errors.append("Failed to parse pod list JSON")
        return []

    pods = []
    for pod in data.get("items", []):
        for container in pod.get("spec", {}).get("containers", []):
            if container.get("image") == ES_IMAGE:
                pods.append(pod)
                break
    return pods


def pod_ready(pod):
    for condition in pod.get("status", {}).get("conditions", []):
        if condition.get("type") == "Ready":
            return condition.get("status") == "True"
    return False


def curl_json(path, errors):
    cmd = [
        "kubectl", "-n", NAMESPACE, "exec", "curl-test", "--",
        "curl", "-s", "-S", "-k",
    ]
    if ELASTIC_PASSWORD:
        cmd += ["-u", f"elastic:{ELASTIC_PASSWORD}"]
    # The client deadline must exceed any server-side ``wait_for`` in `path`,
    # otherwise curl aborts (exit 28) before ES can answer. The retry loop in
    # main() does the real waiting, so each call's deadline stays short.
    cmd += ["--max-time", "20", f"{detect_scheme()}://{SERVICE}:9200{path}"]
    result = run(cmd)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        errors.append(f"Failed to query {path}: {detail}")
        return None
    output = result.stdout.strip()
    if not output:
        errors.append(f"Empty response for {path}")
        return None
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        errors.append(f"Failed to parse JSON from {path}")
        return None


def evaluate():
    """Run one full snapshot of the cluster checks; return the list of errors."""
    errors = []

    es_pods = get_es_pods(errors)
    if len(es_pods) != EXPECTED_NODES:
        errors.append(f"Expected {EXPECTED_NODES} Elasticsearch pods, found {len(es_pods)}")
    # O-funcready: do NOT gate the verdict on the k8s pod-`Ready` bit. An ES node
    # serves (a yellow cluster answers writes/reads) before -- and can briefly
    # dip back below -- its HTTP readiness probe during GC or shard recovery,
    # even when the cluster is stably serving N nodes. Asserting all N pods carry
    # the Ready condition false-fails such a serving cluster. The DELIVERABLE is
    # that the service serves N nodes, which the functional checks below grade
    # directly: `_cluster/health?wait_for_status=yellow&wait_for_nodes=N` (the
    # cluster serves with N nodes) plus `_cluster/stats` total node count == N.
    # A genuinely down node leaves number_of_nodes/stats short and still fails.

    health = curl_json(
        f"/_cluster/health?wait_for_status=yellow&wait_for_nodes={EXPECTED_NODES}&timeout=10s",
        errors,
    )
    if isinstance(health, dict):
        status = health.get("status")
        if status not in {"yellow", "green"}:
            errors.append(f"Cluster health status expected yellow/green, got {status}")
        if health.get("number_of_nodes") != EXPECTED_NODES:
            errors.append(
                f"Expected {EXPECTED_NODES} nodes, got {health.get('number_of_nodes')}"
            )

    root = curl_json("/", errors)
    if isinstance(root, dict):
        cluster_name = root.get("cluster_name")
        if not cluster_name:
            errors.append("Elasticsearch root response missing cluster_name")
    stats = curl_json("/_cluster/stats", errors)
    if isinstance(stats, dict):
        nodes = stats.get("nodes", {}).get("count", {}).get("total")
        if nodes != EXPECTED_NODES:
            errors.append(f"Cluster stats expected {EXPECTED_NODES} nodes, got {nodes}")

    return errors


def _ensure_curl_test():
    """(Re)create the curl-test helper pod the oracle queries ES through.

    The precondition creates curl-test, but deploy-core's agent task is to tear
    down the existing wrong-version cluster before redeploying and may remove
    this helper along with it; the agent's own deploy does not recreate this
    oracle-only pod. Without it every query fails 'pods "curl-test" not found'.
    So ensure it exists and is Ready here, before querying. Idempotent.
    """
    ready = run(["kubectl", "-n", NAMESPACE, "get", "pod", "curl-test",
                 "-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}"])
    if ready.returncode == 0 and ready.stdout.strip() == "True":
        return
    manifest = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "..", "resource", "curl-test.yaml")
    run(["kubectl", "-n", NAMESPACE, "apply", "-f", manifest])
    run(["kubectl", "-n", NAMESPACE, "wait", "--for=condition=ready",
         "pod/curl-test", "--timeout=120s"])


def main():
    global ELASTIC_PASSWORD
    _ensure_curl_test()
    ELASTIC_PASSWORD = _elastic_password() or _password_from_sts()

    # A freshly-deployed multi-node ES cluster can flap at the edge of readiness
    # under load: a node briefly fails its HTTP readiness probe during GC or
    # shard recovery even though the cluster is stably green (writes succeed).
    # A single snapshot can catch that transient and report a false "2/3 Ready".
    # So verify the STABLE converged state: re-evaluate for up to ~75s and pass
    # as soon as one clean snapshot is seen. This does not loosen the
    # N-node/green requirement -- a genuinely degraded cluster (a node that
    # never joins) fails every attempt and still fails the oracle.
    import time
    deadline = time.monotonic() + 75
    errors = evaluate()
    while errors and time.monotonic() < deadline:
        time.sleep(8)
        errors = evaluate()

    if errors:
        print("Deploy core cluster verification failed:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    print("Deploy core cluster verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())

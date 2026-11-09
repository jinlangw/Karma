#!/usr/bin/env python3
# Verify the agent deployed the cluster to the configured spec. The image
# version (BENCH_PARAM_TO_VERSION) and per-pod storage size
# (BENCH_PARAM_STORAGE_SIZE_GI) come from the case params, so a workflow that
# overrides them is honored instead of a hardcoded value. Standalone (default
# params) this behaves identically to the old hardcoded check.
import json
import math
import os
import subprocess
import sys


TO_VERSION = os.environ.get("BENCH_PARAM_TO_VERSION", "24.1.0")
EXPECTED_IMAGE = f"cockroachdb/cockroach:v{TO_VERSION}"
STORAGE_SIZE_GI = os.environ.get("BENCH_PARAM_STORAGE_SIZE_GI", "10")
EXPECTED_STORAGE = f"{STORAGE_SIZE_GI}Gi"
# Replica count the agent must deploy. This is the TASK OUTCOME being verified,
# so it must NOT be read from the live cluster (that would make the count check
# vacuous). It comes from an explicit param override (a workflow that asks for a
# different size is honored) and otherwise defaults to the old hardcoded 3.
# Standalone this behaves identically.
EXPECTED_REPLICAS = int(
    os.environ.get("BENCH_PARAM_EXPECTED_REPLICAS")
    or os.environ.get("BENCH_PARAM_REPLICA_COUNT")
    or "3"
)

# Canonical pod-identity labels every cockroachdb stage relies on (§3.1 identity
# contract). The deploy prompt mandates them, so the oracle enforces them, which
# in turn lets downstream stages select pods by these labels safely.
CANONICAL_LABELS = {
    "app.kubernetes.io/name": "cockroachdb",
    "app.kubernetes.io/instance": "crdb-cluster",
}


def run(cmd):
    return subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


_CONN_FLAG = None


def conn_flag():
    """Return the cockroach SQL connection flag for the live cluster's mode.

    Standalone deploy targets an INSECURE cluster (`--insecure`), but in a
    workflow this stage can run against a SECURE cluster, so detect the mode
    once via the mounted certs dir (mirrors initialize/cluster-settings, C4).
    """
    global _CONN_FLAG
    if _CONN_FLAG is not None:
        return _CONN_FLAG
    probe = run([
        "kubectl", "-n", "cockroachdb", "--request-timeout=15s", "exec",
        "crdb-cluster-0", "--", "ls", "/cockroach/cockroach-certs/ca.crt",
    ])
    if probe.returncode == 0:
        _CONN_FLAG = "--certs-dir=/cockroach/cockroach-certs"
    else:
        _CONN_FLAG = "--insecure"
    return _CONN_FLAG


def _live_node_count():
    """Count nodes reporting is_live=true via `cockroach node status`.

    This is the FUNCTIONAL readiness signal (O-funcready): a node reports
    is_live=true once it serves SQL, which can precede its k8s pod-Ready probe
    flipping (CockroachDB's /health?ready=1 lags while ranges replicate after a
    fresh init / under load). Returns (count, error_or_None).
    """
    result = run([
        "kubectl", "-n", "cockroachdb", "--request-timeout=20s", "exec",
        "crdb-cluster-0", "--", "./cockroach", "node", "status", conn_flag(),
        "--format=tsv",
    ])
    if result.returncode != 0:
        return 0, result.stderr.strip() or "cockroach node status failed"
    lines = [l for l in result.stdout.strip().split("\n") if l.strip()]
    if not lines:
        return 0, "empty node status output"
    header = lines[0].split("\t")
    try:
        live_idx = header.index("is_live")
    except ValueError:
        live_idx = None
    live = 0
    for row in lines[1:]:
        cols = row.split("\t")
        if live_idx is not None and live_idx < len(cols):
            if cols[live_idx].strip().lower() == "true":
                live += 1
        else:
            live += 1
    return live, None


def _sql_serves():
    """Return (ok, error_or_None) for a `SELECT 1` against the cluster."""
    result = run([
        "kubectl", "-n", "cockroachdb", "--request-timeout=20s", "exec",
        "crdb-cluster-0", "--", "./cockroach", "sql", conn_flag(),
        "-e", "SELECT 1;",
    ])
    if result.returncode != 0:
        return False, result.stderr.strip() or "SELECT 1 failed"
    return True, None


def kubectl_json(args, namespace="cockroachdb"):
    cmd = ["kubectl", "-n", namespace] + args + ["-o", "json"]
    result = run(cmd)
    if result.returncode != 0:
        return None, result.stderr.strip() or "kubectl failed"
    try:
        return json.loads(result.stdout), None
    except json.JSONDecodeError as exc:
        return None, f"json decode failed: {exc}"


def _port_map(service):
    ports = service.get("spec", {}).get("ports", [])
    return {port.get("name"): port.get("port") for port in ports if port.get("name")}


def _selector_matches_labels(selector, labels):
    if not selector or not labels:
        return False
    match_labels = selector.get("matchLabels") or {}
    for key, value in match_labels.items():
        if labels.get(key) != value:
            return False
    match_exprs = selector.get("matchExpressions") or []
    for expr in match_exprs:
        key = expr.get("key")
        op = expr.get("operator")
        values = expr.get("values") or []
        if op == "In":
            if labels.get(key) not in values:
                return False
        elif op == "NotIn":
            if labels.get(key) in values:
                return False
        elif op == "Exists":
            if key not in labels:
                return False
        elif op == "DoesNotExist":
            if key in labels:
                return False
        else:
            return False
    return True


def _parse_budget_value(value, total):
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if text.endswith("%"):
            try:
                pct = int(text[:-1])
            except ValueError:
                return None
            return int(math.ceil(total * pct / 100.0))
        if text.isdigit():
            return int(text)
    return None


def _container_command(container):
    parts = []
    for field in ("command", "args"):
        for item in container.get(field) or []:
            parts.append(str(item))
    return " ".join(parts)


def _select_container(containers):
    if not containers:
        return None
    for container in containers:
        image = str(container.get("image") or "")
        if image.startswith("cockroachdb/cockroach"):
            return container
    return containers[0]


def _check_crdbcluster_absent(errors):
    result = run(["kubectl", "-n", "cockroachdb", "get", "crdbcluster", "-o", "json"])
    if result.returncode != 0:
        return
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return
    items = payload.get("items") or []
    if items:
        errors.append("CrdbCluster CRs detected; operator/CRDs are not allowed")


def _check_quorum_budget(labels, replicas, errors):
    pdbs, err = kubectl_json(["get", "poddisruptionbudget"])
    if err:
        errors.append(f"Failed to read PodDisruptionBudgets: {err}")
        return
    items = pdbs.get("items") or []
    for pdb in items:
        selector = (pdb.get("spec") or {}).get("selector") or {}
        if not _selector_matches_labels(selector, labels):
            continue
        spec = pdb.get("spec") or {}
        min_available = spec.get("minAvailable")
        max_unavailable = spec.get("maxUnavailable")
        min_value = _parse_budget_value(min_available, replicas) if min_available is not None else None
        max_value = _parse_budget_value(max_unavailable, replicas) if max_unavailable is not None else None
        if min_value is not None and min_value >= 2:
            return
        if max_value is not None and max_value <= 1:
            return
    errors.append("No disruption budget enforces quorum safety (>=2 pods available)")


def evaluate():
    """One full snapshot of the deploy checks; returns the list of errors."""
    errors = []
    svc = None
    pub_svc = None

    svc, err = kubectl_json(["get", "service", "crdb-cluster"])
    if err:
        errors.append(f"Discovery service 'crdb-cluster' not found: {err}")
    else:
        cluster_ip = svc.get("spec", {}).get("clusterIP")
        if cluster_ip not in (None, "None"):
            errors.append("Discovery service should be headless (clusterIP: None)")
        ports = _port_map(svc)
        if ports.get("grpc") != 26257:
            errors.append("Discovery service missing grpc port 26257")
        if ports.get("http") != 8080:
            errors.append("Discovery service missing http port 8080")

    pub_svc, err = kubectl_json(["get", "service", "crdb-cluster-public"])
    if err:
        errors.append(f"Public service 'crdb-cluster-public' not found: {err}")
    else:
        svc_type = pub_svc.get("spec", {}).get("type")
        if svc_type not in (None, "ClusterIP"):
            errors.append(f"Public service type should be ClusterIP, got {svc_type}")
        ports = _port_map(pub_svc)
        if ports.get("grpc") != 26257:
            errors.append("Public service missing grpc port 26257")
        if ports.get("http") != 8080:
            errors.append("Public service missing http port 8080")

    sts, err = kubectl_json(["get", "statefulset", "crdb-cluster"])
    selector_labels = {}
    pod_labels = {}
    replicas = EXPECTED_REPLICAS
    if err:
        errors.append(f"StatefulSet 'crdb-cluster' not found: {err}")
    else:
        replicas = sts.get("spec", {}).get("replicas")
        if replicas != EXPECTED_REPLICAS:
            errors.append(f"StatefulSet should have {EXPECTED_REPLICAS} replicas, got {replicas}")
        service_name = sts.get("spec", {}).get("serviceName")
        if service_name != "crdb-cluster":
            errors.append(f"StatefulSet serviceName should be 'crdb-cluster', got {service_name}")
        sa_name = (
            sts.get("spec", {})
            .get("template", {})
            .get("spec", {})
            .get("serviceAccountName")
        )
        if sa_name != "crdb-cluster-sa":
            errors.append("StatefulSet must use the pre-provisioned ServiceAccount")
        else:
            sa, sa_err = kubectl_json(["get", "serviceaccount", sa_name])
            if sa_err:
                errors.append(f"ServiceAccount '{sa_name}' not found: {sa_err}")

        containers = (
            sts.get("spec", {})
            .get("template", {})
            .get("spec", {})
            .get("containers")
        ) or []
        container = _select_container(containers)
        if not container:
            errors.append("StatefulSet has no containers")
        else:
            image = container.get("image")
            if image != EXPECTED_IMAGE:
                errors.append(f"StatefulSet image should be {EXPECTED_IMAGE}, got {image}")
            cmd_str = _container_command(container)
            if "--insecure" not in cmd_str:
                errors.append("CockroachDB must run in insecure mode for this case")
            # Accept either advertise flag: --advertise-host is the legacy spelling,
            # --advertise-addr the current one.
            if "--advertise-host" not in cmd_str and "--advertise-addr" not in cmd_str:
                errors.append("CockroachDB start command missing --advertise-host/--advertise-addr")
            if "crdb-cluster" not in cmd_str:
                errors.append("CockroachDB advertise host should use the crdb-cluster DNS")
            # The advertised address must be each pod's own stable identity: an
            # explicit POD_NAME reference, or the pod FQDN via `hostname -f`
            # (which resolves to <pod>.crdb-cluster... -- equivalent and valid).
            _pod_id = ("$(POD_NAME)", "${POD_NAME}", "$POD_NAME", "hostname -f", "$(hostname")
            if not any(tok in cmd_str for tok in _pod_id):
                errors.append("CockroachDB advertise host should use the pod's stable identity")

            required_nodes = [
                f"crdb-cluster-{i}.crdb-cluster" for i in range(EXPECTED_REPLICAS)
            ]
            missing_nodes = [node for node in required_nodes if node not in cmd_str]
            if missing_nodes:
                errors.append(f"CockroachDB join list must include all {EXPECTED_REPLICAS} nodes")

        vclaim_templates = sts.get("spec", {}).get("volumeClaimTemplates", []) or []
        if not vclaim_templates:
            errors.append("StatefulSet missing volumeClaimTemplates")
        else:
            found_storage = False
            for tmpl in vclaim_templates:
                storage = (
                    tmpl.get("spec", {})
                    .get("resources", {})
                    .get("requests", {})
                    .get("storage")
                )
                if storage == EXPECTED_STORAGE:
                    found_storage = True
            if not found_storage:
                errors.append(f"StatefulSet volumeClaimTemplates must request {EXPECTED_STORAGE} storage")

        selector_labels = (
            sts.get("spec", {})
            .get("selector", {})
            .get("matchLabels")
        ) or {}
        pod_labels = (
            sts.get("spec", {})
            .get("template", {})
            .get("metadata", {})
            .get("labels")
        ) or {}
        if not selector_labels:
            errors.append("StatefulSet selector labels are missing")
        # Identity contract (§3.1): every later cockroachdb stage selects pods by
        # the canonical labels app.kubernetes.io/name=cockroachdb and
        # app.kubernetes.io/instance=crdb-cluster. The deploy prompt MANDATES
        # them, so enforce here that both the selector and the pod template carry
        # them -- otherwise a self-consistent but differently-labelled cluster
        # would be invisible to a downstream initialize/health/upgrade oracle.
        for key, value in CANONICAL_LABELS.items():
            if selector_labels.get(key) != value:
                errors.append(
                    f"StatefulSet selector must include canonical label {key}={value}"
                )
            if pod_labels.get(key) != value:
                errors.append(
                    f"Pod template must include canonical label {key}={value}"
                )

    if svc and pod_labels:
        selector = svc.get("spec", {}).get("selector") or {}
        for key, value in selector.items():
            if pod_labels.get(key) != value:
                errors.append("Discovery service selector does not match pod labels")
                break
    if pub_svc and pod_labels:
        selector = pub_svc.get("spec", {}).get("selector") or {}
        for key, value in selector.items():
            if pod_labels.get(key) != value:
                errors.append("Public service selector does not match pod labels")
                break

    if selector_labels:
        label_selector = ",".join(f"{key}={value}" for key, value in selector_labels.items())
        pods, err = kubectl_json(["get", "pods", "-l", label_selector])
        if err:
            errors.append(f"Failed to list pods: {err}")
        else:
            items = pods.get("items") or []
            if len(items) < EXPECTED_REPLICAS:
                errors.append(f"Expected {EXPECTED_REPLICAS} pods, found {len(items)}")
            # Grade FUNCTIONAL readiness (O-funcready) rather than the laggy k8s
            # pod-Ready bit: the cluster serves SQL and all expected nodes report
            # is_live=true. CockroachDB's readiness probe stays not-ready while
            # ranges replicate after a fresh deploy even though the node already
            # serves SQL, so a pod-Ready count can false-fail a healthy cluster.
            # Not a loosening -- a node that never joins is not is_live and an
            # uninitialized cluster fails SELECT 1.
            live, live_err = _live_node_count()
            if live_err:
                errors.append(f"Cluster not serving - node status: {live_err}")
            elif live < EXPECTED_REPLICAS:
                errors.append(
                    f"Expected {EXPECTED_REPLICAS} live nodes, found {live}")
            ok, sql_err = _sql_serves()
            if not ok:
                errors.append(f"Cluster not serving SQL - SELECT 1: {sql_err}")

    endpoints, err = kubectl_json(["get", "endpoints", "crdb-cluster"])
    if err:
        errors.append(f"Failed to read endpoints for crdb-cluster: {err}")
    else:
        # Identity/routing check only: the headless service must enroll every
        # replica. Count notReadyAddresses too -- endpoint READINESS mirrors the
        # laggy pod-Ready bit (O15) that the functional checks above (is_live +
        # SELECT 1) already grade; requiring ready-only addresses here would
        # re-impose the pod-Ready gate this oracle deliberately avoids.
        addresses = 0
        for subset in endpoints.get("subsets") or []:
            addresses += len(subset.get("addresses") or [])
            addresses += len(subset.get("notReadyAddresses") or [])
        if addresses < EXPECTED_REPLICAS:
            errors.append(f"Expected {EXPECTED_REPLICAS} endpoints, found {addresses}")

    if pod_labels:
        _check_quorum_budget(pod_labels, replicas or EXPECTED_REPLICAS, errors)

    _check_crdbcluster_absent(errors)

    return errors


def main():
    # Most checks here are static config (services, StatefulSet spec, image),
    # but pod readiness and endpoint membership are volatile: a freshly-deployed
    # CockroachDB pod takes a moment to pass its readiness probe and register an
    # endpoint, and under concurrent multi-cluster load one of the three can be
    # briefly NotReady at the instant the oracle samples (seen as "found 2"). So
    # re-evaluate for up to ~70s and pass on the first clean snapshot. This does
    # not loosen anything -- a pod that never becomes ready keeps failing after
    # the deadline; it only waits for the deploy to settle.
    import time
    deadline = time.monotonic() + 70
    errors = evaluate()
    while errors and time.monotonic() < deadline:
        time.sleep(7)
        errors = evaluate()

    if errors:
        print("Verification failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print("All resources created successfully")
    return 0


if __name__ == "__main__":
    sys.exit(main())

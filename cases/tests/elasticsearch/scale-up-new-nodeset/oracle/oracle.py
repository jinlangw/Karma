#!/usr/bin/env python3
import json
import os
import re
import shlex
import subprocess
import sys


NAMESPACE = os.environ.get("BENCH_NAMESPACE", "elasticsearch")
SERVICE = os.environ.get("BENCH_PARAM_HTTP_SERVICE_NAME", "es-http")
# Hint for the original StatefulSet name. Used as an override when it names an
# StatefulSet that actually exists; otherwise the original is detected live from
# the cluster (the env PERSISTS across stages, so a workflow's inherited ES
# cluster may carry a different StatefulSet name than this case's standalone
# default).
CLUSTER_PREFIX_HINT = os.environ.get("BENCH_PARAM_CLUSTER_PREFIX", "es-cluster")
INDEX_NAME = os.environ.get("BENCH_PARAM_INDEX_NAME", "app-data")
ORIGINAL_REPLICAS = int(os.environ.get("BENCH_PARAM_ORIGINAL_REPLICAS", "3"))
# Fallback expected-node count when the live cluster's StatefulSets can't be
# resolved (e.g. _cat/nodes failed/empty for an attempt). The real expected
# count is derived per-evaluate from the live cluster — see
# _resolve_expected_nodes().
DEFAULT_EXPECTED_NODES = 5
DEFAULT_SCHEME = "http"
_SCHEME = None
_CREDS = None
_ORIGINAL_STS = None


def run(cmd):
    return subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def _list_es_statefulsets():
    """Return the StatefulSet items in NAMESPACE whose pod template runs an
    Elasticsearch image. Returns a list of (name, replicas, creationTimestamp)."""
    res = run(["kubectl", "-n", NAMESPACE, "get", "sts", "-o", "json"])
    if res.returncode != 0:
        return []
    try:
        items = json.loads(res.stdout).get("items", [])
    except (json.JSONDecodeError, AttributeError):
        return []
    out = []
    for sts in items:
        meta = sts.get("metadata", {})
        spec = sts.get("spec", {})
        containers = spec.get("template", {}).get("spec", {}).get("containers", [])
        imgs = " ".join(c.get("image", "") for c in containers)
        if "elasticsearch" not in imgs:
            continue
        out.append((
            meta.get("name"),
            spec.get("replicas"),
            meta.get("creationTimestamp", ""),
        ))
    return out


def resolve_original_sts():
    """Resolve the ORIGINAL Elasticsearch StatefulSet name (pre-scale-up).

    Priority:
    1. The BENCH_PARAM_CLUSTER_PREFIX hint, IF it names a StatefulSet that
       actually exists in the cluster (explicit override wins).
    2. Live detection: among the namespace's Elasticsearch StatefulSets, the
       original is the one whose replicas match ORIGINAL_REPLICAS (the new
       nodeset is a separate StatefulSet); ties broken by oldest
       creationTimestamp. This makes the oracle workflow-agnostic regardless of
       the inherited cluster's StatefulSet name (e.g. 'es' vs 'es-cluster').
    3. The hint as a last resort (so error messages name something concrete).
    """
    global _ORIGINAL_STS
    if _ORIGINAL_STS is not None:
        return _ORIGINAL_STS

    es_sets = _list_es_statefulsets()
    names = {n for (n, _r, _c) in es_sets if n}

    # 1. Honor an explicit hint that points at a real StatefulSet.
    if CLUSTER_PREFIX_HINT in names:
        _ORIGINAL_STS = CLUSTER_PREFIX_HINT
        return _ORIGINAL_STS

    if es_sets:
        # 2a. Prefer the StatefulSet still at the original replica count.
        at_original = [s for s in es_sets if s[1] == ORIGINAL_REPLICAS and s[0]]
        candidates = at_original or [s for s in es_sets if s[0]]
        # Oldest first — the original cluster predates any new nodeset.
        candidates.sort(key=lambda s: (s[2] or ""))
        if candidates:
            _ORIGINAL_STS = candidates[0][0]
            return _ORIGINAL_STS

    # 3. Nothing detected; fall back to the hint (will surface a NotFound).
    _ORIGINAL_STS = CLUSTER_PREFIX_HINT
    return _ORIGINAL_STS


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


def _detect_creds():
    """Return '-u elastic:<password>' flag string if auth is needed, else ''."""
    global _CREDS
    if _CREDS is not None:
        return _CREDS
    # check explicit env override first
    pw = os.environ.get("BENCH_PARAM_ELASTIC_PASSWORD", "")
    if not pw:
        # try reading from the live secret used by the cluster
        for secret_name in ("elastic-password", "elastic-credentials"):
            res = run([
                "kubectl", "-n", NAMESPACE, "get", "secret", secret_name,
                "-o", "jsonpath={.data.password}",
            ])
            if res.returncode == 0 and res.stdout.strip():
                import base64
                try:
                    pw = base64.b64decode(res.stdout.strip()).decode()
                    break
                except Exception:
                    pass
    if not pw:
        # Secret skip-gated away on an inherited secured cluster -> read the
        # live StatefulSet's ELASTIC_PASSWORD env so the queries don't 401 (C1).
        pw = _password_from_sts() or ""
    _CREDS = f"-u elastic:{pw}" if pw else ""
    return _CREDS


def _sts_name_for_node(node_name):
    """Map a live ES node name to its backing StatefulSet name.

    An ES node name equals its pod name, which for a StatefulSet pod is
    ``<statefulset-name>-<ordinal>`` (e.g. ``es-cluster-0`` -> ``es-cluster``,
    ``es-data-1`` -> ``es-data``). Strip the trailing ``-<digits>`` ordinal.
    Returns the node name unchanged if it carries no ordinal suffix.
    """
    if not node_name:
        return node_name
    return re.sub(r"-\d+$", "", node_name)


def _live_sts_names(node_names):
    """Set of StatefulSet names actually backing the live cluster nodes.

    Derived by stripping each live node name's ordinal. This excludes
    accumulated/stale/other ES StatefulSets in the (persisted) namespace that
    back no node in the queried cluster.
    """
    return {_sts_name_for_node(n) for n in node_names if n}


def _resolve_expected_nodes(node_names, default=5):
    """Expected node count to enforce, derived from the LIVE cluster.

    The expected total is the DESIRED topology of ONLY the StatefulSets that
    actually back the live cluster (the nodes returned by ``_cat/nodes``): the
    sum of spec.replicas over just those StatefulSets. The namespace PERSISTS
    across workflow stages and accumulates multiple ES clusters (different
    stages' agents create differently-named clusters), so summing replicas
    across *every* ES StatefulSet wildly overcounts versus the single cluster
    the oracle queries. Restricting to the live cluster's StatefulSets fixes
    that overcount.

    Using DESIRED spec.replicas (not the live count) keeps the check strict: a
    node that FAILED to join leaves its StatefulSet "live" (siblings are up) but
    absent from ``_cat/nodes``, so EXPECTED stays above the actual count and the
    oracle still fails — no masking of a real node loss.

    BENCH_PARAM_EXPECTED_NODES / EXPECTED_NODE_COUNT is honored FIRST as an
    explicit override. Falls back to ``default`` when no live StatefulSets can
    be resolved (e.g. _cat/nodes failed or returned empty).
    """
    # Derive from the LIVE cluster FIRST (workflow-agnostic + composition-aware):
    # sum spec.replicas over the ES StatefulSets that are an active part of the
    # cluster -- the base cluster PLUS any nodeset a PRIOR stage added to the same
    # cluster (e.g. a transform nodeset in a transform->scale workflow). A static
    # EXPECTED_NODES param is a standalone-baseline assumption (e.g. "3 original +
    # 2 new = 5") that wrongly ignores such inherited nodesets and overcounts is
    # avoided by excluding torn-down StatefulSets (deletionTimestamp); so the
    # param is demoted to a FALLBACK below, used only when the live cluster cannot
    # be resolved. Counting DESIRED spec.replicas (not the live node count) keeps
    # it strict: a node that failed to join leaves its STS replicas>0 but absent
    # from _cat/nodes, so EXPECTED stays above the actual count and the check
    # still fails. The allocation-attribute and shard-relocation checks further
    # catch a no-op agent that leaves the cluster's nodeset topology unchanged.
    res = run(["kubectl", "-n", NAMESPACE, "get", "sts", "-o", "json"])
    if res.returncode == 0:
        try:
            items = json.loads(res.stdout).get("items", [])
        except Exception:
            items = []
        desired = 0
        # Restrict the sum to the StatefulSets that BACK the live cluster's nodes
        # (the names _cat/nodes returned). The persisted namespace can hold MULTIPLE
        # ES clusters -- a prior stage may have deployed a differently-named one
        # (e.g. deploy-core's es-nodes) alongside this case's es-cluster -- and
        # summing every ES StatefulSet overcounts versus the single cluster the
        # oracle queries. When the live set is unknown (no nodes resolved) fall back
        # to summing all (the health check has already failed in that case).
        live = _live_sts_names(node_names)
        for sts in items:
            name = (sts.get("metadata", {}) or {}).get("name")
            if live and name not in live:
                continue
            spec = sts.get("spec", {}) or {}
            containers = spec.get("template", {}).get("spec", {}).get("containers", []) or []
            if "elasticsearch" not in " ".join(c.get("image", "") for c in containers):
                continue
            replicas = spec.get("replicas")
            being_deleted = (sts.get("metadata", {}) or {}).get("deletionTimestamp") is not None
            if isinstance(replicas, int) and replicas > 0 and not being_deleted:
                desired += replicas
        if desired > 0:
            return desired

    # Fallbacks (live cluster unresolvable): explicit param, then the default.
    val = os.environ.get("BENCH_PARAM_EXPECTED_NODES")
    if val is None or not str(val).strip():
        val = os.environ.get("BENCH_PARAM_EXPECTED_NODE_COUNT")
    if val is None or not str(val).strip():
        val = os.environ.get("EXPECTED_NODE_COUNT")
    if val is not None and str(val).strip():
        try:
            return int(val)
        except ValueError:
            pass

    return default


def _probe_scheme(scheme):
    """True if the ES HTTP API answers on the given scheme (auth-agnostic)."""
    creds = _detect_creds()
    result = run([
        "kubectl", "-n", NAMESPACE, "exec", "curl-test", "--", "/bin/sh", "-c",
        f"curl -s -S -k {creds} -o /dev/null -w '%{{http_code}}' --max-time 5 {scheme}://{SERVICE}:9200/",
    ])
    code = (result.stdout or "").strip().strip("'")
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


def curl(path, errors):
    scheme = detect_scheme()
    creds = _detect_creds()
    cmd = [
        "kubectl",
        "-n",
        NAMESPACE,
        "exec",
        "curl-test",
        "--",
        "/bin/sh",
        "-c",
        # The client deadline (--max-time 20) must exceed any server-side
        # ``wait_for`` in `path`, otherwise curl aborts (exit 28) before ES can
        # answer. The retry loop in main() does the real waiting, so each call's
        # server wait stays short (10s).
        # P22: shell-quote the URL — an unquoted `&` in `path` backgrounds curl
        # inside the pod's sh and grep gets no input.
        f"curl -s -S -k {creds} --max-time 20 {shlex.quote(f'{scheme}://{SERVICE}:9200{path}')}",
    ]
    result = run(cmd)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or f"command terminated with exit code {result.returncode}"
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


def get_original_nodes(errors):
    # Query all pods and filter by StatefulSet ownerReference; the app label
    # may not match the original StatefulSet if a prior stage reconfigured it.
    original_sts = resolve_original_sts()
    result = run(["kubectl", "-n", NAMESPACE, "get", "pods", "-o", "json"])
    if result.returncode != 0:
        errors.append(f"Failed to list Elasticsearch pods: {result.stderr.strip()}")
        return []
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        errors.append("Failed to parse pod list JSON")
        return []

    names = []
    for item in payload.get("items", []):
        for owner in item.get("metadata", {}).get("ownerReferences", []):
            if owner.get("kind") == "StatefulSet" and owner.get("name") == original_sts:
                names.append(item.get("metadata", {}).get("name"))
                break
    return names


def sum_original_replicas(node_names):
    """Sum spec.replicas over the ORIGINAL (pre-scale-up) ES StatefulSets.

    The "original" topology is a cross-topology tally, not a single object (O2):
    the base cluster can itself be SEVERAL StatefulSets (a composed
    es-transport(3)+es-data(2)=5 base has no single STS at 5), so match the
    summed total, never a scalar param against one STS. Sums spec.replicas over
    the not-being-deleted live ES StatefulSets EXCEPT the agent's newly-created
    nodeset (the newest by creationTimestamp — the base predates this stage).
    Returns the summed int, or None when it can't be resolved. Works for the
    standalone single-STS case too: base=es-cluster(3), new nodeset excluded ->
    sum 3.
    """
    res = run(["kubectl", "-n", NAMESPACE, "get", "sts", "-o", "json"])
    if res.returncode != 0:
        return None
    try:
        items = json.loads(res.stdout).get("items", [])
    except (json.JSONDecodeError, AttributeError):
        return None
    live = _live_sts_names(node_names)
    es = []
    for sts in items:
        meta = sts.get("metadata", {}) or {}
        spec = sts.get("spec", {}) or {}
        name = meta.get("name")
        containers = spec.get("template", {}).get("spec", {}).get("containers", []) or []
        if "elasticsearch" not in " ".join(c.get("image", "") for c in containers):
            continue
        if live and name not in live:
            continue
        if meta.get("deletionTimestamp") is not None:
            continue
        replicas = spec.get("replicas")
        if not isinstance(replicas, int):
            continue
        es.append((name, replicas, meta.get("creationTimestamp", "")))
    if not es:
        return None
    # Exclude the agent's new nodeset: the newest live ES StatefulSet. The base
    # cluster's StatefulSets predate this stage; the agent created the new nodeset
    # during it, so it carries the latest creationTimestamp.
    newest = max(es, key=lambda s: (s[2] or ""))
    return sum(r for (n, r, _c) in es if n != newest[0])


# ES system/built-in node attributes (not operator-set allocation attributes).
# These vary across nodes for reasons unrelated to allocation awareness (a
# transform/ml node carries transform.node=true, ml.* memory sizing differs by
# pod, etc.), so they must be excluded when deciding whether the agent applied a
# *distinguishing allocation attribute*.
_BUILTIN_ATTR_PREFIXES = ("ml.", "xpack.", "transform.")


def _is_builtin_attr(key):
    return any(key.startswith(p) for p in _BUILTIN_ATTR_PREFIXES)


def attribute_differs(attributes_by_node, original_nodes, new_nodes):
    # The new nodeset is "distinguished" when some new node carries a custom
    # allocation attribute (key,value) that no original node has -- covering BOTH
    # a brand-new key the originals lack (node.attr.rack=new on a scaled-up data
    # nodeset while the originals have no rack) AND a shared key with a different
    # value (node.attr.zone=new on the new nodes while the originals carry
    # node.attr.zone=<other>). ES built-in attributes (transform.node, xpack.*,
    # ml.*) are excluded so a transform/ml node is not mistaken for a
    # distinguishing allocation attribute, and the new nodes need NOT be
    # homogeneous. An agent that added no custom allocation attribute leaves the
    # new nodes carrying only keys/values the originals also have, so this fails.
    if not original_nodes or not new_nodes:
        return False
    original_pairs = set()
    for n in original_nodes:
        for key, value in attributes_by_node.get(n, {}).items():
            if not _is_builtin_attr(key):
                original_pairs.add((key, value))
    for n in new_nodes:
        for key, value in attributes_by_node.get(n, {}).items():
            if _is_builtin_attr(key) or value in (None, ""):
                continue
            if (key, value) not in original_pairs:
                return True
    return False


def evaluate():
    """Run one full snapshot of the scale-up checks; return the list of errors."""
    errors = []

    # Resolve the live cluster's node list FIRST: the expected node count is
    # derived from only the StatefulSets that actually back these live nodes
    # (the persisted namespace accumulates several ES clusters across stages, so
    # summing every ES StatefulSet's replicas overcounts the queried cluster).
    nodes = curl("/_cat/nodes?format=json", errors)
    node_names = []
    if isinstance(nodes, list):
        node_names = [n.get("name") for n in nodes if n.get("name")]
    expected_nodes = _resolve_expected_nodes(node_names, default=DEFAULT_EXPECTED_NODES)

    health = curl(
        f"/_cluster/health?wait_for_status=yellow&wait_for_nodes={expected_nodes}&timeout=10s",
        errors,
    )
    if isinstance(health, dict):
        status = health.get("status")
        if status not in {"yellow", "green"}:
            errors.append(f"Cluster health status expected yellow/green, got {status}")
        if health.get("number_of_nodes") != expected_nodes:
            # Diagnostic: when the desired-replica total disagrees with the live
            # node count, dump the per-StatefulSet replica breakdown so an
            # over-provisioned / inherited nodeset is visible in the verdict.
            print("[diag] es statefulsets (name,replicas,created)=%s" % (_list_es_statefulsets(),), file=sys.stderr)
            errors.append(f"Expected {expected_nodes} nodes, got {health.get('number_of_nodes')}")

    if isinstance(nodes, list):
        if len(node_names) != expected_nodes:
            errors.append(f"Expected {expected_nodes} nodes in _cat/nodes, got {len(node_names)}")

    original_nodes = get_original_nodes(errors)
    if original_nodes:
        new_nodes = [n for n in node_names if n not in original_nodes]
        if len(new_nodes) < 2:
            errors.append("Expected at least 2 new nodes outside original StatefulSet")
    else:
        new_nodes = []
        errors.append("Unable to determine original StatefulSet nodes")

    attrs = curl("/_nodes?filter_path=nodes.*.name,nodes.*.attributes", errors)
    if isinstance(attrs, dict):
        attributes_by_node = {}
        for node in attrs.get("nodes", {}).values():
            name = node.get("name")
            if name:
                attributes_by_node[name] = node.get("attributes", {})
        if original_nodes and new_nodes and not attribute_differs(attributes_by_node, original_nodes, new_nodes):
            errors.append("No allocation attribute differs between original nodes and new nodes")

    shards = curl(f"/_cat/shards/{INDEX_NAME}?format=json", errors)
    if isinstance(shards, list) and new_nodes:
        on_new = [s for s in shards if s.get("node") in new_nodes]
        if not on_new:
            errors.append(f"No {INDEX_NAME} shards found on new nodes")

    # The original-topology replica total is a SUM over the non-new base
    # StatefulSets (O2), not a single STS matched against a scalar param: a
    # composed 3+2 base has no STS at 5, so the old single-STS assertion
    # false-failed a perfect scale-up. Keep the new-nodeset checks (zone attr,
    # green, shard placement) above as-is; this only re-grades the base tally.
    original_total = sum_original_replicas(node_names)
    if original_total is not None and original_total != ORIGINAL_REPLICAS:
        errors.append(
            f"Original nodeset replicas expected {ORIGINAL_REPLICAS}, "
            f"got {original_total} (summed over the non-new base StatefulSets)"
        )

    return errors


def main():
    # A multi-node ES cluster can flap at the edge of readiness under load: a
    # node briefly fails its HTTP readiness probe / drops from the cluster during
    # GC or shard recovery even though it is stably green. A single snapshot can
    # catch that transient and report a false node-count miss. So verify the
    # STABLE converged state: re-evaluate for up to ~75s and pass on the first
    # clean snapshot. This does not loosen the N-node/green/shard-placement
    # requirements -- a genuinely degraded cluster fails every attempt.
    import time
    deadline = time.monotonic() + 150
    errors = evaluate()
    while errors and time.monotonic() < deadline:
        time.sleep(8)
        errors = evaluate()

    if errors:
        print("Scale-up nodeset verification failed:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    print("Scale-up new nodeset verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())

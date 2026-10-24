#!/usr/bin/env python3
import json
import os
import re
import subprocess
import sys

NAMESPACE = "elasticsearch"
SERVICE = "es-http"
# Hint for the Elasticsearch StatefulSet name. Used as an override when it names
# a StatefulSet that actually exists; otherwise the StatefulSet (and its real
# pod selector label) are detected live from the cluster. The env PERSISTS
# across stages, so a workflow's inherited ES cluster may carry a different
# StatefulSet name/label than this case's standalone default of 'es-cluster'.
CLUSTER_PREFIX_HINT = os.environ.get("BENCH_PARAM_CLUSTER_PREFIX", "es-cluster")
REPO_NAME = "minio-repo"
# The S3 *client name* an agent registers the repo under (`s3.client.<name>.*`)
# is a free ES choice the prompt never discloses; the disclosing artifact
# (es-secure-settings) is skip-gated away on an inherited cluster (P33). So the
# keystore key names are NOT hardcoded to `default` (O1) — a valid solve using
# `s3.client.minio.*` false-fails. Instead the effective outcome is graded (repo
# registered + a snapshot reaches SUCCESS, see check_snapshots), and any keystore
# sanity check derives the client name from the live registered repo. Template
# with the resolved client name substituted at check time.
_KEY_TEMPLATE = ("s3.client.{client}.access_key", "s3.client.{client}.secret_key")
# ES 8.x runs with security enabled, so the HTTP API requires authenticating as
# the elastic superuser. When this case inherits a secured cluster from an
# earlier workflow stage, read its password from the secret that stage created
# so the oracle's queries aren't rejected with 401. Absent secret -> None -> no
# -u, so a standalone unsecured cluster still works.
PASSWORD_SECRET = os.environ.get("BENCH_PARAM_ELASTIC_PASSWORD_SECRET_NAME", "elastic-password")
PASSWORD_KEY = os.environ.get("BENCH_PARAM_ELASTIC_PASSWORD_KEY", "password")
DEFAULT_SCHEME = "http"
_SCHEME = None


def run(cmd):
    return subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


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
    """Fall back to the live ES StatefulSet's ELASTIC_PASSWORD env when the
    elastic-password secret is absent.

    That secret is created only by a skip-gated predecessor; on an inherited
    secured cluster it does not exist, so `_elastic_password()` returns None and
    the oracle's curls 401 (C1). The live cluster's password is carried in the ES
    StatefulSet container env `ELASTIC_PASSWORD` — read it (literal value, or via
    its secretKeyRef) so an inherited cluster still authenticates.
    """
    sts = resolve_es_sts()[0]
    if not sts:
        return None
    base = ["kubectl", "-n", NAMESPACE, "get", "sts", sts, "-o"]
    env = ".spec.template.spec.containers[*].env[?(@.name=='ELASTIC_PASSWORD')]"
    r = run(base + ["jsonpath={" + env + ".value}"])
    if r.returncode == 0 and r.stdout.strip():
        return r.stdout.strip()
    # env sourced from a secretKeyRef -> read that secret.
    rn = run(base + ["jsonpath={" + env + ".valueFrom.secretKeyRef.name}"])
    rk = run(base + ["jsonpath={" + env + ".valueFrom.secretKeyRef.key}"])
    name = (rn.stdout or "").strip()
    key = (rk.stdout or "").strip() or "password"
    if name:
        import base64
        rs = run(["kubectl", "-n", NAMESPACE, "get", "secret", name,
                  "-o", "jsonpath={.data." + key + "}"])
        if rs.returncode == 0 and rs.stdout.strip():
            try:
                return base64.b64decode(rs.stdout.strip()).decode()
            except Exception:
                return None
    return None


ELASTIC_PASSWORD = None  # set in main() once kubectl is reachable


_ES_STS = None


def _list_es_statefulsets():
    """Return [(name, app_label_value, creationTimestamp)] for the namespace's
    StatefulSets whose pod template runs an Elasticsearch image."""
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
        if "elasticsearch" not in " ".join(c.get("image", "") for c in containers):
            continue
        app = (spec.get("selector", {}).get("matchLabels", {}) or {}).get("app")
        out.append((meta.get("name"), app, meta.get("creationTimestamp", "")))
    return out


def resolve_es_sts():
    """Resolve (sts_name, app_label_selector) for the live ES StatefulSet.

    Priority: the BENCH_PARAM_CLUSTER_PREFIX hint when it names a real
    StatefulSet (explicit override wins) -> the single ES StatefulSet detected
    live (oldest first if several). Workflow-agnostic: adapts to an inherited
    cluster whose StatefulSet name/label differ from the standalone default.
    """
    global _ES_STS
    if _ES_STS is not None:
        return _ES_STS
    es_sets = _list_es_statefulsets()
    by_name = {n: (n, a) for (n, a, _c) in es_sets if n}
    if CLUSTER_PREFIX_HINT in by_name:
        name, app = by_name[CLUSTER_PREFIX_HINT]
        _ES_STS = (name, f"app={app}" if app else f"app={name}")
        return _ES_STS
    if es_sets:
        candidates = [s for s in es_sets if s[0]]
        candidates.sort(key=lambda s: (s[2] or ""))
        name, app, _c = candidates[0]
        _ES_STS = (name, f"app={app}" if app else f"app={name}")
        return _ES_STS
    _ES_STS = (CLUSTER_PREFIX_HINT, f"app={CLUSTER_PREFIX_HINT}")
    return _ES_STS


STS_NAME = resolve_es_sts()[0]
APP_LABEL = resolve_es_sts()[1]


def _list_es_statefulset_replicas():
    """Return {sts_name: spec.replicas} for the namespace's Elasticsearch
    StatefulSets (those whose pod template runs an Elasticsearch image)."""
    res = run(["kubectl", "-n", NAMESPACE, "get", "sts", "-o", "json"])
    if res.returncode != 0:
        return {}
    try:
        items = json.loads(res.stdout).get("items", [])
    except (json.JSONDecodeError, AttributeError):
        return {}
    out = {}
    for sts in items:
        spec = sts.get("spec", {})
        containers = spec.get("template", {}).get("spec", {}).get("containers", [])
        if "elasticsearch" not in " ".join(c.get("image", "") for c in containers):
            continue
        name = sts.get("metadata", {}).get("name")
        replicas = spec.get("replicas")
        if name and isinstance(replicas, int):
            out[name] = replicas
    return out


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


def _resolve_expected_nodes(node_names, default=3):
    """Expected node count to enforce, derived from the LIVE cluster.

    The expected total is the DESIRED topology of ONLY the StatefulSets that
    actually back the live cluster (the nodes returned by ``_cat/nodes``): the
    sum of spec.replicas over just those StatefulSets. The namespace PERSISTS
    across workflow stages and accumulates multiple ES clusters, so summing
    replicas across *every* ES StatefulSet overcounts versus the single cluster
    the oracle queries. Restricting to the live cluster's StatefulSets fixes that.

    Using DESIRED spec.replicas (not the live count) keeps the check strict: a
    node that FAILED to join leaves its StatefulSet "live" (siblings are up) but
    absent from ``_cat/nodes``, so EXPECTED stays above the actual count -- no
    masking. The LIVE cluster is derived FIRST; the param is a FALLBACK used only
    when no live StatefulSets resolve (e.g. _cat/nodes failed or returned empty).
    """
    # Derive from the LIVE cluster FIRST (workflow-agnostic + composition-aware):
    # sum spec.replicas over ONLY the ES StatefulSets that actually back a live
    # node returned by ``_cat/nodes`` (the queried cluster). The namespace
    # PERSISTS across workflow stages and ACCUMULATES several ES clusters/nodesets
    # (e.g. an inherited transform nodeset, or a prior stage's separate cluster);
    # summing spec.replicas across *every* ES StatefulSet overcounts the single
    # cluster the oracle queries (observed live: EXPECTED=9 vs live_nodes=5). The
    # live-node -> StatefulSet mapping (strip the pod ordinal) scopes the sum to
    # the cluster under test. A static EXPECTED_NODES param encodes a standalone
    # baseline that ignores inherited nodesets, so it is demoted to a FALLBACK
    # below, used only when the live cluster cannot be resolved.
    #
    # Using DESIRED spec.replicas (not the raw live count) keeps the check strict:
    # a node that FAILED to join leaves its StatefulSet "live" (siblings are up and
    # appear in _cat/nodes) but absent itself, so the spec sum stays above the
    # actual count -- no masking. A torn-down prior cluster's StatefulSet backs no
    # live node, so it is excluded.
    live_sts = _live_sts_names(node_names)
    if live_sts:
        res = run(["kubectl", "-n", NAMESPACE, "get", "sts", "-o", "json"])
        if res.returncode == 0:
            try:
                items = json.loads(res.stdout).get("items", [])
            except Exception:
                items = []
            desired = 0
            for sts in items:
                spec = sts.get("spec", {}) or {}
                name = (sts.get("metadata", {}) or {}).get("name")
                if name not in live_sts:
                    continue
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
    for key in ("BENCH_PARAM_EXPECTED_NODES", "BENCH_PARAM_EXPECTED_NODE_COUNT"):
        val = os.environ.get(key)
        if val is not None and str(val).strip():
            try:
                return int(val)
            except ValueError:
                pass
    return default


def _es_pod_name():
    """Name of a live ES pod (for a pod-local curl fallback), or None."""
    r = run(["kubectl", "-n", NAMESPACE, "get", "pods", "-l", APP_LABEL,
             "-o", "jsonpath={.items[0].metadata.name}"])
    name = (r.stdout or "").strip()
    return name or None


def _target_base(scheme):
    """(exec_pod, host) the oracle's curl should hit for the given scheme.

    Prefer the helper ``curl-test`` pod -> the es-http Service. When a prior
    workflow stage (e.g. a password rotation) leaves the StatefulSet pods
    NotReady, the Service has zero endpoints and a Service curl returns exit 7;
    fall back to exec-ing INTO a live ES pod and hitting ``localhost:9200`` so the
    oracle can still grade an otherwise-correct cluster. The es-http path is tried
    first so standalone behaviour is unchanged.
    """
    if _service_has_endpoints():
        return "curl-test", f"{SERVICE}.{NAMESPACE}.svc:9200"
    pod = _es_pod_name()
    if pod:
        return pod, "localhost:9200"
    return "curl-test", f"{SERVICE}.{NAMESPACE}.svc:9200"


def _service_has_endpoints():
    """True if the es-http Service currently has at least one ready endpoint."""
    r = run(["kubectl", "-n", NAMESPACE, "get", "endpoints", SERVICE,
             "-o", "jsonpath={.subsets[*].addresses[*].ip}"])
    return r.returncode == 0 and bool((r.stdout or "").strip())


def _probe_scheme(scheme):
    """True if the ES HTTP API answers on the given scheme (auth-agnostic)."""
    pod, host = _target_base(scheme)
    result = run([
        "kubectl", "-n", NAMESPACE, "exec", pod, "--", "/bin/sh", "-c",
        f"curl -s -S -k -o /dev/null -w '%{{http_code}}' --max-time 5 {scheme}://{host}/",
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
    auth = ""
    if ELASTIC_PASSWORD:
        import shlex
        auth = f"-u {shlex.quote('elastic:' + ELASTIC_PASSWORD)} "
    # Prefer the es-http Service via curl-test; fall back to a pod-local
    # localhost:9200 curl when the Service has no ready endpoints (e.g. a prior
    # stage rotated the password and left pods NotReady, dropping the endpoints).
    pod, host = _target_base(scheme)
    cmd = [
        "kubectl",
        "-n",
        NAMESPACE,
        "exec",
        pod,
        "--",
        "/bin/sh",
        "-c",
        # The client deadline (--max-time 20) must exceed any server-side
        # ``wait_for`` in `path`, otherwise curl aborts (exit 28) before ES can
        # answer. The retry loop in main() does the real waiting, so each call's
        # server wait stays short (10s).
        f"curl -s -S -k {auth}--max-time 20 {scheme}://{host}{path}",
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


def get_pods(errors):
    result = run(
        [
            "kubectl",
            "-n",
            NAMESPACE,
            "get",
            "pods",
            "-l",
            APP_LABEL,
            "-o",
            "json",
        ]
    )
    if result.returncode != 0:
        errors.append(f"Failed to list Elasticsearch pods: {result.stderr.strip()}")
        return []
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        errors.append("Failed to parse pod list JSON")
        return []
    return [item.get("metadata", {}).get("name") for item in payload.get("items", [])]


def _repo_client_name(errors):
    """Client name the registered snapshot repo uses (`settings.client`).

    Derived from the live registered repo (`GET /_snapshot/<repo>`) rather than
    hardcoded to `default` (O1): the client name is a free, undisclosed agent
    choice. Defaults to `default` (ES's implicit client) when the repo omits it.
    Returns None if the repo cannot be resolved (check_snapshots already grades
    the repo's presence, so this stays silent to avoid a duplicate error).
    """
    repo = curl(f"/_snapshot/{REPO_NAME}", errors=[])
    if not isinstance(repo, dict):
        return None
    settings = (repo.get(REPO_NAME, {}) or {}).get("settings", {}) or {}
    client = settings.get("client")
    return client or "default"


def check_keystore(pod, errors):
    # Grade the keystore against the client name the LIVE repo actually uses
    # (O1) — never a hardcoded `default`. A valid solve may register the repo
    # under `s3.client.minio.*`; asserting `default` false-fails it. The
    # effective outcome (repo registered + a SUCCESS snapshot) is already graded
    # in check_snapshots; this is a client-derived sanity check on top of it.
    client = _repo_client_name(errors)
    if not client:
        return
    expected = {tpl.format(client=client) for tpl in _KEY_TEMPLATE}
    result = run(
        [
            "kubectl",
            "-n",
            NAMESPACE,
            "exec",
            pod,
            "--",
            "/usr/share/elasticsearch/bin/elasticsearch-keystore",
            "list",
        ]
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        errors.append(f"Failed to list keystore on {pod}: {detail}")
        return
    keys = {line.strip() for line in result.stdout.splitlines() if line.strip()}
    missing = sorted(expected - keys)
    if missing:
        errors.append(f"Missing keystore keys on {pod}: {', '.join(missing)}")


def check_configmap(errors):
    # The es-config ConfigMap is a STANDALONE-only artifact: only this case's own
    # resource/ creates it. In a chained build the cluster is inherited from an
    # earlier stage (e.g. deploy-core-cluster) that never applies it, so it does
    # not exist. The behavioural property this guards -- "no plaintext S3
    # credentials live in elasticsearch.yml / a ConfigMap" -- is satisfied by its
    # ABSENCE, so gate the check on the ConfigMap's presence rather than demanding
    # the named object. Standalone (where the build created es-config) this still
    # asserts no plaintext creds leaked into it.
    result = run(
        [
            "kubectl",
            "-n",
            NAMESPACE,
            "get",
            "configmap",
            "es-config",
            "-o",
            "json",
        ]
    )
    if result.returncode != 0:
        return
    try:
        cm = json.loads(result.stdout)
    except json.JSONDecodeError:
        errors.append("Failed to parse es-config ConfigMap JSON")
        return
    text = json.dumps(cm)
    if "access_key" in text or "secret_key" in text:
        errors.append("Plaintext credentials found in es-config ConfigMap")


def check_snapshots(errors):
    repo = curl(f"/_snapshot/{REPO_NAME}", errors)
    if repo is None:
        return
    if "error" in repo:
        errors.append(f"Snapshot repository {REPO_NAME} not found")
        return

    snaps = curl(f"/_snapshot/{REPO_NAME}/_all", errors)
    if not isinstance(snaps, dict):
        return
    snapshots = snaps.get("snapshots", [])
    if not snapshots:
        errors.append("No snapshots found in repository")
        return
    success = [s for s in snapshots if s.get("state") == "SUCCESS"]
    if not success:
        errors.append("No SUCCESS snapshots found in repository")


def evaluate():
    """Run one full snapshot of the snapshot-repo checks; return the errors."""
    errors = []

    # Resolve the live cluster's node list FIRST: the expected node count is
    # derived from only the StatefulSets that actually back these live nodes
    # (the persisted namespace accumulates several ES clusters across stages, so
    # summing every ES StatefulSet's replicas overcounts the queried cluster).
    nodes = curl("/_cat/nodes?format=json", errors)
    node_names = []
    if isinstance(nodes, list):
        node_names = [n.get("name") for n in nodes if n.get("name")]
    expected_nodes = _resolve_expected_nodes(node_names, default=3)

    health = curl(
        f"/_cluster/health?wait_for_status=yellow&wait_for_nodes={expected_nodes}&timeout=10s",
        errors,
    )
    if isinstance(health, dict):
        status = health.get("status")
        if status not in {"yellow", "green"}:
            errors.append(f"Cluster health status expected yellow/green, got {status}")
        if health.get("number_of_nodes") != expected_nodes:
            # Diagnostic: dump the per-StatefulSet replica breakdown so a topology
            # mismatch (a live node not backed by an ES-image StatefulSet the sum
            # counts) is visible in the verdict on the next run.
            _sts = run(["kubectl", "-n", NAMESPACE, "get", "sts", "-o",
                        "jsonpath={range .items[*]}{.metadata.name}={.spec.replicas}:{.spec.template.spec.containers[0].image} {end}"])
            print(f"[diag] EXPECTED={expected_nodes} live_nodes={health.get('number_of_nodes')} sts={(_sts.stdout or '').strip()}", file=sys.stderr)
            errors.append(
                f"Expected {expected_nodes} nodes, got {health.get('number_of_nodes')}"
            )

    check_snapshots(errors)
    check_configmap(errors)

    pods = get_pods(errors)
    if pods:
        for pod in pods:
            check_keystore(pod, errors)
    else:
        errors.append("No Elasticsearch pods found to verify keystore")

    return errors


def main():
    global ELASTIC_PASSWORD
    # Prefer the elastic-password secret; when it is absent (skip-gated on an
    # inherited cluster) fall back to the live StatefulSet's ELASTIC_PASSWORD env
    # so the oracle authenticates instead of 401-ing (C1).
    ELASTIC_PASSWORD = _elastic_password() or _password_from_sts()

    # A multi-node ES cluster can flap at the edge of readiness under load: a
    # node briefly fails its HTTP readiness probe / drops from the cluster during
    # GC or shard recovery even though it is stably green; and on a busy cluster a
    # kubectl exec/curl can transiently fail to reach an otherwise-healthy pod
    # ("unable to upgrade connection" / empty response). A single snapshot can
    # catch that transient and report a false miss. So verify the STABLE converged
    # state: re-evaluate for up to ~120s and pass on the first clean snapshot. The
    # window is wider here than in lighter cases because composed runs inherit a
    # larger cluster (extra nodesets) that takes longer to settle. This does not
    # loosen the N-node/green/snapshot/keystore requirements -- a genuinely
    # degraded cluster fails every attempt.
    import time
    deadline = time.monotonic() + 120
    errors = evaluate()
    while errors and time.monotonic() < deadline:
        time.sleep(8)
        errors = evaluate()

    if errors:
        print("Secure settings verification failed:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    print("Secure settings verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())

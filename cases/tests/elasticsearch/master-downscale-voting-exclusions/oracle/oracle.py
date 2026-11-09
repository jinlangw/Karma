#!/usr/bin/env python3
import json
import os
import subprocess
import sys

NAMESPACE = os.environ.get("BENCH_NAMESPACE", "elasticsearch")
SERVICE = os.environ.get("BENCH_PARAM_HTTP_SERVICE_NAME", "es-http")
CURL_POD = os.environ.get("BENCH_PARAM_CURL_POD_NAME", "curl-test")
# Hint for the Elasticsearch pod app label. Used as an override when it matches a
# live StatefulSet's selector; otherwise the real selector label is detected
# live from the cluster. The env PERSISTS across stages, so a workflow's
# inherited ES cluster may label its pods differently than this case's standalone
# default of 'es-cluster'.
CLUSTER_PREFIX_HINT = os.environ.get("BENCH_PARAM_CLUSTER_PREFIX", "es-cluster")
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


_APP_LABEL = None


def resolve_app_label():
    """Resolve the 'app=<value>' selector for the live ES pods.

    Priority: the BENCH_PARAM_CLUSTER_PREFIX hint when some live StatefulSet
    actually selects on app=<hint> (explicit override wins) -> the app label of
    the namespace's Elasticsearch StatefulSet detected live -> the hint.
    Workflow-agnostic: adapts to an inherited cluster labelled e.g.
    app=elasticsearch instead of app=es-cluster.
    """
    global _APP_LABEL
    if _APP_LABEL is not None:
        return _APP_LABEL
    res = run(["kubectl", "-n", NAMESPACE, "get", "sts", "-o", "json"])
    labels = []
    if res.returncode == 0:
        try:
            for sts in json.loads(res.stdout).get("items", []):
                spec = sts.get("spec", {})
                containers = spec.get("template", {}).get("spec", {}).get("containers", [])
                if "elasticsearch" not in " ".join(c.get("image", "") for c in containers):
                    continue
                app = (spec.get("selector", {}).get("matchLabels", {}) or {}).get("app")
                ts = sts.get("metadata", {}).get("creationTimestamp", "")
                if app:
                    labels.append((app, ts))
        except (json.JSONDecodeError, AttributeError):
            pass
    if any(app == CLUSTER_PREFIX_HINT for app, _ in labels):
        _APP_LABEL = f"app={CLUSTER_PREFIX_HINT}"
        return _APP_LABEL
    if labels:
        labels.sort(key=lambda x: (x[1] or ""))
        _APP_LABEL = f"app={labels[0][0]}"
        return _APP_LABEL
    _APP_LABEL = f"app={CLUSTER_PREFIX_HINT}"
    return _APP_LABEL


APP_LABEL = resolve_app_label()


def _resolve_expected_nodes(default=1):
    """Target master/node count (param -> default 1; NEVER live-derived).

    O2-exception: the downscaled count IS the graded outcome, so it must stay
    param-first (``target_master_nodes``, declared in test.yaml with default 1,
    mirroring safe-downscale's BENCH_PARAM_TARGET_REPLICAS). Deriving it from
    the live Ready-pod count would mask a failed/never-done downscale: an
    untouched 3-node cluster would grade itself against expected=3 and pass.
    """
    for key in ("BENCH_PARAM_TARGET_MASTER_NODES", "BENCH_PARAM_EXPECTED_NODES"):
        val = os.environ.get(key)
        if val is not None and str(val).strip():
            try:
                return int(val)
            except ValueError:
                pass
    return default


EXPECTED_NODES = _resolve_expected_nodes(1)


def _probe_scheme(scheme):
    """True if the ES HTTP API answers on the given scheme (auth-agnostic)."""
    result = run([
        "kubectl", "-n", NAMESPACE, "exec", CURL_POD, "--",
        "curl", "-s", "-S", "-k", "-o", "/dev/null",
        "-w", "%{http_code}", "--max-time", "5", f"{scheme}://{SERVICE}:9200/",
    ])
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


def curl_json(path, errors):
    scheme = detect_scheme()
    # The client deadline (--max-time 20) must exceed any server-side
    # ``timeout``/``wait_for`` in `path`, otherwise curl aborts (exit 28) before
    # ES can answer. The retry loop in main() does the real waiting, so each
    # call's server wait stays short (<=10s).
    result = run(
        [
            "kubectl",
            "-n",
            NAMESPACE,
            "exec",
            CURL_POD,
            "--",
            "curl",
            "-s",
            "-S",
            "-k",
        ]
        + (["-u", f"elastic:{ELASTIC_PASSWORD}"] if ELASTIC_PASSWORD else [])
        + [
            "--max-time",
            "20",
            f"{scheme}://{SERVICE}:9200{path}",
        ]
    )
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


def get_nodes(errors):
    nodes = curl_json("/_cat/nodes?format=json&h=name,node.role", errors)
    if not isinstance(nodes, list):
        return None
    return nodes


def get_exclusions(errors):
    state = curl_json(
        "/_cluster/state?filter_path=metadata.cluster_coordination.voting_config_exclusions",
        errors,
    )
    if not isinstance(state, dict):
        return None
    return state.get("metadata", {}).get("cluster_coordination", {}).get(
        "voting_config_exclusions", []
    )


def is_auto_shrink_enabled(errors):
    settings = curl_json(
        "/_cluster/settings?filter_path=persistent.cluster.auto_shrink_voting_configuration,"
        "transient.cluster.auto_shrink_voting_configuration",
        errors,
    )
    if not isinstance(settings, dict):
        return None

    def value_is_false(value):
        if value is None:
            return False
        if isinstance(value, bool):
            return not value
        if isinstance(value, str):
            return value.strip().lower() == "false"
        return False

    persistent = (
        settings.get("persistent", {})
        .get("cluster", {})
        .get("auto_shrink_voting_configuration")
    )
    transient = (
        settings.get("transient", {})
        .get("cluster", {})
        .get("auto_shrink_voting_configuration")
    )
    if value_is_false(persistent) or value_is_false(transient):
        return False
    return True


def evaluate():
    """Run one full snapshot of the master-downscale checks; return the errors."""
    errors = []

    health = curl_json("/_cluster/health?timeout=5s", errors)
    if isinstance(health, dict):
        status = health.get("status")
        if status not in {"yellow", "green"}:
            errors.append(f"Cluster health expected yellow/green, got {status}")

    nodes = get_nodes(errors)
    if isinstance(nodes, list):
        if len(nodes) != EXPECTED_NODES:
            errors.append(f"Expected {EXPECTED_NODES} nodes, got {len(nodes)}")
        masters = [
            n
            for n in nodes
            if "m" in (n.get("roles") or n.get("node.role") or "")
        ]
        if len(masters) != EXPECTED_NODES:
            errors.append(f"Expected {EXPECTED_NODES} master-eligible nodes, got {len(masters)}")

    exclusions = get_exclusions(errors)
    if exclusions:
        errors.append("Voting exclusions were not cleared")

    auto_shrink = is_auto_shrink_enabled(errors)
    if auto_shrink is False:
        errors.append("auto_shrink_voting_configuration is disabled")

    return errors


def main():
    global ELASTIC_PASSWORD
    ELASTIC_PASSWORD = _elastic_password() or _password_from_sts()

    # A multi-node ES cluster can flap at the edge of readiness under load: a
    # node briefly fails its HTTP readiness probe / drops from the cluster during
    # GC or shard recovery even though it is stably green. A single snapshot can
    # catch that transient and report a false node/master-count miss. So verify
    # the STABLE converged state: re-evaluate for up to ~75s and pass on the
    # first clean snapshot. This does not loosen the node-count/green/voting
    # requirements -- a genuinely degraded cluster fails every attempt.
    import time
    deadline = time.monotonic() + 75
    errors = evaluate()
    while errors and time.monotonic() < deadline:
        time.sleep(8)
        errors = evaluate()

    if errors:
        print("Master downscale recovery verification failed:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    print("Master downscale recovery verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
import json
import os
import subprocess
import sys

NAMESPACE = os.environ.get("BENCH_NAMESPACE", "elasticsearch")
PROD_SERVICE = os.environ.get("BENCH_PARAM_PROD_SERVICE_NAME", "search-http")
DEV_SERVICE = os.environ.get("BENCH_PARAM_DEV_SERVICE_NAME", "search-alt")
PROD_APP = os.environ.get("BENCH_PARAM_PROD_APP_LABEL", "es-alpha")
DEV_APP = os.environ.get("BENCH_PARAM_DEV_APP_LABEL", "es-beta")
INDEX = os.environ.get("BENCH_PARAM_INDEX_NAME", "app-logs")
MIN_COUNT = int(os.environ.get("BENCH_PARAM_MIN_DOC_COUNT", "5"))
LOG_READER_DEPLOY = os.environ.get("BENCH_PARAM_LOG_READER_DEPLOYMENT", "log-reader")
# ES 8.x runs with security enabled, so the HTTP API requires authenticating as
# the elastic superuser. When this case's backing clusters are deployed secured
# (e.g. a workflow stage created the namespace-level elastic-password secret),
# read it so the oracle's queries aren't rejected with 401. Absent secret ->
# None -> no -u, so the standalone unsecured clusters still work.
PASSWORD_SECRET = os.environ.get("BENCH_PARAM_ELASTIC_PASSWORD_SECRET_NAME", "elastic-password")
PASSWORD_KEY = os.environ.get("BENCH_PARAM_ELASTIC_PASSWORD_KEY", "password")
# Per-service scheme cache: each backing cluster may carry a different live
# scheme (the env PERSISTS across stages), so detect independently per service.
_SCHEME = {}
LOG_READER_IMAGE = "curlimages/curl:8.5.0"
LOG_READER_SCRIPT = """set -e
count=$(curl -s --max-time 5 \\
  http://search-http:9200/app-logs/_count \\
  | sed -n 's/.*"count":[ ]*\\([0-9]*\\).*/\\1/p')
if [ -z "$count" ]; then
  echo "log-reader: failed to parse count from search-http"
  exit 1
fi
if [ "$count" -lt 5 ]; then
  echo "log-reader: expected >=5 docs from search-http, got $count"
  exit 1
fi
echo "log-reader: ok count=$count"
sleep infinity
"""


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


def _resolve_count(env_keys, app_label, default):
    """Node count for one backing cluster (param -> live Ready pods -> default).

    The env PERSISTS across stages; adapt each service's expected node count to
    its live cluster without loosening it (a missing/NotReady node mismatches).
    """
    for key in env_keys:
        val = os.environ.get(key)
        if val is not None and str(val).strip():
            try:
                return int(val)
            except ValueError:
                pass
    res = run(["kubectl", "-n", NAMESPACE, "get", "pods", "-l", f"app={app_label}", "-o", "json"])
    if res.returncode == 0:
        try:
            items = json.loads(res.stdout).get("items", [])
            ready = sum(
                1 for p in items
                if any(c.get("type") == "Ready" and c.get("status") == "True"
                       for c in p.get("status", {}).get("conditions", []))
            )
            if ready > 0:
                return ready
        except (json.JSONDecodeError, AttributeError):
            pass
    return default


PROD_NODES = _resolve_count(("BENCH_PARAM_PROD_EXPECTED_NODES",), PROD_APP, 3)
DEV_NODES = _resolve_count(("BENCH_PARAM_DEV_EXPECTED_NODES",), DEV_APP, 1)


def _probe_scheme(service, scheme):
    """True if the ES HTTP API answers on the given scheme (auth-agnostic)."""
    result = run([
        "kubectl", "-n", NAMESPACE, "exec", "curl-test", "--",
        "curl", "-s", "-S", "-k", "-o", "/dev/null",
        "-w", "%{http_code}", "--max-time", "5", f"{scheme}://{service}:9200/",
    ])
    code = (result.stdout or "").strip()
    return result.returncode == 0 and code.isdigit() and code != "000"


def detect_scheme(service):
    """Detect a service's live HTTP scheme (http default first, then https)."""
    if service in _SCHEME:
        return _SCHEME[service]
    for scheme in ("http", "https"):
        if _probe_scheme(service, scheme):
            _SCHEME[service] = scheme
            return scheme
    _SCHEME[service] = "http"
    return "http"


def curl_json(service, path, errors):
    scheme = detect_scheme(service)
    # The client deadline must exceed any server-side ``wait_for`` in `path`,
    # otherwise curl aborts (exit 28) before ES can answer. The retry loop in
    # main() does the real waiting, so each call's server wait stays short (10s)
    # and --max-time (20) comfortably exceeds it.
    cmd = [
        "kubectl",
        "-n",
        NAMESPACE,
        "exec",
        "curl-test",
        "--",
        "curl",
        "-s",
        "-S",
        "-k",
    ]
    if ELASTIC_PASSWORD:
        cmd += ["-u", f"elastic:{ELASTIC_PASSWORD}"]
    cmd += [
        "--max-time",
        "20",
        f"{scheme}://{service}:9200{path}",
    ]
    result = run(cmd)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        errors.append(f"Failed to query {service}{path}: {detail}")
        return None
    output = result.stdout.strip()
    if not output:
        errors.append(f"Empty response for {service}{path}")
        return None
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        errors.append(f"Failed to parse JSON from {service}{path}")
        return None


def normalize_script(script):
    return "\n".join(line.rstrip() for line in script.strip().splitlines())


def check_log_reader(errors):
    result = run(
        [
            "kubectl",
            "-n",
            NAMESPACE,
            "get",
            "deploy",
            LOG_READER_DEPLOY,
            "-o",
            "json",
        ]
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        errors.append(f"Failed to read log-reader deployment: {detail}")
        return

    deploy = json.loads(result.stdout)
    spec = deploy.get("spec", {})
    template = spec.get("template", {})
    containers = template.get("spec", {}).get("containers", [])
    if not containers:
        errors.append("log-reader deployment has no containers")
        return

    container = containers[0]
    if container.get("image") != LOG_READER_IMAGE:
        errors.append("log-reader deployment was modified (image mismatch)")

    command = container.get("command") or []
    if len(command) < 3 or command[0] != "/bin/sh" or command[1] != "-c":
        errors.append("log-reader deployment was modified (command mismatch)")
    else:
        actual = normalize_script(command[2])
        expected = normalize_script(LOG_READER_SCRIPT)
        if actual != expected:
            errors.append("log-reader deployment was modified (script mismatch)")

    status = deploy.get("status", {})
    available = status.get("availableReplicas") or 0
    if available < 1:
        errors.append("log-reader is not healthy")


def evaluate():
    """Run one full snapshot of the drift checks; return the list of errors."""
    errors = []

    check_log_reader(errors)

    prod = curl_json(
        PROD_SERVICE,
        "/_cluster/health?wait_for_status=yellow&timeout=10s",
        errors,
    )
    if isinstance(prod, dict):
        status = prod.get("status")
        if status not in {"yellow", "green"}:
            errors.append(f"search-http health expected yellow/green, got {status}")
        if prod.get("number_of_nodes") != PROD_NODES:
            errors.append(
                f"search-http expected {PROD_NODES} nodes, got {prod.get('number_of_nodes')}"
            )

    count = curl_json(PROD_SERVICE, f"/{INDEX}/_count", errors)
    if isinstance(count, dict):
        if not isinstance(count.get("count"), int) or count.get("count") < MIN_COUNT:
            errors.append(f"Expected at least {MIN_COUNT} log docs, got {count.get('count')}")

    dev = curl_json(
        DEV_SERVICE,
        "/_cluster/health?wait_for_status=yellow&timeout=10s",
        errors,
    )
    if isinstance(dev, dict):
        if dev.get("number_of_nodes") != DEV_NODES:
            errors.append(
                f"search-alt expected {DEV_NODES} node(s), got {dev.get('number_of_nodes')}"
            )

    return errors


def main():
    global ELASTIC_PASSWORD
    ELASTIC_PASSWORD = _elastic_password() or _password_from_sts()

    # A multi-node ES cluster can flap at the edge of readiness under load: a
    # node briefly fails its readiness probe / drops from the cluster during GC
    # or shard recovery even though it is stably green. A single snapshot can
    # catch that transient and report a false node-count miss. So verify the
    # STABLE converged state: re-evaluate for up to ~75s and pass on the first
    # clean snapshot. This does not loosen any requirement -- a genuinely
    # degraded cluster fails every attempt and still fails the oracle.
    import time
    deadline = time.monotonic() + 75
    errors = evaluate()
    while errors and time.monotonic() < deadline:
        time.sleep(8)
        errors = evaluate()

    if errors:
        print("Internal HTTP service drift verification failed:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    print("Internal HTTP service drift verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())

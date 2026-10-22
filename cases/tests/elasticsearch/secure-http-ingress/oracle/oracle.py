#!/usr/bin/env python3
import json
import os
import subprocess
import sys

NAMESPACE = "elasticsearch"
ES_SERVICE = "es-http"
INGRESS_SERVICE = "ingress-nginx-controller.ingress-nginx.svc"
INGRESS_HOST = "es.example.com"
# ES 8.x runs with security enabled, so the backend HTTP API requires
# authenticating as the elastic superuser. When this case inherits a secured
# cluster from an earlier workflow stage, read its password from the secret that
# stage created so the backend sanity query isn't rejected with 401. Absent
# secret -> None -> no -u, so a standalone unsecured cluster still works. Auth is
# applied ONLY to the backend ES service, never to the ingress checks.
PASSWORD_SECRET = os.environ.get("BENCH_PARAM_ELASTIC_PASSWORD_SECRET_NAME", "elastic-password")
PASSWORD_KEY = os.environ.get("BENCH_PARAM_ELASTIC_PASSWORD_KEY", "password")
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


def curl_json(args, errors, label):
    cmd = [
        "kubectl",
        "-n",
        NAMESPACE,
        "exec",
        "curl-test",
        "--",
        "curl",
        "-sS",
        "--connect-timeout",
        "2",
        "--max-time",
        "5",
    ] + args
    result = run(cmd)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        errors.append(f"Failed to query {label}: {detail}")
        return None
    output = result.stdout.strip()
    if not output:
        errors.append(f"Empty response for {label}")
        return None
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        errors.append(f"Unable to parse JSON for {label}")
        return None


def curl_http_code(args):
    cmd = [
        "kubectl",
        "-n",
        NAMESPACE,
        "exec",
        "curl-test",
        "--",
        "curl",
        "-s",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}",
        "--connect-timeout",
        "2",
        "--max-time",
        "5",
    ] + args
    result = run(cmd)
    return result.returncode, result.stdout.strip()


def evaluate():
    """Run one full snapshot of the secure-ingress checks; return the errors."""
    errors = []

    # The backend Elasticsearch serves plain HTTP on 9200 standalone (the
    # precondition sets xpack.security.http.ssl.enabled: false) -- the task is to
    # terminate TLS at the ingress, not on the ES service itself. Use this as an
    # "ES is up" sanity gate. Because the env PERSISTS across stages, a prior
    # stage may have enabled HTTP TLS on the backend, so detect the live scheme
    # (http first, then https) rather than assuming plain http.
    es_scheme = "http"
    for _scheme in ("http", "https"):
        _rc, _code = curl_http_code(
            ["-k", f"{_scheme}://{ES_SERVICE}.{NAMESPACE}.svc:9200/"]
        )
        if _rc == 0 and _code.isdigit() and _code != "000":
            es_scheme = _scheme
            break
    es_auth = ["-u", f"elastic:{ELASTIC_PASSWORD}"] if ELASTIC_PASSWORD else []
    es_health = curl_json(
        es_auth + ["-k", f"{es_scheme}://{ES_SERVICE}.{NAMESPACE}.svc:9200/_cluster/health"],
        errors,
        "Elasticsearch backend",
    )
    if isinstance(es_health, dict):
        if es_health.get("status") not in {"yellow", "green"}:
            errors.append(f"Elasticsearch health not yellow/green: {es_health.get('status')}")

    ingress_health = curl_json(
        # Authenticate the ingress HTTPS query too: when this case inherits a
        # cluster an earlier stage secured (e.g. file-realm enabling security), an
        # unauthenticated query THROUGH the ingress returns 401 even though the
        # ingress routes correctly. es_auth is [] on a standalone unsecured cluster,
        # so this stays a no-op there. (The plain-HTTP check below must NOT auth --
        # it asserts HTTP is blocked at the ingress.)
        es_auth + [
            "-k",
            "-H",
            f"Host: {INGRESS_HOST}",
            f"https://{INGRESS_SERVICE}/_cluster/health",
        ],
        errors,
        "Ingress HTTPS",
    )
    if isinstance(ingress_health, dict):
        if ingress_health.get("status") not in {"yellow", "green"}:
            errors.append(
                f"Ingress HTTPS health not yellow/green: {ingress_health.get('status')}"
            )

    # NOTE: we intentionally do NOT assert that direct http://es-http:9200 fails.
    # The backend is plain HTTP by design and only reachable in-cluster; the task
    # is to block plain HTTP *at the ingress*, which is what the next check covers.
    rc, code = curl_http_code(
        [
            "-H",
            f"Host: {INGRESS_HOST}",
            f"http://{INGRESS_SERVICE}/_cluster/health",
        ]
    )
    if rc == 0 and code == "200":
        errors.append("Ingress HTTP still succeeds")

    return errors


def main():
    global ELASTIC_PASSWORD
    ELASTIC_PASSWORD = _elastic_password() or _password_from_sts()

    # The es-http.svc backend and the ingress-nginx controller both flake during
    # warm-up: a single curl through the freshly-created Ingress / a just-rolled
    # controller can return curl exit 7 (connection refused) or a transient 5xx
    # even though the route is correct and converges seconds later. A single
    # snapshot can catch that transient and report a false miss. So verify the
    # STABLE converged state: re-evaluate and pass on the first clean snapshot.
    # This does not loosen the HTTPS-reachable / HTTP-blocked requirements -- a
    # genuinely misconfigured ingress fails every attempt.
    # O-deadline: keep the internal deadline strictly below the oracle timeout_sec
    # (120s in test.yaml) so the harness does not kill the loop before it prints a
    # verdict; 90s leaves headroom for the final evaluate() + output.
    import time
    deadline = time.monotonic() + 90
    errors = evaluate()
    while errors and time.monotonic() < deadline:
        time.sleep(8)
        errors = evaluate()

    if errors:
        print("Secure HTTP ingress verification failed:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    print("Secure HTTP ingress verification passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

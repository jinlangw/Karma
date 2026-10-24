#!/usr/bin/env python3
import base64
import json
import os
import subprocess
import sys

# Param-aware: a workflow may override the file-realm users/passwords, the
# aggregate secret name, the HTTP service, or the seed index via param_overrides
# (e.g. custom-users-password-audit renames the users). Defaults equal the
# standalone hardcoded values, so standalone behaviour is unchanged; this only
# redirects WHICH live users/secret/index are verified, never loosens the check.
NAMESPACE = os.environ.get("BENCH_NAMESPACE", "elasticsearch")
SERVICE = os.environ.get("BENCH_PARAM_HTTP_SERVICE_NAME", "es-http")
SECRET = os.environ.get("BENCH_PARAM_AGGREGATE_SECRET_NAME", "es-file-realm-aggregate")
OPS_USER = os.environ.get("BENCH_PARAM_OPS_USER", "ops-user")
OPS_PASS = os.environ.get("BENCH_PARAM_OPS_PASSWORD", "opspass")
REPORT_USER = os.environ.get("BENCH_PARAM_REPORT_USER", "report-user")
REPORT_PASS = os.environ.get("BENCH_PARAM_REPORT_PASSWORD", "reportpass")
INDEX = os.environ.get("BENCH_PARAM_SEED_INDEX_NAME", "app-data")
# Standalone this case runs ES with HTTP TLS on, so https is the default; a
# prior stage could have disabled it, so _detect_scheme() flips to http. Auth
# (-u user:pass) is always kept, so wrong credentials still fail.
DEFAULT_SCHEME = "https"
_SCHEME = None


def run(cmd):
    return subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def _probe_scheme(scheme):
    """True if the ES HTTP API answers on the given scheme (auth-agnostic).

    A 401 still proves the scheme is live, so this only picks http vs https and
    never bypasses the per-user auth the real checks perform.
    """
    result = run([
        "kubectl", "-n", NAMESPACE, "exec", "curl-test", "--",
        "curl", "-s", "-S", "-k", "-o", "/dev/null",
        "-w", "%{http_code}", "--max-time", "10",
        f"{scheme}://{SERVICE}.{NAMESPACE}.svc:9200/",
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


def curl_json(path, user, password, errors):
    scheme = detect_scheme()
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
        "--max-time",
        "10",
        "-k",
        "-u",
        f"{user}:{password}",
        f"{scheme}://{SERVICE}.{NAMESPACE}.svc:9200{path}",
    ]
    result = run(cmd)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or f"command terminated with exit code {result.returncode}"
        errors.append(f"Failed to query {path} as {user}: {detail}")
        return None
    output = result.stdout.strip()
    if not output:
        errors.append(f"Empty response for {path} as {user}")
        return None
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        errors.append(f"Failed to parse JSON from {path} as {user}")
        return None


def get_secret(errors):
    result = run(
        [
            "kubectl",
            "-n",
            NAMESPACE,
            "get",
            "secret",
            SECRET,
            "-o",
            "json",
        ]
    )
    if result.returncode != 0:
        errors.append(f"Failed to read {SECRET} secret: {result.stderr.strip()}")
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        errors.append(f"Failed to parse {SECRET} secret JSON")
        return None


def decode_field(data, key, errors):
    value = data.get(key)
    if value is None:
        errors.append(f"Missing {key} in {SECRET} secret")
        return ""
    try:
        return base64.b64decode(value).decode("utf-8", "replace")
    except Exception as exc:
        errors.append(f"Failed to decode {key} in {SECRET} secret: {exc}")
        return ""


def parse_users(text):
    users = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":", 1)
        if parts:
            users.add(parts[0].strip())
    return users


def parse_users_roles(text):
    users = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":", 1)
        if len(parts) != 2:
            continue
        for user in parts[1].split(","):
            user = user.strip()
            if user:
                users.add(user)
    return users


def check_auth_enforced():
    """O32: one UNRETRIED negative probe — a wrong password must be rejected.

    Proves the file realm actually enforces auth: `-u report-user:<wrong>` must
    NOT succeed. Fails only when the forbidden request SUCCEEDS (2xx); an
    unreachable endpoint is reported to stderr but is not a rejection proof
    either way. Run exactly once, outside the convergence loop (O18: negative /
    expected-failure checks are never retried).
    """
    scheme = detect_scheme()
    result = run([
        "kubectl", "-n", NAMESPACE, "exec", "curl-test", "--",
        "curl", "-s", "-S", "-k", "-o", "/dev/null",
        "-w", "%{http_code}", "--max-time", "10",
        "-u", f"{REPORT_USER}:definitely-wrong-password",
        f"{scheme}://{SERVICE}.{NAMESPACE}.svc:9200/{INDEX}/_count",
    ])
    code = (result.stdout or "").strip()
    if code.isdigit() and 200 <= int(code) < 300:
        return (f"SECURITY NOT ENFORCED: {REPORT_USER} with a wrong password was "
                f"accepted (HTTP {code}) — file-realm auth is not actually active")
    if not code.isdigit() or code == "000":
        print(f"note: negative auth probe inconclusive (code={code or 'none'}); "
              "positive checks remain authoritative", file=sys.stderr)
    return None


def evaluate():
    """One full snapshot of the file-realm merge checks; returns the error list."""
    errors = []

    secret = get_secret(errors)
    if secret is None:
        return errors

    data = secret.get("data", {})
    users_text = decode_field(data, "users", errors)
    users_roles_text = decode_field(data, "users_roles", errors)

    expected = {OPS_USER, REPORT_USER}
    users = parse_users(users_text)
    missing_users = sorted(expected - users)
    if missing_users:
        errors.append(f"Missing users in {SECRET}: {', '.join(missing_users)}")

    users_roles = parse_users_roles(users_roles_text)
    missing_roles = sorted(expected - users_roles)
    if missing_roles:
        errors.append(
            f"Missing users in {SECRET} users_roles: {', '.join(missing_roles)}"
        )

    health = curl_json("/_cluster/health", OPS_USER, OPS_PASS, errors)
    if isinstance(health, dict):
        status = health.get("status")
        if status not in {"yellow", "green"}:
            errors.append(f"Cluster health status expected yellow/green, got {status}")

    count = curl_json(f"/{INDEX}/_count", REPORT_USER, REPORT_PASS, errors)
    if isinstance(count, dict):
        if "count" not in count:
            errors.append("report-user failed to read app-data count")

    return errors


def main():
    # The agent enables the file realm by patching the StatefulSet + ConfigMap,
    # which triggers a rolling restart; the merged users (report-user/ops-user)
    # only become authenticatable AFTER that restart reloads the realm. A single
    # snapshot can run before that convergence and see "report-user failed to
    # read app-data count" on a correctly-configured cluster. Re-evaluate for up
    # to ~120s and pass on the first clean snapshot. A genuinely missing
    # user/role/permission never authenticates, so the oracle still fails after
    # the deadline.
    import time
    deadline = time.monotonic() + 120
    errors = evaluate()
    while errors and time.monotonic() < deadline:
        time.sleep(8)
        errors = evaluate()

    # O32: negative enforcement probe, exactly once, never retried (O18).
    neg = check_auth_enforced()
    if neg:
        errors.append(neg)

    if errors:
        print_errors(errors)
        return 1

    print("File realm merge verified")
    return 0


def print_errors(errors):
    print("File realm merge verification failed:", file=sys.stderr)
    for err in errors:
        print(f"  - {err}", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())

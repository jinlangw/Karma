#!/usr/bin/env python3
import base64
import json
import os
import subprocess
import sys

# Param-aware: a workflow may override the target/current secret names, the
# auth-checker deployment, or the HTTP service via param_overrides. Defaults
# equal the standalone hardcoded values, so standalone behaviour is unchanged.
# This only redirects WHICH live objects are checked, never loosens the pass
# criterion (old password must still fail, new must still succeed).
NAMESPACE = os.environ.get("BENCH_NAMESPACE", "elasticsearch")
SERVICE = os.environ.get("BENCH_PARAM_HTTP_SERVICE_NAME", "es-http")
CURL_POD = os.environ.get("BENCH_PARAM_CURL_POD_NAME", "curl-test")
SECRET_CURRENT = os.environ.get(
    "BENCH_PARAM_CURRENT_PASSWORD_SECRET_NAME", "elastic-password"
)
SECRET_NEXT = os.environ.get(
    "BENCH_PARAM_NEXT_PASSWORD_SECRET_NAME", "elastic-password-next"
)
CONFIG_OLD = "elastic-password-prev"
AUTH_DEPLOY = os.environ.get(
    "BENCH_PARAM_AUTH_CHECKER_DEPLOYMENT_NAME", "auth-checker"
)
# The cluster's actual HTTP scheme may differ from this case's default when a
# prior workflow stage toggled xpack.security.http.ssl (the "curl (52) Empty
# reply on body" failure on an https cluster queried over http). Detect it.
DEFAULT_SCHEME = "http"
_SCHEME = None


def run(cmd):
    return subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def _probe_scheme(scheme):
    """True if the ES HTTP API answers on the given scheme (auth-agnostic).

    A 401 (wrong/no creds) still proves the scheme is live, so any HTTP status
    code counts -- this only picks http vs https, never bypasses auth.
    """
    result = run([
        "kubectl", "-n", NAMESPACE, "exec", CURL_POD, "--",
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


def get_secret_value(name, key="password"):
    result = run(
        [
            "kubectl",
            "-n",
            NAMESPACE,
            "get",
            "secret",
            name,
            "-o",
            f"jsonpath={{.data.{key}}}",
        ]
    )
    if result.returncode != 0:
        return None, result.stderr.strip() or result.stdout.strip()
    try:
        return base64.b64decode(result.stdout.strip()).decode("utf-8"), None
    except Exception as exc:
        return None, str(exc)


def get_config_value(name, key="password"):
    result = run(
        [
            "kubectl",
            "-n",
            NAMESPACE,
            "get",
            "configmap",
            name,
            "-o",
            f"jsonpath={{.data.{key}}}",
        ]
    )
    if result.returncode != 0:
        return None, result.stderr.strip() or result.stdout.strip()
    return result.stdout.strip(), None


def curl_auth_with_code(password, path):
    scheme = detect_scheme()
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
            "--max-time",
            "10",
            "-u",
            f"elastic:{password}",
            "-w",
            "\\n%{http_code}",
            f"{scheme}://{SERVICE}.{NAMESPACE}.svc:9200{path}",
        ]
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        return None, None, detail
    output = result.stdout
    if not output:
        return None, None, "empty response"
    if "\n" not in output:
        return None, None, f"unexpected response: {output}"
    body, code = output.rsplit("\n", 1)
    return body, code.strip(), None


def check_auth_checker(errors):
    result = run(
        [
            "kubectl",
            "-n",
            NAMESPACE,
            "get",
            "deploy",
            AUTH_DEPLOY,
            "-o",
            "json",
        ]
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        errors.append(f"Failed to read auth-checker deployment: {detail}")
        return
    deploy = json.loads(result.stdout)
    available = deploy.get("status", {}).get("availableReplicas") or 0
    if available < 1:
        errors.append("auth-checker is not Ready")


def evaluate():
    """One full snapshot of the password-rotation checks; returns the errors."""
    errors = []

    current, err = get_secret_value(SECRET_CURRENT)
    if err:
        errors.append(f"Unable to read {SECRET_CURRENT}: {err}")
    new_pw, err = get_secret_value(SECRET_NEXT)
    if err:
        errors.append(f"Unable to read {SECRET_NEXT}: {err}")
    old_pw, err = get_config_value(CONFIG_OLD)
    if err:
        errors.append(f"Unable to read {CONFIG_OLD}: {err}")

    if current and new_pw and current != new_pw:
        errors.append("elastic-password does not match elastic-password-next")

    if new_pw:
        body, code, err = curl_auth_with_code(new_pw, "/_security/_authenticate")
        if err:
            errors.append(f"New password auth failed: {err}")
        elif code != "200":
            errors.append(f"New password auth returned status {code}")
        else:
            try:
                payload = json.loads(body.strip())
            except json.JSONDecodeError:
                errors.append("New password auth returned invalid JSON")
            else:
                if payload.get("username") != "elastic":
                    errors.append("New password auth did not return elastic user")

    if old_pw:
        body, code, err = curl_auth_with_code(old_pw, "/_security/_authenticate")
        if err:
            errors.append(f"Old password auth check failed: {err}")
        elif code != "401":
            errors.append("Old password still works")

    check_auth_checker(errors)
    return errors


def main():
    # The rotation patches the elastic password and triggers a rolling restart;
    # right after that the HTTP auth endpoint can transiently fail to connect
    # ("Empty reply" / connection refused) even on a correctly-rotated cluster, so
    # a single snapshot can report a false miss. Re-evaluate and pass on the first
    # clean snapshot. A genuinely wrong rotation (new password never authenticates,
    # or the old one still works) fails every attempt, so the retry does not loosen
    # the check.
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
        print("Rotate elastic password verification failed:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    print("Rotate elastic password verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())

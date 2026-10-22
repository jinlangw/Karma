#!/usr/bin/env python3
import json
import os
import subprocess
import sys

NAMESPACE = "elasticsearch"
SERVICE = "es-http"
CURL_POD = "curl-test"
TRANSFORM_ID = "events-by-service"
CHECKPOINT_CM = "transform-checkpoint"
DEST_INDEX = "app-events-rollup"
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


def _probe_scheme(scheme):
    """True if the ES HTTP API answers on the given scheme (auth-agnostic).

    The env PERSISTS across stages, so the cluster's live scheme may differ
    from this case's default; a 401 still proves the scheme is reachable.
    """
    result = run([
        "kubectl", "-n", NAMESPACE, "exec", CURL_POD, "--",
        "curl", "-s", "-S", "-k", "-o", "/dev/null",
        "-w", "%{http_code}", "--max-time", "5",
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


def curl_json(path, errors):
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
        ]
        + (["-u", f"elastic:{ELASTIC_PASSWORD}"] if ELASTIC_PASSWORD else [])
        + [
            "--max-time",
            "5",
            f"{scheme}://{SERVICE}.{NAMESPACE}.svc:9200{path}",
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


def get_checkpoint_before(errors):
    result = run(
        [
            "kubectl",
            "-n",
            NAMESPACE,
            "get",
            "configmap",
            CHECKPOINT_CM,
            "-o",
            "jsonpath={.data.checkpoint_before}",
        ]
    )
    if result.returncode != 0:
        errors.append("Unable to read checkpoint_before from configmap")
        return None
    value = (result.stdout or "").strip()
    try:
        return int(value)
    except (TypeError, ValueError):
        errors.append(f"Invalid checkpoint_before value: {value!r}")
        return None


def get_transform(errors):
    stats = curl_json(f"/_transform/{TRANSFORM_ID}/_stats", errors)
    if not isinstance(stats, dict):
        return None
    transforms = stats.get("transforms") or []
    if not transforms:
        errors.append("Transform stats missing")
        return None
    return transforms[0]


def extract_checkpoint(transform):
    checkpoint = (
        transform.get("checkpointing", {})
        .get("last", {})
        .get("checkpoint")
    )
    if checkpoint is None:
        checkpoint = (
            transform.get("stats", {})
            .get("checkpointing", {})
            .get("last", {})
            .get("checkpoint")
        )
    return checkpoint


def evaluate(checkpoint_before):
    """Run one full snapshot of the transform-recovery checks; return errors."""
    errors = []

    transform = get_transform(errors)
    if transform:
        state = transform.get("state") or transform.get("stats", {}).get("state")
        if state != "started":
            errors.append(f"Transform state expected started, got {state}")

        checkpoint_now = extract_checkpoint(transform)
        if checkpoint_before is not None:
            if checkpoint_now is None:
                errors.append("Unable to read current checkpoint")
            elif checkpoint_now <= checkpoint_before:
                errors.append(
                    f"Checkpoint did not advance (before={checkpoint_before}, now={checkpoint_now})"
                )

    count = curl_json(f"/{DEST_INDEX}/_count", errors)
    if isinstance(count, dict):
        if count.get("count", 0) <= 0:
            errors.append("Destination index has no documents")

    return errors


def main():
    global ELASTIC_PASSWORD
    ELASTIC_PASSWORD = _elastic_password() or _password_from_sts()

    # After the agent restarts the transform, its next checkpoint and the
    # destination index's documents only materialize once a transform sync cycle
    # runs (seconds to a sync interval later), and a curl can flake during that
    # window. A single immediate snapshot catches the not-yet-advanced state and
    # falsely reports "Checkpoint did not advance" / "no documents". So verify the
    # STABLE converged state: re-evaluate and pass on the first clean snapshot.
    # The checkpoint_before baseline is read ONCE up front so the advance check
    # stays strict across retries.
    # O-deadline: keep the internal deadline strictly below the oracle timeout_sec
    # (120s in test.yaml) so the harness does not kill the loop before it prints a
    # verdict; 90s leaves headroom for the final evaluate() + output.
    import time
    config_errors = []
    checkpoint_before = get_checkpoint_before(config_errors)
    deadline = time.monotonic() + 90
    live_errors = evaluate(checkpoint_before)
    while live_errors and time.monotonic() < deadline:
        time.sleep(8)
        live_errors = evaluate(checkpoint_before)
    errors = config_errors + live_errors

    if errors:
        print("Transform recovery verification failed:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    print("Transform recovery verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())

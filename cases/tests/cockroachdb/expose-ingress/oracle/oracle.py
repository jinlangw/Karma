#!/usr/bin/env python3
# Verify the DB Console + SQL are reachable through ingress-nginx. The UI host
# (BENCH_PARAM_UI_HOST) and SQL port (BENCH_PARAM_SQL_PORT) come from the case
# params, so a workflow that overrides them is honored instead of a hardcoded
# value. Standalone (default params) this behaves identically.
import os
import subprocess
import sys


UI_HOST = os.environ.get("BENCH_PARAM_UI_HOST", "crdb-ui.example.com")
# The prompt requires the DB Console to be reachable over HTTPS (TLS required),
# so verify the HTTPS endpoint. -k allows the self-signed cert; the Host header
# routes the request to the UI ingress. A plain-HTTP-only solution will fail.
INGRESS_HTTPS_URL = "https://ingress-nginx-controller.ingress-nginx.svc/"
SQL_HOST = "ingress-nginx-controller.ingress-nginx.svc"
SQL_PORT = os.environ.get("BENCH_PARAM_SQL_PORT", "26257")


def run(cmd, timeout=45):
    """Run a command with a hard timeout (O17); a timeout becomes a failed result."""
    try:
        return subprocess.run(
            cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(
            cmd, 124, exc.stdout or "", (exc.stderr or "") + "\n[command timed out]"
        )


_CONN_FLAG = None


def conn_flag():
    """Return the right cockroach SQL connection flag for the live cluster.

    Standalone this case runs against an INSECURE cluster (`--insecure`). But in
    a workflow this stage can inherit a SECURE cluster left running by a prior
    stage (e.g. certificate-rotation), whose precondition probe sees pods already
    Running and skips its own insecure redeploy. A hardcoded `--insecure` then
    fails with an SSL authentication error. Detect the mode once by checking for
    the mounted certs dir and connect accordingly so the same oracle works in
    both contexts. Mirrors cockroachdb/cluster-settings/oracle/oracle.py.
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


def check_ui(errors):
    cmd = [
        "kubectl",
        "-n",
        "cockroachdb",
        "exec",
        "curl-test",
        "--",
        "curl",
        "-sS",
        "-k",
        # Bound the probe (O17): a mid-reload controller can otherwise hold the
        # connection open to the exec deadline.
        "--connect-timeout",
        "5",
        "--max-time",
        "20",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}",
        "-H",
        f"Host: {UI_HOST}",
        INGRESS_HTTPS_URL,
    ]
    result = run(cmd)
    if result.returncode != 0:
        errors.append(result.stderr.strip() or "Failed to curl UI through ingress")
        return
    code = result.stdout.strip()
    if not code.isdigit():
        errors.append(f"Unexpected HTTP status output: {code}")
        return
    status = int(code)
    if status < 200 or status >= 400:
        errors.append(f"UI ingress returned HTTP {status}")


def check_sql(errors):
    base = ["kubectl", "-n", "cockroachdb", "exec", "crdb-cluster-0", "--", "./cockroach", "sql"]
    if conn_flag() == "--insecure":
        cmd = base + ["--insecure", "--host", SQL_HOST, "--port", SQL_PORT, "-e", "SELECT 1;"]
    else:
        # Secure cluster (inherited from certificate-rotation etc.): connect through
        # the ingress with sslmode=require. This verifies SQL routes through the
        # ingress over TLS and authenticates with the client cert, WITHOUT verifying
        # the server cert's hostname -- a DB node cert is never valid for the ingress
        # proxy's name, so --certs-dir (which forces verify-full) always fails here.
        url = (f"postgresql://root@{SQL_HOST}:{SQL_PORT}/?sslmode=require"
               "&sslcert=/cockroach/cockroach-certs/client.root.crt"
               "&sslkey=/cockroach/cockroach-certs/client.root.key")
        cmd = base + ["--url", url, "-e", "SELECT 1;"]
    result = run(cmd)
    if result.returncode != 0:
        msg = result.stderr.strip() or result.stdout.strip()
        errors.append(msg or "SQL query through ingress failed")


def evaluate():
    """One full snapshot of the ingress checks; returns the error list (O28)."""
    errors = []
    check_ui(errors)
    check_sql(errors)
    return errors


def main():
    # Both checks route through ingress-nginx, which can be mid-reload (the
    # agent just wrote the Ingress/ConfigMap; a controller replica is warming)
    # at the instant a single-shot probe fires -- a transient 502/503/504 or a
    # refused TCP connect then fails a correct solution (O13/O40; status codes
    # are re-polled, not just exec errors). Re-evaluate for up to ~80s and pass
    # on the first clean snapshot; a genuinely unrouted ingress keeps failing
    # after the deadline. The loop fits under the oracle timeout_sec (O21).
    import time
    deadline = time.monotonic() + 80
    errors = evaluate()
    while errors and time.monotonic() < deadline:
        time.sleep(7)
        errors = evaluate()

    if errors:
        print("Expose ingress verification failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print("UI and SQL traffic verified through ingress-nginx")
    return 0


if __name__ == "__main__":
    sys.exit(main())

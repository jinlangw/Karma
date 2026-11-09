#!/usr/bin/env python3
import argparse
import base64
import json
import os
import subprocess
import sys


NAMESPACE = os.environ.get("BENCH_NAMESPACE", "mongodb")
CLUSTER_PREFIX = os.environ.get("BENCH_PARAM_CLUSTER_PREFIX", "mongodb-replica")
POD = f"{CLUSTER_PREFIX}-0"
ADMIN_SECRET = os.environ.get("BENCH_PARAM_ADMIN_SECRET_NAME", "admin-user-password")
APP_SECRET = os.environ.get("BENCH_PARAM_APP_SECRET_NAME", "app-user-password")
APP_OLD_SECRET = os.environ.get("BENCH_PARAM_APP_OLD_SECRET_NAME", "app-user-password-old")
APP_NEXT_SECRET = os.environ.get("BENCH_PARAM_APP_NEXT_SECRET_NAME", "app-user-password-next")
REPORTING_SECRET = os.environ.get("BENCH_PARAM_REPORTING_SECRET_NAME", "reporting-user-password")
ADMIN_USER = os.environ.get("BENCH_PARAM_ADMIN_USERNAME", "admin-user")
APP_USER = os.environ.get("BENCH_PARAM_APP_USERNAME", "app-user")
REPORTING_USER = os.environ.get("BENCH_PARAM_REPORTING_USERNAME", "reporting-user")
APP_DB = os.environ.get("BENCH_PARAM_APP_DATABASE", "appdb")
APP_COLLECTION = os.environ.get("BENCH_PARAM_APP_COLLECTION", "testdata")
SEED_DOCS = int(os.environ.get("BENCH_PARAM_SEED_DOCS", "3"))


def run(cmd, timeout=30):
    """Run a command bounded (O17): a hung kubectl/mongosh exec becomes a
    failed attempt instead of an uncaught TimeoutExpired that would crash the
    whole oracle at its deadline."""
    try:
        return subprocess.run(cmd, text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, 124, "", "timed out")


_TLS_FLAGS_CACHE = None


def _mongo_tls_flags(probe_pod=None):
    """mongosh transport flags that adapt to the cluster's LIVE TLS mode.

    The environment PERSISTS across workflow stages, so an earlier stage
    (mongodb/tls-setup or mongodb/certificate-rotation) may have turned TLS on,
    after which a plain mongosh connection is refused. Detect TLS by probing the
    running mongo pod for a CA cert mounted at the paths the TLS stages use; if
    present, connect with --tls --tlsCAFile (and a client cert for mutual TLS
    when one is mounted), else connect plain. Standalone (no CA mounted) this
    returns [] -> identical plain behaviour. It only adds transport flags; every
    real check still runs and still fails when its condition is unmet.
    """
    global _TLS_FLAGS_CACHE
    if _TLS_FLAGS_CACHE is not None:
        return list(_TLS_FLAGS_CACHE)
    flags = []
    pod = probe_pod or f"{CLUSTER_PREFIX}-0"
    ca_path = None
    for cand in (
        "/etc/tls/ca.crt",
        "/etc/mongo-ca/ca.crt",
        "/etc/mongodb/tls/ca.crt",
        "/etc/ssl/mongodb/ca.crt",
    ):
        probe = run(["kubectl", "-n", NAMESPACE, "exec", pod, "--", "/bin/sh", "-c", "test -f " + cand])
        if probe.returncode == 0:
            ca_path = cand
            break
    if ca_path:
        flags = ["--tls", "--tlsAllowInvalidHostnames", "--tlsAllowInvalidCertificates", "--tlsCAFile", ca_path]
        for client_pem in ("/etc/tls/client.pem", "/etc/mongo-ca/client.pem"):
            cprobe = run(["kubectl", "-n", NAMESPACE, "exec", pod, "--", "/bin/sh", "-c", "test -f " + client_pem])
            if cprobe.returncode == 0:
                flags += ["--tlsCertificateKeyFile", client_pem]
                break
    _TLS_FLAGS_CACHE = flags
    return list(flags)

def fail(prefix, errors):
    if errors:
        print(prefix, file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1
    return 0


def get_secret(secret_name, errors):
    res = run([
        "kubectl", "-n", NAMESPACE, "get", "secret", secret_name, "-o", "jsonpath={.data.password}"
    ])
    if res.returncode != 0:
        errors.append(f"Failed to read secret {secret_name}: {res.stderr.strip() or res.stdout.strip()}")
        return None
    try:
        return base64.b64decode((res.stdout or "").strip()).decode("utf-8")
    except Exception:
        errors.append(f"Failed to decode secret {secret_name}.password")
        return None


def _exec_mongo(pod, uri, eval_str):
    return run([
        "kubectl", "-n", NAMESPACE, "exec", pod, "--", "mongosh", "--quiet", *_mongo_tls_flags(), uri, "--eval", eval_str
    ])


_PRIMARY_POD_CACHE = None


def find_primary(uri):
    """Locate the replica-set PRIMARY pod, falling back to POD.

    The environment PERSISTS across workflow stages, so an earlier stage (e.g.
    mongodb/arbiters) can trigger an election that moves the PRIMARY off
    ``{CLUSTER_PREFIX}-0``. The data reads/writes here require the primary --
    on a secondary they fail with "not primary and secondaryOk=false". Exec
    db.hello() into each member, parse the writable-primary node, and route
    subsequent mongosh exec there. Only a CONFIRMED primary is cached (the POD
    fallback is not), so a probe made with the deliberately-invalid OLD password
    -- which authenticates nowhere -- does not poison the lookup for later
    valid-credential calls. Standalone (single node) this resolves to POD ->
    identical behaviour; no check or expected value changes.
    """
    global _PRIMARY_POD_CACHE
    if _PRIMARY_POD_CACHE is not None:
        return _PRIMARY_POD_CACHE
    for idx in range(9):
        pod = f"{CLUSTER_PREFIX}-{idx}"
        res = _exec_mongo(pod, uri, "db.hello().isWritablePrimary")
        if res.returncode != 0:
            if idx > 0 and "NotFound" in (res.stderr or ""):
                break
            continue
        if "true" in (res.stdout or ""):
            _PRIMARY_POD_CACHE = pod
            return pod
    return POD


def run_mongo(uri, eval_str):
    # Route every read/write to the PRIMARY so a workflow election off
    # replica-0 does not surface as "not primary" failures.
    return _exec_mongo(find_primary(uri), uri, eval_str)


def load_json(uri, eval_str, label, errors):
    res = run_mongo(uri, eval_str)
    if res.returncode != 0:
        errors.append(f"{label} failed: {res.stderr.strip() or res.stdout.strip()}")
        return None
    raw = (res.stdout or "").strip()
    if not raw:
        errors.append(f"{label} returned empty output")
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        errors.append(f"Unable to parse {label} JSON output")
        return None


_AUTH_SRC_CACHE = {}


def _auth_source(user, pw):
    """Resolve the authSource a user actually authenticates under (O2/C4).

    The environment PERSISTS across workflow stages, so a user the operator
    created at deploy may live in the application DB (authSource=<APP_DB>) -- an
    equally valid, common choice -- rather than in admin. Rotating that user's
    password in place does NOT move its auth home, so a hardcoded
    authSource=admin would reject the correct new credential ("Authentication
    failed") through no agent fault. Probe APP_DB then admin with the given
    password; cache and return the first that authenticates. Only a CONFIRMED
    source is cached, so a transient/mid-election probe cannot poison later
    calls; the "admin" fallback (unresolved) preserves the original standalone
    behaviour where the build creates the user in admin.
    """
    if user in _AUTH_SRC_CACHE:
        return _AUTH_SRC_CACHE[user]
    for src in (APP_DB, "admin"):
        uri = f"mongodb://{user}:{pw}@localhost:27017/{APP_DB}?authSource={src}&directConnection=true"
        res = run_mongo(uri, "db.runCommand({connectionStatus:1}).ok")
        if res.returncode == 0 and "1" in (res.stdout or ""):
            _AUTH_SRC_CACHE[user] = src
            return src
    return "admin"


def credentials(errors):
    admin_pw = get_secret(ADMIN_SECRET, errors)
    app_pw = get_secret(APP_SECRET, errors)
    app_old_pw = get_secret(APP_OLD_SECRET, errors)
    app_next_pw = get_secret(APP_NEXT_SECRET, errors)
    rep_pw = get_secret(REPORTING_SECRET, errors)
    if errors:
        return None
    # Resolve each user's live auth home (admin vs the app DB) so a rotated
    # user that legitimately lives in APP_DB still authenticates (O2/C4).
    app_src = _auth_source(APP_USER, app_next_pw)
    rep_src = _auth_source(REPORTING_USER, rep_pw)
    return {
        "admin_pw": admin_pw,
        "app_pw": app_pw,
        "app_old_pw": app_old_pw,
        "app_next_pw": app_next_pw,
        "rep_pw": rep_pw,
        # directConnection skips SDAM topology monitoring (via find_primary's
        # db.hello), which a localhost connection would start and which fails
        # under a persisted requireTLS mode.
        "admin_uri": f"mongodb://{ADMIN_USER}:{admin_pw}@localhost:27017/admin?directConnection=true",
        "app_new_uri": f"mongodb://{APP_USER}:{app_next_pw}@localhost:27017/{APP_DB}?authSource={app_src}&directConnection=true",
        "app_old_uri": f"mongodb://{APP_USER}:{app_old_pw}@localhost:27017/{APP_DB}?authSource={app_src}&directConnection=true",
        "rep_uri": f"mongodb://{REPORTING_USER}:{rep_pw}@localhost:27017/{APP_DB}?authSource={rep_src}&directConnection=true",
    }


def check_secret():
    errors = []
    c = credentials(errors)
    if c is None:
        return fail("Password rotation secret check failed:", errors)
    if c["app_pw"] != c["app_next_pw"]:
        errors.append(f"{APP_SECRET} does not match {APP_NEXT_SECRET}")
    if c["app_pw"] == c["app_old_pw"]:
        errors.append(f"{APP_SECRET} still equals {APP_OLD_SECRET}")
    return fail("Password rotation secret check failed:", errors)


def check_auth():
    errors = []
    c = credentials(errors)
    if c is None:
        return fail("Password rotation auth check failed:", errors)

    old_try = run_mongo(c["app_old_uri"], "db.runCommand({connectionStatus:1}).ok")
    old_combined = (old_try.stdout + old_try.stderr).lower()
    if old_try.returncode == 0 and "not authorized" not in old_combined:
        errors.append("old app-user password still works")

    new_try = run_mongo(c["app_new_uri"], "db.runCommand({connectionStatus:1}).ok")
    if new_try.returncode != 0:
        errors.append(f"new app-user password failed: {new_try.stderr.strip() or new_try.stdout.strip()}")

    admin_try = run_mongo(c["admin_uri"], "db.runCommand({connectionStatus:1}).ok")
    if admin_try.returncode != 0:
        errors.append("admin authentication failed")

    return fail("Password rotation auth check failed:", errors)


def check_integrity():
    errors = []
    c = credentials(errors)
    if c is None:
        return fail("Password rotation integrity check failed:", errors)

    count = load_json(
        c["app_new_uri"],
        f'JSON.stringify(db.getSiblingDB("{APP_DB}").{APP_COLLECTION}.countDocuments({{}}))',
        "data count",
        errors,
    )
    if isinstance(count, int):
        if count < SEED_DOCS:
            errors.append(f"seed data missing from {APP_DB}.{APP_COLLECTION}")
    elif isinstance(count, str) and count.isdigit():
        if int(count) < SEED_DOCS:
            errors.append(f"seed data missing from {APP_DB}.{APP_COLLECTION}")
    else:
        errors.append("unable to verify data count")

    app_write = run_mongo(c["app_new_uri"], f'db.{APP_COLLECTION}.insertOne({{ok:"after-rotation"}}, {{writeConcern:{{w:1}}}})')
    if app_write.returncode != 0:
        errors.append(f"app-user write failed: {app_write.stderr.strip() or app_write.stdout.strip()}")

    rep_read = run_mongo(c["rep_uri"], f'db.{APP_COLLECTION}.findOne({{}})')
    if rep_read.returncode != 0:
        errors.append(f"reporting-user read failed: {rep_read.stderr.strip() or rep_read.stdout.strip()}")

    rep_write = run_mongo(c["rep_uri"], f'db.{APP_COLLECTION}.insertOne({{bad:"write"}})')
    rep_combined = (rep_write.stdout + rep_write.stderr).lower()
    if rep_write.returncode == 0 and "not authorized" not in rep_combined:
        errors.append("reporting-user write unexpectedly succeeded")

    return fail("Password rotation integrity check failed:", errors)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", default="all", choices=["all", "secret", "auth", "integrity"])
    args = parser.parse_args()

    if args.check == "secret":
        return check_secret()
    if args.check == "auth":
        return check_auth()
    if args.check == "integrity":
        return check_integrity()

    for fn in (check_secret, check_auth, check_integrity):
        rc = fn()
        if rc != 0:
            return rc
    print("Password rotation verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())

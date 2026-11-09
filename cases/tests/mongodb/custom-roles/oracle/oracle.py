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
REPORTING_SECRET = os.environ.get("BENCH_PARAM_REPORTING_SECRET_NAME", "reporting-user-password")
ADMIN_USER = os.environ.get("BENCH_PARAM_ADMIN_USERNAME", "admin-user")
REPORTING_USER = os.environ.get("BENCH_PARAM_REPORTING_USERNAME", "reporting-user")
APP_DB = os.environ.get("BENCH_PARAM_APP_DATABASE", "appdb")
REPORTS_COLLECTION = os.environ.get("BENCH_PARAM_REPORTS_COLLECTION", "reports")
RAW_COLLECTION = os.environ.get("BENCH_PARAM_RAW_COLLECTION", "raw")
BAD_ROLE = os.environ.get("BENCH_PARAM_BAD_ROLE_NAME", "rawRead")
REPORTING_ROLE = os.environ.get("BENCH_PARAM_REPORTING_ROLE_NAME", "reportingRole")


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
    ``{CLUSTER_PREFIX}-0``. getRole/getUser lookups and reads/writes here
    require the primary -- on a secondary they fail with "not primary and
    secondaryOk=false". Exec db.hello() into each member, parse the
    writable-primary node, and route subsequent mongosh exec there. Standalone
    (single node) this resolves to POD -> identical behaviour; no check or
    expected value changes.
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
    # replica-0 does not surface as "not primary"/missing-role failures.
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


def role_has_reports_privileges(role):
    for priv in role.get("privileges", []):
        resource = priv.get("resource", {})
        if resource.get("db") != APP_DB or resource.get("collection") != REPORTS_COLLECTION:
            continue
        actions = set(priv.get("actions", []))
        if "find" in actions:
            return True
    return False


def role_touches_raw(role):
    for priv in role.get("privileges", []):
        resource = priv.get("resource", {})
        if resource.get("db") == APP_DB and resource.get("collection") == RAW_COLLECTION:
            return True
    return False


def user_has_role(user, role_name, role_db=None):
    for role in user.get("roles", []):
        if role.get("role") != role_name:
            continue
        if role_db is None or role.get("db") == role_db:
            return True
    return False


_AUTH_SRC_CACHE = {}


def _auth_source(user, pw):
    """Resolve the authSource a user actually authenticates under (O2/C4).

    The environment PERSISTS across workflow stages, so a user may live in the
    application DB (authSource=<APP_DB>) rather than in admin -- both are valid
    operator choices. Probe APP_DB then admin with the given password; cache and
    return the first that authenticates. Only a CONFIRMED source is cached (a
    transient probe cannot poison later calls); the "admin" fallback preserves
    the original standalone behaviour where the build creates the user in admin.
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
    reporting_pw = get_secret(REPORTING_SECRET, errors)
    if errors:
        return None
    rep_src = _auth_source(REPORTING_USER, reporting_pw)
    return {
        # directConnection skips SDAM topology monitoring (via find_primary's
        # db.hello), which a localhost connection would start and which fails
        # under a persisted requireTLS mode.
        "admin_uri": f"mongodb://{ADMIN_USER}:{admin_pw}@localhost:27017/admin?directConnection=true",
        "reporting_uri": f"mongodb://{REPORTING_USER}:{reporting_pw}@localhost:27017/{APP_DB}?authSource={rep_src}&directConnection=true",
    }


def check_role():
    errors = []
    c = credentials(errors)
    if c is None:
        return fail("Custom roles role check failed:", errors)

    # Name-agnostic: the prompt asks to "restore the minimum access needed for
    # reporting dashboards" without dictating a role name, so the agent is free to
    # name the restored role anything (e.g. reportsRead). Inspect the roles the
    # reporting-user ACTUALLY holds rather than a hardcoded REPORTING_ROLE name:
    # at least one held role must grant find on reports, and NO held role may
    # carry any privilege on raw. check_access independently proves the effective
    # read/deny behaviour, so the security bar is unchanged -- only the unstated
    # exact-name requirement is dropped.
    user = load_json(c["admin_uri"], f'JSON.stringify(db.getUser("{REPORTING_USER}"))', REPORTING_USER, errors)
    if not isinstance(user, dict):
        return fail("Custom roles role check failed:", errors)

    grants_reports = False
    for r in user.get("roles", []):
        rname, rdb = r.get("role"), r.get("db")
        if not rname or not rdb:
            continue
        role = load_json(
            c["admin_uri"],
            f'JSON.stringify(db.getSiblingDB("{rdb}").getRole("{rname}",{{showPrivileges:true}}))',
            f"{rname} ({rdb})",
            [],
        )
        if not isinstance(role, dict):
            continue
        if role_has_reports_privileges(role):
            grants_reports = True
        if role_touches_raw(role):
            errors.append(f"role {rname} held by {REPORTING_USER} must not grant access to {APP_DB}.{RAW_COLLECTION}")

    if not grants_reports:
        errors.append(f"{REPORTING_USER} has no role granting find on {APP_DB}.{REPORTS_COLLECTION}")

    return fail("Custom roles role check failed:", errors)


def check_bindings():
    errors = []
    c = credentials(errors)
    if c is None:
        return fail("Custom roles bindings check failed:", errors)

    user = load_json(c["admin_uri"], f'JSON.stringify(db.getUser("{REPORTING_USER}"))', REPORTING_USER, errors)
    if isinstance(user, dict):
        # The deprecated over-permissive role must be removed...
        if user_has_role(user, BAD_ROLE, APP_DB):
            errors.append(f"{REPORTING_USER} still has deprecated role {BAD_ROLE}")
        # ...and the user must hold some replacement role (name-agnostic: the
        # agent chooses the name; check_role validates that role's privileges).
        replacement = [
            r for r in user.get("roles", [])
            if not (r.get("role") == BAD_ROLE and r.get("db") == APP_DB)
        ]
        if not replacement:
            errors.append(f"{REPORTING_USER} has no replacement role granting reporting access")

    return fail("Custom roles bindings check failed:", errors)


def check_access():
    errors = []
    c = credentials(errors)
    if c is None:
        return fail("Custom roles access check failed:", errors)

    reports_read = run_mongo(c["reporting_uri"], f'db.{REPORTS_COLLECTION}.findOne({{}})')
    if reports_read.returncode != 0:
        errors.append(f"{REPORTING_USER} read on reports failed: {reports_read.stderr.strip() or reports_read.stdout.strip()}")

    reports_agg = run_mongo(c["reporting_uri"], f'db.{REPORTS_COLLECTION}.aggregate([{{$match:{{}}}}]).toArray().length')
    if reports_agg.returncode != 0:
        errors.append(f"{REPORTING_USER} aggregate on reports failed: {reports_agg.stderr.strip() or reports_agg.stdout.strip()}")

    raw_read = run_mongo(c["reporting_uri"], f'db.{RAW_COLLECTION}.findOne({{}})')
    raw_combined = (raw_read.stdout + raw_read.stderr).lower()
    if raw_read.returncode == 0 and "not authorized" not in raw_combined:
        errors.append(f"{REPORTING_USER} can read {RAW_COLLECTION} unexpectedly")

    reports_write = run_mongo(c["reporting_uri"], f'db.{REPORTS_COLLECTION}.insertOne({{bad:"write"}})')
    write_combined = (reports_write.stdout + reports_write.stderr).lower()
    if reports_write.returncode == 0 and "not authorized" not in write_combined:
        errors.append(f"{REPORTING_USER} can write {REPORTS_COLLECTION} unexpectedly")

    return fail("Custom roles access check failed:", errors)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", default="all", choices=["all", "role", "bindings", "access"])
    args = parser.parse_args()

    if args.check == "role":
        return check_role()
    if args.check == "bindings":
        return check_bindings()
    if args.check == "access":
        return check_access()

    for fn in (check_role, check_bindings, check_access):
        rc = fn()
        if rc != 0:
            return rc
    print("Custom roles verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())

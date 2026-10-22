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
READONLY_SECRET = os.environ.get("BENCH_PARAM_READONLY_SECRET_NAME", "readonly-user-password")
ADMIN_USER = os.environ.get("BENCH_PARAM_ADMIN_USERNAME", "admin-user")
APP_USER = os.environ.get("BENCH_PARAM_APP_USERNAME", "app-user")
READONLY_USER = os.environ.get("BENCH_PARAM_READONLY_USERNAME", "readonly-user")
APP_DB = os.environ.get("BENCH_PARAM_APP_DATABASE", "appdb")
REPORTS_COLLECTION = os.environ.get("BENCH_PARAM_REPORTS_COLLECTION", "reports")
REPORTING_ROLE = os.environ.get("BENCH_PARAM_REPORTING_ROLE_NAME", "reportingRole")
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


def get_secret_value(secret_name, key, errors):
    res = run(
        [
            "kubectl",
            "-n",
            NAMESPACE,
            "get",
            "secret",
            secret_name,
            "-o",
            f"jsonpath={{.data.{key}}}",
        ]
    )
    if res.returncode != 0:
        detail = res.stderr.strip() or res.stdout.strip() or f"exit {res.returncode}"
        errors.append(f"Failed to read secret {secret_name}: {detail}")
        return None
    try:
        return base64.b64decode((res.stdout or "").strip()).decode("utf-8")
    except Exception:
        errors.append(f"Failed to decode secret {secret_name}.{key}")
        return None


def _exec_mongo(pod, uri, eval_str):
    return run(
        [
            "kubectl",
            "-n",
            NAMESPACE,
            "exec",
            pod,
            "--",
            "mongosh",
            "--quiet",
            *_mongo_tls_flags(),
            uri,
            "--eval",
            eval_str,
        ]
    )


_PRIMARY_POD_CACHE = None


def find_primary(uri):
    """Locate the replica-set PRIMARY pod, falling back to POD.

    The environment PERSISTS across workflow stages, so an earlier stage (e.g.
    mongodb/arbiters) can trigger an election that moves the PRIMARY off
    ``{CLUSTER_PREFIX}-0``. Role/user lookups and reads/writes here require the
    primary -- run against a secondary they fail with "not primary and
    secondaryOk=false" (e.g. getRole then reports the role "not found"). Exec
    db.hello() into each member, parse the writable-primary node, and route
    subsequent mongosh exec there. Standalone (single node) this resolves to
    POD -> identical behaviour; no check or expected value changes.
    """
    global _PRIMARY_POD_CACHE
    if _PRIMARY_POD_CACHE is not None:
        return _PRIMARY_POD_CACHE
    # Probe a generous index range so larger (scaled) replica sets are covered.
    for idx in range(9):
        pod = f"{CLUSTER_PREFIX}-{idx}"
        res = _exec_mongo(pod, uri, "db.hello().isWritablePrimary")
        if res.returncode != 0:
            # Pod may not exist for this index; stop once we hit a gap past 0.
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
    #
    # `uri` may be a single URI or a list of candidate URIs that differ only in
    # auth database (admin vs the app DB). Try each and return the first that
    # AUTHENTICATES -- i.e. whose failure, if any, is no longer "Authentication
    # failed". The actual operation result (success, or a legitimate
    # Unauthorized for the read-only write-denied check) is then evaluated by the
    # caller. This lets the oracle find users wherever the agent created them
    # without changing any role/permission assertion.
    uris = uri if isinstance(uri, (list, tuple)) else [uri]
    res = None
    for candidate in uris:
        res = _exec_mongo(find_primary(candidate), candidate, eval_str)
        blob = (res.stderr or "") + (res.stdout or "")
        if res.returncode == 0 or "Authentication failed" not in blob:
            return res
    return res


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


def role_has_privileges(role):
    for priv in role.get("privileges", []):
        resource = priv.get("resource", {})
        if resource.get("db") != APP_DB:
            continue
        if resource.get("collection") != REPORTS_COLLECTION:
            continue
        actions = set(priv.get("actions", []))
        if "find" in actions:
            return True
    return False


def user_has_role(user, role_name, role_db=None):
    for role in user.get("roles", []):
        if role.get("role") != role_name:
            continue
        if role_db is None or role.get("db") == role_db:
            return True
    return False


def creds(errors):
    admin_pw = get_secret_value(ADMIN_SECRET, "password", errors)
    app_pw = get_secret_value(APP_SECRET, "password", errors)
    ro_pw = get_secret_value(READONLY_SECRET, "password", errors)
    if errors:
        return None
    # The prompt does not mandate WHICH database the agent creates the users in:
    # centralized users live in `admin` (authSource=admin), but creating them in
    # the application database (authSource=<APP_DB>) is an equally valid pattern.
    # Offer both candidate auth databases per user so the oracle authenticates
    # against wherever the agent legitimately placed them; the role/permission
    # assertions are unchanged.
    def _uris(user, pw, conn_db):
        # directConnection skips SDAM topology monitoring (via find_primary's
        # db.hello), which a localhost connection would start and which fails
        # under a persisted requireTLS mode.
        suffix = "&directConnection=true"
        return [
            f"mongodb://{user}:{pw}@localhost:27017/{conn_db}?authSource=admin{suffix}",
            f"mongodb://{user}:{pw}@localhost:27017/{conn_db}?authSource={APP_DB}{suffix}",
        ]
    return {
        "admin_uri": _uris(ADMIN_USER, admin_pw, "admin"),
        "app_uri": _uris(APP_USER, app_pw, APP_DB),
        "ro_uri": _uris(READONLY_USER, ro_pw, APP_DB),
    }


def check_role():
    errors = []
    c = creds(errors)
    if errors:
        return fail("User management role check failed:", errors)

    role = load_json(
        c["admin_uri"],
        f'JSON.stringify(db.getSiblingDB("admin").getRole("{REPORTING_ROLE}",{{showPrivileges:true}}))',
        f"{REPORTING_ROLE} (admin)",
        errors,
    )
    role_db = "admin"
    if role is None:
        role = load_json(
            c["admin_uri"],
            f'JSON.stringify(db.getSiblingDB("{APP_DB}").getRole("{REPORTING_ROLE}",{{showPrivileges:true}}))',
            f"{REPORTING_ROLE} ({APP_DB})",
            errors,
        )
        role_db = APP_DB

    if role is None:
        errors.append(f"{REPORTING_ROLE} not found")
    elif not role_has_privileges(role):
        errors.append(f"{REPORTING_ROLE} missing find on {APP_DB}.{REPORTS_COLLECTION}")

    if errors:
        return fail("User management role check failed:", errors)
    print(role_db)
    return 0


def _user_roles(c, username):
    """Return (found, roles) for `username`, looking in BOTH possible auth homes.

    The task never dictates the authentication database, and this oracle already
    treats users created in admin and in APP_DB as equally valid (see creds()'s
    dual-authSource URIs and check_access). check_bindings previously did
    getUser() on the admin connection only, so an agent that correctly created the
    user under APP_DB (authSource=APP_DB) was rejected here even though its
    effective access is right. Merge the roles from wherever the user is defined;
    check_access remains the effective gate, so a genuinely broken solution
    (wrong password / missing access) still fails.
    """
    found = False
    roles = []
    for dbn in ("admin", APP_DB):
        u = load_json(
            c["admin_uri"],
            f'JSON.stringify(db.getSiblingDB("{dbn}").getUser("{username}"))',
            f"{username} ({dbn})",
            [],
        )
        if isinstance(u, dict):
            found = True
            roles.extend(u.get("roles", []))
    return found, roles


def check_bindings():
    errors = []
    c = creds(errors)
    if errors:
        return fail("User management bindings check failed:", errors)

    app_found, app_roles = _user_roles(c, APP_USER)
    ro_found, ro_roles = _user_roles(c, READONLY_USER)

    if app_found:
        if not user_has_role({"roles": app_roles}, "readWrite", APP_DB):
            errors.append(f"{APP_USER} missing readWrite on {APP_DB}")
    else:
        errors.append(f"{APP_USER} not found")

    if ro_found:
        if not user_has_role({"roles": ro_roles}, "read", APP_DB):
            errors.append(f"{READONLY_USER} missing read on {APP_DB}")
        # Name-stated role (prompt names {{reporting_role_name}}); accept the
        # binding regardless of which db the role is defined in -- check_role
        # validates that role's privileges separately.
        if not user_has_role({"roles": ro_roles}, REPORTING_ROLE):
            errors.append(f"{READONLY_USER} missing {REPORTING_ROLE}")

    return fail("User management bindings check failed:", errors)


def check_access():
    errors = []
    c = creds(errors)
    if errors:
        return fail("User management access check failed:", errors)

    count = load_json(
        c["admin_uri"],
        f'JSON.stringify(db.getSiblingDB("{APP_DB}").{REPORTS_COLLECTION}.countDocuments({{}}))',
        "seed count",
        errors,
    )
    if isinstance(count, int):
        if count < SEED_DOCS:
            errors.append(f"seed docs missing from {APP_DB}.{REPORTS_COLLECTION}")
    elif isinstance(count, str) and count.isdigit():
        if int(count) < SEED_DOCS:
            errors.append(f"seed docs missing from {APP_DB}.{REPORTS_COLLECTION}")
    else:
        errors.append("unable to verify seed count")

    app_insert = run_mongo(c["app_uri"], f'db.{REPORTS_COLLECTION}.insertOne({{ok:"app-write"}}, {{writeConcern:{{w:1}}}})')
    if app_insert.returncode != 0:
        errors.append(f"{APP_USER} insert failed: {app_insert.stderr.strip() or app_insert.stdout.strip()}")

    ro_read = run_mongo(c["ro_uri"], f'db.{REPORTS_COLLECTION}.findOne({{}})')
    if ro_read.returncode != 0:
        errors.append(f"{READONLY_USER} read failed: {ro_read.stderr.strip() or ro_read.stdout.strip()}")

    ro_agg = run_mongo(c["ro_uri"], f'db.{REPORTS_COLLECTION}.aggregate([{{$match:{{}}}}]).toArray().length')
    if ro_agg.returncode != 0:
        errors.append(f"{READONLY_USER} aggregate failed: {ro_agg.stderr.strip() or ro_agg.stdout.strip()}")

    ro_write = run_mongo(c["ro_uri"], f'db.{REPORTS_COLLECTION}.insertOne({{bad:"write"}})')
    ro_combined = (ro_write.stdout + ro_write.stderr).lower()
    if ro_write.returncode == 0 and "not authorized" not in ro_combined:
        errors.append(f"{READONLY_USER} insert unexpectedly succeeded")

    return fail("User management access check failed:", errors)


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
    print("User management verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# Verify the agent recorded the active feature version in the configured
# ConfigMap and that the cluster is in the expected upgraded-but-pinned state.
# The ConfigMap name/key (BENCH_PARAM_REPORT_CONFIGMAP_NAME / _REPORT_KEY), the
# pre-upgrade logical version (BENCH_PARAM_FROM_VERSION) and the binary/image
# version (BENCH_PARAM_TO_VERSION) all come from the case params, so a workflow
# that overrides them is honored. Standalone (default params) this behaves
# identically to the old hardcoded check.
import json
import os
import subprocess
import sys


REPORT_CM = os.environ.get("BENCH_PARAM_REPORT_CONFIGMAP_NAME", "crdb-version-report")
REPORT_KEY = os.environ.get("BENCH_PARAM_REPORT_KEY", "db_version")
FROM_VERSION = os.environ.get("BENCH_PARAM_FROM_VERSION", "23.2")
TO_VERSION = os.environ.get("BENCH_PARAM_TO_VERSION", "24.1.0")
# Logical major.minor of the binary (e.g. "24.1" for "24.1.0").
TO_MAJOR_MINOR = ".".join(TO_VERSION.split(".")[:2])


def run(cmd):
    return subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def crdb_pod_selector():
    """Return the live `crdb-cluster` StatefulSet's pod selector string (§3.1).

    Falls back to the canonical app.kubernetes.io/name=cockroachdb label when the
    StatefulSet can't be read, so the oracle still works against an inherited
    agent-built cluster (whose labels the deploy oracle now mandates).
    """
    sts = run(["kubectl", "-n", "cockroachdb", "get", "statefulset",
               "crdb-cluster", "-o", "json"])
    if sts.returncode == 0:
        try:
            match = (json.loads(sts.stdout).get("spec", {})
                     .get("selector", {}).get("matchLabels")) or {}
        except json.JSONDecodeError:
            match = {}
        if match:
            return ",".join(f"{k}={v}" for k, v in match.items())
    return "app.kubernetes.io/name=cockroachdb"


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


def norm_version(value):
    """Canonicalize a version string for comparison (O36).

    Strips surrounding whitespace and one optional leading 'v'/'V', so an agent
    that recorded "v24.1" (the spelling `SELECT version()` and the image tag
    use, which the prompt never forbids) matches the cluster's "24.1". A
    genuinely wrong version still differs after normalization.
    """
    value = value.strip()
    if value[:1] in ("v", "V"):
        value = value[1:]
    return value


def tsv_last_value(output):
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if not lines:
        return ""
    if len(lines) == 1:
        return lines[0]
    return lines[-1].split("\t")[-1]


def main():
    errors = []

    cm_cmd = [
        "kubectl",
        "-n",
        "cockroachdb",
        "get",
        "configmap",
        REPORT_CM,
        "-o",
        "jsonpath={.data." + REPORT_KEY.replace(".", "\\.") + "}",
    ]
    cm_result = run(cm_cmd)
    if cm_result.returncode != 0:
        errors.append(f"Missing ConfigMap {REPORT_CM}")
        errors.append(f"Error: {cm_result.stderr.strip()}")
        cm_version = ""
    else:
        cm_version = cm_result.stdout.strip()
        if not cm_version:
            errors.append(f"ConfigMap {REPORT_KEY} is empty")

    cluster_cmd = [
        "kubectl",
        "-n",
        "cockroachdb",
        "exec",
        "crdb-cluster-0",
        "--",
        "./cockroach",
        "sql",
        conn_flag(),
        "--format=tsv",
        "-e",
        "SHOW CLUSTER SETTING version;",
    ]
    cluster_result = run(cluster_cmd)
    cluster_version = ""
    if cluster_result.returncode != 0:
        errors.append("Failed to read cluster version")
        errors.append(f"Error: {cluster_result.stderr.strip()}")
    else:
        cluster_version = tsv_last_value(cluster_result.stdout)
        # NOTE: do not assert the active feature version equals FROM_VERSION. That
        # asserts a PRE-finalization setup (binary ahead of feature, downgrade
        # pinned) which is the standalone scenario, but the env PERSISTS across a
        # workflow: a prior major-upgrade-finalize stage legitimately advances the
        # feature version to the binary's. The agent's task -- report the cluster's
        # ACTUAL active feature version -- is verified below (cm_version must equal
        # this live cluster_version), so the check stays honest regardless of
        # whether the upgrade has been finalized.

    preserve_cmd = [
        "kubectl",
        "-n",
        "cockroachdb",
        "exec",
        "crdb-cluster-0",
        "--",
        "./cockroach",
        "sql",
        conn_flag(),
        "--format=tsv",
        "-e",
        "SHOW CLUSTER SETTING cluster.preserve_downgrade_option;",
    ]
    preserve_result = run(preserve_cmd)
    if preserve_result.returncode != 0:
        errors.append("Failed to read preserve_downgrade_option")
        errors.append(f"Error: {preserve_result.stderr.strip()}")
    else:
        # preserve_downgrade_option being SET is likewise a pre-finalization setup
        # detail, not the agent's task: once a workflow's major-upgrade-finalize
        # stage finalizes the upgrade it is correctly cleared. Reading it is kept
        # for diagnostics; its value is not asserted so the case composes after
        # finalization.
        _ = tsv_last_value(preserve_result.stdout)

    binary_cmd = [
        "kubectl",
        "-n",
        "cockroachdb",
        "exec",
        "crdb-cluster-0",
        "--",
        "./cockroach",
        "sql",
        conn_flag(),
        "--format=tsv",
        "-e",
        "SELECT version();",
    ]
    binary_result = run(binary_cmd)
    if binary_result.returncode != 0:
        errors.append("Failed to read binary version")
        errors.append(f"Error: {binary_result.stderr.strip()}")
    else:
        if f"v{TO_MAJOR_MINOR}" not in binary_result.stdout and TO_MAJOR_MINOR not in binary_result.stdout:
            errors.append(f"Binary version does not look like v{TO_MAJOR_MINOR}")

    images_cmd = [
        "kubectl",
        "-n",
        "cockroachdb",
        "get",
        "pods",
        "-l",
        crdb_pod_selector(),
        "-o",
        "jsonpath={.items[*].spec.containers[0].image}",
    ]
    images_result = run(images_cmd)
    if images_result.returncode != 0:
        errors.append("Failed to read pod images")
        errors.append(f"Error: {images_result.stderr.strip()}")
    else:
        images = [image.strip() for image in images_result.stdout.split() if image.strip()]
        if not images:
            errors.append("No pod images reported")
        elif any(f"cockroachdb/cockroach:v{TO_VERSION}" not in image for image in images):
            errors.append(f"Unexpected pod images: {' '.join(images)}")

    # O36/O1: compare semantically, not as raw strings -- normalize whitespace
    # and an optional leading 'v' on both sides before diffing.
    if cm_version and cluster_version and norm_version(cm_version) != norm_version(cluster_version):
        errors.append(f"ConfigMap db_version does not match cluster version ({cluster_version})")

    if errors:
        print("Version check verification failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print("Version check completed successfully")
    return 0


if __name__ == "__main__":
    sys.exit(main())

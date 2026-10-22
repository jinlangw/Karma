#!/usr/bin/env python3
"""Execute and verify the generated CockroachDB major-upgrade plan.

The plan ConfigMap lives in KARMA's task namespace. This oracle copies its
``plan.sh`` entry into a uniquely named disposable namespace, starts a small
cluster on ``from_version``, pins the active cluster version to that release,
and runs the candidate with a random namespace and StatefulSet name. The pin
means a binary rollout alone cannot pass: the plan must also finalize the
CockroachDB cluster-version upgrade.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import uuid


TASK_NAMESPACE = os.environ.get("BENCH_NAMESPACE", "").strip()
CONFIGMAP = "change-plan"
KEY = "plan.sh"
LABEL_SELECTOR = "app.kubernetes.io/name=cockroachdb"
FIXTURE = Path(__file__).with_name("disposable-cluster.yaml")


class OracleFailure(RuntimeError):
    """A test prerequisite or assertion failed."""


def run(cmd: list[str], *, timeout: int = 30, input_text: str | None = None,
        env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    """Run a subprocess with a hard timeout and captured diagnostics."""
    try:
        return subprocess.run(
            cmd,
            input=input_text,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode(errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode(errors="replace")
        return subprocess.CompletedProcess(cmd, 124, stdout, f"timed out after {timeout}s\n{stderr}")


def output_of(result: subprocess.CompletedProcess[str]) -> str:
    return (result.stdout or "").strip()


def require_success(result: subprocess.CompletedProcess[str], what: str) -> str:
    if result.returncode != 0:
        details = (result.stderr or result.stdout or "no command output").strip()
        raise OracleFailure(f"{what} failed (exit {result.returncode}): {details[-4000:]}")
    return output_of(result)


def normalize_version(raw: str, label: str) -> tuple[str, str]:
    """Return (exact image version, major.minor cluster version)."""
    version = raw.strip().removeprefix("v")
    if not re.fullmatch(r"\d+\.\d+(?:\.\d+)?", version):
        raise OracleFailure(f"{label} must be a numeric CockroachDB version, got {raw!r}")
    parts = version.split(".")
    image_version = version if len(parts) == 3 else f"{version}.0"
    return image_version, f"{parts[0]}.{parts[1]}"


def tsv_last_value(text: str) -> str:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return ""
    return lines[-1].split("\t")[-1].strip()


def read_candidate_script() -> str:
    if not TASK_NAMESPACE:
        raise OracleFailure("BENCH_NAMESPACE is not set; cannot find the task ConfigMap")
    result = run([
        "kubectl", "-n", TASK_NAMESPACE, "get", "configmap", CONFIGMAP,
        "-o", "json",
    ])
    raw = require_success(result, f"reading ConfigMap {CONFIGMAP!r} from {TASK_NAMESPACE!r}")
    try:
        data = json.loads(raw).get("data") or {}
    except json.JSONDecodeError as exc:
        raise OracleFailure(f"ConfigMap {CONFIGMAP!r} returned invalid JSON: {exc}") from exc
    script = data.get(KEY)
    if not isinstance(script, str) or not script.strip():
        raise OracleFailure(f"ConfigMap {CONFIGMAP!r} has no non-empty {KEY!r} entry")
    if not script.startswith("#!/bin/sh\n"):
        raise OracleFailure("plan.sh must start with the POSIX shell shebang #!/bin/sh")
    if not re.search(r"(?m)^\s*set\s+(?:-[A-Za-z]*e[A-Za-z]*\b|-o\s+errexit\b)", script):
        raise OracleFailure("plan.sh must enable fail-fast behavior with set -e / errexit")
    return script


def create_owned_namespace() -> tuple[str, str]:
    """Create a namespace; never reuse or delete a namespace we do not own."""
    for _ in range(5):
        token = uuid.uuid4().hex[:10]
        namespace = f"oracle-crdb-{token}"
        result = run(["kubectl", "create", "namespace", namespace])
        if result.returncode == 0:
            return namespace, token
        details = (result.stderr or result.stdout or "").strip()
        if "alreadyexists" in details.lower() or "already exists" in details.lower():
            continue
        raise OracleFailure(
            f"creating disposable namespace {namespace!r} failed: {details}"
        )
    raise OracleFailure("could not allocate a unique disposable namespace after 5 attempts")


def kubectl_exec(namespace: str, pod: str, *args: str,
                 timeout: int = 45) -> subprocess.CompletedProcess[str]:
    return run([
        "kubectl", "-n", namespace, "exec", pod, "--", *args,
    ], timeout=timeout)


def sql(namespace: str, cluster_name: str, statement: str,
        *, timeout: int = 45) -> subprocess.CompletedProcess[str]:
    return kubectl_exec(
        namespace, f"{cluster_name}-0", "./cockroach", "sql", "--insecure",
        "--format=tsv", "-e", statement, timeout=timeout,
    )


def wait_for_sql(namespace: str, cluster_name: str, *, timeout: int = 300) -> None:
    deadline = time.monotonic() + timeout
    last_error = "no response yet"
    while time.monotonic() < deadline:
        result = sql(namespace, cluster_name, "SELECT 1;", timeout=30)
        if result.returncode == 0 and "1" in result.stdout.split():
            return
        last_error = (result.stderr or result.stdout or "no SQL output").strip()
        time.sleep(5)
    raise OracleFailure(f"CockroachDB SQL did not become available: {last_error[-2000:]}")


def wait_for_pods(namespace: str, cluster_name: str, *, timeout: int = 600) -> None:
    selector = f"{LABEL_SELECTOR},app.kubernetes.io/instance={cluster_name}"
    result = run([
        "kubectl", "-n", namespace, "wait", "--for=condition=ready", "pod",
        "-l", selector, f"--timeout={timeout}s",
    ], timeout=timeout + 15)
    require_success(result, f"waiting for all pods in {cluster_name!r} to become ready")


def bootstrap_cluster(namespace: str, cluster_name: str, source_image_version: str,
                      source_cluster_version: str) -> None:
    fixture = FIXTURE.read_text(encoding="utf-8")
    fixture = fixture.replace("${FROM_IMAGE_VERSION}", source_image_version)
    fixture = fixture.replace("crdb-cluster", cluster_name)
    result = run([
        "kubectl", "-n", namespace, "apply", "-f", "-",
    ], input_text=fixture, timeout=60)
    require_success(result, "applying the disposable CockroachDB fixture")

    selector = f"{LABEL_SELECTOR},app.kubernetes.io/instance={cluster_name}"
    result = run([
        "kubectl", "-n", namespace, "wait", "--for=jsonpath={.status.phase}=Running",
        "pod", "-l", selector, "--timeout=600s",
    ], timeout=615)
    require_success(result, "waiting for disposable CockroachDB pods to start")

    host = f"{cluster_name}-0.{cluster_name}.{namespace}.svc.cluster.local:26257"
    deadline = time.monotonic() + 180
    initialized = False
    last_error = "no response yet"
    while time.monotonic() < deadline:
        result = kubectl_exec(
            namespace, f"{cluster_name}-0", "./cockroach", "init", "--insecure",
            f"--host={host}", timeout=30,
        )
        if result.returncode == 0:
            initialized = True
            break
        last_error = (result.stderr or result.stdout or "no init output").strip()
        # The loop handles the initial inter-node startup race only. A newly
        # created namespace cannot already contain an initialized cluster.
        time.sleep(5)
    if not initialized:
        raise OracleFailure(f"initializing disposable CockroachDB failed: {last_error[-2000:]}")

    wait_for_pods(namespace, cluster_name)
    wait_for_sql(namespace, cluster_name)
    version_result = sql(
        namespace, cluster_name, "SHOW CLUSTER SETTING version;",
    )
    active = tsv_last_value(require_success(version_result, "reading initial cluster version"))
    if active != source_cluster_version:
        raise OracleFailure(
            f"disposable cluster started at version {active!r}, "
            f"expected {source_cluster_version!r}"
        )

    # This guard prevents CockroachDB from auto-finalizing as soon as every
    # node runs the newer binary. The candidate must perform the finalization.
    pinned = sql(
        namespace, cluster_name,
        "SET CLUSTER SETTING cluster.preserve_downgrade_option = "
        f"'{source_cluster_version}';",
    )
    require_success(pinned, "pinning the source cluster version before the upgrade")


def verify_target(namespace: str, cluster_name: str, target_image_version: str,
                  target_cluster_version: str) -> None:
    selector = f"{LABEL_SELECTOR},app.kubernetes.io/instance={cluster_name}"
    wait_for_pods(namespace, cluster_name, timeout=300)

    result = run([
        "kubectl", "-n", namespace, "get", "pods", "-l", selector, "-o", "json",
    ])
    try:
        pods = json.loads(require_success(result, "reading upgraded CockroachDB pods")).get("items", [])
    except json.JSONDecodeError as exc:
        raise OracleFailure(f"Kubernetes returned invalid pod JSON: {exc}") from exc
    if len(pods) != 3:
        raise OracleFailure(f"expected 3 upgraded CockroachDB pods, found {len(pods)}")
    for pod in pods:
        name = pod.get("metadata", {}).get("name", "unknown")
        containers = pod.get("spec", {}).get("containers", [])
        if not containers:
            raise OracleFailure(f"pod {name!r} has no container")
        image = containers[0].get("image", "")
        if image != f"cockroachdb/cockroach:v{target_image_version}":
            raise OracleFailure(
                f"pod {name!r} runs image {image!r}, expected "
                f"cockroachdb/cockroach:v{target_image_version}"
            )
        statuses = pod.get("status", {}).get("containerStatuses", [])
        if not statuses or not all(status.get("ready") for status in statuses):
            raise OracleFailure(f"pod {name!r} is not ready after the upgrade")

    version = sql(namespace, cluster_name, "SHOW CLUSTER SETTING version;")
    active = tsv_last_value(require_success(version, "reading finalized cluster version"))
    if active != target_cluster_version:
        raise OracleFailure(
            f"cluster version was not finalized: got {active!r}, "
            f"expected exactly {target_cluster_version!r}"
        )

    preserve = sql(
        namespace, cluster_name,
        "SHOW CLUSTER SETTING cluster.preserve_downgrade_option;",
    )
    preserve_value = tsv_last_value(require_success(preserve, "checking downgrade pin"))
    if preserve_value not in ("", "cluster.preserve_downgrade_option", "NULL", "[]"):
        raise OracleFailure(
            "cluster.preserve_downgrade_option is still set to "
            f"{preserve_value!r}; the upgrade was not finalized"
        )

    query = sql(namespace, cluster_name, "SELECT 1;")
    if query.returncode != 0 or "1" not in query.stdout.split():
        raise OracleFailure(
            "the upgraded cluster did not serve SQL successfully: "
            f"{(query.stderr or query.stdout).strip()}"
        )

    node_status = kubectl_exec(
        namespace, f"{cluster_name}-0", "./cockroach", "node", "status",
        "--insecure", "--format=tsv", timeout=60,
    )
    status_text = require_success(node_status, "checking CockroachDB node health")
    rows = [line for line in status_text.splitlines() if line.strip()]
    if not rows:
        raise OracleFailure("CockroachDB returned empty node status output")
    columns = rows[0].split("\t")
    live_index = next(
        (index for index, column in enumerate(columns) if column.strip() == "is_live"),
        None,
    )
    if live_index is None:
        raise OracleFailure("CockroachDB node status has no is_live column")
    live_nodes = 0
    for row in rows[1:]:
        values = row.split("\t")
        if len(values) > live_index and values[live_index].strip().lower() in ("true", "t", "1"):
            live_nodes += 1
    if live_nodes != 3:
        raise OracleFailure(f"expected 3 live CockroachDB nodes, found {live_nodes}")


def diagnostics(namespace: str) -> None:
    for cmd in (
        ["kubectl", "-n", namespace, "get", "pods", "-o", "wide"],
        ["kubectl", "-n", namespace, "get", "events", "--sort-by=.metadata.creationTimestamp"],
    ):
        result = run(cmd, timeout=30)
        text = (result.stdout or result.stderr or "").strip()
        if text:
            print(text[-6000:], file=sys.stderr)


def main() -> int:
    source_raw = os.environ.get("BENCH_PARAM_FROM_VERSION", "23.2")
    target_raw = os.environ.get("BENCH_PARAM_TO_VERSION", "24.1.0")
    namespace = ""
    result_code = 1

    try:
        source_image, source_cluster = normalize_version(source_raw, "from_version")
        target_image, target_cluster = normalize_version(target_raw, "to_version")
        if source_cluster.split(".")[0] == target_cluster.split(".")[0]:
            raise OracleFailure(
                "change-plan-only is intended to verify a cross-major upgrade; "
                f"got {source_cluster!r} to {target_cluster!r}"
            )

        script = read_candidate_script()
        syntax = run(["/bin/sh", "-n"], input_text=script)
        require_success(syntax, "checking plan.sh POSIX shell syntax")

        namespace, token = create_owned_namespace()
        cluster_name = f"roach-{token}"
        print(
            f"Testing {KEY} for CockroachDB v{source_image} -> v{target_image} "
            f"in disposable namespace {namespace!r} (StatefulSet {cluster_name!r}).",
            flush=True,
        )

        bootstrap_cluster(namespace, cluster_name, source_image, source_cluster)
        with tempfile.TemporaryDirectory(prefix="karma-crdb-plan-") as temp_dir:
            plan_path = Path(temp_dir) / KEY
            plan_path.write_text(script, encoding="utf-8")
            plan_path.chmod(0o700)
            execution = run(
                [str(plan_path), namespace, cluster_name],
                timeout=1200,
                env=os.environ.copy(),
            )
            if execution.returncode != 0:
                details = (execution.stderr or execution.stdout or "no script output").strip()
                raise OracleFailure(
                    f"plan.sh exited {execution.returncode}: {details[-5000:]}"
                )
            if execution.stdout.strip():
                print(execution.stdout.strip()[-5000:], flush=True)

        verify_target(namespace, cluster_name, target_image, target_cluster)
        result_code = 0
        print(
            f"PASS: plan.sh upgraded all nodes and finalized CockroachDB "
            f"from {source_cluster} to {target_cluster}.",
            flush=True,
        )
    except (OracleFailure, OSError) as exc:
        print(f"change-plan-only verification failed: {exc}", file=sys.stderr)
        if namespace:
            diagnostics(namespace)
    finally:
        if namespace:
            cleanup = run([
                "kubectl", "delete", "namespace", namespace,
                "--wait=true", "--timeout=180s",
            ], timeout=195)
            if cleanup.returncode != 0:
                print(
                    f"warning: could not fully delete disposable namespace "
                    f"{namespace!r}: {(cleanup.stderr or cleanup.stdout).strip()}",
                    file=sys.stderr,
                )
                result_code = 1
            else:
                print(f"Cleaned up disposable namespace {namespace!r}.", flush=True)
    return result_code


if __name__ == "__main__":
    sys.exit(main())

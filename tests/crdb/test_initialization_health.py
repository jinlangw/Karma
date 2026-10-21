from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess

import pytest

from karma.crdb.health import observe_initialization_state


ROOT = Path(__file__).resolve().parents[2]
CASE_PATHS = [
    "cases/cockroachdb/initialize/scripts/cluster.py",
    "cases/cockroachdb/major-upgrade-finalize/scripts/cluster.py",
    "cases/cockroachdb/readonly-audit/scripts/cluster.py",
    "cases/cockroachdb/rollback-rehearsal/scripts/cluster.py",
    "cases/cockroachdb/zone-config/scripts/cluster.py",
    "cases/cockroachdb/version-check/scripts/cluster.py",
    "cases/cockroachdb/monitoring-integration/scripts/cluster.py",
]


def load_case_cluster(relative_path: str):
    path = ROOT / relative_path
    spec = importlib.util.spec_from_file_location(f"node_state_{path.parent.parent.name}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def ready_pod(*, scheme="HTTP", port="http", running=True, sql_tls=False):
    state = {"running": {}} if running else {"waiting": {"reason": "CrashLoopBackOff"}}
    startup = ["/cockroach/cockroach", "start"]
    startup.append("--certs-dir=/cockroach/certs" if sql_tls else "--insecure")
    return {
        "metadata": {"name": "db-0"},
        "spec": {
            "containers": [
                {
                    "name": "db",
                    "image": "cockroachdb/cockroach:v24.1.0",
                    "command": startup,
                    "ports": [{"name": "http", "containerPort": 8080}],
                    "readinessProbe": {
                        "httpGet": {
                            "path": "/health?ready=1",
                            "port": port,
                            "scheme": scheme,
                        }
                    },
                }
            ]
        },
        "status": {
            "phase": "Running",
            "containerStatuses": [{"name": "db", "state": state}],
        },
    }


def run_case_node_state(case_path, pod, output):
    case = load_case_cluster(case_path)
    cluster = object.__new__(case.Cluster)
    calls = []

    def kubectl(*args, timeout=20):
        calls.append((args, timeout))
        return subprocess.CompletedProcess(args, 0, output, "")

    cluster.kubectl = kubectl
    result = cluster.node_state(pod)
    return result, calls


@pytest.mark.parametrize("case_path", CASE_PATHS)
@pytest.mark.parametrize(
    "scheme,port,sql_tls,expected",
    [
        ("HTTP", "http", True, "http://localhost:8080/health?ready=1"),
        ("HTTPS", 8080, False, "https://localhost:8080/health?ready=1"),
    ],
)
def test_case_node_state_uses_configured_http_transport_independently_of_sql_tls(
    case_path, scheme, port, sql_tls, expected
):
    state, calls = run_case_node_state(
        case_path,
        ready_pod(scheme=scheme, port=port, sql_tls=sql_tls),
        '{"ok":true}\n200',
    )

    assert state == "initialized"
    assert len(calls) == 1
    args, timeout = calls[0]
    assert args == (
        "exec",
        "db-0",
        "-c",
        "db",
        "--",
        "curl",
        "--silent",
        "--show-error",
        "--insecure",
        "--connect-timeout",
        "2",
        "--max-time",
        "3",
        "--write-out",
        "\n%{http_code}",
        expected,
    )
    assert timeout == 8


@pytest.mark.parametrize("case_path", CASE_PATHS)
@pytest.mark.parametrize("status,body", [(503, '{"error":"other"}'), (500, '{"error":"other"}')])
def test_case_node_state_distinguishes_only_the_original_uninitialized_sentinel(case_path, status, body):
    state, _ = run_case_node_state(
        case_path,
        ready_pod(scheme="HTTPS"),
        '{"error":"node is waiting for cluster initialization"}\n503',
    )
    assert state == "uninitialized"

    with pytest.raises(
        RuntimeError,
        match="^database health failed for a reason other than waiting for initialization$",
    ):
        run_case_node_state(case_path, ready_pod(), f"{body}\n{status}")


@pytest.mark.parametrize("case_path", CASE_PATHS)
def test_case_node_state_preserves_running_and_probe_guards_without_exec(case_path):
    case = load_case_cluster(case_path)
    cluster = object.__new__(case.Cluster)
    cluster.kubectl = lambda *args, **kwargs: pytest.fail("unsupported state must not exec curl")

    with pytest.raises(RuntimeError, match="^database process is not Running$"):
        cluster.node_state(ready_pod(running=False))

    invalid = ready_pod()
    invalid["spec"]["containers"][0]["readinessProbe"]["httpGet"]["path"] = "/health"
    with pytest.raises(
        case.UnsafeState,
        match=r"^case requires an HTTP /health\?ready=1 readiness probe on the database listener$",
    ):
        cluster.node_state(invalid)


def test_shared_helper_keeps_malformed_json_and_exec_failures_unwrapped():
    with pytest.raises(json.JSONDecodeError):
        observe_initialization_state(
            ready_pod(),
            execute_curl=lambda *_: "not-json\n200",
            error_type=RuntimeError,
        )

    def exec_failure(*_):
        raise RuntimeError("kubectl exec failed")

    with pytest.raises(RuntimeError, match="^kubectl exec failed$"):
        observe_initialization_state(ready_pod(), execute_curl=exec_failure, error_type=RuntimeError)


@pytest.mark.parametrize("case_path", CASE_PATHS)
def test_case_node_state_preserves_malformed_json_error(case_path):
    with pytest.raises(json.JSONDecodeError):
        run_case_node_state(case_path, ready_pod(), "not-json\n200")


@pytest.mark.parametrize("case_path", CASE_PATHS)
def test_case_node_state_preserves_native_kubectl_failure(case_path):
    case = load_case_cluster(case_path)
    cluster = object.__new__(case.Cluster)
    cluster.kubectl = lambda *args, **kwargs: subprocess.CompletedProcess(
        args, 7, "", "native kubectl failure"
    )

    with pytest.raises(RuntimeError, match="^native kubectl failure$"):
        cluster.node_state(ready_pod())

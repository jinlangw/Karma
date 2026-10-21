from __future__ import annotations

import ast
import builtins
import importlib.util
from pathlib import Path
import subprocess

import pytest

import karma.crdb as crdb
from karma.crdb.types import (
    AuthenticationError,
    KubernetesAccessError,
    SQLConnectionObservation,
    TLSMode,
    TransientError,
    UnsupportedLayoutError,
)


ROOT = Path(__file__).resolve().parents[2]
ORACLE_REL = "cases/cockroachdb/certificate-rotation/oracle/oracle.py"
ORACLE_PATH = ROOT / ORACLE_REL
SPEC = importlib.util.spec_from_file_location("certificate_rotation_oracle", ORACLE_PATH)
assert SPEC is not None and SPEC.loader is not None
ORACLE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ORACLE)
LIBRARY_TEST_PATH = ROOT / "tests/crdb/test_library.py"
LIBRARY_SPEC = importlib.util.spec_from_file_location("certificate_rotation_library_fixture", LIBRARY_TEST_PATH)
assert LIBRARY_SPEC is not None and LIBRARY_SPEC.loader is not None
LIBRARY_TEST = importlib.util.module_from_spec(LIBRARY_SPEC)
LIBRARY_SPEC.loader.exec_module(LIBRARY_TEST)


def observed_connection(*, certs_dir="/cockroach/cockroach-certs", tls_mode=TLSMode.TLS):
    return SQLConnectionObservation(
        namespace="bench-ns",
        workload_name="db",
        workload_uid="sts-uid",
        pod_name="db-0",
        pod_uid="pod-uid",
        container_name="cockroach-server",
        image="cockroachdb/cockroach:v24.1.0",
        sql_binary="/opt/cockroach/cockroach",
        sql_host="db-0.db.bench-ns.svc.cluster.local",
        sql_port=26270,
        rpc_port=26258,
        tls_mode=tls_mode,
        certs_dir=certs_dir,
    )


class FakeLibrary:
    connection = observed_connection()
    error = None
    calls = []

    def __init__(self, _adapter):
        pass

    def inspect_sql_connection(self, ref, *, ordinal):
        self.calls.append((ref, ordinal))
        if self.error is not None:
            raise self.error
        return self.connection


class FakeAdapter:
    instances = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.instances.append(self)


def setup_fake_observer(monkeypatch, *, connection=None, error=None):
    FakeLibrary.connection = connection or observed_connection()
    FakeLibrary.error = error
    FakeLibrary.calls = []
    FakeAdapter.instances = []
    monkeypatch.setattr(crdb, "CrdbLibrary", FakeLibrary)
    monkeypatch.setattr(crdb, "KubectlAdapter", FakeAdapter)


def configure_oracle(monkeypatch):
    monkeypatch.setattr(ORACLE, "NAMESPACE", "bench-ns")
    monkeypatch.setattr(ORACLE, "CLUSTER_NAME", "db")
    monkeypatch.setattr(ORACLE, "NODE_NAME", "db-0")


def completed(command, status):
    return subprocess.CompletedProcess(command, status, "", "legacy SQL failed")


def test_legacy_sql_success_does_not_import_or_query_shared_observer(monkeypatch):
    configure_oracle(monkeypatch)
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        return completed(command, 0)

    original_import = builtins.__import__

    def reject_library_import(name, *args, **kwargs):
        if name == "karma.crdb" or name.startswith("karma.crdb."):
            raise AssertionError("the legacy-success path must not import the shared observer")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(ORACLE, "run", run)
    monkeypatch.setattr(builtins, "__import__", reject_library_import)

    result = ORACLE.secure_sql_result()

    assert result.returncode == 0
    assert calls == [(
        [
            "kubectl", "-n", "bench-ns", "exec", "db-0", "--", "./cockroach", "sql",
            "--certs-dir=/cockroach/cockroach-certs", "-e", "SELECT 1;",
        ],
        {},
    )]


def test_observed_retry_uses_real_inspector_selected_container_and_endpoint(monkeypatch):
    memory = LIBRARY_TEST.MemoryAdapter(tls=True, replicas=1, custom_ports=True)
    configure_oracle(monkeypatch)
    monkeypatch.setattr(ORACLE, "NAMESPACE", memory.namespace)
    monkeypatch.setattr(ORACLE, "CLUSTER_NAME", memory.name)
    monkeypatch.setattr(ORACLE, "NODE_NAME", f"{memory.name}-0")
    monkeypatch.setattr(crdb, "KubectlAdapter", lambda **_kwargs: memory)

    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        if len(calls) == 1:
            return subprocess.CompletedProcess(command, 1, "legacy output", "legacy SQL failed")
        return subprocess.CompletedProcess(command, 0, "observed SQL passed", "")

    monkeypatch.setattr(ORACLE, "run", run)
    result = ORACLE.secure_sql_result()

    assert result.returncode == 0
    assert result.args == calls[1][0]
    assert result.stdout == "observed SQL passed"
    assert result.stderr == ""
    assert calls[0][0] == [
        "kubectl", "-n", memory.namespace, "exec", f"{memory.name}-0", "--", "./cockroach", "sql",
        "--certs-dir=/cockroach/cockroach-certs", "-e", "SELECT 1;",
    ]
    assert calls[1][0] == [
        "kubectl", "-n", memory.namespace, "exec", f"{memory.name}-0", "--container", "db", "--",
        "/cockroach/cockroach", "sql", "--certs-dir=/cockroach/cockroach-certs",
        f"--host={memory.name}-0.{memory.name}.{memory.namespace}.svc.cluster.local",
        "--port=26270", "-e", "SELECT 1;",
    ]
    assert calls[1][1] == {"timeout": 15}
    assert memory.get_count == 2


def test_observed_cert_directory_is_second_tls_candidate_after_canonical(monkeypatch):
    configure_oracle(monkeypatch)
    setup_fake_observer(monkeypatch, connection=observed_connection(certs_dir="/mounted/root-client"))
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        return completed(command, 1 if len(calls) < 3 else 0)

    monkeypatch.setattr(ORACLE, "run", run)
    result = ORACLE.secure_sql_result()

    assert result.returncode == 0
    assert result.args == calls[2][0]
    assert result.stdout == ""
    assert [call[0][10] for call in calls[1:]] == [
        "--certs-dir=/cockroach/cockroach-certs",
        "--certs-dir=/mounted/root-client",
    ]
    assert [call[1]["timeout"] for call in calls[1:]] == [15, 15]
    assert all("--insecure" not in call[0] for call in calls)
    assert FakeAdapter.instances[0].kwargs == {"kubectl": "kubectl", "get_timeout": 1.0}
    assert FakeLibrary.calls[0][0].container_name is None
    assert FakeLibrary.calls[0][1] == 0


def test_all_observed_tls_candidates_failed_returns_original_legacy_result(monkeypatch):
    configure_oracle(monkeypatch)
    setup_fake_observer(monkeypatch, connection=observed_connection(certs_dir="/mounted/root-client"))
    calls = []
    legacy_result = None

    def run(command, **kwargs):
        nonlocal legacy_result
        calls.append((command, kwargs))
        if len(calls) == 1:
            legacy_result = subprocess.CompletedProcess(command, 1, "legacy stdout", "legacy stderr")
            return legacy_result
        return subprocess.CompletedProcess(command, 1, f"retry {len(calls)} stdout", f"retry {len(calls)} stderr")

    monkeypatch.setattr(ORACLE, "run", run)
    result = ORACLE.secure_sql_result()

    assert result is legacy_result
    assert result.returncode == 1
    assert result.args == calls[0][0]
    assert result.stdout == "legacy stdout"
    assert result.stderr == "legacy stderr"
    assert len(calls) == 3
    assert all("--insecure" not in call[0] for call in calls)


@pytest.mark.parametrize(
    "error",
    [
        AuthenticationError("authentication denied"),
        KubernetesAccessError("Kubernetes read failed"),
        TransientError("inspection timed out"),
        UnsupportedLayoutError("unsupported SQL startup layout"),
    ],
)
def test_observer_errors_preserve_failed_legacy_verdict_without_insecure_fallback(monkeypatch, error):
    configure_oracle(monkeypatch)
    setup_fake_observer(monkeypatch, error=error)
    calls = []
    monkeypatch.setattr(ORACLE, "run", lambda command, **kwargs: calls.append(command) or completed(command, 1))

    result = ORACLE.secure_sql_result()

    assert result.returncode == 1
    assert len(calls) == 1
    assert "--insecure" not in calls[0]


def test_observed_insecure_layout_is_not_used_as_a_retry(monkeypatch):
    configure_oracle(monkeypatch)
    setup_fake_observer(monkeypatch, connection=observed_connection(tls_mode=TLSMode.INSECURE))
    calls = []
    monkeypatch.setattr(ORACLE, "run", lambda command, **kwargs: calls.append(command) or completed(command, 1))

    assert ORACLE.secure_sql_result().returncode == 1
    assert len(calls) == 1
    assert "--insecure" not in calls[0]


def test_connection_retry_preserves_all_non_sql_oracle_assertion_ast():
    baseline = subprocess.run(
        ["git", "show", f"352c0608:{ORACLE_REL}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    original_tree = ast.parse(baseline)
    current_tree = ast.parse(ORACLE_PATH.read_text(encoding="utf-8"))
    original = {node.name: node for node in original_tree.body if isinstance(node, ast.FunctionDef)}
    current = {node.name: node for node in current_tree.body if isinstance(node, ast.FunctionDef)}

    for name in ("run", "served_leaf_fingerprint", "statefulset_replicas", "target_pod_names"):
        assert ast.dump(current[name], include_attributes=False) == ast.dump(original[name], include_attributes=False)

    def after_old_fingerprint_command(function):
        index = next(
            index for index, statement in enumerate(function.body)
            if isinstance(statement, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "old_fp_cmd" for target in statement.targets)
        )
        return ast.Module(body=function.body[index:], type_ignores=[])

    assert ast.dump(after_old_fingerprint_command(current["main"]), include_attributes=False) == ast.dump(
        after_old_fingerprint_command(original["main"]), include_attributes=False
    )

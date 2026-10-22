from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import subprocess
import textwrap

import pytest

from cases.common.cockroachdb.types import (
    KubernetesAccessError,
    SQLConnectionObservation,
    TLSMode,
    UnsupportedLayoutError,
)
from cases.common.cockroachdb import CrdbLibrary


ROOT = Path(__file__).resolve().parents[2]
HELPER_PATH = ROOT / "cases/tests/cockroachdb/certificate-rotation/resource/sql_ready.py"
SPEC = importlib.util.spec_from_file_location("certificate_rotation_sql_ready", HELPER_PATH)
assert SPEC is not None and SPEC.loader is not None
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)

LIBRARY_TEST_PATH = ROOT / "tests/crdb/test_library.py"
LIBRARY_SPEC = importlib.util.spec_from_file_location("certificate_rotation_library_fixture", LIBRARY_TEST_PATH)
assert LIBRARY_SPEC is not None and LIBRARY_SPEC.loader is not None
LIBRARY_TEST = importlib.util.module_from_spec(LIBRARY_SPEC)
LIBRARY_SPEC.loader.exec_module(LIBRARY_TEST)

CLUSTER_SCRIPT = ROOT / "cases/tests/cockroachdb/certificate-rotation/resource/ensure-target-cluster.sh"
TLS_SCRIPT = ROOT / "cases/tests/cockroachdb/certificate-rotation/resource/ensure-target-tls.sh"
DEFAULT_CERTS = "/cockroach/cockroach-certs"


def connection(*, certs_dir=DEFAULT_CERTS) -> SQLConnectionObservation:
    return SQLConnectionObservation(
        namespace="bench-ns",
        workload_name="db",
        workload_uid="sts-uid",
        pod_name="db-0",
        pod_uid="pod-uid",
        container_name="server",
        image="cockroachdb/cockroach:v24.1.0",
        sql_binary="/opt/cockroach/cockroach",
        sql_host="db-0.custom.svc.cluster.local",
        sql_port=26300,
        rpc_port=26258,
        tls_mode=TLSMode.TLS,
        certs_dir=certs_dir,
        rpc_host=None,
    )


class FakeLibrary:
    result = connection()
    error = None
    refs = []

    def __init__(self, _adapter):
        pass

    def inspect_sql_connection(self, ref):
        self.refs.append(ref)
        if self.error is not None:
            raise self.error
        return self.result


class FakeAdapter:
    instances = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.instances.append(self)


def reset_fakes(monkeypatch, *, observed=None, error=None):
    FakeLibrary.result = observed or connection()
    FakeLibrary.error = error
    FakeLibrary.refs = []
    FakeAdapter.instances = []
    monkeypatch.setattr(HELPER, "CrdbLibrary", FakeLibrary)
    monkeypatch.setattr(HELPER, "KubectlAdapter", FakeAdapter)


def test_bound_probe_uses_actual_connection_and_preserves_tls_candidate_order(monkeypatch, capsys):
    reset_fakes(monkeypatch, observed=connection(certs_dir="/mounted/root-client"))
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 1 if len(calls) == 1 else 0, None, None)

    monkeypatch.setattr(HELPER, "run", run)
    assert HELPER.main(["--namespace", "bench-ns", "--statefulset", "db", "--policy", "tls-then-insecure"]) == 0

    assert FakeAdapter.instances[0].kwargs == {"kubectl": "kubectl", "get_timeout": 1.0}
    assert len(calls) == 2
    commands = [call[0] for call in calls]
    assert commands[0] == [
        "kubectl", "--namespace", "bench-ns", "exec", "db-0", "--container", "server", "--",
        "/opt/cockroach/cockroach", "sql", f"--certs-dir={DEFAULT_CERTS}",
        "--host=db-0.custom.svc.cluster.local", "--port=26300", "-e", "SELECT 1;",
    ]
    assert commands[1][10] == "--certs-dir=/mounted/root-client"
    for _command, kwargs in calls:
        assert kwargs["timeout"] == 4.0
        assert kwargs["stdout"] is HELPER.DEVNULL
        assert kwargs["stderr"] is HELPER.DEVNULL
    assert FakeLibrary.refs[0].namespace == "bench-ns"
    assert FakeLibrary.refs[0].name == "db"
    assert capsys.readouterr() == ("", "")


def test_bound_probe_adds_insecure_only_for_the_existing_cluster_policy(monkeypatch):
    reset_fakes(monkeypatch)
    calls = []

    def run(command, **_kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 1, None, None)

    monkeypatch.setattr(HELPER, "run", run)
    assert HELPER.check("bench-ns", "db", "tls-then-insecure") == 1
    assert [command[10] for command in calls] == [f"--certs-dir={DEFAULT_CERTS}", "--insecure"]

    calls.clear()
    assert HELPER.check("bench-ns", "db", "tls-only") == 1
    assert [command[10] for command in calls] == [f"--certs-dir={DEFAULT_CERTS}"]


def test_real_inspector_connection_is_wired_to_the_selected_sql_command(monkeypatch):
    adapter = LIBRARY_TEST.MemoryAdapter(tls=True, replicas=1, custom_ports=True)
    monkeypatch.setattr(HELPER, "KubectlAdapter", lambda **_kwargs: adapter)
    monkeypatch.setattr(HELPER, "CrdbLibrary", CrdbLibrary)
    commands = []

    def run(command, **_kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, None, None)

    monkeypatch.setattr(HELPER, "run", run)
    assert HELPER.check(adapter.namespace, adapter.name, "tls-only") == 0

    assert len(commands) == 1
    assert commands[0] == [
        "kubectl", "--namespace", adapter.namespace, "exec", "db-0", "--container", "db", "--",
        "/cockroach/cockroach", "sql", f"--certs-dir={DEFAULT_CERTS}",
        "--host=db-0.db.crdb-fixture.svc.cluster.local", "--port=26270", "-e", "SELECT 1;",
    ]


@pytest.mark.parametrize(
    "error",
    [KubernetesAccessError("denied"), UnsupportedLayoutError("metadata unavailable")],
)
def test_metadata_errors_select_legacy_shell_fallback_without_emitting_error(monkeypatch, capsys, error):
    reset_fakes(monkeypatch, error=error)
    calls = []
    monkeypatch.setattr(HELPER, "run", lambda command, **kwargs: calls.append(command))

    assert HELPER.check("bench-ns", "db", "tls-then-insecure") == HELPER.METADATA_UNAVAILABLE
    assert calls == []
    assert capsys.readouterr() == ("", "")


def test_timeout_and_local_exec_error_remain_failed_candidates(monkeypatch):
    reset_fakes(monkeypatch)
    monkeypatch.setattr(HELPER, "run", lambda *_args, **_kwargs: (_ for _ in ()).throw(HELPER.TimeoutExpired("kubectl", 4)))
    assert HELPER.check("bench-ns", "db", "tls-then-insecure") == 1

    monkeypatch.setattr(HELPER, "run", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("private detail")))
    assert HELPER.check("bench-ns", "db", "tls-only") == 1


def executable(path: Path, source: str) -> Path:
    path.write_text(source, encoding="utf-8")
    path.chmod(0o755)
    return path


def run_cluster_verify(tmp_path, bridge_status: int):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    bridge_log = tmp_path / "bridge.log"
    kubectl_log = tmp_path / "kubectl.log"
    executable(
        bindir / "python3",
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$BRIDGE_LOG\"\nexit \"$BRIDGE_STATUS\"\n",
    )
    executable(
        bindir / "kubectl",
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$KUBECTL_LOG\"\nexit 1\n",
    )
    env = os.environ.copy()
    env.update(
        {
            "PATH": f"{bindir}:{env['PATH']}",
            "BENCH_NAMESPACE": "bench-ns",
            "BENCH_PARAM_CLUSTER_NAME": "db",
            "BRIDGE_STATUS": str(bridge_status),
            "BRIDGE_LOG": str(bridge_log),
            "KUBECTL_LOG": str(kubectl_log),
        }
    )
    result = subprocess.run(
        ["sh", str(CLUSTER_SCRIPT), "verify"],
        cwd=ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return result, bridge_log.read_text(encoding="utf-8").splitlines(), (
        kubectl_log.read_text(encoding="utf-8").splitlines() if kubectl_log.exists() else []
    )


@pytest.mark.parametrize(
    ("bridge_status", "expected_status", "expected_legacy_calls"),
    [(0, 0, 0), (1, 1, 0), (2, 1, 2), (126, 1, 2), (127, 1, 2)],
)
def test_cluster_shell_uses_legacy_probe_only_for_metadata_fallback(
    tmp_path, bridge_status, expected_status, expected_legacy_calls
):
    result, bridge_calls, kubectl_calls = run_cluster_verify(tmp_path, bridge_status)

    assert result.returncode == expected_status
    assert len(bridge_calls) == 1
    assert "--policy tls-then-insecure" in bridge_calls[0]
    assert len(kubectl_calls) == expected_legacy_calls
    if bridge_status == 2:
        assert kubectl_calls == [
            "-n bench-ns exec db-0 -- ./cockroach sql --certs-dir=/cockroach/cockroach-certs "
            "--host=db-0.db.bench-ns.svc.cluster.local -e SELECT 1;",
            "-n bench-ns exec db-0 -- ./cockroach sql --insecure "
            "--host=db-0.db.bench-ns.svc.cluster.local -e SELECT 1;",
        ]


def test_tls_shell_falls_back_to_its_exact_tls_only_command(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    bridge_log = tmp_path / "bridge.log"
    kubectl_log = tmp_path / "kubectl.log"
    executable(
        bindir / "python3",
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$BRIDGE_LOG\"\nexit 2\n",
    )
    executable(
        bindir / "kubectl",
        textwrap.dedent(
            """\
            #!/bin/sh
            printf '%s\\n' "$*" >> "$KUBECTL_LOG"
            case "$*" in
              *"get statefulset db"*)
                printf '%s\\n' '--certs-dir=/cockroach/cockroach-certs' 'secretName: db-certs'
                ;;
              *"get secret db-certs -o jsonpath="*) printf '%s' 'eA==' ;;
              *"exec openssl-toolbox"*) printf '%s\\n' 'sha256 Fingerprint=ABCD' ;;
              *"exec db-0"*) exit 0 ;;
              *) exit 0 ;;
            esac
            """
        ),
    )
    executable(
        bindir / "openssl",
        textwrap.dedent(
            """\
            #!/bin/sh
            case "$*" in
              *"-ext subjectAltName"*)
                printf '%s\\n' 'DNS:localhost, DNS:db-0.db.bench-ns.svc.cluster.local, DNS:db-1.db.bench-ns.svc.cluster.local, DNS:db-2.db.bench-ns.svc.cluster.local'
                ;;
              *"-modulus"*) printf '%s\\n' 'Modulus=ABCD' ;;
              *"-fingerprint -sha256"*) printf '%s\\n' 'sha256 Fingerprint=ABCD' ;;
              *) exit 0 ;;
            esac
            """
        ),
    )
    executable(bindir / "sleep", "#!/bin/sh\nexit 0\n")

    env = os.environ.copy()
    env.update(
        {
            "PATH": f"{bindir}:{env['PATH']}",
            "BENCH_NAMESPACE": "bench-ns",
            "BENCH_PARAM_CLUSTER_NAME": "db",
            "BRIDGE_LOG": str(bridge_log),
            "KUBECTL_LOG": str(kubectl_log),
        }
    )
    result = subprocess.run(
        ["sh", str(TLS_SCRIPT), "verify"],
        cwd=ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode == 0
    assert result.stdout == ""
    assert result.stderr == ""
    assert "--policy tls-only" in bridge_log.read_text(encoding="utf-8")
    calls = kubectl_log.read_text(encoding="utf-8").splitlines()
    assert any(
        call == "-n bench-ns exec db-0 -- ./cockroach sql --certs-dir=/cockroach/cockroach-certs "
        "--host=db-0.db.bench-ns.svc.cluster.local -e SELECT 1;"
        for call in calls
    )
    assert not any("--insecure" in call for call in calls)

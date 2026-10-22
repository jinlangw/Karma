"""Settings-oracle connection tests exercise the shared observer boundary."""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

import pytest

from cases.common.cockroachdb import CrdbLibrary, KubectlAdapter, SQLConnectionObservation, TLSMode, WorkloadRef
from cases.common.cockroachdb.types import (
    AuthenticationError,
    KubernetesAccessError,
    RolloutInProgressError,
    TransientError,
)


ROOT = Path(__file__).resolve().parents[2]
ORACLE = ROOT / "cases/tests/cockroachdb/cluster-settings/oracle/oracle.py"


@pytest.fixture
def oracle_module(monkeypatch):
    monkeypatch.setenv("BENCH_NAMESPACE", "settings-test")
    monkeypatch.setenv("BENCH_PARAM_CLUSTER_NAME", "settings-db")
    spec = importlib.util.spec_from_file_location("settings_oracle_under_test", ORACLE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    yield module
    sys.modules.pop(spec.name, None)


def _connection(
    *,
    tls: bool = True,
    host: str = "db-0.db.settings-test.svc.cluster.local",
    port: int = 26300,
    container: str = "cockroach",
    certs_dir: str | None = "/custom/root-certs",
    uid: str = "pod-a",
):
    return SQLConnectionObservation(
        namespace="settings-test",
        workload_name="settings-db",
        workload_uid="sts-a",
        pod_name="settings-db-0",
        pod_uid=uid,
        container_name=container,
        image="cockroachdb/cockroach:v24.1.0",
        sql_binary="/cockroach/cockroach",
        sql_host=host,
        sql_port=port,
        rpc_port=26258,
        tls_mode=TLSMode.TLS if tls else TLSMode.INSECURE,
        certs_dir=certs_dir if tls else None,
    )


def _live_resources(container_name: str = "cockroach"):
    namespace, name, uid = "settings-test", "settings-db", "sts-uid"
    labels = {"app": "settings-db"}
    container = {
        "name": container_name,
        "image": "cockroachdb/cockroach:v24.1.0",
        "command": [
            "/bin/bash", "-ec",
            "exec /cockroach/cockroach start --certs-dir=/cockroach/cert-root --sql-addr=:26300 "
            "--listen-addr=:26258 --advertise-host=$(POD_NAME).settings-db.$(POD_NAMESPACE).svc.cluster.local",
        ],
        "volumeMounts": [{"name": "certs", "mountPath": "/cockroach/cert-root", "readOnly": True}],
        "env": [
            {"name": "POD_NAME", "valueFrom": {"fieldRef": {"fieldPath": "metadata.name"}}},
            {"name": "POD_NAMESPACE", "valueFrom": {"fieldRef": {"fieldPath": "metadata.namespace"}}},
        ],
    }
    statefulset = {
        "kind": "StatefulSet",
        "metadata": {"name": name, "namespace": namespace, "uid": uid, "resourceVersion": "17"},
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": labels},
            "template": {"spec": {"containers": [copy.deepcopy(container)], "volumes": [
                {"name": "certs", "secret": {"secretName": "client-certs"}},
            ]}},
        },
    }
    pod = {
        "kind": "Pod",
        "metadata": {
            "name": f"{name}-0", "namespace": namespace, "uid": "pod-uid",
            "labels": labels,
            "ownerReferences": [{"kind": "StatefulSet", "name": name, "uid": uid, "controller": True}],
        },
        "spec": {"containers": [container]},
    }
    return namespace, name, statefulset, pod


@pytest.mark.parametrize("timeout,expected", [(None, 15), (2, 2)])
def test_kubectl_get_resource_keeps_default_and_accepts_bounded_timeout(timeout, expected):
    adapter = KubectlAdapter() if timeout is None else KubectlAdapter(get_timeout=timeout)
    result = subprocess.CompletedProcess(["kubectl"], 0, '{"kind":"Pod"}', "")
    with patch("cases.common.cockroachdb.adapter.subprocess.run", return_value=result) as run:
        adapter.get_resource("pod", "settings-test", "settings-db-0")
    assert run.call_args.kwargs["timeout"] == expected


@pytest.mark.parametrize("timeout", [0, -1, float("inf"), float("nan"), True])
def test_kubectl_get_timeout_rejects_unbounded_values(timeout):
    with pytest.raises(ValueError, match="positive and finite"):
        KubectlAdapter(get_timeout=timeout)


def test_real_sql_connection_observer_honors_get_budget_and_renamed_container():
    namespace, name, statefulset, pod = _live_resources()

    def fake_run(command, *, check, capture_output, text, timeout):
        assert check is False and capture_output and text
        assert timeout == 2
        if command[command.index("get") + 1] == "statefulsets":
            value = statefulset
        else:
            value = pod
        return subprocess.CompletedProcess(command, 0, json.dumps(value), "")

    adapter = KubectlAdapter(get_timeout=2)
    with patch("cases.common.cockroachdb.adapter.subprocess.run", side_effect=fake_run) as run:
        observed = CrdbLibrary(adapter).inspect_sql_connection(WorkloadRef(namespace, name), ordinal=0)

    assert observed.container_name == "cockroach"
    assert observed.sql_binary == "/cockroach/cockroach"
    assert observed.sql_host == "settings-db-0.settings-db.settings-test.svc.cluster.local"
    assert observed.sql_port == 26300
    assert observed.certs_dir == "/cockroach/cert-root"
    assert run.call_count == 4


@pytest.mark.parametrize(
    ("connection", "expected_flags"),
    [
        (_connection(), ["--certs-dir=/custom/root-certs", "--host=db-0.db.settings-test.svc.cluster.local", "--port=26300"]),
        (_connection(tls=False, certs_dir=None), ["--insecure", "--host=db-0.db.settings-test.svc.cluster.local", "--port=26300"]),
    ],
)
def test_setting_read_uses_observed_container_host_port_and_tls(oracle_module, monkeypatch, connection, expected_flags):
    oracle_module._SQL_CONNECTION = connection
    oracle_module._SQL_CONNECTION_VERIFIED = True
    commands = []

    def fake_run(command, timeout=30):
        commands.append((list(command), timeout))
        return subprocess.CompletedProcess(command, 0, "setting\n128MiB\n", "")

    monkeypatch.setattr(oracle_module, "run", fake_run)
    actual, error = oracle_module.get_setting()

    assert (actual, error) == ("128MiB", None)
    command, timeout = commands[-1]
    assert command[command.index("exec") + 1] == connection.pod_name
    assert command[command.index("--container") + 1] == connection.container_name
    assert all(flag in command for flag in expected_flags)
    assert "SHOW CLUSTER SETTING" in command[-1]
    assert timeout == 25


@pytest.mark.parametrize(
    "observer_error",
    [
        TransientError("selected Pod is rolling"),
        RolloutInProgressError("selected Pod is rolling"),
        AuthenticationError("selected SQL credentials were rejected"),
        KubernetesAccessError("Kubernetes access denied"),
    ],
)
def test_observer_errors_are_read_failures_without_insecure_fallback(oracle_module, monkeypatch, observer_error):
    class Library:
        def __init__(self, _adapter):
            pass

        def inspect_sql_connection(self, _ref, *, ordinal):
            assert ordinal == 0
            raise observer_error

    commands = []
    monkeypatch.setattr(oracle_module, "CrdbLibrary", Library)
    monkeypatch.setattr(oracle_module, "run", lambda command, timeout=30: commands.append(command))

    actual, error = oracle_module.get_setting()

    assert actual is None
    assert str(observer_error) in error
    assert commands == []


def test_each_oracle_check_rebinds_connection_after_restart(oracle_module, monkeypatch):
    connections = iter(
        (
            _connection(host="old.db.settings-test.svc.cluster.local", uid="old-pod"),
            _connection(host="new.db.settings-test.svc.cluster.local", uid="new-pod"),
        )
    )
    observed = []

    class Library:
        def __init__(self, _adapter):
            pass

        def inspect_sql_connection(self, ref, *, ordinal):
            assert ref == WorkloadRef("settings-test", "settings-db")
            assert ordinal == 0
            connection = next(connections)
            observed.append(connection)
            return connection

    commands = []

    def fake_run(command, timeout=30):
        commands.append(list(command))
        sql = command[command.index("-e") + 1]
        output = "1\n" if sql == "SELECT 1;" else "setting\n128MiB\n"
        return subprocess.CompletedProcess(command, 0, output, "")

    monkeypatch.setattr(oracle_module, "CrdbLibrary", Library)
    monkeypatch.setattr(oracle_module, "run", fake_run)
    errors = []
    oracle_module.check(errors, "before restart")
    oracle_module.check(errors, "after restart")

    assert errors == []
    assert [connection.pod_uid for connection in observed] == ["old-pod", "new-pod"]
    setting_commands = [command for command in commands if "SHOW CLUSTER SETTING" in command[-1]]
    assert any("old.db.settings-test.svc.cluster.local" in " ".join(command) for command in setting_commands)
    assert any("new.db.settings-test.svc.cluster.local" in " ".join(command) for command in setting_commands)


def test_transient_observation_error_retries_with_a_fresh_binding(oracle_module, monkeypatch):
    calls = []

    class Library:
        def __init__(self, _adapter):
            pass

        def inspect_sql_connection(self, _ref, *, ordinal):
            assert ordinal == 0
            calls.append(ordinal)
            if len(calls) == 1:
                raise TransientError("selected Pod is rolling")
            return _connection(host="replacement.db.settings-test.svc.cluster.local")

    commands = []

    def fake_run(command, timeout=30):
        commands.append(list(command))
        sql = command[command.index("-e") + 1]
        return subprocess.CompletedProcess(command, 0, "1\n" if sql == "SELECT 1;" else "128MiB\n", "")

    oracle_module._RESOLVED_NAME = oracle_module.SETTING_NAME
    monkeypatch.setattr(oracle_module, "CrdbLibrary", Library)
    monkeypatch.setattr(oracle_module, "run", fake_run)
    monkeypatch.setattr(oracle_module.time, "sleep", lambda _seconds: None)
    errors = []

    oracle_module.check(errors, "before restart")

    assert errors == []
    assert calls == [0, 0]
    assert any("replacement.db.settings-test.svc.cluster.local" in " ".join(command) for command in commands)


def test_oracle_uses_observed_renamed_container_for_sql_exec(oracle_module, monkeypatch):
    oracle_module._SQL_CONNECTION = _connection(container="cockroach")
    oracle_module._SQL_CONNECTION_VERIFIED = True
    commands = []
    monkeypatch.setattr(
        oracle_module,
        "run",
        lambda command, timeout=30: commands.append(list(command))
        or subprocess.CompletedProcess(command, 0, "setting\n128MiB\n", ""),
    )

    actual, error = oracle_module.get_setting()

    assert (actual, error) == ("128MiB", None)
    command = commands[-1]
    assert command[command.index("--container") + 1] == "cockroach"
    assert command[command.index("exec") + 1] == "settings-db-0"


def test_sql_readiness_auth_failure_stops_before_show_without_insecure_fallback(oracle_module, monkeypatch):
    oracle_module._SQL_CONNECTION = _connection(tls=True)
    oracle_module._SQL_CONNECTION_VERIFIED = False
    oracle_module._RESOLVED_NAME = oracle_module.SETTING_NAME
    commands = []

    def fake_run(command, timeout=30):
        commands.append(list(command))
        return subprocess.CompletedProcess(command, 1, "", "authentication failed")

    monkeypatch.setattr(oracle_module, "run", fake_run)
    actual, error = oracle_module.get_setting()

    assert actual is None
    assert "authentication failed" in error
    assert len(commands) == 1
    assert commands[0][-1] == "SELECT 1;"
    assert "--insecure" not in commands[0]
    assert not any("SHOW CLUSTER SETTING" in command[-1] for command in commands)


def test_actual_wrong_setting_value_still_fails_oracle_check(oracle_module, monkeypatch):
    oracle_module._RESOLVED_NAME = oracle_module.SETTING_NAME

    class Library:
        def __init__(self, _adapter):
            pass

        def inspect_sql_connection(self, _ref, *, ordinal):
            assert ordinal == 0
            return _connection()

    def fake_run(command, timeout=30):
        output = "1\n" if command[-1] == "SELECT 1;" else "setting\n64MiB\n"
        return subprocess.CompletedProcess(command, 0, output, "")

    monkeypatch.setattr(oracle_module, "CrdbLibrary", Library)
    monkeypatch.setattr(
        oracle_module,
        "run",
        fake_run,
    )
    errors = []

    oracle_module.check(errors, "before restart")

    assert len(errors) == 1
    assert "64MiB" in errors[0]
    assert "128MiB" in errors[0]

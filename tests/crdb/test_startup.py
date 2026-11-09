from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from cases.common.cockroachdb import startup as startup_module
from cases.common.cockroachdb.startup import (
    arguments,
    certificate_directory,
    client_connection_flags,
    database_container,
    flag_value,
)


ROOT = Path(__file__).resolve().parents[2]
CASE_CLUSTER = ROOT / "cases/tests/cockroachdb/readonly-audit/scripts/cluster.py"
SPEC = importlib.util.spec_from_file_location("readonly_audit_cluster_startup_test", CASE_CLUSTER)
assert SPEC is not None and SPEC.loader is not None
CASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CASE)


def test_database_container_selects_exact_cockroach_start_container():
    selected = {"name": "db", "image": "cockroachdb/cockroach:v24.1.0", "command": ["start"]}
    template = {
        "spec": {
            "containers": [
                {"name": "metrics", "image": "prometheus/exporter:v1"},
                selected,
            ]
        }
    }

    assert database_container(template, error_type=CASE.UnsafeState) is selected


def test_direct_and_shell_wrapped_arguments_preserve_kubernetes_expansions():
    direct = {
        "command": ["/cockroach/cockroach", "start"],
        "args": ["--insecure", "--join=db-0.$(POD_NAMESPACE).svc:26258"],
    }
    wrapped = {
        "command": ["/bin/bash", "-ec", "exec /cockroach/cockroach start --insecure"],
        "args": ["--join=db-0.$(POD_NAMESPACE).svc:26258"],
    }
    direct_expected = [
        "/cockroach/cockroach",
        "start",
        "--insecure",
        "--join=db-0.$(POD_NAMESPACE).svc:26258",
    ]
    wrapped_expected = [
        "exec",
        "/cockroach/cockroach",
        "start",
        "--insecure",
        "--join=db-0.$(POD_NAMESPACE).svc:26258",
    ]

    assert CASE.arguments(direct) == direct_expected
    assert CASE.arguments(wrapped) == wrapped_expected


@pytest.mark.parametrize(
    "script",
    [
        "exec /cockroach/cockroach start; touch /tmp/unwanted",
        "exec /cockroach/cockroach start && touch /tmp/unwanted",
        "exec /cockroach/cockroach start | cat",
        "exec /cockroach/cockroach start > /tmp/unwanted",
    ],
)
def test_shell_control_flow_is_rejected_with_case_error(script):
    with pytest.raises(CASE.UnsafeState, match="^compound server startup is unsupported$"):
        CASE.arguments({"command": ["/bin/bash", "-ec", script]})


def test_shell_parser_requires_cockroach_start_even_without_control_flow():
    with pytest.raises(CASE.UnsafeState, match="^multi-node cockroach start command is required$"):
        CASE.arguments({"command": ["/bin/bash", "-ec", "echo ready"]})


def test_flag_value_supports_equals_split_and_default_forms():
    equals = {"command": ["cockroach", "start", "--http-addr=localhost:8080"]}
    split = {"command": ["cockroach", "start", "--http-addr", "localhost:8080"]}
    absent = {"command": ["cockroach", "start"]}

    assert CASE.flag_value(equals, "--http-addr") == "localhost:8080"
    assert CASE.flag_value(split, "--http-addr") == "localhost:8080"
    assert CASE.flag_value(absent, "--http-addr") is None
    assert CASE.flag_value(absent, "--http-addr", "0.0.0.0:8080") == "0.0.0.0:8080"


def test_ambiguous_flag_preserves_case_error_class_and_message():
    container = {
        "command": ["cockroach", "start", "--listen-addr=0.0.0.0:26258"],
        "args": ["--listen-addr", "localhost:26258"],
    }

    with pytest.raises(CASE.UnsafeState, match="^ambiguous startup flag: --listen-addr$"):
        CASE.flag_value(container, "--listen-addr")


def test_central_helpers_use_injected_error_type():
    class StartupError(ValueError):
        pass

    with pytest.raises(StartupError, match="^ambiguous startup flag: --port$"):
        flag_value(
            {"command": ["cockroach", "start", "--port=26257", "--port=26258"]},
            "--port",
            error_type=StartupError,
        )

    with pytest.raises(StartupError, match="^multi-node cockroach start command is required$"):
        arguments({"command": ["/bin/sh", "-c", "echo no server"]}, error_type=StartupError)


def test_certificate_directory_resolves_explicit_and_relative_paths_lazily():
    def unused_context():
        pytest.fail("the explicit-path branch must not read the pod security context")

    assert certificate_directory(
        {"workingDir": "/work/db"}, "/mnt/certs/../tls", pod_security_context=unused_context, error_type=CASE.UnsafeState
    ) == "/mnt/tls"
    assert certificate_directory(
        {"workingDir": "/work/db"}, "certs", pod_security_context=unused_context, error_type=CASE.UnsafeState
    ) == "/work/db/certs"
    assert certificate_directory(
        {}, "certs", pod_security_context=unused_context, error_type=CASE.UnsafeState
    ) == "/cockroach/certs"


def test_certificate_directory_uses_literal_home_without_security_context_read():
    def unused_context():
        pytest.fail("a literal HOME must avoid the pod security context lookup")

    assert certificate_directory(
        {"env": [{"name": "HOME", "value": "/var/lib/cockroach"}]},
        None,
        pod_security_context=unused_context,
        error_type=CASE.UnsafeState,
    ) == "/var/lib/cockroach/.cockroach-certs"


def test_certificate_directory_uses_guarded_official_root_default_lazily():
    calls = []

    def pod_security_context():
        calls.append("read")
        return {"runAsUser": 0}

    assert certificate_directory(
        {}, None, pod_security_context=pod_security_context, error_type=CASE.UnsafeState
    ) == "/root/.cockroach-certs"
    assert calls == ["read"]


def test_client_connection_flags_preserve_insecure_flags_and_skip_certificate_resolution():
    calls = []
    container = {
        "command": ["cockroach", "start", "--insecure", "--cluster-name=dev"],
    }

    flags = client_connection_flags(
        container,
        certificate_directory=lambda: calls.append("certificates") or "/never/read",
        error_type=CASE.UnsafeState,
    )

    assert flags == ["--insecure", "--cluster-name=dev"]
    assert calls == []


def test_client_connection_flags_resolve_tls_lazily_before_optional_cluster_name(monkeypatch):
    events = []
    original_flag_value = startup_module.flag_value

    def flag_value_after_certificate(container, name, default=None, *, error_type):
        events.append("cluster-name")
        return original_flag_value(container, name, default, error_type=error_type)

    monkeypatch.setattr(startup_module, "flag_value", flag_value_after_certificate)
    container = {"command": ["cockroach", "start", "--cluster-name=dev"]}

    flags = client_connection_flags(
        container,
        certificate_directory=lambda: events.append("certificate-directory") or "/root/.cockroach-certs",
        error_type=CASE.UnsafeState,
    )

    assert flags == ["--certs-dir=/root/.cockroach-certs", "--cluster-name=dev"]
    assert events == ["certificate-directory", "cluster-name"]


def test_client_connection_flags_preserve_parse_and_late_flag_errors():
    calls = []
    with pytest.raises(CASE.UnsafeState, match="^multi-node cockroach start command is required$"):
        client_connection_flags(
            {"command": ["echo", "not a server"]},
            certificate_directory=lambda: calls.append("certificates") or "/certs",
            error_type=CASE.UnsafeState,
        )
    assert calls == []

    with pytest.raises(CASE.UnsafeState, match="^ambiguous startup flag: --cluster-name$"):
        client_connection_flags(
            {"command": ["cockroach", "start", "--cluster-name=one", "--cluster-name=two"]},
            certificate_directory=lambda: calls.append("certificates") or "/certs",
            error_type=CASE.UnsafeState,
        )
    assert calls == ["certificates"]


@pytest.mark.parametrize(
    "container,pod_context",
    [
        ({"securityContext": {"runAsUser": 1000}}, {}),
        ({"envFrom": [{"configMapRef": {"name": "startup-env"}}]}, {"runAsUser": 0}),
    ],
)
def test_certificate_directory_rejects_unresolved_implicit_home(container, pod_context):
    with pytest.raises(
        CASE.UnsafeState,
        match="^implicit TLS certificate path needs literal HOME or explicit certs-dir for this startup$",
    ):
        certificate_directory(
            container, None, pod_security_context=lambda: pod_context, error_type=CASE.UnsafeState
        )


@pytest.mark.parametrize(
    "home_env",
    [
        {"name": "HOME", "value": "relative/home"},
        {"name": "HOME", "valueFrom": {"fieldRef": {"fieldPath": "metadata.name"}}},
    ],
)
def test_certificate_directory_rejects_nonliteral_home(home_env):
    with pytest.raises(
        CASE.UnsafeState,
        match="^implicit TLS certificate path requires a literal absolute HOME$",
    ):
        certificate_directory(
            {"env": [home_env]}, None, pod_security_context=lambda: {}, error_type=CASE.UnsafeState
        )


def test_database_container_requires_one_candidate():
    with pytest.raises(CASE.UnsafeState, match="^expected exactly one multi-node CockroachDB server container$"):
        CASE.database_container({"spec": {"containers": []}})

    two = {
        "spec": {
            "containers": [
                {"image": "cockroachdb/cockroach:v24.1.0", "command": ["start"]},
                {"image": "cockroachdb/cockroach:v25.1.0", "command": ["start"]},
            ]
        }
    }
    with pytest.raises(CASE.UnsafeState, match="^expected exactly one multi-node CockroachDB server container$"):
        CASE.database_container(two)

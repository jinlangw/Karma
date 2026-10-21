from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[2]
CASE_DIR = ROOT / "cases/cockroachdb/initialize/scripts"


def load_case_modules():
    cluster_spec = importlib.util.spec_from_file_location(
        "initialize_certificate_paths_cluster", CASE_DIR / "cluster.py"
    )
    assert cluster_spec is not None and cluster_spec.loader is not None
    cluster_module = importlib.util.module_from_spec(cluster_spec)
    cluster_spec.loader.exec_module(cluster_module)

    old_cluster = sys.modules.get("cluster")
    sys.modules["cluster"] = cluster_module
    try:
        prepare_spec = importlib.util.spec_from_file_location(
            "initialize_certificate_paths_prepare", CASE_DIR / "prepare.py"
        )
        assert prepare_spec is not None and prepare_spec.loader is not None
        prepare_module = importlib.util.module_from_spec(prepare_spec)
        prepare_spec.loader.exec_module(prepare_module)
    finally:
        if old_cluster is None:
            sys.modules.pop("cluster", None)
        else:
            sys.modules["cluster"] = old_cluster
    return cluster_module, prepare_module


def fixture_statefulset(
    certificate_path: str | None,
    *,
    home: str | None = None,
    scheme: str = "HTTPS",
    container_name: str = "db",
):
    command = [
        "/cockroach/cockroach",
        "start",
        "--listen-addr=:26257",
        "--http-addr=:8080",
        "--join=crdb-0.db.ns.svc.cluster.local:26257",
    ]
    if certificate_path is not None:
        command.append("--certs-dir=" + certificate_path)
    env = [{"name": "HOME", "value": home}] if home is not None else []
    db = {
        "name": container_name,
        "image": "cockroachdb/cockroach:v24.1.0",
        "command": command,
        "env": env,
        "ports": [{"name": "http", "containerPort": 8080}],
        "readinessProbe": {
            "httpGet": {"path": "/health?ready=1", "port": "http", "scheme": scheme}
        },
    }
    if certificate_path is not None and not certificate_path.startswith("/"):
        db["workingDir"] = "/cockroach/work"
    resolved_path = certificate_path
    if certificate_path is None:
        resolved_path = (home or "/root") + "/.cockroach-certs"
    elif not certificate_path.startswith("/"):
        resolved_path = "/cockroach/work/" + certificate_path
    db["volumeMounts"] = [{"name": "certificates", "mountPath": resolved_path}]
    template = {
        "metadata": {"labels": {"app": "crdb"}},
        "spec": {
            "securityContext": {"runAsUser": 0},
            "containers": [db],
            "volumes": [{"name": "certificates", "secret": {"secretName": "crdb-certs"}}],
        },
    }
    sts = {
        "metadata": {"uid": "sts-uid"},
        "spec": {
            "replicas": 1,
            "serviceName": "db",
            "template": template,
            "volumeClaimTemplates": [],
        },
    }
    pod = {
        "metadata": {"name": "crdb-0"},
        "spec": {"containers": [dict(db)], "volumes": []},
    }
    return sts, db, pod, resolved_path


def make_preparation(cluster_module, prepare_module, monkeypatch, sts, pod):
    cluster = object.__new__(cluster_module.Cluster)
    cluster.name = "crdb"
    cluster.namespace = "ns"
    cluster.labels = {"app.kubernetes.io/instance": "crdb"}
    cluster.statefulset = lambda: pytest.fail("provided StatefulSet must be reused")
    cluster.connection_flags = lambda container=None, sts=None: cluster_module.Cluster.connection_flags(
        cluster, container, sts
    )
    cluster.certificate_directory = lambda container, sts=None: cluster_module.Cluster.certificate_directory(
        cluster, container, sts
    )
    cluster.host = lambda ordinal, sts=None: f"crdb-{ordinal}.db.ns.svc.cluster.local"
    cluster.stores = lambda _sts, count=None: []
    cluster.pods = lambda _sts: [pod]
    cluster.get = lambda *_args, **_kwargs: None
    cluster.require = lambda result: cluster_module.Cluster.require(result)
    commands = []

    def kubectl(*args, timeout=20, **_kwargs):
        commands.append((args, timeout))
        return subprocess.CompletedProcess(args, 0, "", "")

    cluster.kubectl = kubectl
    preparation = prepare_module.Preparation(cluster)
    preparation.load = lambda: None
    preparation.exclusive = lambda *_args, **_kwargs: None
    monkeypatch.setattr(prepare_module, "signatures", lambda *_args: {})
    return preparation, commands


@pytest.mark.parametrize(
    "certificate_path,home,expected",
    [
        (None, None, "/root/.cockroach-certs"),
        (None, "/var/lib/db", "/var/lib/db/.cockroach-certs"),
        ("certs", None, "/cockroach/work/certs"),
        ("/mnt/explicit-certs", None, "/mnt/explicit-certs"),
    ],
)
def test_preflight_uses_shared_effective_directory_for_mount_file_cert_and_health_checks(
    monkeypatch, certificate_path, home, expected
):
    cluster_module, prepare_module = load_case_modules()
    sts, db, pod, resolved_path = fixture_statefulset(certificate_path, home=home)
    assert resolved_path == expected
    preparation, commands = make_preparation(cluster_module, prepare_module, monkeypatch, sts, pod)

    assert preparation.preflight(sts) == []

    # The database CLI preserves explicit path spelling; preparation checks
    # use the effective absolute path resolved by the common helper.
    flags = cluster_module.Cluster.connection_flags(
        preparation.cluster, db, sts=sts
    )
    if certificate_path is None:
        assert flags == ["--certs-dir=" + expected]
    else:
        assert flags == ["--certs-dir=" + certificate_path]

    command_vectors = [args for args, _timeout in commands]
    cert_list = next(args for args in command_vectors if "cert" in args and "list" in args)
    assert "--certs-dir=" + expected in cert_list
    file_check = next(args for args in command_vectors if "test -s" in args[-1])
    for filename in ("ca.crt", "node.crt", "node.key", "client.root.crt", "client.root.key"):
        assert expected + "/" + filename in file_check[-1]
    health_check = next(args for args in command_vectors if "curl" in args)
    assert expected + "/ca.crt" in health_check
    assert expected + "/client.root.crt" in health_check
    assert expected + "/client.root.key" in health_check
    assert health_check[-1] == "https://crdb-0.db.ns.svc.cluster.local:8080/health?ready=1"


def test_preflight_keeps_secret_backed_mount_guard_before_certificate_execs(monkeypatch):
    cluster_module, prepare_module = load_case_modules()
    sts, _db, pod, _directory = fixture_statefulset(None)
    sts["spec"]["template"]["spec"]["volumes"] = []
    preparation, commands = make_preparation(cluster_module, prepare_module, monkeypatch, sts, pod)

    with pytest.raises(prepare_module.UnsafeState, match="^TLS initialization reset requires Secret-backed certificate material$"):
        preparation.preflight(sts)

    command_vectors = [args for args, _timeout in commands]
    assert any("command -v readlink mkdir rm touch" in args for args in command_vectors[-1])
    assert not any("test -s" in args[-1] or "cert" in args or "curl" in args for args in command_vectors)


def test_preflight_keeps_https_health_requirement_before_curl(monkeypatch):
    cluster_module, prepare_module = load_case_modules()
    sts, _db, pod, _directory = fixture_statefulset(None, scheme="HTTP")
    preparation, commands = make_preparation(cluster_module, prepare_module, monkeypatch, sts, pod)

    with pytest.raises(prepare_module.UnsafeState, match="^TLS initialization preparation requires an HTTPS health listener$"):
        preparation.preflight(sts)

    command_vectors = [args for args, _timeout in commands]
    assert any("test -s" in args[-1] for args in command_vectors)
    assert any("cert" in args and "list" in args for args in command_vectors)
    assert not any("curl" in args for args in command_vectors)


@pytest.mark.parametrize("configured", ["/cockroach/certs", "relative/certs"])
def test_tls_connection_flags_preserve_explicit_path_text(configured):
    cluster_module, _prepare_module = load_case_modules()
    cluster = object.__new__(cluster_module.Cluster)
    cluster.statefulset = lambda: pytest.fail("explicit certs-dir must avoid API reads")
    db = {"command": ["/cockroach/cockroach", "start", "--certs-dir=" + configured]}

    assert cluster.connection_flags(db) == ["--certs-dir=" + configured]


def test_insecure_connection_flags_do_not_resolve_certificate_path_or_read_statefulset():
    cluster_module, _prepare_module = load_case_modules()
    cluster = object.__new__(cluster_module.Cluster)
    cluster.statefulset = lambda: pytest.fail("insecure mode must not inspect TLS paths")

    assert cluster.connection_flags({"command": ["cockroach", "start", "--insecure"]}) == ["--insecure"]


@pytest.mark.parametrize(
    "command_kind,security_flags,sql_addr,listen_addr,expected_port,timeout",
    [
        (
            "init",
            ["--certs-dir=/cockroach/cockroach-certs", "--cluster-name=chosen-cluster"],
            "0.0.0.0:26257",
            "0.0.0.0:26258",
            "26258",
            15,
        ),
        (
            "sql",
            ["--insecure"],
            "0.0.0.0:26259",
            "0.0.0.0:26258",
            "26259",
            10,
        ),
    ],
)
def test_client_uses_original_init_and_sql_ports_and_selected_container(
    command_kind, security_flags, sql_addr, listen_addr, expected_port, timeout
):
    cluster_module, _prepare_module = load_case_modules()
    startup = [
        "/cockroach/cockroach",
        "start",
        "--sql-addr=" + sql_addr,
        "--listen-addr=" + listen_addr,
    ] + security_flags
    if security_flags == ["--insecure"]:
        startup.append("--cluster-name=chosen-cluster")
    sts, _db, _pod, _directory = fixture_statefulset(
        None, container_name="server"
    )
    sts["spec"]["template"]["spec"]["containers"][0]["command"] = startup
    expected_flags = security_flags + (
        ["--cluster-name=chosen-cluster"] if security_flags == ["--insecure"] else []
    )
    cluster = object.__new__(cluster_module.Cluster)
    cluster.name = "crdb"
    cluster.namespace = "ns"
    statefulset_reads = []
    cluster.statefulset = lambda: statefulset_reads.append("read") or sts
    calls = []

    def kubectl(*args, timeout=20):
        calls.append((args, timeout))
        return subprocess.CompletedProcess(args, 0, "", "")

    cluster.kubectl = kubectl

    if command_kind == "init":
        cluster.client("init")
        expected_args = (
            "exec",
            "crdb-0",
            "-c",
            "server",
            "--",
            "./cockroach",
            "init",
            *expected_flags,
            "--host=crdb-0.db.ns.svc.cluster.local:26258",
        )
    else:
        cluster.client("sql", "-e", "SELECT 1")
        expected_args = (
            "exec",
            "crdb-0",
            "-c",
            "server",
            "--",
            "./cockroach",
            "sql",
            "-e",
            "SELECT 1",
            *expected_flags,
            "--host=crdb-0.db.ns.svc.cluster.local",
            "--port=" + expected_port,
            "--format=csv",
        )

    assert calls == [(expected_args, timeout)]
    assert statefulset_reads == ["read"]


def test_client_uses_resolved_root_default_when_certs_dir_is_omitted():
    cluster_module, _prepare_module = load_case_modules()
    sts, _db, _pod, _directory = fixture_statefulset(None)
    cluster = object.__new__(cluster_module.Cluster)
    cluster.name = "crdb"
    cluster.namespace = "ns"
    statefulset_reads = []
    cluster.statefulset = lambda: statefulset_reads.append("read") or sts
    calls = []
    cluster.kubectl = lambda *args, timeout=20: calls.append((args, timeout)) or subprocess.CompletedProcess(args, 0, "", "")

    cluster.client("init")

    assert "--certs-dir=/root/.cockroach-certs" in calls[0][0]
    assert calls[0][0][-1] == "--host=crdb-0.db.ns.svc.cluster.local:26257"
    assert statefulset_reads == ["read"]


def test_preservation_uses_supplied_statefulset_for_implicit_root_certificate_path(monkeypatch):
    cluster_module, prepare_module = load_case_modules()
    sts, _db, _pod, _directory = fixture_statefulset(None)
    cluster = object.__new__(cluster_module.Cluster)
    cluster.name = "crdb"
    cluster.statefulset = lambda: pytest.fail("the checked StatefulSet snapshot must be reused")
    cluster.connection_flags = lambda container=None, sts=None: cluster_module.Cluster.connection_flags(
        cluster, container, sts
    )
    cluster.stores = lambda _sts, _count=None: []
    preparation = prepare_module.Preparation(cluster)
    monkeypatch.setattr(prepare_module, "signatures", lambda *_args: {})
    baseline = {
        "data": {
            "replicas": "1",
            "connection_flags": json.dumps(["--certs-dir=/root/.cockroach-certs"]),
            "stores": "[]",
            "secret_signatures": "{}",
        }
    }

    preparation.preserved(baseline, sts)

from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess

import pytest

from karma.crdb.connections import select_sql_readiness_flag


ROOT = Path(__file__).resolve().parents[2]
CASE_CLUSTER = ROOT / "cases/cockroachdb/generate-cert/scripts/cluster.py"
SPEC = importlib.util.spec_from_file_location("generate_cert_cluster_connection_test", CASE_CLUSTER)
assert SPEC is not None and SPEC.loader is not None
CASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CASE)

EXPOSE_PATH = ROOT / "cases/cockroachdb/expose-ingress/scripts/cluster.py"
EXPOSE_SPEC = importlib.util.spec_from_file_location("expose_ingress_cluster_connection_test", EXPOSE_PATH)
assert EXPOSE_SPEC is not None and EXPOSE_SPEC.loader is not None
EXPOSE_CASE = importlib.util.module_from_spec(EXPOSE_SPEC)
EXPOSE_SPEC.loader.exec_module(EXPOSE_CASE)

DECOMMISSION_PATH = ROOT / "cases/cockroachdb/decommission/scripts/cluster.py"
DECOMMISSION_SPEC = importlib.util.spec_from_file_location("decommission_cluster_connection_test", DECOMMISSION_PATH)
assert DECOMMISSION_SPEC is not None and DECOMMISSION_SPEC.loader is not None
DECOMMISSION_CASE = importlib.util.module_from_spec(DECOMMISSION_SPEC)
DECOMMISSION_SPEC.loader.exec_module(DECOMMISSION_CASE)


def test_selector_uses_fixed_query_and_returns_first_successful_candidate():
    calls = []

    def sql(query, flag):
        calls.append((query, flag))
        return subprocess.CompletedProcess([], 0 if flag == "--insecure" else 1, "", "")

    selected = select_sql_readiness_flag(
        ("--certs-dir=/mounted", "--certs-dir=/default", "--insecure"),
        sql,
        unavailable_message="unavailable",
    )

    assert selected == "--insecure"
    assert calls == [
        ("SELECT 1;", "--certs-dir=/mounted"),
        ("SELECT 1;", "--certs-dir=/default"),
        ("SELECT 1;", "--insecure"),
    ]


def test_selector_stops_at_first_success_and_does_not_deduplicate_candidates():
    calls = []

    def sql(query, flag):
        calls.append((query, flag))
        return subprocess.CompletedProcess([], 0 if len(calls) == 3 else 1, "", "")

    selected = select_sql_readiness_flag(
        ("--insecure", "--insecure", "--certs-dir=/default"),
        sql,
        unavailable_message="unavailable",
    )

    assert selected == "--certs-dir=/default"
    assert calls == [
        ("SELECT 1;", "--insecure"),
        ("SELECT 1;", "--insecure"),
        ("SELECT 1;", "--certs-dir=/default"),
    ]


def test_selector_preserves_candidate_failures_and_callback_exceptions():
    def failed_sql(query, flag):
        return subprocess.CompletedProcess([], 1, "", "connection unavailable")

    with pytest.raises(RuntimeError, match="^original unavailable message$"):
        select_sql_readiness_flag(
            ("--certs-dir=/mounted", "--insecure"),
            failed_sql,
            unavailable_message="original unavailable message",
        )

    sentinel = OSError("original SQL callback failure")

    def raising_sql(_query, _flag):
        raise sentinel

    with pytest.raises(OSError) as raised:
        select_sql_readiness_flag(("--insecure",), raising_sql, unavailable_message="unused")
    assert raised.value is sentinel


def generate_cert_cluster(directory):
    cluster = object.__new__(CASE.Cluster)
    cluster.flag = None
    cluster.sql_container = None
    cluster.statefulset = lambda: {
        "spec": {
            "template": {
                "spec": {
                    "containers": [{
                        "name": "db",
                        "image": "cockroachdb/cockroach:v24.1.0",
                        "command": ["/cockroach/cockroach", "start", f"--certs-dir={directory}"],
                    }]
                }
            }
        }
    }
    return cluster


def test_generate_cert_wrapper_preserves_candidate_order_dedup_and_cached_flag():
    cluster = generate_cert_cluster(CASE.CERT_DIR)
    calls = []

    def sql(query, *, flag):
        calls.append((query, flag))
        return subprocess.CompletedProcess([], 0 if flag == "--certs-dir=" + CASE.CERT_DIR else 1, "", "")

    cluster.sql = sql

    assert cluster.connection_flag() == "--certs-dir=" + CASE.CERT_DIR
    assert calls == [("SELECT 1;", "--certs-dir=" + CASE.CERT_DIR)]
    assert cluster.connection_flag() == "--certs-dir=" + CASE.CERT_DIR
    assert len(calls) == 1


def test_generate_cert_wrapper_preserves_ordered_fallback_and_retries_after_all_failures():
    cluster = generate_cert_cluster("/mounted/certs")
    calls = []
    results = iter((1, 1, 1, 1, 1, 0))

    def sql(query, *, flag):
        calls.append((query, flag))
        return subprocess.CompletedProcess([], next(results), "", "")

    cluster.sql = sql
    expected = [
        "--certs-dir=/mounted/certs",
        "--certs-dir=" + CASE.CERT_DIR,
        "--insecure",
    ]

    with pytest.raises(RuntimeError, match="^selected database has no working TLS or insecure SQL connection$"):
        cluster.connection_flag()

    assert [flag for _query, flag in calls] == expected
    assert cluster.flag is None

    assert cluster.connection_flag() == "--insecure"
    assert [flag for _query, flag in calls] == expected + expected
    assert cluster.flag == "--insecure"


def test_generate_cert_wrapper_propagates_sql_callback_exception():
    cluster = generate_cert_cluster("/mounted/certs")
    sentinel = OSError("SQL transport failed")

    def sql(_query, *, flag):
        raise sentinel

    cluster.sql = sql

    with pytest.raises(OSError) as raised:
        cluster.connection_flag()
    assert raised.value is sentinel


def test_expose_ingress_wrapper_preserves_candidate_order_and_cached_flag():
    cluster = object.__new__(EXPOSE_CASE.Cluster)
    cluster.flag = None
    calls = []

    def sql(query, *, flag):
        calls.append((query, flag))
        return subprocess.CompletedProcess([], 0 if flag == "--insecure" else 1, "", "")

    cluster.sql = sql

    assert cluster.connection_flag() == "--insecure"
    assert calls == [
        ("SELECT 1;", "--certs-dir=/cockroach/cockroach-certs"),
        ("SELECT 1;", "--insecure"),
    ]
    assert cluster.connection_flag() == "--insecure"
    assert len(calls) == 2


def test_expose_ingress_wrapper_preserves_original_all_fail_message():
    cluster = object.__new__(EXPOSE_CASE.Cluster)
    cluster.flag = None
    calls = []

    def sql(query, *, flag):
        calls.append((query, flag))
        return subprocess.CompletedProcess([], 1, "", "connection unavailable")

    cluster.sql = sql

    with pytest.raises(RuntimeError, match="^selected database is not SQL-ready with TLS or insecure credentials$"):
        cluster.connection_flag()
    assert calls == [
        ("SELECT 1;", "--certs-dir=/cockroach/cockroach-certs"),
        ("SELECT 1;", "--insecure"),
    ]


def test_decommission_wrapper_preserves_order_timeout_cache_and_retry_after_all_failures():
    cluster = object.__new__(DECOMMISSION_CASE.Cluster)
    cluster.flag = None
    calls = []
    results = iter((1, 1, 1, 0))

    def sql_result(query, *, flag, timeout):
        calls.append((query, flag, timeout))
        return subprocess.CompletedProcess([], next(results), "", "")

    cluster.sql_result = sql_result
    candidates = [
        ("SELECT 1;", "--certs-dir=/cockroach/cockroach-certs", 10),
        ("SELECT 1;", "--insecure", 10),
    ]

    with pytest.raises(RuntimeError, match="^selected cluster is not SQL-ready in TLS or insecure mode$"):
        cluster.connection_flag()
    assert calls == candidates
    assert cluster.flag is None

    assert cluster.connection_flag() == "--insecure"
    assert calls == candidates + candidates
    assert cluster.flag == "--insecure"

    assert cluster.connection_flag() == "--insecure"
    assert calls == candidates + candidates

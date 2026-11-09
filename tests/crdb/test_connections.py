from __future__ import annotations

import subprocess

import pytest

from cases.common.cockroachdb.connections import select_sql_readiness_flag


def test_selector_uses_fixed_query_and_returns_first_successful_candidate():
    calls = []

    def sql(query, flag):
        calls.append((query, flag))
        return subprocess.CompletedProcess([], 0 if flag == "--insecure" else 1, "", "")

    selected = select_sql_readiness_flag(
        ("--certs-dir=/mounted", "--certs-dir=/default", "--insecure", "--certs-dir=/unused"),
        sql,
        unavailable_message="unavailable",
    )

    assert selected == "--insecure"
    assert calls == [
        ("SELECT 1;", "--certs-dir=/mounted"),
        ("SELECT 1;", "--certs-dir=/default"),
        ("SELECT 1;", "--insecure"),
    ]


def test_selector_retries_duplicate_candidates():
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

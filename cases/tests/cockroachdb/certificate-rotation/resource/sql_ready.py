#!/usr/bin/env python3
"""Probe one certificate-rotation target using its observed SQL connection."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from subprocess import CompletedProcess, DEVNULL, TimeoutExpired, run
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cases.common.cockroachdb.types import SQLConnectionObservation

try:
    from cases.common.cockroachdb import CrdbLibrary, KubectlAdapter, WorkloadRef
    from cases.common.cockroachdb.connections import select_sql_readiness_flag
    from cases.common.cockroachdb.types import CrdbError
except ImportError:  # Keep the original shell probe available without the package.
    CrdbLibrary = None  # type: ignore[assignment,misc]
    KubectlAdapter = None  # type: ignore[assignment,misc]
    WorkloadRef = None  # type: ignore[assignment,misc]
    CrdbError = Exception  # type: ignore[assignment,misc,valid-type]
    select_sql_readiness_flag = None  # type: ignore[assignment]


DEFAULT_CERTS_DIR = "/cockroach/cockroach-certs"
SQL = "SELECT 1;"
GET_TIMEOUT_SECONDS = 1.0
EXEC_TIMEOUT_SECONDS = 4.0
METADATA_UNAVAILABLE = 2


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--statefulset", required=True)
    parser.add_argument("--policy", choices=("tls-then-insecure", "tls-only"), required=True)
    return parser


def _probe_command(
    kubectl: str,
    observation: SQLConnectionObservation,
    candidate: str,
) -> list[str]:
    namespace = observation.namespace
    pod_name = observation.pod_name
    container_name = observation.container_name
    binary = observation.sql_binary
    sql_host = observation.sql_host
    sql_port = observation.sql_port

    command = [
        kubectl,
        "--namespace",
        namespace,
        "exec",
        pod_name,
        "--container",
        container_name,
        "--",
        binary,
        "sql",
    ]
    command.append(candidate)
    command.extend(
        [
            f"--host={sql_host}",
            f"--port={sql_port}",
            "-e",
            SQL,
        ]
    )
    return command


def _run_candidate(
    kubectl: str,
    observation: SQLConnectionObservation,
    candidate: str,
) -> CompletedProcess[str]:
    command = _probe_command(kubectl, observation, candidate)
    try:
        return run(
            command,
            check=False,
            stdout=DEVNULL,
            stderr=DEVNULL,
            timeout=EXEC_TIMEOUT_SECONDS,
            text=True,
        )
    except TimeoutExpired:
        return CompletedProcess(command, 124, "", "")
    except OSError:
        return CompletedProcess(command, 127, "", "")


def check(namespace: str, statefulset: str, policy: str, *, kubectl: str = "kubectl") -> int:
    """Return 0 for ready, 1 for failed candidates, or 2 for legacy fallback."""
    if policy not in {"tls-then-insecure", "tls-only"}:
        return METADATA_UNAVAILABLE
    if CrdbLibrary is None or KubectlAdapter is None or WorkloadRef is None:
        return METADATA_UNAVAILABLE
    try:
        adapter = KubectlAdapter(kubectl=kubectl, get_timeout=GET_TIMEOUT_SECONDS)
        observation = CrdbLibrary(adapter).inspect_sql_connection(WorkloadRef(namespace, statefulset))
    except CrdbError:
        return METADATA_UNAVAILABLE

    candidates = [f"--certs-dir={DEFAULT_CERTS_DIR}"]
    observed_certs = observation.certs_dir
    if observed_certs and observed_certs != DEFAULT_CERTS_DIR:
        candidates.append(f"--certs-dir={observed_certs}")
    if policy == "tls-then-insecure":
        candidates.append("--insecure")

    try:
        select_sql_readiness_flag(
            candidates,
            lambda _sql, candidate: _run_candidate(kubectl, observation, candidate),
            unavailable_message="SQL readiness candidates did not connect",
        )
    except RuntimeError:
        return 1
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    return check(args.namespace, args.statefulset, args.policy)


if __name__ == "__main__":
    sys.exit(main())

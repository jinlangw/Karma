"""Small, case-neutral CockroachDB health measurements."""

from collections.abc import Callable, Sequence
import json
from typing import Any

from .startup import database_container


def observe_initialization_state(
    pod: dict[str, Any],
    *,
    execute_curl: Callable[[str, str, Sequence[str], int], str],
    error_type: type[Exception],
) -> str:
    """Measure one Pod's configured readiness endpoint for init state.

    This reports only the configured HTTP readiness result for one Pod. It
    does not establish SQL identity, cluster membership, or whole-cluster
    health. Callers retain their own deployment and recovery decisions.
    """
    db = database_container({"spec": pod["spec"]}, error_type=error_type)
    if pod.get("status", {}).get("phase") != "Running" or not any(
        status["name"] == db["name"] and "running" in status.get("state", {})
        for status in pod["status"].get("containerStatuses", [])
    ):
        raise RuntimeError("database process is not Running")

    probe = db.get("readinessProbe", {}).get("httpGet", {})
    ports = {port.get("name"): port["containerPort"] for port in db.get("ports", [])}
    port = ports.get(probe.get("port"), probe.get("port"))
    scheme = probe.get("scheme", "HTTP").lower()
    if (
        probe.get("path") != "/health?ready=1"
        or probe.get("host")
        or not isinstance(port, int)
        or scheme not in ("http", "https")
    ):
        raise error_type(
            "case requires an HTTP /health?ready=1 readiness probe on the database listener"
        )

    argv = (
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
        f"{scheme}://localhost:{port}/health?ready=1",
    )
    output = execute_curl(pod["metadata"]["name"], db["name"], argv, 8)
    body, status = output.rsplit("\n", 1)
    payload = json.loads(body)
    if status == "503" and payload.get("error") == "node is waiting for cluster initialization":
        return "uninitialized"
    if status == "200":
        return "initialized"
    raise RuntimeError("database health failed for a reason other than waiting for initialization")

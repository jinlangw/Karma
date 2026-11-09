"""Small, case-neutral CockroachDB health measurements."""

from collections.abc import Callable, Sequence
import json
from typing import Any

from .inspection import _address_parts, _flags, _shell_start_tokens
from .startup import database_container
from .types import UnsupportedLayoutError


def observe_initialization_state(
    pod: dict[str, Any],
    *,
    execute_curl: Callable[[str, str, Sequence[str], int], str],
    error_type: type[Exception],
) -> str:
    """Measure one Pod's HTTP endpoint for init state.

    Use its HTTP readiness configuration when present, or derive the HTTP
    listener from startup flags when readiness uses another handler. This
    does not establish SQL identity, membership, or whole-cluster health.
    Callers retain their own deployment and recovery decisions.
    """
    db = database_container({"spec": pod["spec"]}, error_type=error_type)
    if pod.get("status", {}).get("phase") != "Running" or not any(
        status["name"] == db["name"] and "running" in status.get("state", {})
        for status in pod["status"].get("containerStatuses", [])
    ):
        raise RuntimeError("database process is not Running")

    readiness = db.get("readinessProbe") or {}
    probe = readiness.get("httpGet", {})
    if "httpGet" in readiness:
        ports = {port.get("name"): port["containerPort"] for port in db.get("ports", [])}
        port = ports.get(probe.get("port"), probe.get("port"))
        scheme = probe.get("scheme", "HTTP").lower()
        if (
            probe.get("host")
            or not isinstance(port, int)
            or scheme not in ("http", "https")
        ):
            raise error_type(
                "case requires an HTTP /health?ready=1 readiness probe on the database listener"
            )
    else:
        try:
            flags = _flags(_shell_start_tokens(db))
            if "http-port" in flags:
                raise UnsupportedLayoutError(
                    "Startup uses unsupported --http-port; HTTP listener port must be resolved from --http-addr"
                )
            if "http-addr" in flags:
                http_addr = flags["http-addr"]
                if http_addr is None:
                    raise UnsupportedLayoutError("--http-addr has no value")
                _host, port = _address_parts(http_addr, "http-addr")
            else:
                port = 8080
            insecure = "insecure" in flags and flags.get("insecure") not in {"false", "0"}
            unencrypted_http = (
                "unencrypted-localhost-http" in flags
                and flags.get("unencrypted-localhost-http") not in {"false", "0"}
            )
            scheme = "http" if insecure or unencrypted_http else "https"
        except UnsupportedLayoutError as error:
            raise error_type(str(error)) from error

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

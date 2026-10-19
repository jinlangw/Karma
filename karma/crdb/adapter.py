"""Kubernetes and process adapters used by the CRDB library."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from typing import Any, Mapping, Protocol, Sequence

from .types import (
    AuthenticationError,
    ConnectionError,
    KubernetesAccessError,
    MissingResourceError,
    SecretFingerprint,
    StaleIdentityError,
    TransientError,
    UninitializedError,
    WorkloadRef,
    UnsupportedLayoutError,
)


_READ_ONLY_SQL = (
    "SELECT crdb_internal.cluster_id() AS cluster_id, "
    "crdb_internal.node_id() AS node_id, version() AS version;"
)


@dataclass(frozen=True, slots=True)
class HttpHealthResponse:
    status: int
    body: str


class ClusterAdapter(Protocol):
    """The only external seam required by :class:`CrdbLibrary`.

    Implementations must return Kubernetes objects in memory only. The library
    projects them into immutable redacted observations before exposing them.
    """

    def get_resource(self, kind: str, namespace: str, name: str) -> Mapping[str, Any] | None: ...

    def list_resources(self, kind: str, namespace: str) -> Sequence[Mapping[str, Any]]: ...

    def secret_fingerprint(self, namespace: str, name: str) -> SecretFingerprint: ...

    def query_sql(
        self,
        *,
        namespace: str,
        pod_name: str,
        container_name: str,
        binary: str,
        sql_host: str,
        sql_port: int,
        tls_mode: str,
        certs_dir: str | None,
        sql: str,
        timeout: float,
    ) -> str: ...

    def health_http(
        self,
        *,
        namespace: str,
        pod_name: str,
        container_name: str,
        http_port: int,
        tls: bool,
        certs_dir: str | None,
        client_cert_available: bool,
        path: str,
        timeout: float,
    ) -> HttpHealthResponse: ...

    def patch_statefulset_json(
        self,
        *,
        namespace: str,
        name: str,
        uid: str,
        resource_version: str,
        operations: Sequence[Mapping[str, Any]],
        timeout: float,
    ) -> Mapping[str, Any]: ...


class KubectlAdapter:
    """A bounded kubectl adapter with shell-free commands and redacted errors."""

    _resource_names = {
        "statefulset": "statefulsets",
        "pod": "pods",
        "service": "services",
        "pvc": "persistentvolumeclaims",
    }

    def __init__(self, kubectl: str = "kubectl", context: str | None = None):
        self.kubectl = kubectl
        self.context = context

    def _base(self, namespace: str) -> list[str]:
        command = [self.kubectl]
        if self.context:
            command.extend(["--context", self.context])
        command.extend(["--namespace", namespace])
        return command

    @staticmethod
    def _safe_error(stderr: str, operation: str) -> Exception:
        lowered = stderr.lower()
        if "forbidden" in lowered or "unauthorized" in lowered or "authentication required" in lowered:
            return KubernetesAccessError(f"Kubernetes access denied while {operation}")
        if "the server doesn't have a resource type" in lowered or "no matches for kind" in lowered:
            return KubernetesAccessError(f"Kubernetes API does not support the requested resource while {operation}")
        if "timed out" in lowered or "i/o timeout" in lowered or "deadline exceeded" in lowered:
            return TransientError(f"Kubernetes request timed out while {operation}")
        return KubernetesAccessError(f"Kubernetes request failed while {operation}")

    def _run(
        self,
        command: Sequence[str],
        timeout: float,
        operation: str,
        *,
        stale_guard: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        try:
            result = subprocess.run(
                list(command),
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as error:
            raise TransientError(f"Timed out while {operation}") from error
        except OSError as error:
            raise KubernetesAccessError(f"Could not run kubectl while {operation}") from error
        if result.returncode:
            lowered = result.stderr.lower()
            if stale_guard and (
                "test failed" in lowered
                or "object has been modified" in lowered
                or "the server rejected our request" in lowered
            ):
                raise StaleIdentityError("Selected workload changed before the guarded mutation")
            raise self._safe_error(result.stderr, operation)
        return result

    def get_resource(self, kind: str, namespace: str, name: str) -> Mapping[str, Any] | None:
        resource = self._resource_names.get(kind.lower())
        if not resource:
            raise KubernetesAccessError("Unsupported Kubernetes resource kind")
        command = self._base(namespace) + [
            "get",
            resource,
            name,
            "--ignore-not-found=true",
            "--output=json",
        ]
        result = self._run(command, 15, f"reading {kind}")
        if not result.stdout.strip():
            return None
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise KubernetesAccessError(f"Kubernetes returned invalid {kind} data") from error

    def list_resources(self, kind: str, namespace: str) -> Sequence[Mapping[str, Any]]:
        resource = self._resource_names.get(kind.lower())
        if not resource:
            raise KubernetesAccessError("Unsupported Kubernetes resource kind")
        result = self._run(self._base(namespace) + ["get", resource, "--output=json"], 20, f"listing {kind}")
        try:
            value = json.loads(result.stdout)
            return tuple(value.get("items", ()))
        except (json.JSONDecodeError, AttributeError) as error:
            raise KubernetesAccessError(f"Kubernetes returned invalid {kind} list data") from error

    def secret_fingerprint(self, namespace: str, name: str) -> SecretFingerprint:
        command = self._base(namespace) + [
            "get",
            "secret",
            name,
            "--ignore-not-found=true",
            "--output=json",
        ]
        result = self._run(command, 15, "reading Secret metadata")
        if not result.stdout.strip():
            raise MissingResourceError(f"Referenced Secret {name!r} is missing")
        try:
            value = json.loads(result.stdout)
            metadata = value["metadata"]
            data = value.get("data", {})
            hashes = []
            for key, encoded in sorted(data.items()):
                raw = base64.b64decode(encoded, validate=True)
                hashes.append((str(key), hashlib.sha256(raw).hexdigest()))
            return SecretFingerprint(
                name=str(metadata["name"]),
                uid=str(metadata["uid"]),
                resource_version=str(metadata["resourceVersion"]),
                keys=tuple(key for key, _ in hashes),
                sha256_by_key=tuple(hashes),
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise KubernetesAccessError("Kubernetes returned invalid Secret metadata") from error

    @staticmethod
    def _safe_insecure_sql_stderr(stderr: str) -> str:
        """Keep a small useful diagnostic from the fixed no-credential SQL probe."""
        text = re.sub(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
            "[redacted private key]",
            stderr,
            flags=re.IGNORECASE | re.DOTALL,
        )
        text = re.sub(
            r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            "[redacted certificate]",
            text,
            flags=re.IGNORECASE | re.DOTALL,
        )
        text = re.sub(
            r"(?i)\b(password|token|secret|api[-_]?key)(\s*[:=]\s*)\S+",
            r"\1\2[redacted]",
            text,
        )
        text = re.sub(r"(?i)\bBearer\s+\S+", "Bearer [redacted]", text)
        return " ".join(text.split())[:512]

    @staticmethod
    def _connection_error(
        stderr: str,
        *,
        command_name: str,
        tls_mode: str | None = None,
        endpoint: str | None = None,
    ) -> Exception:
        text = stderr.lower()
        if re.search(r"\bpods? [\"'][a-z0-9][a-z0-9.-]*[\"'] not found\b", text):
            return TransientError("Selected CockroachDB pod changed during observation")
        if "curl: not found" in text or "executable file not found" in text:
            if command_name == "curl":
                return UnsupportedLayoutError("Selected database image does not provide curl for the health endpoint")
            return UnsupportedLayoutError("Selected database image does not provide the configured CockroachDB SQL binary")
        if "permission denied" in text or "forbidden" in text or "unauthorized" in text:
            return KubernetesAccessError("Kubernetes denied access to the selected database pod")
        if "authentication failed" in text or "certificate authentication" in text or "password authentication" in text:
            return AuthenticationError("CockroachDB rejected the selected SQL credentials")
        if "cluster has not been initialized" in text or "not been initialized" in text:
            return UninitializedError("CockroachDB node has not been initialized")
        if (
            "timed out" in text
            or "connection refused" in text
            or "no route to host" in text
            or "connection reset by peer" in text
            or re.search(r"lookup [^\n:]+: no such host", text)
            or "temporary failure in name resolution" in text
        ):
            return TransientError("CockroachDB SQL connection is not ready")
        tls_clue = None
        if re.search(r"\bx509:\s*certificate", text) or re.search(
            r"\bcertificate (?:has expired|is valid for|signed by|verification failed)", text
        ):
            tls_clue = "certificate validation"
        elif re.search(r"\b(?:tls handshake|tls alert|tls: first record|ssl routines:)", text) or re.search(
            r"\bremote error: tls:", text
        ):
            tls_clue = "TLS handshake"
        endpoint_detail = f" at {endpoint}" if endpoint else ""
        if tls_clue:
            return ConnectionError(f"CockroachDB TLS connection failed ({tls_clue}){endpoint_detail}")
        if tls_mode == "insecure":
            diagnostic = KubectlAdapter._safe_insecure_sql_stderr(stderr)
            if diagnostic:
                return ConnectionError(f"CockroachDB SQL query failed{endpoint_detail}: {diagnostic}")
        return ConnectionError(f"CockroachDB SQL query failed{endpoint_detail}")

    def _exec(
        self,
        namespace: str,
        pod_name: str,
        container_name: str,
        inner_command: Sequence[str],
        timeout: float,
        operation: str,
    ) -> subprocess.CompletedProcess[str]:
        command = self._base(namespace) + [
            "exec",
            pod_name,
            "--container",
            container_name,
            "--",
            *inner_command,
        ]
        try:
            return subprocess.run(command, check=False, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            raise TransientError(f"Timed out while {operation}") from error
        except OSError as error:
            raise KubernetesAccessError(f"Could not run kubectl while {operation}") from error

    def query_sql(
        self,
        *,
        namespace: str,
        pod_name: str,
        container_name: str,
        binary: str,
        sql_host: str,
        sql_port: int,
        tls_mode: str,
        certs_dir: str | None,
        sql: str,
        timeout: float,
    ) -> str:
        if sql != _READ_ONLY_SQL:
            raise UnsupportedLayoutError("Only the library's fixed read-only SQL witness is allowed")
        if tls_mode not in {"tls", "insecure"}:
            raise ConnectionError("CockroachDB connection mode is unknown")
        if not re.fullmatch(r"[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?", sql_host) or ".." in sql_host:
            raise UnsupportedLayoutError("CockroachDB SQL host is not a validated DNS name")
        command = [binary, "sql"]
        if tls_mode == "insecure":
            command.append("--insecure")
        elif certs_dir:
            command.append(f"--certs-dir={certs_dir}")
        else:
            raise ConnectionError("CockroachDB certificate directory is unavailable")
        # Inspector derives this host only from an explicit advertised address;
        # no cluster DNS suffix is guessed.
        command.extend(
            [
                f"--host={sql_host}",
                f"--port={sql_port}",
                "--format=csv",
                "-e",
                sql,
            ]
        )
        result = self._exec(namespace, pod_name, container_name, command, timeout + 5, "querying CockroachDB")
        if result.returncode:
            raise self._connection_error(
                result.stderr,
                command_name=binary.rsplit("/", 1)[-1],
                tls_mode=tls_mode,
                endpoint=f"{sql_host}:{sql_port}",
            )
        return result.stdout

    def health_http(
        self,
        *,
        namespace: str,
        pod_name: str,
        container_name: str,
        http_port: int,
        tls: bool,
        certs_dir: str | None,
        client_cert_available: bool,
        path: str,
        timeout: float,
    ) -> HttpHealthResponse:
        scheme = "https" if tls else "http"
        url = f"{scheme}://localhost:{http_port}{path}"
        command = [
            "curl",
            "--silent",
            "--show-error",
            "--connect-timeout",
            "2",
            "--max-time",
            str(max(1, int(timeout))),
            "--write-out",
            "\n%{http_code}",
        ]
        if tls:
            # Like kubelet HTTPS probes, skip server-certificate verification.
            # Supplying the already-mounted root client pair is an explicit
            # connection choice; no certificate is generated or rewritten.
            command.append("--insecure")
            if client_cert_available and certs_dir:
                command.extend(
                    [
                        "--cacert",
                        f"{certs_dir}/ca.crt",
                        "--cert",
                        f"{certs_dir}/client.root.crt",
                        "--key",
                        f"{certs_dir}/client.root.key",
                    ]
                )
        command.append(url)
        result = self._exec(namespace, pod_name, container_name, command, timeout + 5, "checking CockroachDB health")
        if result.returncode:
            raise self._connection_error(result.stderr, command_name="curl")
        try:
            body, code = result.stdout.rsplit("\n", 1)
            return HttpHealthResponse(status=int(code), body=body[:4096])
        except (ValueError, AttributeError) as error:
            raise ConnectionError("CockroachDB health endpoint returned an invalid response") from error

    def patch_statefulset_json(
        self,
        *,
        namespace: str,
        name: str,
        uid: str,
        resource_version: str,
        operations: Sequence[Mapping[str, Any]],
        timeout: float,
    ) -> Mapping[str, Any]:
        # The JSON Patch starts with tests on both identity and resourceVersion.
        # These checks are intentionally kept in the adapter as well as the
        # library's preflight so Kubernetes applies them atomically.
        if len(operations) < 2:
            raise StaleIdentityError("Mutation is missing identity preconditions")
        if (
            operations[0].get("op") != "test"
            or operations[0].get("path") != "/metadata/uid"
            or operations[0].get("value") != uid
        ):
            raise StaleIdentityError("Mutation UID precondition does not match the inspected workload")
        if (
            operations[1].get("op") != "test"
            or operations[1].get("path") != "/metadata/resourceVersion"
            or operations[1].get("value") != resource_version
        ):
            raise StaleIdentityError("Mutation resourceVersion precondition does not match the inspection")
        payload = json.dumps(list(operations), separators=(",", ":"))
        command = self._base(namespace) + [
            "patch",
            "statefulset",
            name,
            "--type=json",
            "--patch",
            payload,
            "--output=json",
        ]
        result = self._run(command, timeout, "patching StatefulSet probes", stale_guard=True)
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise KubernetesAccessError("Kubernetes returned invalid mutation result") from error

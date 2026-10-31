"""Kubernetes and process adapters used by the CRDB library."""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import subprocess
import time
from http.cookies import SimpleCookie
from dataclasses import dataclass
from typing import Any, Mapping, Protocol, Sequence
from urllib.parse import urlencode

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
_READ_ONLY_LIVENESS_SQL = (
    "SELECT node_id, membership, draining, "
    "split_part(expiration, ',', 1)::DECIMAL > now()::DECIMAL AS is_live "
    "FROM crdb_internal.kv_node_liveness ORDER BY node_id;"
)
_SERVER_VERSION_SQL = "SELECT version() AS version;"
_READINESS_SQL = "SELECT 1;"
_READ_ONLY_SQL_QUERIES = frozenset({_READINESS_SQL, _READ_ONLY_SQL, _READ_ONLY_LIVENESS_SQL, _SERVER_VERSION_SQL})


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

    def node_status(
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
        timeout: float,
    ) -> str: ...

    def health_http(
        self,
        *,
        namespace: str,
        pod_name: str,
        container_name: str,
        http_port: int,
        http_transport: str,
        certs_dir: str | None,
        client_cert_available: bool,
        path: str,
        timeout: float,
    ) -> HttpHealthResponse: ...

    def native_identity(
        self,
        *,
        namespace: str,
        pod_name: str,
        pod_uid: str,
        container_name: str,
        binary: str,
        sql_host: str,
        sql_port: int,
        tls_mode: str,
        certs_dir: str | None,
        http_port: int,
        http_transport: str,
        client_cert_available: bool,
        auth_scope: str,
        timeout: float,
    ) -> tuple[int, str]: ...

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
    """A bounded kubectl adapter with shell-free commands and redacted errors.

    ``get_timeout`` bounds each named-resource GET independently; other
    operations retain their own existing budgets.
    """

    _resource_names = {
        "statefulset": "statefulsets",
        "pod": "pods",
        "service": "services",
        "pvc": "persistentvolumeclaims",
    }

    def __init__(
        self,
        kubectl: str = "kubectl",
        context: str | None = None,
        *,
        get_timeout: float = 15.0,
    ):
        if (
            isinstance(get_timeout, bool)
            or not isinstance(get_timeout, (int, float))
            or not math.isfinite(get_timeout)
            or get_timeout <= 0
        ):
            raise ValueError("Kubernetes GET timeout must be positive and finite")
        self.kubectl = kubectl
        self.context = context
        self.get_timeout = float(get_timeout)
        self._auth_sessions: dict[tuple[str, str, str, str, int, str], tuple[float, str]] = {}

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
        result = self._run(command, self.get_timeout, f"reading {kind}")
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
        if sql not in _READ_ONLY_SQL_QUERIES:
            raise UnsupportedLayoutError("Only the library's fixed read-only SQL queries are allowed")
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

    def _exec_with_input(
        self,
        namespace: str,
        pod_name: str,
        container_name: str,
        inner_command: Sequence[str],
        timeout: float,
        operation: str,
        input_text: str | None,
    ) -> subprocess.CompletedProcess[str]:
        """Run a command with private stdin without exposing its contents on errors."""
        if input_text is None:
            return self._exec(namespace, pod_name, container_name, inner_command, timeout, operation)
        command = self._base(namespace) + [
            "exec",
            "-i",
            pod_name,
            "--container",
            container_name,
            "--",
            *inner_command,
        ]
        try:
            return subprocess.run(
                command,
                input=input_text,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            raise TransientError(f"Timed out while {operation}") from None
        except OSError:
            raise KubernetesAccessError(f"Could not run kubectl while {operation}") from None

    @staticmethod
    def _parse_session_cookie(output: str) -> str:
        """Extract only Cockroach's session cookie, discarding safe attributes."""
        if not output or len(output) > 8192 or any(ord(char) < 0x20 or ord(char) == 0x7F for char in output):
            raise AuthenticationError("CockroachDB returned an unsupported HTTP session cookie")
        parsed = SimpleCookie()
        try:
            parsed.load(output.strip())
        except (TypeError, ValueError):
            raise AuthenticationError("CockroachDB returned an unsupported HTTP session cookie") from None
        if set(parsed) != {"session"}:
            raise AuthenticationError("CockroachDB returned an unsupported HTTP session cookie")
        value = parsed["session"].value
        # RFC 6265 cookie-octets; excluding separators prevents curl-config
        # injection when the validated value is placed in a private header.
        if not value or len(value) > 4096 or not re.fullmatch(r"[!#$%&'*+\-.^_`|~0-9A-Za-z:/?@\[\]=]+", value):
            raise AuthenticationError("CockroachDB returned an unsupported HTTP session cookie")
        return f"session={value}"

    def _session_cookie(
        self,
        *,
        namespace: str,
        pod_name: str,
        pod_uid: str,
        container_name: str,
        binary: str,
        sql_host: str,
        sql_port: int,
        certs_dir: str | None,
        auth_scope: str,
        timeout: float,
    ) -> str:
        cache_key = (namespace, pod_uid, container_name, sql_host, sql_port, auth_scope)
        cached = self._auth_sessions.get(cache_key)
        if cached and cached[0] > time.monotonic():
            return cached[1]
        if not certs_dir or not re.fullmatch(r"[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?", sql_host):
            raise UnsupportedLayoutError("Native CockroachDB identity requires a validated TLS SQL endpoint")
        query = urlencode(
            {
                "sslmode": "verify-full",
                "sslrootcert": f"{certs_dir}/ca.crt",
                "sslcert": f"{certs_dir}/client.root.crt",
                "sslkey": f"{certs_dir}/client.root.key",
            }
        )
        url = f"postgresql://root@{sql_host}:{sql_port}/?{query}"
        command = [
            binary,
            "auth-session",
            "login",
            "root",
            "--only-cookie",
            "--expire-after=45s",
            f"--url={url}",
        ]
        login_started = time.monotonic()
        result = self._exec(
            namespace,
            pod_name,
            container_name,
            command,
            timeout + 5,
            "creating a short-lived CockroachDB HTTP session",
        )
        if result.returncode:
            raise self._connection_error(
                result.stderr,
                command_name=binary.rsplit("/", 1)[-1],
                tls_mode="tls",
                endpoint=f"{sql_host}:{sql_port}",
            )
        cookie = self._parse_session_cookie(result.stdout.strip())
        # Cockroach stores this session server-side. Keep the cookie only in
        # memory and cache for less than its requested server expiry. Start the
        # local bound before the login command so a slow login cannot extend it.
        cache_expiry = login_started + 30
        if cache_expiry > time.monotonic():
            self._auth_sessions[cache_key] = (cache_expiry, cookie)
        else:
            self._auth_sessions.pop(cache_key, None)
        return cookie

    def native_identity(
        self,
        *,
        namespace: str,
        pod_name: str,
        pod_uid: str,
        container_name: str,
        binary: str,
        sql_host: str,
        sql_port: int,
        tls_mode: str,
        certs_dir: str | None,
        http_port: int,
        http_transport: str,
        client_cert_available: bool,
        auth_scope: str,
        timeout: float,
    ) -> tuple[int, str]:
        """Read the fixed local node and cluster identity endpoints."""
        if http_transport not in {"http", "https"}:
            raise UnsupportedLayoutError("CockroachDB HTTP transport is unresolved")
        if tls_mode not in {"tls", "insecure"}:
            raise UnsupportedLayoutError("CockroachDB SQL TLS mode is unresolved")
        if http_transport == "https" and not client_cert_available:
            raise UnsupportedLayoutError("Secure CockroachDB HTTP identity requires the observed client certificate")
        cookie = None
        if tls_mode == "tls":
            cookie = self._session_cookie(
                namespace=namespace,
                pod_name=pod_name,
                pod_uid=pod_uid,
                container_name=container_name,
                binary=binary,
                sql_host=sql_host,
                sql_port=sql_port,
                certs_dir=certs_dir,
                auth_scope=auth_scope,
                timeout=timeout,
            )
        node = self._native_http_json(
            namespace=namespace,
            pod_name=pod_name,
            container_name=container_name,
            http_port=http_port,
            http_transport=http_transport,
            certs_dir=certs_dir,
            client_cert_available=client_cert_available,
            cookie=cookie,
            path="/_status/details/local",
            timeout=timeout,
        )
        cluster = self._native_http_json(
            namespace=namespace,
            pod_name=pod_name,
            container_name=container_name,
            http_port=http_port,
            http_transport=http_transport,
            certs_dir=certs_dir,
            client_cert_available=client_cert_available,
            cookie=cookie,
            path="/_admin/v1/cluster",
            timeout=timeout,
        )
        raw_node_id = node.get("nodeId", node.get("node_id"))
        if type(raw_node_id) is int:
            node_id = raw_node_id
        elif isinstance(raw_node_id, str) and raw_node_id.isascii() and raw_node_id.isdecimal():
            node_id = int(raw_node_id)
        else:
            raise UnsupportedLayoutError("CockroachDB local identity response omitted the node ID")
        cluster_id = cluster.get("clusterId", cluster.get("cluster_id"))
        if node_id < 1 or not isinstance(cluster_id, str) or not re.fullmatch(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            cluster_id,
        ):
            raise UnsupportedLayoutError("CockroachDB native identity response is incomplete")
        return node_id, cluster_id

    def _native_http_json(
        self,
        *,
        namespace: str,
        pod_name: str,
        container_name: str,
        http_port: int,
        http_transport: str,
        certs_dir: str | None,
        client_cert_available: bool,
        cookie: str | None,
        path: str,
        timeout: float,
    ) -> Mapping[str, Any]:
        if path not in {"/_status/details/local", "/_admin/v1/cluster"}:
            raise UnsupportedLayoutError("CockroachDB native identity path is not allowlisted")
        command = [
            "curl",
            "--silent",
            "--show-error",
            "--connect-timeout",
            "2",
            "--max-time",
            str(max(1, int(timeout))),
            "--write-out",
            "\\n%{http_code}",
        ]
        if http_transport == "https":
            # Native HTTP identity runs in the selected pod against localhost.
            # Match kubelet's certificate behavior while presenting the
            # already-mounted client pair for SQL-TLS workloads.
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
        if cookie is not None:
            command.extend(["--config", "-"])
        command.append(f"{http_transport}://localhost:{http_port}{path}")
        private_config = f'header = "Cookie: {cookie}"\n' if cookie is not None else None
        result = self._exec_with_input(
            namespace,
            pod_name,
            container_name,
            command,
            timeout + 5,
            "reading CockroachDB native identity",
            private_config,
        )
        if result.returncode:
            raise self._connection_error(result.stderr, command_name="curl")
        try:
            body, status_text = result.stdout.rsplit("\n", 1)
            status = int(status_text)
        except (ValueError, AttributeError):
            raise ConnectionError("CockroachDB native identity endpoint returned an invalid response") from None
        if status in {401, 403}:
            raise AuthenticationError("CockroachDB native identity endpoint rejected the selected credentials")
        if status == 404:
            raise UnsupportedLayoutError("CockroachDB native identity endpoint is not supported by the selected node")
        if status >= 500:
            raise TransientError("CockroachDB native identity endpoint is not ready")
        if status != 200:
            raise ConnectionError("CockroachDB native identity endpoint returned an unexpected status")
        try:
            payload = json.loads(body)
        except (TypeError, ValueError):
            raise ConnectionError("CockroachDB native identity endpoint returned invalid JSON") from None
        if not isinstance(payload, Mapping):
            raise UnsupportedLayoutError("CockroachDB native identity endpoint returned an unexpected value")
        return payload

    def node_status(
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
        timeout: float,
    ) -> str:
        """Run Cockroach's fixed read-only node-status command over SQL."""
        if tls_mode not in {"tls", "insecure"}:
            raise ConnectionError("CockroachDB connection mode is unknown")
        if not re.fullmatch(r"[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?", sql_host) or ".." in sql_host:
            raise UnsupportedLayoutError("CockroachDB SQL host is not a validated DNS name")
        command = [binary, "node", "status", "--all"]
        if tls_mode == "insecure":
            command.append("--insecure")
        elif certs_dir:
            command.append(f"--certs-dir={certs_dir}")
        else:
            raise ConnectionError("CockroachDB certificate directory is unavailable")
        command.extend([f"--host={sql_host}", f"--port={sql_port}", "--format=csv"])
        result = self._exec(
            namespace,
            pod_name,
            container_name,
            command,
            timeout + 5,
            "reading CockroachDB node status",
        )
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
        http_transport: str,
        certs_dir: str | None,
        client_cert_available: bool,
        path: str,
        timeout: float,
    ) -> HttpHealthResponse:
        if http_transport not in {"http", "https"}:
            raise UnsupportedLayoutError("CockroachDB HTTP transport is unresolved")
        scheme = http_transport
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
        if scheme == "https":
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
        result = self._run(command, timeout, "patching StatefulSet", stale_guard=True)
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise KubernetesAccessError("Kubernetes returned invalid mutation result") from error

"""Safe readiness, carryover verification, and narrowly scoped probe repair."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import math
import re
import time
from collections.abc import Mapping
from dataclasses import replace
from typing import Any

from .adapter import ClusterAdapter, _READ_ONLY_LIVENESS_SQL
from .inspection import WorkloadInspector
from .types import (
    AcceptedState,
    Assessment,
    AuthenticationError,
    ConnectionError,
    FullHealthAssessment,
    HealthObservation,
    HTTPTransport,
    InvalidRequirementError,
    Lifecycle,
    MissingResourceError,
    NodeLivenessObservation,
    NodeStatusObservation,
    Observation,
    PreservationMismatchError,
    ProbePreparationResult,
    ProbeStatus,
    ReconcileResult,
    Requirement,
    ServingHealthAssessment,
    SQLConnectionObservation,
    RolloutInProgressError,
    StaleIdentityError,
    TLSMode,
    TransientError,
    UninitializedError,
    UnsupportedLayoutError,
    WorkloadRef,
)


_WITNESS_SQL = (
    "SELECT crdb_internal.cluster_id() AS cluster_id, "
    "crdb_internal.node_id() AS node_id, version() AS version;"
)
_SERVER_VERSION_SQL = "SELECT version() AS version;"
_PROBE_HANDLERS = ("httpGet", "tcpSocket", "exec", "grpc")


def _probe_port_targets_http_listener(port: Any, workload: Observation) -> bool:
    if type(port) is int:
        return port == workload.http_port
    return isinstance(port, str) and workload.http_port_name is not None and port == workload.http_port_name


def _http_probe_handler_matches(
    handler: str,
    current: Mapping[str, Any],
    *,
    path: str,
    workload: Observation,
    scheme: str,
) -> bool:
    actual_scheme = current.get("scheme")
    if actual_scheme is None:
        actual_scheme = "HTTP"
    return (
        handler == "httpGet"
        and current.get("path") == path
        and _probe_port_targets_http_listener(current.get("port"), workload)
        and actual_scheme == scheme
        and current.get("host") in (None, "")
        and current.get("httpHeaders") in (None, [])
        and set(current) <= {"path", "port", "scheme", "host", "httpHeaders"}
    )


def _observed_probe_matches(
    probe: Any,
    *,
    path: str,
    workload: Observation,
    scheme: str,
) -> bool:
    actual_scheme = probe.scheme if probe.scheme is not None else "HTTP"
    return (
        probe.handler == "httpGet"
        and probe.path == path
        and _probe_port_targets_http_listener(probe.port, workload)
        and actual_scheme == scheme
        and probe.host in (None, "")
        and not probe.has_custom_headers
    )


def _parse_witness(output: str) -> tuple[str | None, int | None, str | None]:
    rows = [row for row in csv.reader(io.StringIO(output)) if any(cell.strip() for cell in row)]
    if rows and rows[0] and rows[0][0].strip().lower() in {"cluster_id", "crdb_internal.cluster_id()"}:
        rows = rows[1:]
    if len(rows) != 1 or len(rows[0]) < 3:
        raise ConnectionError("CockroachDB returned an unexpected read-only witness result")
    cluster_text, node_text, version_text = (cell.strip() for cell in rows[0][:3])
    if cluster_text.lower() in {"", "null", "\x00"}:
        return None, None, version_text or None
    try:
        node_id = int(node_text)
    except ValueError as error:
        raise ConnectionError("CockroachDB returned an invalid node identity") from error
    if node_id < 1 or not cluster_text or not version_text:
        raise ConnectionError("CockroachDB returned an incomplete read-only witness result")
    return cluster_text, node_id, version_text


def _parse_server_version(output: str) -> str:
    rows = _csv_records(output, {"version"}, "server version")
    if len(rows) != 1 or not rows[0]["version"]:
        raise UnsupportedLayoutError("CockroachDB server version query returned an unexpected result")
    version = rows[0]["version"]
    if _server_version_tuple(version) is None:
        raise UnsupportedLayoutError("CockroachDB server version string is not recognized")
    return version


def _server_version_tuple(version: str) -> tuple[int, int, int] | None:
    match = re.search(r"\bv(\d+)\.(\d+)(?:\.(\d+))?\b", version, re.IGNORECASE)
    if not match:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3) or 0)


def _requires_native_identity(version: str) -> bool:
    parsed = _server_version_tuple(version)
    return parsed is not None and parsed >= (26, 1, 0)


def _csv_records(output: str, required: set[str], operation: str) -> tuple[dict[str, str], ...]:
    reader = csv.DictReader(io.StringIO(output))
    if reader.fieldnames is None:
        raise UnsupportedLayoutError(f"CockroachDB {operation} response is missing its CSV header")
    fields = [field.strip().lower() for field in reader.fieldnames]
    if len(set(fields)) != len(fields) or not required.issubset(fields):
        raise UnsupportedLayoutError(f"CockroachDB {operation} response is missing required fields")
    rows: list[dict[str, str]] = []
    for raw in reader:
        if None in raw or any(value is None for value in raw.values()):
            raise UnsupportedLayoutError(f"CockroachDB {operation} response has a malformed CSV row")
        rows.append({field: str(value).strip() for field, value in zip(fields, raw.values(), strict=True)})
    return tuple(rows)


def _parse_bool(value: str, operation: str) -> bool:
    lowered = value.strip().lower()
    if lowered in {"true", "t", "1"}:
        return True
    if lowered in {"false", "f", "0"}:
        return False
    raise UnsupportedLayoutError(f"CockroachDB {operation} response has an invalid boolean field")


def _parse_nonnegative_int(value: str, operation: str, *, positive: bool = False) -> int:
    if not value.isascii() or not value.isdecimal():
        raise UnsupportedLayoutError(f"CockroachDB {operation} response has an invalid integer field")
    parsed = int(value)
    if (positive and parsed < 1) or (not positive and parsed < 0):
        raise UnsupportedLayoutError(f"CockroachDB {operation} response has an out-of-range integer field")
    return parsed


def _parse_node_status(output: str) -> tuple[NodeStatusObservation, ...]:
    required = {
        "id",
        "is_available",
        "ranges_unavailable",
        "ranges_underreplicated",
    }
    rows = _csv_records(output, required, "node status")
    observed = []
    seen: set[int] = set()
    for row in rows:
        node_id = _parse_nonnegative_int(row["id"], "node status", positive=True)
        if node_id in seen:
            raise UnsupportedLayoutError("CockroachDB node status response has duplicate node identities")
        membership = row.get("membership")
        membership = membership.strip().lower() if membership is not None else None
        if membership == "":
            raise UnsupportedLayoutError("CockroachDB node status response has an empty membership field")
        draining = row.get("is_draining")
        if draining == "":
            raise UnsupportedLayoutError("CockroachDB node status response has an empty draining field")
        seen.add(node_id)
        observed.append(
            NodeStatusObservation(
                node_id=node_id,
                membership=membership,
                is_draining=_parse_bool(draining, "node status") if draining is not None else None,
                is_available=_parse_bool(row["is_available"], "node status"),
                ranges_unavailable=_parse_nonnegative_int(row["ranges_unavailable"], "node status"),
                ranges_underreplicated=_parse_nonnegative_int(row["ranges_underreplicated"], "node status"),
                is_live=_parse_bool(row["is_live"], "node status") if row.get("is_live") not in (None, "") else None,
            )
        )
    return tuple(observed)


def _parse_node_liveness(output: str) -> tuple[NodeLivenessObservation, ...]:
    rows = _csv_records(output, {"node_id", "membership", "draining", "is_live"}, "node liveness")
    observed = []
    seen: set[int] = set()
    for row in rows:
        node_id = _parse_nonnegative_int(row["node_id"], "node liveness", positive=True)
        if node_id in seen:
            raise UnsupportedLayoutError("CockroachDB node liveness response has duplicate node identities")
        membership = row["membership"].strip().lower()
        if not membership:
            raise UnsupportedLayoutError("CockroachDB node liveness response has an empty membership field")
        seen.add(node_id)
        observed.append(
            NodeLivenessObservation(
                node_id=node_id,
                membership=membership,
                draining=_parse_bool(row["draining"], "node liveness"),
                is_live=_parse_bool(row["is_live"], "node liveness"),
            )
        )
    return tuple(observed)


def _requirement_nodes(requirement: Requirement, workload: Observation) -> int:
    return requirement.minimum_nodes if requirement.minimum_nodes is not None else workload.desired_replicas


class CrdbLibrary:
    """CRDB common library with an injected, testable Kubernetes/SQL adapter.

    V1 observes existing workloads, waits within caller bounds, and can
    atomically rewrite only two probe handlers. It reads the server version
    from each selected Pod, then uses fixed SQL identity queries on versions
    before 26.1 and CockroachDB's native HTTP identity endpoints on 26.1 and
    later. HTTP transport is observed independently from SQL TLS. Secure SQL
    identity checks create a short-lived CockroachDB web session; its cookie
    stays in memory and the session row expires. No accepted workload or
    configuration is normalized. The library never creates a workload,
    initializes a cluster, resets data, or changes TLS, image, storage,
    replicas, services, or cluster identity.
    """

    def __init__(self, adapter: ClusterAdapter):
        self.adapter = adapter
        self.inspector = WorkloadInspector(adapter)

    def inspect(self, ref: WorkloadRef) -> Observation:
        return self.inspector.inspect(ref)

    def inspect_sql_connection(
        self,
        ref: WorkloadRef,
        ordinal: int = 0,
    ) -> SQLConnectionObservation:
        """Observe one live Pod's SQL endpoint without requiring peer readiness."""
        return self.inspector.inspect_sql_connection(ref, ordinal=ordinal)

    def probe(
        self,
        ref: WorkloadRef,
        requirement: Requirement,
        *,
        per_node_timeout: float = 5.0,
    ) -> Assessment:
        return self._probe(
            ref,
            requirement,
            per_node_timeout=per_node_timeout,
            allow_image_rollout=False,
        )

    def _probe(
        self,
        ref: WorkloadRef,
        requirement: Requirement,
        *,
        per_node_timeout: float,
        allow_image_rollout: bool,
    ) -> Assessment:
        if not isinstance(requirement, Requirement):
            raise InvalidRequirementError("requirement must be a Requirement value")
        if type(per_node_timeout) not in (int, float) or not math.isfinite(per_node_timeout) or per_node_timeout <= 0:
            raise InvalidRequirementError("per_node_timeout must be positive")
        workload = (
            self.inspector.inspect_for_health(ref)
            if allow_image_rollout
            else self.inspect(ref)
        )
        if workload.tls_mode is TLSMode.UNKNOWN:
            raise UnsupportedLayoutError("TLS mode cannot be resolved safely for SQL inspection")
        if any(pod.sql_host is None for pod in workload.pods):
            raise UnsupportedLayoutError(
                "CockroachDB SQL inspection requires a supported per-pod --advertise-host pattern"
            )
        sql_ready: list[str] = []
        uninitialized: list[str] = []
        deployed: list[str] = []
        cluster_ids: list[str] = []
        node_ids: list[int] = []
        versions: list[str] = []
        initialized_pods: list[tuple[Any, str]] = []
        for pod in workload.pods:
            assert pod.sql_host is not None
            # Cockroach's readiness endpoint gives a positive semantic answer
            # for the deployed-but-not-initialized state. Check that fixed
            # endpoint before SQL, which may fail during initialization with
            # CLI-specific TLS/transport text. Only the exact Cockroach
            # sentinel classifies that state; auth, API, and unrelated HTTP
            # failures remain errors.
            response = self.adapter.health_http(
                namespace=workload.namespace,
                pod_name=pod.name,
                container_name=workload.container_name,
                http_port=workload.http_port,
                http_transport=workload.http_transport.value,
                certs_dir=workload.certs_dir,
                client_cert_available=workload.tls_mode is TLSMode.TLS,
                path="/health?ready=1",
                timeout=per_node_timeout,
            )
            try:
                payload = json.loads(response.body)
            except (TypeError, ValueError):
                payload = None
            if (
                response.status == 503
                and isinstance(payload, dict)
                and payload.get("error") == "node is waiting for cluster initialization"
            ):
                uninitialized.append(pod.name)
                if pod.phase == "Running" and pod.container_state == "running":
                    deployed.append(pod.name)
                continue
            if response.status in {401, 403}:
                raise AuthenticationError("CockroachDB readiness endpoint rejected the selected credentials")
            if response.status >= 500:
                raise TransientError("CockroachDB readiness endpoint is not ready")
            if response.status != 200:
                raise ConnectionError("CockroachDB readiness endpoint returned an unexpected status")
            try:
                version_output = self.adapter.query_sql(
                    namespace=workload.namespace,
                    pod_name=pod.name,
                    container_name=workload.container_name,
                    binary=workload.sql_binary,
                    sql_host=pod.sql_host,
                    sql_port=workload.sql_port,
                    tls_mode=workload.tls_mode.value,
                    certs_dir=workload.certs_dir,
                    sql=_SERVER_VERSION_SQL,
                    timeout=per_node_timeout,
                )
                version = _parse_server_version(version_output)
                sql_ready.append(pod.name)
                deployed.append(pod.name)
                versions.append(version)
                initialized_pods.append((pod, version))
            except UninitializedError:
                uninitialized.append(pod.name)
            if pod.phase == "Running" and pod.container_state == "running" and (
                pod.name in sql_ready or pod.name in uninitialized
            ):
                if pod.name not in deployed:
                    deployed.append(pod.name)

        if sql_ready and uninitialized:
            raise RolloutInProgressError("Some CockroachDB nodes are initialized while others are not")
        auth_scope = hashlib.sha256(
            json.dumps(
                {
                    "certs_dir": workload.certs_dir,
                    "secrets": [
                        (secret.name, secret.uid, secret.sha256_by_key)
                        for secret in workload.secrets
                    ],
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        for pod, observed_version in initialized_pods:
            assert pod.sql_host is not None
            if _requires_native_identity(observed_version):
                node_id, cluster_id = self.adapter.native_identity(
                    namespace=workload.namespace,
                    pod_name=pod.name,
                    pod_uid=pod.uid,
                    container_name=workload.container_name,
                    binary=workload.sql_binary,
                    sql_host=pod.sql_host,
                    sql_port=workload.sql_port,
                    tls_mode=workload.tls_mode.value,
                    certs_dir=workload.certs_dir,
                    http_port=workload.http_port,
                    http_transport=workload.http_transport.value,
                    client_cert_available=workload.tls_mode is TLSMode.TLS,
                    auth_scope=auth_scope,
                    timeout=per_node_timeout,
                )
            else:
                output = self.adapter.query_sql(
                    namespace=workload.namespace,
                    pod_name=pod.name,
                    container_name=workload.container_name,
                    binary=workload.sql_binary,
                    sql_host=pod.sql_host,
                    sql_port=workload.sql_port,
                    tls_mode=workload.tls_mode.value,
                    certs_dir=workload.certs_dir,
                    sql=_WITNESS_SQL,
                    timeout=per_node_timeout,
                )
                cluster_id, node_id, witness_version = _parse_witness(output)
                if cluster_id is None or node_id is None or witness_version is None:
                    raise RolloutInProgressError("CockroachDB SQL identity is not initialized")
                if _server_version_tuple(witness_version) != _server_version_tuple(observed_version):
                    raise RolloutInProgressError("CockroachDB binary version changed during the identity observation")
            cluster_ids.append(cluster_id)
            node_ids.append(node_id)
        if sql_ready and (len(set(cluster_ids)) != 1 or len(set(node_ids)) != len(node_ids)):
            raise RolloutInProgressError("CockroachDB nodes disagree on cluster or node identity")
        if not sql_ready and len(uninitialized) != len(workload.pods):
            # API, authentication, and transport failures propagate above; this
            # branch is only defensive against an incomplete adapter result.
            raise ConnectionError("CockroachDB did not return a complete node health observation")

        lifecycle = Lifecycle.INITIALIZED if sql_ready else Lifecycle.DEPLOYED
        health = HealthObservation(
            lifecycle=lifecycle,
            cluster_id=cluster_ids[0] if cluster_ids else None,
            node_ids=tuple(node_ids),
            sql_versions=tuple(versions),
            sql_ready_pods=tuple(sql_ready),
            uninitialized_pods=tuple(uninitialized),
            deployed_pods=tuple(deployed),
        )
        reasons: list[str] = []
        requested_nodes = _requirement_nodes(requirement, workload)
        observed_nodes = len(health.sql_ready_pods) if requirement.lifecycle is Lifecycle.INITIALIZED else len(health.deployed_pods)
        if observed_nodes < requested_nodes:
            reasons.append(f"{observed_nodes} nodes meet the requested lifecycle; {requested_nodes} required")
        if requirement.lifecycle is Lifecycle.INITIALIZED and health.lifecycle is not Lifecycle.INITIALIZED:
            reasons.append("CockroachDB is deployed but has not been initialized")
        if requirement.tls_mode is not None and workload.tls_mode is not requirement.tls_mode:
            reasons.append(f"TLS mode is {workload.tls_mode.value}; {requirement.tls_mode.value} required")
        return Assessment(
            status=ProbeStatus.SATISFIED if not reasons else ProbeStatus.UNSATISFIED,
            reasons=tuple(reasons),
            workload=workload,
            health=health,
        )

    def _probe_cluster_health(
        self,
        ref: WorkloadRef,
        *,
        per_node_timeout: float = 5.0,
        require_replicated: bool,
        assessment_type: type[FullHealthAssessment] | type[ServingHealthAssessment],
    ) -> FullHealthAssessment | ServingHealthAssessment:
        """Observe initialized identity, selected nodes, ranges, and liveness.

        CockroachDB versions before 26.1 use fixed SQL identity and KV
        liveness queries. Versions 26.1 and later use the fixed native HTTP
        identity endpoints and node-status liveness fields because restricted
        internals block those SQL tables by default. Secure SQL identity uses
        a short-lived web session, which creates an expiring server-side
        session row; credentials and the cookie are not returned. The method
        exposes no arbitrary SQL/API entry point and never mutates accepted
        workload configuration.
        """
        assessment = self._probe(
            ref,
            Requirement(Lifecycle.INITIALIZED),
            per_node_timeout=per_node_timeout,
            allow_image_rollout=True,
        )
        pod_node_ids = tuple(zip(assessment.health.sql_ready_pods, assessment.health.node_ids, strict=True))
        reasons = list(assessment.reasons)
        if assessment.status is ProbeStatus.UNSATISFIED:
            return assessment_type(
                status=ProbeStatus.UNSATISFIED,
                reasons=tuple(reasons),
                assessment=assessment,
                pod_node_ids=pod_node_ids,
                node_status=(),
                node_liveness=(),
            )

        not_ready = tuple(
            pod.name
            for pod in assessment.workload.pods
            if pod.phase != "Running"
            or pod.container_state != "running"
            or not pod.container_ready
            or not pod.pod_ready
        )
        if not_ready:
            reasons.append("Selected CockroachDB pods are not all Ready")
            return assessment_type(
                status=ProbeStatus.UNSATISFIED,
                reasons=tuple(reasons),
                assessment=assessment,
                pod_node_ids=pod_node_ids,
                node_status=(),
                node_liveness=(),
            )

        first_pod = assessment.workload.pods[0]
        if first_pod.sql_host is None:
            raise UnsupportedLayoutError("Full health requires a resolved advertised SQL host")
        connection = {
            "namespace": assessment.workload.namespace,
            "pod_name": first_pod.name,
            "container_name": assessment.workload.container_name,
            "binary": assessment.workload.sql_binary,
            "sql_host": first_pod.sql_host,
            "sql_port": assessment.workload.sql_port,
            "tls_mode": assessment.workload.tls_mode.value,
            "certs_dir": assessment.workload.certs_dir,
            "timeout": per_node_timeout,
        }
        status_output = self.adapter.node_status(**connection)
        node_status = _parse_node_status(status_output)
        if any(_requires_native_identity(version) for version in assessment.health.sql_versions):
            if any(
                node.membership is None or node.is_draining is None or node.is_live is None
                for node in node_status
            ):
                raise UnsupportedLayoutError(
                    "CockroachDB native node status lacks membership, draining, or liveness fields"
                )
            node_liveness = tuple(
                NodeLivenessObservation(
                    node_id=node.node_id,
                    membership=node.membership or "",
                    draining=bool(node.is_draining),
                    is_live=bool(node.is_live),
                )
                for node in node_status
            )
        else:
            liveness_output = self.adapter.query_sql(sql=_READ_ONLY_LIVENESS_SQL, **connection)
            node_liveness = _parse_node_liveness(liveness_output)

        selected_ids = {node_id for _, node_id in pod_node_ids}
        expected_count = assessment.workload.desired_replicas
        active_liveness = tuple(node for node in node_liveness if node.membership != "decommissioned")
        status_by_id = {node.node_id: node for node in node_status}
        liveness_ids = {node.node_id for node in active_liveness}
        selected_status = tuple(status_by_id[node_id] for node_id in sorted(selected_ids) if node_id in status_by_id)
        extra_status_ids = set(status_by_id) - selected_ids
        decommissioned_ids = {node.node_id for node in node_liveness if node.membership == "decommissioned"}
        inconsistent_extra_status_ids = {
            node_id
            for node_id in extra_status_ids
            if node_id not in decommissioned_ids
            or status_by_id[node_id].membership not in (None, "decommissioned")
        }
        if len(selected_status) != expected_count:
            reasons.append("CockroachDB node status does not cover every selected StatefulSet replica")
        if inconsistent_extra_status_ids:
            reasons.append("CockroachDB node status includes nodes outside the selected active cluster")
        if len(active_liveness) != expected_count or liveness_ids != selected_ids:
            reasons.append("KV liveness does not match the selected StatefulSet replicas")
        if any(node.membership not in (None, "active") for node in selected_status):
            reasons.append("A selected CockroachDB node is not active")
        if any(node.is_draining is True for node in selected_status):
            reasons.append("A selected CockroachDB node is draining")
        if any(not node.is_available for node in selected_status):
            reasons.append("A selected CockroachDB node is unavailable")
        unavailable = any(node.ranges_unavailable != 0 for node in selected_status)
        under_replicated = any(node.ranges_underreplicated != 0 for node in selected_status)
        if require_replicated and (unavailable or under_replicated):
            reasons.append("CockroachDB reports unavailable or under-replicated ranges")
        elif unavailable:
            reasons.append("CockroachDB reports unavailable ranges")
        if any(node.membership != "active" for node in active_liveness):
            reasons.append("A selected KV node is not an active member")
        if any(node.draining for node in active_liveness):
            reasons.append("A selected KV node is draining")
        if any(not node.is_live for node in active_liveness):
            reasons.append("A selected KV node has an expired liveness heartbeat")
        return assessment_type(
            status=ProbeStatus.SATISFIED if not reasons else ProbeStatus.UNSATISFIED,
            reasons=tuple(reasons),
            assessment=assessment,
            pod_node_ids=pod_node_ids,
            node_status=node_status,
            node_liveness=node_liveness,
        )

    def probe_full_health(
        self,
        ref: WorkloadRef,
        *,
        per_node_timeout: float = 5.0,
    ) -> FullHealthAssessment:
        """Require initialized serving health and no under-replicated ranges."""
        return self._probe_cluster_health(
            ref,
            per_node_timeout=per_node_timeout,
            require_replicated=True,
            assessment_type=FullHealthAssessment,
        )

    def probe_serving_health(
        self,
        ref: WorkloadRef,
        *,
        per_node_timeout: float = 5.0,
    ) -> ServingHealthAssessment:
        """Require usable selected nodes and no unavailable ranges.

        Under-replicated ranges are permitted, which is useful while a
        case-owned zone-policy change is pending.
        """
        return self._probe_cluster_health(
            ref,
            per_node_timeout=per_node_timeout,
            require_replicated=False,
            assessment_type=ServingHealthAssessment,
        )

    def wait_for_full_health(
        self,
        ref: WorkloadRef,
        *,
        timeout: float = 30.0,
        poll_interval: float = 1.0,
        per_node_timeout: float = 5.0,
    ) -> FullHealthAssessment:
        """Wait for full health, retrying only transient observation states.

        ``timeout`` bounds the polling window. Each in-flight adapter call has
        its own ``per_node_timeout`` plus the adapter's process allowance.
        """
        return self._wait_for_cluster_health(
            ref,
            self.probe_full_health,
            timeout=timeout,
            poll_interval=poll_interval,
            per_node_timeout=per_node_timeout,
            description="CockroachDB full health",
        )

    def wait_for_serving_health(
        self,
        ref: WorkloadRef,
        *,
        timeout: float = 30.0,
        poll_interval: float = 1.0,
        per_node_timeout: float = 5.0,
    ) -> ServingHealthAssessment:
        """Wait for serving health while permitting under-replication."""
        return self._wait_for_cluster_health(
            ref,
            self.probe_serving_health,
            timeout=timeout,
            poll_interval=poll_interval,
            per_node_timeout=per_node_timeout,
            description="CockroachDB serving health",
        )

    def _wait_for_cluster_health(
        self,
        ref: WorkloadRef,
        probe,
        *,
        timeout: float,
        poll_interval: float,
        per_node_timeout: float,
        description: str,
    ):
        if (
            type(timeout) not in (int, float)
            or type(poll_interval) not in (int, float)
            or not math.isfinite(timeout)
            or not math.isfinite(poll_interval)
            or timeout < 0
            or poll_interval <= 0
        ):
            raise InvalidRequirementError("timeout must be non-negative and poll_interval positive")
        if type(per_node_timeout) not in (int, float) or not math.isfinite(per_node_timeout) or per_node_timeout <= 0:
            raise InvalidRequirementError("per_node_timeout must be a finite positive number")
        deadline = time.monotonic() + timeout
        attempts = 0
        last: FullHealthAssessment | ServingHealthAssessment | None = None
        while True:
            attempts += 1
            try:
                last = probe(ref, per_node_timeout=per_node_timeout)
            except (RolloutInProgressError, TransientError) as error:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TransientError(f"{description} was not observable within the requested bound") from error
                time.sleep(min(poll_interval, remaining))
                continue
            if last.status is ProbeStatus.SATISFIED:
                return replace(last, attempts=attempts)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return replace(last, attempts=attempts)
            time.sleep(min(poll_interval, remaining))

    def probe_health_endpoint(
        self,
        ref: WorkloadRef,
        *,
        path: str = "/health?ready=1",
        per_node_timeout: float = 3.0,
    ) -> tuple[tuple[str, int, bool], ...]:
        """Read Cockroach's HTTP health endpoint in each selected pod.

        ``path`` is deliberately restricted to the two fixed Cockroach health
        endpoints. The return value is an immutable tuple of pod, HTTP status,
        and success flag; response bodies never leave the adapter boundary.
        """
        if path not in {"/health", "/health?ready=1"}:
            raise InvalidRequirementError("health path must be /health or /health?ready=1")
        if type(per_node_timeout) not in (int, float) or not math.isfinite(per_node_timeout) or per_node_timeout <= 0:
            raise InvalidRequirementError("per_node_timeout must be a finite positive number")
        workload = self.inspect(ref)
        if workload.http_port is None:
            raise UnsupportedLayoutError("CockroachDB HTTP port is unavailable")
        if workload.tls_mode is TLSMode.UNKNOWN:
            raise UnsupportedLayoutError("TLS mode cannot be resolved safely for HTTP health checks")
        if workload.http_transport is HTTPTransport.UNKNOWN:
            raise UnsupportedLayoutError("HTTP transport cannot be resolved safely for health checks")
        results = []
        for pod in workload.pods:
            response = self.adapter.health_http(
                namespace=workload.namespace,
                pod_name=pod.name,
                container_name=workload.container_name,
                http_port=workload.http_port,
                http_transport=workload.http_transport.value,
                certs_dir=workload.certs_dir,
                client_cert_available=workload.tls_mode is TLSMode.TLS,
                path=path,
                timeout=per_node_timeout,
            )
            results.append((pod.name, response.status, 200 <= response.status < 300))
        return tuple(results)

    @staticmethod
    def accepted_state(assessment: Assessment) -> AcceptedState:
        """Create an immutable, redacted snapshot from an initialized probe."""
        workload, health = assessment.workload, assessment.health
        if health.lifecycle is not Lifecycle.INITIALIZED or health.cluster_id is None:
            raise InvalidRequirementError("accepted state requires an initialized CockroachDB cluster")
        if assessment.status is not ProbeStatus.SATISFIED:
            raise InvalidRequirementError("accepted state requires a satisfied assessment")
        if any(not pod.startup_matches_template for pod in workload.pods):
            raise InvalidRequirementError("accepted state requires every selected Pod to match the desired image")
        versions = tuple(zip(health.sql_ready_pods, health.sql_versions, strict=True))
        pvc_identities = tuple(
            (pvc.name, pvc.uid, pvc.volume_name, pvc.phase, pvc.spec_hash)
            for pvc in workload.pvcs
        )
        certificate_fingerprints = tuple(
            sorted(
                (secret.name, secret.uid, key, digest)
                for secret in workload.secrets
                for key, digest in secret.sha256_by_key
            )
        )
        service_routing = tuple(
            (service.name, service.uid, service.routing_hash)
            for service in workload.services
        )
        return AcceptedState(
            namespace=workload.namespace,
            workload_name=workload.name,
            workload_uid=workload.workload_uid,
            cluster_id=health.cluster_id,
            node_ids=health.node_ids,
            sql_versions=versions,
            tls_mode=workload.tls_mode,
            image=workload.image,
            desired_replicas=workload.desired_replicas,
            workload_spec_hash=workload.workload_spec_hash,
            pvc_identities=pvc_identities,
            certificate_fingerprints=certificate_fingerprints,
            service_routing=service_routing,
        )

    def capture_accepted_state(
        self,
        ref: WorkloadRef,
        *,
        per_node_timeout: float = 5.0,
    ) -> AcceptedState:
        assessment = self.probe(
            ref,
            Requirement(Lifecycle.INITIALIZED),
            per_node_timeout=per_node_timeout,
        )
        if assessment.status is ProbeStatus.UNSATISFIED:
            raise InvalidRequirementError("cannot accept an unhealthy or incomplete CockroachDB observation")
        return self.accepted_state(assessment)

    def verify_accepted_state(
        self,
        ref: WorkloadRef,
        accepted: AcceptedState,
        *,
        per_node_timeout: float = 5.0,
    ) -> Assessment:
        current = self.probe(ref, Requirement(Lifecycle.INITIALIZED), per_node_timeout=per_node_timeout)
        observed = self.accepted_state(current)
        if observed != accepted:
            raise PreservationMismatchError("CockroachDB identity or preserved workload state changed")
        return current

    def reconcile(
        self,
        ref: WorkloadRef,
        requirement: Requirement,
        *,
        timeout: float = 30.0,
        poll_interval: float = 1.0,
        per_node_timeout: float = 5.0,
        accepted_state: AcceptedState | None = None,
    ) -> ReconcileResult:
        """Wait for existing state to meet a requirement; never creates or initializes."""
        if (
            type(timeout) not in (int, float)
            or type(poll_interval) not in (int, float)
            or not math.isfinite(timeout)
            or not math.isfinite(poll_interval)
            or timeout < 0
            or poll_interval <= 0
        ):
            raise InvalidRequirementError("timeout must be non-negative and poll_interval positive")
        deadline = time.monotonic() + timeout
        attempts = 0
        last_assessment: Assessment | None = None
        while True:
            attempts += 1
            try:
                last_assessment = self.probe(ref, requirement, per_node_timeout=per_node_timeout)
            except (RolloutInProgressError, TransientError) as error:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TransientError("CockroachDB did not become observable within the requested bound") from error
                time.sleep(min(poll_interval, remaining))
                continue
            if accepted_state is not None:
                current = self.accepted_state(last_assessment)
                if current != accepted_state:
                    raise PreservationMismatchError("CockroachDB state changed while reconciling")
            if last_assessment.status is ProbeStatus.SATISFIED:
                return ReconcileResult(assessment=last_assessment, changed_by_library=False, attempts=attempts)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return ReconcileResult(assessment=last_assessment, changed_by_library=False, attempts=attempts)
            time.sleep(min(poll_interval, remaining))

    @staticmethod
    def _probe_patch_operations(workload: Observation, raw_statefulset: Mapping[str, Any]) -> list[dict[str, Any]]:
        if workload.http_port is None:
            raise UnsupportedLayoutError("Probe preparation requires a resolved CockroachDB HTTP port")
        if workload.http_bind_host not in {"0.0.0.0", "::", "[::]"}:
            raise UnsupportedLayoutError(
                "HTTP probe preparation requires an explicitly externally reachable HTTP bind address"
            )
        if workload.http_transport is HTTPTransport.UNKNOWN:
            raise UnsupportedLayoutError("Probe preparation requires a resolved HTTP transport")
        spec = raw_statefulset.get("spec", {})
        template = spec.get("template", {}) if isinstance(spec, Mapping) else {}
        template_spec = template.get("spec", {}) if isinstance(template, Mapping) else {}
        containers = template_spec.get("containers", ()) if isinstance(template_spec, Mapping) else ()
        if workload.container_index >= len(containers):
            raise StaleIdentityError("Selected container disappeared before probe preparation")
        container = containers[workload.container_index]
        if not isinstance(container, Mapping) or container.get("name") != workload.container_name:
            raise StaleIdentityError("Selected container identity changed before probe preparation")
        port: int | str = workload.http_port_name or workload.http_port
        scheme = "HTTPS" if workload.http_transport is HTTPTransport.HTTPS else "HTTP"
        operations: list[dict[str, Any]] = []
        for probe_name, path in (("livenessProbe", "/health"), ("readinessProbe", "/health?ready=1")):
            probe = container.get(probe_name)
            if not isinstance(probe, Mapping):
                raise UnsupportedLayoutError("Probe preparation requires existing liveness and readiness probes")
            handlers = [handler for handler in _PROBE_HANDLERS if handler in probe]
            if len(handlers) != 1:
                raise UnsupportedLayoutError("Probe handler is missing or ambiguous")
            handler = handlers[0]
            current = probe.get(handler)
            if not isinstance(current, Mapping):
                raise UnsupportedLayoutError("Probe handler has an unsupported shape")
            if current.get("host") not in (None, ""):
                raise UnsupportedLayoutError("Probe preparation does not discard a custom probe host")
            if current.get("httpHeaders"):
                raise UnsupportedLayoutError("Probe preparation does not discard custom HTTP headers")
            expected = {"path": path, "port": port, "scheme": scheme}
            if _http_probe_handler_matches(
                handler,
                current,
                path=path,
                workload=workload,
                scheme=scheme,
            ):
                continue
            base = f"/spec/template/spec/containers/{workload.container_index}/{probe_name}"
            operations.append({"op": "remove", "path": f"{base}/{handler}"})
            operations.append(
                {
                    "op": "add",
                    "path": f"{base}/httpGet",
                    "value": expected,
                }
            )
        return operations

    def prepare_health_recovery_probes(
        self,
        ref: WorkloadRef,
        *,
        timeout: float = 60.0,
        poll_interval: float = 1.0,
        per_node_timeout: float = 5.0,
    ) -> ProbePreparationResult:
        """Replace only existing probe handlers with HTTP health checks.

        The operation is a single JSON Patch guarded by StatefulSet UID and
        resourceVersion. Re-running after an interrupted client is safe: the
        already-correct handlers result in a verified no-op.
        """
        if (
            type(timeout) not in (int, float)
            or type(poll_interval) not in (int, float)
            or not math.isfinite(timeout)
            or not math.isfinite(poll_interval)
            or timeout <= 0
            or poll_interval <= 0
        ):
            raise InvalidRequirementError("timeout and poll_interval must be positive")
        baseline = self.probe(ref, Requirement(Lifecycle.INITIALIZED), per_node_timeout=per_node_timeout)
        if baseline.status is not ProbeStatus.SATISFIED:
            raise InvalidRequirementError("probe preparation requires a healthy initialized cluster")
        accepted_before = self.accepted_state(baseline)
        workload = baseline.workload
        if workload.http_bind_host not in {"0.0.0.0", "::", "[::]"}:
            raise UnsupportedLayoutError(
                "Probe preparation requires an HTTP listener reachable by Kubernetes probes"
            )
        if workload.http_transport is HTTPTransport.UNKNOWN:
            raise UnsupportedLayoutError("Probe preparation requires a resolved HTTP transport")
        for path in ("/health", "/health?ready=1"):
            endpoint_results = self.probe_health_endpoint(ref, path=path, per_node_timeout=per_node_timeout)
            if any(not passed for _, _, passed in endpoint_results):
                raise TransientError("HTTP health endpoint preflight failed; StatefulSet was not changed")
        if workload.controller_owned:
            raise UnsupportedLayoutError("Probe preparation does not mutate StatefulSets owned by another controller")
        raw_statefulset = self.adapter.get_resource("statefulset", ref.namespace, ref.name)
        if raw_statefulset is None:
            raise MissingResourceError(f"StatefulSet {ref.namespace}/{ref.name} is missing")
        metadata = raw_statefulset.get("metadata", {})
        if not isinstance(metadata, Mapping) or metadata.get("uid") != workload.workload_uid:
            raise StaleIdentityError("StatefulSet identity changed before probe preparation")
        if metadata.get("resourceVersion") != workload.resource_version:
            raise StaleIdentityError("StatefulSet changed before probe preparation")
        if metadata.get("deletionTimestamp"):
            raise RolloutInProgressError("Selected StatefulSet is terminating")
        spec = raw_statefulset.get("spec", {})
        strategy = spec.get("updateStrategy", {}) if isinstance(spec, Mapping) else {}
        if isinstance(strategy, Mapping):
            if strategy.get("type", "RollingUpdate") != "RollingUpdate":
                raise UnsupportedLayoutError("Probe preparation requires the StatefulSet RollingUpdate strategy")
            rolling = strategy.get("rollingUpdate", {})
            if isinstance(rolling, Mapping) and rolling.get("partition", 0) != 0:
                raise UnsupportedLayoutError("Probe preparation does not support a partitioned StatefulSet rollout")
        operations = self._probe_patch_operations(workload, raw_statefulset)
        changed = bool(operations)
        if changed:
            self.adapter.patch_statefulset_json(
                namespace=ref.namespace,
                name=ref.name,
                uid=workload.workload_uid,
                resource_version=workload.resource_version,
                operations=[
                    {"op": "test", "path": "/metadata/uid", "value": workload.workload_uid},
                    {"op": "test", "path": "/metadata/resourceVersion", "value": workload.resource_version},
                    *operations,
                ],
                timeout=min(timeout, 20.0),
            )

        deadline = time.monotonic() + timeout
        last_error: Exception | None = None
        while True:
            try:
                after = self.probe(ref, Requirement(Lifecycle.INITIALIZED), per_node_timeout=per_node_timeout)
                accepted_after = self.accepted_state(after)
                if after.workload.probe_preservation_hash != workload.probe_preservation_hash:
                    raise PreservationMismatchError("Probe preparation changed workload state outside probe handlers")
                if replace(accepted_after, workload_spec_hash=accepted_before.workload_spec_hash) != accepted_before:
                    raise PreservationMismatchError("Probe preparation changed accepted cluster state")
                if not self.health_recovery_probes_prepared(after.workload):
                    raise PreservationMismatchError("Probe handlers do not match the requested HTTP health checks")
                for path in ("/health", "/health?ready=1"):
                    results = self.probe_health_endpoint(ref, path=path, per_node_timeout=per_node_timeout)
                    if any(not passed for _, _, passed in results):
                        raise TransientError("CockroachDB HTTP health endpoint is not ready on every pod")
                if after.status is ProbeStatus.SATISFIED:
                    return ProbePreparationResult(
                        changed=changed,
                        before=workload,
                        after=after.workload,
                        verified=after,
                        accepted_before=accepted_before,
                        accepted_after=accepted_after,
                    )
            except (RolloutInProgressError, TransientError) as error:
                last_error = error
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                if last_error:
                    raise RolloutInProgressError("Probe preparation did not finish within the requested bound") from last_error
                raise TransientError("CockroachDB did not become ready within the probe preparation bound")
            time.sleep(min(poll_interval, remaining))

    @staticmethod
    def health_recovery_probes_prepared(workload: Observation) -> bool:
        """Return whether the observed probe handlers match the health-recovery contract.

        This is a read-only predicate for callers that need to distinguish a
        semantically healthy cluster from one whose Kubernetes probes still
        need explicit preparation. It checks the observed TLS scheme and HTTP
        port as well as both fixed CockroachDB health paths.
        """
        if (
            workload.tls_mode not in (TLSMode.INSECURE, TLSMode.TLS)
            or workload.http_transport is HTTPTransport.UNKNOWN
            or workload.http_port is None
            or workload.http_bind_host not in {"0.0.0.0", "::", "[::]"}
        ):
            return False
        expected_scheme = "HTTPS" if workload.http_transport is HTTPTransport.HTTPS else "HTTP"
        return (
            workload.liveness_probe is not None
            and workload.readiness_probe is not None
            and _observed_probe_matches(
                workload.liveness_probe,
                path="/health",
                workload=workload,
                scheme=expected_scheme,
            )
            and _observed_probe_matches(
                workload.readiness_probe,
                path="/health?ready=1",
                workload=workload,
                scheme=expected_scheme,
            )
        )

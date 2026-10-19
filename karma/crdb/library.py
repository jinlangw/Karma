"""Safe readiness, carryover verification, and narrowly scoped probe repair."""

from __future__ import annotations

import csv
import io
import json
import math
import time
from collections.abc import Mapping
from dataclasses import replace
from typing import Any

from .adapter import ClusterAdapter
from .inspection import WorkloadInspector
from .types import (
    AcceptedState,
    Assessment,
    AuthenticationError,
    HealthObservation,
    InvalidRequirementError,
    Lifecycle,
    MissingResourceError,
    Observation,
    PreservationMismatchError,
    ProbePreparationResult,
    ProbeStatus,
    ReconcileResult,
    Requirement,
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
_PROBE_HANDLERS = ("httpGet", "tcpSocket", "exec", "grpc")


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


def _requirement_nodes(requirement: Requirement, workload: Observation) -> int:
    return requirement.minimum_nodes if requirement.minimum_nodes is not None else workload.desired_replicas


class CrdbLibrary:
    """CRDB common library with an injected, testable Kubernetes/SQL adapter.

    V1 observes existing workloads, performs fixed read-only SQL checks, waits
    within caller bounds, and can atomically rewrite only two probe handlers.
    It never creates a workload, initializes a cluster, resets data, or changes
    TLS, image, storage, replicas, services, or cluster identity.
    """

    def __init__(self, adapter: ClusterAdapter):
        self.adapter = adapter
        self.inspector = WorkloadInspector(adapter)

    def inspect(self, ref: WorkloadRef) -> Observation:
        return self.inspector.inspect(ref)

    def probe(
        self,
        ref: WorkloadRef,
        requirement: Requirement,
        *,
        per_node_timeout: float = 5.0,
    ) -> Assessment:
        if not isinstance(requirement, Requirement):
            raise InvalidRequirementError("requirement must be a Requirement value")
        if type(per_node_timeout) not in (int, float) or not math.isfinite(per_node_timeout) or per_node_timeout <= 0:
            raise InvalidRequirementError("per_node_timeout must be positive")
        workload = self.inspect(ref)
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
                tls=workload.tls_mode is TLSMode.TLS,
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
                cluster_id, node_id, version = _parse_witness(output)
                if cluster_id is None:
                    uninitialized.append(pod.name)
                else:
                    assert node_id is not None and version is not None
                    sql_ready.append(pod.name)
                    deployed.append(pod.name)
                    cluster_ids.append(cluster_id)
                    node_ids.append(node_id)
                    versions.append(version)
            except UninitializedError:
                uninitialized.append(pod.name)
            if pod.phase == "Running" and pod.container_state == "running" and (
                pod.name in sql_ready or pod.name in uninitialized
            ):
                if pod.name not in deployed:
                    deployed.append(pod.name)

        if sql_ready and uninitialized:
            raise RolloutInProgressError("Some CockroachDB nodes are initialized while others are not")
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
        tls = workload.tls_mode is TLSMode.TLS
        if workload.tls_mode is TLSMode.UNKNOWN:
            raise UnsupportedLayoutError("TLS mode cannot be resolved safely for HTTP health checks")
        results = []
        for pod in workload.pods:
            response = self.adapter.health_http(
                namespace=workload.namespace,
                pod_name=pod.name,
                container_name=workload.container_name,
                http_port=workload.http_port,
                tls=tls,
                certs_dir=workload.certs_dir,
                client_cert_available=tls,
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
        scheme = "HTTPS" if workload.tls_mode is TLSMode.TLS else "HTTP"
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
            if handler == "httpGet" and all(current.get(key) == value for key, value in expected.items()) and set(current) <= {
                "path", "port", "scheme"
            }:
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
                if not self._probes_match_preparation(after.workload):
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
    def _probes_match_preparation(workload: Observation) -> bool:
        expected_port: int | str = workload.http_port_name or workload.http_port
        expected_scheme = "HTTPS" if workload.tls_mode is TLSMode.TLS else "HTTP"
        return (
            workload.liveness_probe is not None
            and workload.readiness_probe is not None
            and workload.liveness_probe.handler == "httpGet"
            and workload.liveness_probe.path == "/health"
            and workload.liveness_probe.port == expected_port
            and workload.liveness_probe.scheme == expected_scheme
            and workload.liveness_probe.host is None
            and not workload.liveness_probe.has_custom_headers
            and workload.readiness_probe.handler == "httpGet"
            and workload.readiness_probe.path == "/health?ready=1"
            and workload.readiness_probe.port == expected_port
            and workload.readiness_probe.scheme == expected_scheme
            and workload.readiness_probe.host is None
            and not workload.readiness_probe.has_custom_headers
        )

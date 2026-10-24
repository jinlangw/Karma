"""Public, credential-safe data types for the CockroachDB support library."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import re


class Lifecycle(StrEnum):
    """The least lifecycle state a caller requires from the selected cluster."""

    DEPLOYED = "deployed"
    INITIALIZED = "initialized"


class TLSMode(StrEnum):
    INSECURE = "insecure"
    TLS = "tls"
    UNKNOWN = "unknown"


class HTTPTransport(StrEnum):
    """Observed transport for CockroachDB's HTTP listener, independent of SQL TLS."""

    HTTP = "http"
    HTTPS = "https"
    UNKNOWN = "unknown"


class ProbeStatus(StrEnum):
    SATISFIED = "satisfied"
    UNSATISFIED = "unsatisfied"


class ErrorCode(StrEnum):
    MISSING_RESOURCE = "missing_resource"
    UNSUPPORTED_LAYOUT = "unsupported_layout"
    STALE_IDENTITY = "stale_identity"
    API_ERROR = "api_error"
    AUTHENTICATION = "authentication"
    CONNECTION = "connection"
    UNINITIALIZED = "uninitialized"
    TRANSIENT = "transient"
    MIXED_INITIALIZATION = "mixed_initialization"
    ROLLOUT_IN_PROGRESS = "rollout_in_progress"
    PRESERVATION_MISMATCH = "preservation_mismatch"
    INVALID_REQUIREMENT = "invalid_requirement"


class CrdbError(RuntimeError):
    """A safe-to-report error; messages must never include secret values."""

    code = ErrorCode.API_ERROR


class MissingResourceError(CrdbError):
    code = ErrorCode.MISSING_RESOURCE


class UnsupportedLayoutError(CrdbError):
    code = ErrorCode.UNSUPPORTED_LAYOUT


class StaleIdentityError(CrdbError):
    code = ErrorCode.STALE_IDENTITY


class KubernetesAccessError(CrdbError):
    code = ErrorCode.API_ERROR


class AuthenticationError(CrdbError):
    code = ErrorCode.AUTHENTICATION


class ConnectionError(CrdbError):
    code = ErrorCode.CONNECTION


class UninitializedError(CrdbError):
    code = ErrorCode.UNINITIALIZED


class TransientError(CrdbError):
    code = ErrorCode.TRANSIENT


class MixedInitializationError(CrdbError):
    code = ErrorCode.MIXED_INITIALIZATION


class RolloutInProgressError(CrdbError):
    code = ErrorCode.ROLLOUT_IN_PROGRESS


class PreservationMismatchError(CrdbError):
    code = ErrorCode.PRESERVATION_MISMATCH


class InvalidRequirementError(CrdbError):
    code = ErrorCode.INVALID_REQUIREMENT


@dataclass(frozen=True, slots=True)
class WorkloadRef:
    namespace: str
    name: str
    container_name: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.namespace, str) or not isinstance(self.name, str):
            raise InvalidRequirementError("namespace and StatefulSet name must be strings")
        label = r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?"
        if not re.fullmatch(label, self.namespace) or len(self.namespace) > 63:
            raise InvalidRequirementError("namespace must be a valid Kubernetes DNS label")
        if len(self.name) > 253 or not all(re.fullmatch(label, part) for part in self.name.split(".")):
            raise InvalidRequirementError("StatefulSet name must be a valid Kubernetes DNS subdomain")
        if self.container_name is not None and (
            not isinstance(self.container_name, str)
            or len(self.container_name) > 63
            or not re.fullmatch(label, self.container_name)
        ):
            raise InvalidRequirementError("container_name must be a valid Kubernetes DNS label")
        if not self.namespace or not self.name:
            raise InvalidRequirementError("namespace and StatefulSet name are required")


@dataclass(frozen=True, slots=True)
class Requirement:
    """Readiness contract. ``None`` means preserve/accept the observed value."""

    lifecycle: Lifecycle
    minimum_nodes: int | None = None
    tls_mode: TLSMode | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.lifecycle, Lifecycle):
            raise InvalidRequirementError("lifecycle must be Lifecycle.DEPLOYED or Lifecycle.INITIALIZED")
        if self.minimum_nodes is not None and (
            type(self.minimum_nodes) is not int or self.minimum_nodes < 1
        ):
            raise InvalidRequirementError("minimum_nodes must be at least one")
        if self.tls_mode is not None and not isinstance(self.tls_mode, TLSMode):
            raise InvalidRequirementError("tls_mode must be a TLSMode or None")
        if self.tls_mode is TLSMode.UNKNOWN:
            raise InvalidRequirementError("UNKNOWN is an observation, not a TLS requirement")


@dataclass(frozen=True, slots=True)
class PortObservation:
    name: str | None
    number: int
    protocol: str = "TCP"


@dataclass(frozen=True, slots=True)
class MountObservation:
    name: str
    path: str
    read_only: bool
    source_kind: str
    source_name: str | None
    sub_path: str | None
    mounted_files: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True, slots=True)
class SecretFingerprint:
    name: str
    uid: str
    resource_version: str
    keys: tuple[str, ...]
    sha256_by_key: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class ProbeObservation:
    handler: str
    path: str | None = None
    port: int | str | None = None
    scheme: str | None = None
    host: str | None = None
    period_seconds: int | None = None
    initial_delay_seconds: int | None = None
    timeout_seconds: int | None = None
    failure_threshold: int | None = None
    success_threshold: int | None = None
    has_custom_headers: bool = False


@dataclass(frozen=True, slots=True)
class PodObservation:
    name: str
    sql_host: str | None
    uid: str
    owner_uid: str | None
    phase: str
    container_state: str
    container_ready: bool
    pod_ready: bool
    revision: str | None
    image: str
    startup_matches_template: bool


@dataclass(frozen=True, slots=True)
class SQLConnectionObservation:
    """Connection settings from one owned Pod; RPC host may be unresolved."""

    namespace: str
    workload_name: str
    workload_uid: str
    pod_name: str
    pod_uid: str
    container_name: str
    image: str
    sql_binary: str
    sql_host: str
    sql_port: int
    rpc_port: int
    tls_mode: TLSMode
    certs_dir: str | None
    rpc_host: str | None = None


@dataclass(frozen=True, slots=True)
class ServicePortObservation:
    name: str | None
    port: int
    target_port: int | str | None
    protocol: str


@dataclass(frozen=True, slots=True)
class ServiceObservation:
    name: str
    uid: str
    resource_version: str
    cluster_ip: str | None
    selector: tuple[tuple[str, str], ...]
    ports: tuple[ServicePortObservation, ...]
    routing_hash: str


@dataclass(frozen=True, slots=True)
class PvcObservation:
    name: str
    uid: str
    resource_version: str
    volume_name: str | None
    phase: str | None
    spec_hash: str


@dataclass(frozen=True, slots=True)
class EnvReference:
    name: str
    source: str
    secret_name: str | None = None
    secret_key: str | None = None
    has_literal_value: bool = False


@dataclass(frozen=True, slots=True)
class Observation:
    namespace: str
    name: str
    workload_uid: str
    controller_owned: bool
    resource_version: str
    generation: int
    observed_generation: int
    desired_replicas: int
    ready_replicas: int
    updated_replicas: int
    service_name: str
    advertised_sql_host_template: str | None
    container_name: str
    container_index: int
    image: str
    sql_binary: str
    workload_spec_hash: str
    probe_preservation_hash: str
    env_references: tuple[EnvReference, ...]
    tls_mode: TLSMode
    http_transport: HTTPTransport
    certs_dir: str | None
    sql_port: int
    rpc_port: int
    http_port: int | None
    sql_bind_host: str | None
    rpc_bind_host: str | None
    http_bind_host: str | None
    sql_port_name: str | None
    rpc_port_name: str | None
    http_port_name: str | None
    mounts: tuple[MountObservation, ...]
    secrets: tuple[SecretFingerprint, ...]
    liveness_probe: ProbeObservation | None
    readiness_probe: ProbeObservation | None
    pods: tuple[PodObservation, ...]
    services: tuple[ServiceObservation, ...]
    pvcs: tuple[PvcObservation, ...]
    volume_claim_templates: tuple[str, ...]
    controller_revision: str | None
    update_revision: str | None


@dataclass(frozen=True, slots=True)
class HealthObservation:
    lifecycle: Lifecycle
    cluster_id: str | None
    node_ids: tuple[int, ...]
    sql_versions: tuple[str, ...]
    sql_ready_pods: tuple[str, ...]
    uninitialized_pods: tuple[str, ...]
    deployed_pods: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Assessment:
    status: ProbeStatus
    reasons: tuple[str, ...]
    workload: Observation
    health: HealthObservation


@dataclass(frozen=True, slots=True)
class NodeStatusObservation:
    node_id: int
    membership: str | None
    is_draining: bool | None
    is_available: bool
    ranges_unavailable: int | None
    ranges_underreplicated: int | None
    is_live: bool | None = None


@dataclass(frozen=True, slots=True)
class NodeLivenessObservation:
    node_id: int
    membership: str
    draining: bool
    is_live: bool


@dataclass(frozen=True, slots=True)
class _ClusterHealthAssessment:
    """Read-only join of selected SQL nodes, node status, and KV liveness."""

    status: ProbeStatus
    reasons: tuple[str, ...]
    assessment: Assessment
    pod_node_ids: tuple[tuple[str, int], ...]
    node_status: tuple[NodeStatusObservation, ...]
    node_liveness: tuple[NodeLivenessObservation, ...]
    attempts: int = 1


@dataclass(frozen=True, slots=True)
class FullHealthAssessment(_ClusterHealthAssessment):
    """Serving health plus the requirement that ranges are fully replicated."""


@dataclass(frozen=True, slots=True)
class ServingHealthAssessment(_ClusterHealthAssessment):
    """Usable selected-node quorum, allowing under-replicated ranges."""


@dataclass(frozen=True, slots=True)
class AcceptedState:
    """A value projection suitable for explicit caller-owned carryover storage."""

    namespace: str
    workload_name: str
    workload_uid: str
    cluster_id: str | None
    node_ids: tuple[int, ...]
    sql_versions: tuple[tuple[str, str], ...]
    tls_mode: TLSMode
    image: str
    desired_replicas: int
    workload_spec_hash: str
    pvc_identities: tuple[tuple[str, str, str | None, str | None, str], ...]
    certificate_fingerprints: tuple[tuple[str, str, str, str], ...]
    service_routing: tuple[tuple[str, str, str], ...]


@dataclass(frozen=True, slots=True)
class ReconcileResult:
    """A bounded observation/wait result. V1 does not create or initialize."""

    assessment: Assessment
    changed_by_library: bool
    attempts: int


@dataclass(frozen=True, slots=True)
class ProbePreparationResult:
    changed: bool
    before: Observation
    after: Observation
    verified: Assessment
    accepted_before: AcceptedState
    accepted_after: AcceptedState

# CockroachDB common library

`cases.common.cockroachdb` provides a small shared interface for observing an existing
CockroachDB StatefulSet, checking semantic readiness, recording accepted
state, and preparing its HTTP health probes. It is independent of the
case-specific implementations under `cases/tests/cockroachdb`; it does not import
them or require a case directory.

Requires Python 3.11 or later. The focused suite was run on Python 3.12.

`cases.common.cockroachdb.storage.pvc_store_mappings()` shares the legacy CockroachDB store
flag and claim-template mount-path parsing used by case preparation. It only
returns volume-name/relative-path mappings; each case still owns PVC lookup,
identity checks, reset policy, cleanup, and recovery.

`cases.common.cockroachdb.connections.select_sql_readiness_flag()` shares the fixed
`SELECT 1;` candidate loop used by case readiness checks. The case owns its
ordered connection flags, caching, callback timeout, and unavailable message;
the helper returns the first successful flag and leaves other readiness,
Service, task, and recovery checks with the case.

`cases.common.cockroachdb.health.observe_initialization_state()` measures the configured
HTTP readiness endpoint on one already-observed Pod. It preserves the
caller-supplied error type for unsupported probe layouts and delegates the
bounded curl execution to the caller. Its result distinguishes the exact
CockroachDB deployed-but-uninitialized response from HTTP-ready state; it does
not establish SQL identity, cluster membership, or whole-cluster health.

`cases.common.cockroachdb.security.secure_template()` and `insecure_template()` return
transformed copies of supported CockroachDB StatefulSet templates. The secure
transform targets secure SQL and HTTPS readiness; the generate-cert inverse
retains that case's original command parser, certificate-path default, Secret
mount checks, and HTTPS-to-HTTP probe conversion. These helpers do not apply
the returned template, scale a StatefulSet, restart Pods, or choose when a
case should transition TLS modes. The caller owns those decisions and their
recovery policy.

```python
from cases.common.cockroachdb import CrdbLibrary, KubectlAdapter, Lifecycle, Requirement, WorkloadRef

library = CrdbLibrary(KubectlAdapter())  # uses the current kubectl context
ref = WorkloadRef("bench-crdb", "db")
assessment = library.probe(ref, Requirement(Lifecycle.INITIALIZED, minimum_nodes=3))
```

Full `inspect()` reads the StatefulSet, all selected Pods, Services, PVCs, and
the certificate Secrets required by a verified TLS mount. It reads `version()`
from each Pod, then uses a fixed SQL identity query on versions before 26.1 or
CockroachDB's fixed native HTTP identity endpoints on 26.1 and later. HTTP
transport is resolved independently from SQL TLS, including the supported
secure-SQL/plain-local-HTTP layout. The HTTP health checker only calls
CockroachDB's fixed `/health` and `/health?ready=1` endpoints. `probe()`
distinguishes a deployed but uninitialized process from a healthy initialized
cluster. It checks the fixed `/health?ready=1` endpoint before SQL. Only HTTP
503 with the exact JSON sentinel `node is waiting for cluster
initialization` establishes the deployed-but-uninitialized state; HTTP 200
proceeds to version and identity inspection. Authentication errors, unrelated
HTTP failures, and SQL/API errors remain errors. It never initializes a
cluster implicitly.

`inspect_sql_connection(ref, ordinal=0)` is the narrower observer for a
case-specific gateway SQL readiness check such as the original cluster-settings
`SELECT 1` gate. It reads the selected live Pod's startup flags and validates
that Pod's StatefulSet ownership and identity. It does not require peer Pods,
Services, PVCs, template convergence, or Secret-read access. For TLS, it returns
the resolved certificate directory without fingerprinting Secret contents;
the directory can come from explicit `--certs-dir` or a supported implicit
HOME/root default. The caller's actual SQL query validates that mounted
credentials work. The strict full
inspection and health APIs continue to validate Secret material and the whole
selected workload. This method is not a cluster-wide health or preservation
assessment, and unsupported SQL host layouts remain typed failures. Its
optional `rpc_host` is resolved independently from `--advertise-addr` or
`--advertise-host`; an explicit `--advertise-sql-addr` is never reused as the
RPC host. SQL-only inspection still succeeds when the RPC host cannot be
resolved, leaving `rpc_host=None` for callers that do not need RPC. When an
explicit advertised RPC port differs from the observed RPC listener port,
`rpc_host` is also left unset so callers cannot combine an advertised host
with the wrong port. The observation reports SQL and RPC listener ports;
advertised SQL port mappings are not modeled in this version.

For secure SQL, native HTTP identity uses CockroachDB's `auth-session login`
to obtain a short-lived cookie. CockroachDB stores an expiring row in
`system.web_sessions`; the library keeps the cookie only in process memory,
scoped to the observed Pod UID, endpoint, and certificate identity. This is an
observational operation with a bounded authentication-session side effect; it
does not alter user data or accepted workload configuration.

`capture_accepted_state()` records the observed cluster UUID and node IDs,
per-node SQL versions, TLS mode, image, replica count, full StatefulSet spec
hash, PVC identity and spec hashes, certificate fingerprints, and Service
routing. `reconcile()` can verify this accepted snapshot while waiting for a
requirement. A successful no-op reports `changed_by_library=False`. Its
`timeout` bounds the polling window between observations; an in-flight
observation can extend that window by the selected pods' bounded per-node
adapter operations, so it is not a hard total-call deadline.

`probe_full_health()` and `probe_serving_health()` are fixed observations of
the selected workload. They do not alter workload configuration, cluster
settings, or application data. For secure SQL on versions using native HTTP
identity, the bounded authentication step described above creates an expiring
`system.web_sessions` row. Both health operations require the same selected
Pod to node mapping, SQL node identity, active KV membership, live liveness
records, non-draining and available nodes, and zero unavailable ranges. Full
health also requires zero under-replicated ranges; serving health permits
under-replication while retaining the other checks. The corresponding
`wait_for_full_health()` and `wait_for_serving_health()` retry only typed
transient observations and rollout-in-progress states within a bounded
polling window. These APIs do not inspect or reconcile case-specific zone
placement policy.

CockroachDB's under-replication metric is not a universal proof that every
desired replica count is achievable. In v24.1.0, the metric's required voter
count is clamped to the number of available cluster nodes. Therefore a
five-replica table policy on a healthy three-node cluster can still report
zero under-replicated ranges. Callers must verify their specific zone policy
separately; `probe_full_health()` reports CockroachDB's fixed range-health
signals, not arbitrary placement-policy satisfaction.

Read-only full/serving health accepts a completed `OnDelete` rollout when the
StatefulSet observed generation is current, `updatedReplicas` equals the
desired replica count, and every selected Pod matches the validated
`updateRevision` and template. In that state, a lagging `currentRevision` is
controller status lag and does not block the health observation. This
completed-rollout allowance requires the convergence checks above. Stale
generations, wrong revisions, and non-image template mismatches still fail;
the existing read-only observation of image-only mixed rollouts is unchanged.
This allowance is limited to read-only health; strict inspection, probes, and
probe preparation keep their existing guards.

`prepare_health_recovery_probes()` is the only v1 workload-configuration
mutation. It requires a healthy initialized workload, checks both HTTP
endpoints before changing anything, and performs one JSON Patch guarded by
StatefulSet UID and resourceVersion. It changes only existing liveness and
readiness handlers to `/health` and `/health?ready=1`, using the observed HTTP/HTTPS scheme and
listener port. It preserves timing fields and verifies accepted state,
unrelated StatefulSet spec, the resulting probe handlers, and endpoint health
after rollout. It refuses controller-owned, terminating, `OnDelete`, or
partitioned StatefulSets, custom probe hosts or headers, and ambiguous
layouts.

Call `CrdbLibrary.health_recovery_probes_prepared(assessment.workload)` before
preparing probes when a caller needs a read-only decision. It returns true
only for a known insecure or TLS mode with both fixed health paths on the
observed HTTP listener. It treats a numeric port and the exact declared name
for that listener as equivalent, an omitted Kubernetes HTTP `scheme` as
`HTTP`, and an empty `host` or `httpHeaders` as the default. These equivalent
forms remain a no-op and do not roll the StatefulSet. A missing or incorrect
handler returns false; the caller can then choose the explicit mutator only
for a workload whose update strategy supports the guarded rollout.

The CLI is available with `python -m cases.common.cockroachdb`. Actions are `inspect`,
`probe`, `reconcile`, `capture`, `verify`, `health-endpoint`, and the explicit
mutating action `prepare-health-probes`. Exit codes are 0 for satisfied, 1
for unsatisfied, and 2 for typed errors. Accepted snapshots are redacted JSON;
startup scripts and literal environment values are never included. Store
accepted snapshots in a trusted location and pass them back with
`--accepted-state`.

The v1 inspector supports direct shell-wrapped CockroachDB `start` commands
and known Kubernetes Downward API substitutions for pod name and namespace.
It permits the standard admission-injected read-only ServiceAccount projection
only when its token, `kube-root-ca.crt`, and namespace Downward API sources
match the Kubernetes default layout; other live-only mounts remain unsupported.
The advertised SQL address must use an explicit literal DNS host for a
singleton or an explicit per-pod FQDN pattern. The cluster DNS domain is read
from the startup address; it is never guessed. SQL, RPC, and HTTP listener
ports come from supported CockroachDB flags or CockroachDB defaults, not
container port declarations. The deprecated `--http-port` alias is currently
unsupported and fails closed rather than being mistaken for the default HTTP
port. TLS must resolve to a supported certificate directory (explicit
`--certs-dir`, literal absolute `HOME`, or the guarded official-image root
default) and a read-only, validated Secret mount containing the root CA and
node certificate and key; a direct Secret volume and a single-source Secret
projection are supported. Unsupported command expansion, competing mounts,
`subPath`, ambiguous certificates, and unverified actual pod/template
differences fail closed.

The native HTTP identity route and SQL TLS/HTTP transport separation are
covered by unit tests, but they have not yet been exercised through this
library against a live cluster. No live 26.1+ restricted-internals validation
has been performed. A local HTTP listener selected with
`--unencrypted-localhost-http` is reachable from the in-container adapter but
not by a Kubernetes network probe. Probe preparation therefore rejects it
before issuing a StatefulSet patch. Use the observed HTTP transport when
evaluating health endpoints, and keep Kubernetes probe reachability as a
separate constraint.

This library does not create workloads, initialize or reset clusters, change
versions, apply TLS-mode transitions, alter topology or storage, decommission
nodes, or maintain a durable operation journal. The pure template helpers
above describe supported TLS-mode transformations but do not perform them.
A caller that needs bootstrap or broader transitions must provide a separate
explicit operation with its own preconditions and recovery record. The
library does not infer whether an unrecognized workload is safe to normalize.

Run the pytest-based CRDB-focused suite from the repository root with:

```sh
PYTHONDONTWRITEBYTECODE=1 python3.12 -m pytest -q tests/crdb
```

`unittest discover` does not collect all function-based CRDB tests; use
`pytest` to run the focused suite.

## Existing workflow validation

The existing `cert-rotation-audit` workflow review2 passed all four stages and
all four full final-sweep oracles. The existing three-stage
`cockroachdb-health-recovery` workflow review1 passed all three stages and all
three full final-sweep oracles. Together these runs passed seven stage oracles
and seven sweep oracles. Both used resource-limited external snapshots capped
at three database nodes and 1Gi per PVC, with cached v24.1.0 and the existing
v24.2.10 version-gap image. All seven stage agents reported `gpt-6-luna` with
`max` reasoning. Both workflows completed normal cleanup, followed by
independent checks that found no database workloads or PVCs/PVs.

The shared library is used by 13 applicable CockroachDB case folders; `deploy`
and `change-plan-only` are outside this scope. These representative workflows
validate only their executed stages and oracles. They do not certify every
recovery branch or every case end to end, and they do not validate live 26.1+
restricted-internals behavior.

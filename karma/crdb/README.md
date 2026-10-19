# CockroachDB common library

`karma.crdb` provides a small shared interface for observing an existing
CockroachDB StatefulSet, checking semantic readiness, recording accepted
state, and preparing its HTTP health probes. It is independent of the
case-specific implementations under `cases/cockroachdb`; it does not import
them or require a case directory.

Requires Python 3.11 or later. The focused suite was run on Python 3.12.

```python
from karma.crdb import CrdbLibrary, KubectlAdapter, Lifecycle, Requirement, WorkloadRef

library = CrdbLibrary(KubectlAdapter())  # uses the current kubectl context
ref = WorkloadRef("bench-crdb", "db")
assessment = library.probe(ref, Requirement(Lifecycle.INITIALIZED, minimum_nodes=3))
```

The adapter reads the StatefulSet, selected Pods, Services, PVCs, and only the
certificate Secrets required by a verified TLS mount. SQL inspection runs one
fixed `SELECT` witness per pod to observe cluster UUID, node ID, and SQL
version. It is read-only. The HTTP checker only calls CockroachDB's fixed
`/health` and `/health?ready=1` endpoints. `probe()` distinguishes a deployed
but uninitialized process from a healthy initialized cluster. It checks the
fixed `/health?ready=1` endpoint before SQL. Only HTTP 503 with the exact JSON
sentinel `node is waiting for cluster initialization` establishes the
deployed-but-uninitialized state; HTTP 200 proceeds to the fixed SQL witness.
Authentication errors, unrelated HTTP failures, and SQL/API errors remain
errors. It never initializes a cluster implicitly.

`capture_accepted_state()` records the observed cluster UUID and node IDs,
per-node SQL versions, TLS mode, image, replica count, full StatefulSet spec
hash, PVC identity and spec hashes, certificate fingerprints, and Service
routing. `reconcile()` can verify this accepted snapshot while waiting for a
requirement. A successful no-op reports `changed_by_library=False`. Its
`timeout` bounds the polling window between observations; an in-flight
observation can extend that window by the selected pods' bounded per-node
adapter operations, so it is not a hard total-call deadline.

`prepare_health_recovery_probes()` is the only v1 mutation. It requires a
healthy initialized workload, checks both HTTP endpoints before changing
anything, and performs one JSON Patch guarded by StatefulSet UID and
resourceVersion. It changes only existing liveness and readiness handlers to
`/health` and `/health?ready=1`, using the observed HTTP/HTTPS scheme and
listener port. It preserves timing fields and verifies accepted state,
unrelated StatefulSet spec, the resulting probe handlers, and endpoint health
after rollout. It refuses controller-owned, terminating, `OnDelete`, or
partitioned StatefulSets, custom probe hosts or headers, and ambiguous
layouts.

The CLI is available with `python -m karma.crdb`. Actions are `inspect`,
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
ports come from explicit CockroachDB flags or CockroachDB defaults, not
container port declarations. TLS requires an explicit `--certs-dir` and a
read-only, validated Secret mount containing the root CA and node certificate
and key; a direct Secret volume and a single-source Secret projection are
supported. Unsupported command expansion, competing mounts, `subPath`,
ambiguous certificates, and unverified actual pod/template differences fail
closed.

This library does not create workloads, initialize or reset clusters, change
versions, convert TLS modes, alter topology or storage, decommission nodes,
or maintain a durable operation journal. A caller that needs bootstrap or
broader transitions must provide a separate explicit operation with its own
preconditions and recovery record. The library does not infer whether an
unrecognized workload is safe to normalize.

Run the focused suite from the repository root with:

```sh
PYTHONDONTWRITEBYTECODE=1 python3.12 -m unittest discover -s tests/crdb -v
```

The focused suite currently has 50 passing tests on Python 3.12. A bounded
one-node v24.1.0 experiment passed for both an insecure fixture and a separate
TLS fixture, including no-op preservation and explicit HTTP probe preparation.
The experiment scope and results are documented in
[`experiments/crdb-common-library/README.md`](../../experiments/crdb-common-library/README.md)
and [`RESULTS.md`](../../experiments/crdb-common-library/RESULTS.md).

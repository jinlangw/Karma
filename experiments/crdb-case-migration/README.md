# CockroachDB case migration experiments

These isolated harnesses exercise specific `karma.crdb` case migrations. They
do not run a Karma solver workflow, deploy a controller, or modify native
workflow definitions. Use a unique evidence directory and verify the cleanup
journal after every run.

## Health-check-recovery

`health_recovery_case_smoke.py` validates the healthy-path library and actual
case fault units against sequential native-shaped insecure and TLS
three-node fixtures on cached CockroachDB v24.1.0. It uses 3 x 1Gi PVCs,
100m/256Mi requests and 1 CPU/1Gi limits per node, and pins to `kind-worker`
by default. It checks capacity and competing DB workloads before each phase,
uses no image pulls/builds, and performs normal UID-preconditioned cleanup.

## Cluster-settings

`settings_case_smoke.py` runs sequential insecure, TLS, and explicit
fresh-create phases, with one single-node fixture at a time. The first two
use the actual case probe/apply/verify commands, compare accepted state, keep
a two-row SQL witness, call the independent oracle's read-only `check()`
function before/after a controlled setting change and normal-grace
UID-guarded pod restart, and verify the witness afterward. The fresh phase
uses six temporary small manifests through the case helper's explicit
manifest-directory seam. Those one-node/1Gi manifests are experiment-only and
do not validate the production default topology or resource budget.

The settings harness calls `oracle.check()` directly; it does not execute the
oracle CLI's `main()`, a complete case workflow, or the Karma solver. It never
rewrites inherited probe handlers, resets an existing cluster, pulls images,
or force-deletes resources. Every created object is journaled by UID and
cleaned with normal grace and UID preconditions. Read
[`RESULTS.md`](RESULTS.md) for completed proof scope, and
[`/private/tmp/karma-crdb-case-migration-20261019/REPORT.md`](/private/tmp/karma-crdb-case-migration-20261019/REPORT.md)
for the durable external migration record.

## Zone-config

`zone_config_case_smoke.py --proof policy-carryover` validates the actual zone
environment `probe/apply/verify` path on one inherited three-node TLS fixture.
It changes only an owned witness table to a five-replica policy, observes
actual serving/full health without expecting positive under-replication, and
checks that the case preserves the policy, a controlled 128MiB setting, the
accepted workload state, Pod UIDs, and a two-row SQL witness. It does not run
the zone task oracle, create a fresh cluster, or run a solver. The separate
`--proof underreplication` mode retains its original positive-signal assertion;
the v24.1.0 three-node fixture did not establish that signal. See
[`RESULTS.md`](RESULTS.md) for the failed premise and successful
carryover-only proof.

Before any future live run, install Karma into the Python environment used by
the case command scripts and verify `karma.crdb` imports outside the
repository. Then run the selected harness with that Python, a unique evidence
directory, and the required cached test dependencies. Each phase performs a
fresh DB-slot, capacity, disk, storage-class, and cached-image preflight.

The bounded proofs validate only the native-shaped configurations explicitly
listed in `RESULTS.md`; they do not establish arbitrary manifest compatibility,
all topologies and versions, TLS mode conversion, bootstrap for every case,
or a full solver/workflow run.

## Rollback-rehearsal

`rollback_rehearsal_case_smoke.py` validates only the actual rollback
Environment `probe/apply/verify` path on one inherited three-node TLS fixture.
It verifies preservation of the accepted workload state, Pod/PVC/certificate/
Service identities, the controlled 128MiB setting, an owned witness-table GC
TTL, and a two-row SQL witness. The reviewed proof passed with the table TTL at
3600 seconds against the observed 14400-second range default. Review1 is a
preserved setup failure before any case command; see [`RESULTS.md`](RESULTS.md)
and the external report. The harness does not run the rollback task oracle,
`Targets.apply`, a second cluster, fresh bootstrap, or a solver workflow.

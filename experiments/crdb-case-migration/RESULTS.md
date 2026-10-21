# CRDB case migration proof results

The reviewed proof passed on 2026-10-19 with two sequential native three-node
fixtures on the cached `cockroachdb/cockroach:v24.1.0` image. The insecure
fixture completed UID-guarded cleanup before the TLS fixture began; both
phases exited successfully and left no database StatefulSets, PVCs, or PVs.

| Check | Insecure fixture | TLS fixture |
| --- | --- | --- |
| Nodes and SQL version | 3 nodes, IDs 1–3; v24.1.0 on each | 3 nodes, IDs 1–3; v24.1.0 on each |
| Before explicit init | `DEPLOYED` satisfied; `INITIALIZED` unsatisfied | `DEPLOYED` satisfied; `INITIALIZED` unsatisfied |
| Explicit Cockroach init | Succeeded over RPC listener 26258 | Succeeded over RPC listener 26258 |
| Health endpoint checks | All nodes returned HTTP 200 | All nodes returned HTTPS 200 |
| Cluster case unit | Probe required explicit health preparation; apply and verify passed | Probe required explicit health preparation; apply and verify passed |
| Fault case unit | Fault precondition, apply, verify, and idempotent retry checks passed | Fault precondition, apply, verify, and idempotent retry checks passed |
| Independent oracle | Rejected the planted fault; accepted the restored state | Rejected the planted fault; accepted the restored state |
| Data witness | Two known rows persisted across probe rollout and deterministic restore | Two known rows persisted across probe rollout and deterministic restore |
| Cleanup | UID-preconditioned normal deletion completed | UID-preconditioned normal deletion completed |

Both phases distinguished the deployed/uninitialized state before issuing the
explicit init command. They then verified SQL readiness, the exact health
handlers, accepted state across probe preparation, and accepted-state
restoration after the fault. The two-row witness digest was
`384dac095d870725bae3b2700d55dba09b61a05aaf15f1cd522e78b5cffeadd3` before
and after probe preparation and restoration in both phases. TLS certificate
fingerprints were recorded and preserved during the TLS fixture; raw
certificate and private-key bytes were not written to evidence.

The second attempt at
`/private/tmp/karma-crdb-case-migration-20261019/health-live-3node-20261019-review2/`
is the successful run. The earlier reviewed attempt at
`.../health-live-3node-20261019-review1/` passed setup, probe preparation,
fault injection, and oracle rejection but failed at deterministic restoration
because the harness patch command omitted its namespace. Its raw Kubernetes
error was intentionally not captured. A red regression reproduced the missing
namespace argument; the corrected command now explicitly targets the owned
namespace and retains UID/resourceVersion JSON Patch preconditions. The first
attempt remains preserved as a failed outcome and was not rerun automatically.

The full regression run after the correction passed 781 unit and CRDB tests,
2 subtests, and 7 integration tests; 2 integration tests were skipped. It ran
on Python 3.12.14 with bytecode writing disabled. Two existing tests emitted
`datetime.utcnow()` deprecation warnings.

Full phase journals, diagnostics, and ownership records are in the external
evidence directory above. This is a bounded case integration proof, not a
Karma solver workflow. It validates only the native-shaped three-node
v24.1.0 fixtures exercised here; it does not prove arbitrary manifests,
multi-version behavior, TLS mode conversion, or the remaining 14 cases.


## Cluster-settings reviewed smoke (2026-10-19)

The approved run at
`/private/tmp/karma-crdb-case-migration-20261019/settings-live-1node-20261019-review1/`
passed three sequential one-node phases on the cached
`cockroachdb/cockroach:v24.1.0` image with `imagePullPolicy: Never`:

| Phase | Result | Main checks |
| --- | --- | --- |
| Insecure inherited target | Passed; UID-preconditioned cleanup completed | Actual case `probe/apply/verify`; accepted-state no-op; direct oracle `check()` rejected pre-change setting, accepted after explicit change and after normal-grace pod restart; two-row SQL witness unchanged |
| TLS inherited target | Passed; UID-preconditioned cleanup completed | Same assertions over the native custom-cert mount and TLS connection; witness digest unchanged |
| Fresh create | Passed; UID-preconditioned cleanup completed | Case helper created and journaled exactly six objects (ServiceAccount, Role, RoleBinding, headless Service, public Service, StatefulSet); explicit init was tied to the new target; downward-API substitutions remained present |

Insecure and TLS witness SHA-256 values matched before/after the case's
no-op apply and after the controlled restart:
`1be721d5a60f53e41678beaa7ff31bbc988f6363f00c04879b3c8927e668c815`.
The oracle was called through its read-only `check()` function; the script's
`main()` was not run. No solver or complete case workflow ran.

The fresh-create phase used a temporary one-node manifest override with one
1Gi PVC, 100m/256Mi requests, and a 1 CPU/1Gi limit. It validates the helper's
create-only path and is not evidence for the native default topology or
resource budget. Native case manifests were not changed for this experiment.

Every phase rechecked the DB slot, free CPU/memory and disk, storage class,
and worker cache; each namespace and all created objects were cleaned before
the next phase. Final cluster inventory had only the original 15 infrastructure
Pods and no DB StatefulSet, Deployment, PVC, PV, or smoke namespace. No image
was built or pulled. This is a bounded case-level proof, not a solver run.

## Repository regression before readonly-audit

The Python 3.12.14 `tests/unit tests/crdb tests/integration` run reported
829 passed, 2 skipped, and 3 failures caused by sandbox denial of local
process/socket operations. Only the three failing test IDs were rerun with
elevated execution; all three passed. The full suite was not rerun. The
combined validated evidence is 832 passed and 2 skipped. Exact commands and
failure details are in the external
`settings-regression-20261019.md` record.


## Readonly-audit reviewed live proof (2026-10-19)

The parent-approved run at `/private/tmp/karma-crdb-case-migration-20261019/audit-live-3node-20261019-review1/` passed two sequential three-node phases using cached CockroachDB v24.1.0, `imagePullPolicy: Never`, three 1Gi PVCs, 100m/256Mi requests, and 1 CPU/1Gi limits. The TLS phase completed UID-preconditioned normal-grace cleanup before the fresh phase began. Each phase completed the same capacity guard; no image was built or pulled.

| Phase | Result | Main checks |
| --- | --- | --- |
| Native-shaped TLS inherited target | Passed; UID-preconditioned cleanup completed | Three pods were positively observed deployed/uninitialized before explicit RPC 26258 initialization. Actual cluster-settings preconditions observed and preserved `128 MiB`. Actual readonly-audit environment, baseline and report commands passed; a frozen authenticated baseline retry preserved its UID and ciphertext hash. Wrong stage key was rejected and remained only in memory/stdin. |
| Missing-target fresh fixture | Passed; UID-preconditioned cleanup completed | Actual `Environment.apply()` through `Cluster(manifest_dir=...)` created six absent resources, then actual environment probe/apply/verify passed. Accepted state, three Pod UIDs, and two-row witness were verified. |

In the TLS phase, actual readonly-audit oracle CLI rejected the missing report and accepted the report created from fresh `Audit.snapshot()` observations. The report uses the same snapshot reader as the oracle, so this proof does not claim an independent report parser. Before/after audit preparation comparisons preserved the full accepted snapshot, all three Pod UIDs, controlled setting, and witness. The two-row SQL witness SHA-256 was `e073b7b07a8d538f2ba5045e4fa119cd1433cc512217cf2afabfc943356376aa`. The encrypted baseline UID and digest stayed `b4f6c32a-9e88-470e-b9a0-be52a84d6133` / `0422730c58499cff2b5c71d83f7c1455e7dad57e5b1076e3f93cf94e934a118f` through the frozen retry. Evidence contains only artifact identities/hashes; no stage key, plaintext baseline, cert, or private-key bytes.

The fresh phase's six created objects were ServiceAccount, Role, RoleBinding, two Services, and StatefulSet. Its temporary manifest override used the same three-node/3Gi aggregate PVC and resource budget; this proves the case seam at three replicas, not the production native manifest defaults. A read-only post-start check confirmed the created StatefulSet had exactly 3 replicas. The harness now explicitly pins `BENCH_PARAM_REPLICA_COUNT=3`; the case-environment regression proves it overrides a caller value of `99` and restores that value afterward. The focused readonly-audit suites after this change passed **45 tests**.

The post-run inventory under `kind-kind` contained only the original 15 infrastructure Pods, with no StatefulSets, PVCs, or PVs. Both owned namespaces completed exact-UID cleanup using normal grace. Host free disk was 17GiB and kind-worker free disk 141GiB. No case workflow, solver, or automatic retry was run.

## Historical repository regression after readonly-audit

The complete supported-runtime command covered `tests/unit`, `tests/crdb`, and `tests/integration` once, with elevated execution to permit the existing localhost/socket tests. Python was 3.12.14 and bytecode writing was disabled. Result: **883 passed, 2 skipped, 2 warnings, and 2 subtests passed in 20.04s**. The warnings are existing `datetime.utcnow()` deprecations in `tests/unit/test_zone_config_preparation.py`. Full output is preserved at `/private/tmp/karma-crdb-case-migration-20261019/readonly-audit-final-regression-20261019.txt`. `git diff --check` passed.

## Zone-config TLS policy-carryover proof (2026-10-19)

The first zone attempt at
`/private/tmp/karma-crdb-case-migration-20261019/zone-live-3node-20261019-review1/`
tested the premise that a table-only `num_replicas=5` policy would produce
positive under-replication on three CockroachDB nodes. It did not produce the
expected signal, so the actual zone environment commands were not reached.
Pinned v24.1.0 source clamps required voter count to available cluster nodes;
the phase also did not preserve each poll's final counters. Preserve that
failed outcome and its source-supported explanation in the external report.

The next attempt at
`/private/tmp/karma-crdb-case-migration-20261019/zone-live-3node-20261019-review2-policy-carryover/`
stopped in capacity preflight before creating a namespace or database
resource. It was launched without elevated execution; its Python subprocess
could not connect to the local Kind API (`operation not permitted`). The
identical read-only Python subprocess query succeeded with elevated execution.
The journal recorded zero owned UIDs and completed cleanup. Keep its failure
record unchanged; its diagnostic gap from independently loaded
`SmokeFailure` classes was fixed in the harness and regression-tested.

The parent-approved retry at
`/private/tmp/karma-crdb-case-migration-20261019/zone-live-3node-20261019-review3-policy-carryover/`
passed one inherited TLS phase on cached CockroachDB v24.1.0, with three
CockroachDB nodes scheduled on the pinned `kind-worker`. Before changing the
owned witness table policy, the harness observed full health with node IDs
1–3, zero unavailable/under-replicated counts, the 128MiB controlled setting,
and the full accepted state. It changed only the witness table's policy to
`num_replicas=5`; the SQL readback remained 5. Both serving and full health
were SAT after the change, with the same selected Pod/node/liveness/status
IDs and zero unavailable/under-replicated counts. This does not demonstrate
positive under-replication or verify arbitrary zone placement constraints.

The actual zone environment `probe`, `apply`, and `verify` commands all
passed. The table policy remained 5, the setting remained 128MiB, the accepted
workload state and all three Pod UIDs were unchanged, and the two-row SQL
witness remained unchanged with SHA-256
`e073b7b07a8d538f2ba5045e4fa119cd1433cc512217cf2afabfc943356376aa`.
PVC identities, certificate fingerprints, image/version, cluster UUID, and
Service routing also matched. Cleanup completed with exact UID preconditions
and normal deletion grace. Final inventory had only the original 15
infrastructure Pods and no DB StatefulSet, PVC, PV, proof namespace, or active
runner. No task oracle, fresh bootstrap, solver, or full workflow ran.

The harness records bounded structured health samples before cleanup. The
zone proof is limited to the inherited native-shaped TLS/v24.1.0 path and
policy carryover; positive under-replication remains covered by independent
library tests, and fresh-zone bootstrap remains unit-tested only.

## Final repository regression after zone-config (2026-10-19)

After the inherited TLS policy-carryover proof and final documentation updates,
the supported Python 3.12.14 command covered `tests/unit`, `tests/crdb`, and
`tests/integration` once, with elevated execution for the existing
localhost/socket tests and `PYTHONDONTWRITEBYTECODE=1`. Result: **934 passed,
2 skipped, 2 subtests passed, and 2 existing `datetime.utcnow()` deprecation
warnings in 20.23s**. Full output is preserved at
`/private/tmp/karma-crdb-case-migration-20261019/zone-final-regression-20261019.txt`.
`git diff --check` passed. Final SHA-256 comparison covered all 144 original
CockroachDB source files: exactly 10 intended files changed, 134 unchanged,
none missing or added. The other cases' files remain byte-identical to the
recorded baseline.

## Rollback-rehearsal inherited TLS environment proof (2026-10-19)

The first reviewed attempt at
`/private/tmp/karma-crdb-case-migration-20261019/rollback-live-3node-20261019-review1/`
reached three running TLS Pods, positively observed deployed/uninitialized,
initialized over RPC 26258, and reached initialized semantic readiness and
Kubernetes Ready. It then stopped while preparing the owned witness-table GC
policy, before any rollback Environment command. The fixed table TTL was not
distinct from the range default. The immutable phase recorded only that
comparison failure, not the numeric default/request/readback values. Exact-UID
normal-grace cleanup completed and post-run inventory found no database
workloads, PVCs, PVs, proof namespace, or runner. This was proof setup failure,
not a rollback Environment failure; no case command ran.

The parent-approved corrected attempt at
`/private/tmp/karma-crdb-case-migration-20261019/rollback-live-3node-20261019-review2/`
passed on cached `cockroachdb/cockroach:v24.1.0` with three nodes on
`kind-worker`, three 1Gi PVCs, 100m/256Mi requests, 1 CPU/1Gi limits, and
`imagePullPolicy: Never`. The observed range-default GC TTL was 14400 seconds;
the harness selected and read back an owned witness-table TTL of 3600 seconds.
All three actual rollback Environment commands—probe, apply, verify—returned 0.

The proof verified the accepted workload state, three Pod UIDs, PVC/PV
identities, certificate fingerprints, Service routes, image/version, and
cluster UUID were preserved. The controlled setting remained 128MiB, the
witness-table TTL remained 3600 against the 14400 default, and the two-row SQL
witness digest remained
`e073b7b07a8d538f2ba5045e4fa119cd1433cc512217cf2afabfc943356376aa`.
Exact-UID normal-grace cleanup completed. Independent post-run inventory found
only the original 15 infrastructure Pods and five system namespaces, with no
DB workload, PVC, PV, proof namespace, or active runner. No rollback task
oracle, target apply, fresh bootstrap, second cluster, solver, or full workflow
ran. Review1 remains unchanged and both outcomes are recorded separately in
the external report.

The corrected proof harness selects 3600 seconds unless the observed range
default is 3600, in which case it selects 7200. It checkpoints the observed
default, requested TTL, and readback (or readback error type) before each
assertion. Focused rollback environment and harness tests passed 54 tests.

## Final repository regression after rollback-rehearsal (2026-10-19)

The supported Python 3.12.14 run covered `tests/unit`, `tests/crdb`, and
`tests/integration` once with `PYTHONDONTWRITEBYTECODE=1` and elevated execution
for existing local socket tests. Result: **981 passed, 2 skipped, 2 subtests
passed, and 2 existing `datetime.utcnow()` deprecation warnings in 20.73s**.
The preserved output is
`/private/tmp/karma-crdb-case-migration-20261019/rollback-final-regression-20261019.txt`.
`git diff --check` passed. The original CockroachDB baseline has 144 files;
13 intended differences span the five validated cases, 131 hashes match, and
no files are missing or added. Exact changed paths are in the external
`baseline-verification-after-rollback.json`.


## Cluster-settings inherited TLS recovery (2026-10-20)

The corrected review3 run passed on one cached v24.1.0 TLS fixture:
 /private/tmp/karma-crdb-case-migration-20261019/settings-recovery-tls-1node-20261020-review3/
The selected target was observed DEPLOYED/uninitialized, the owned Pod was restarted, and the
original recovery policy recreated its StatefulSet and PVC from observed configuration before
explicit initialization. The actual case probe/apply/verify commands all passed.

TLS mode, image, desired replicas, StatefulSet workload-spec hash, Services/routing, and
certificate fingerprints were preserved. Pod, StatefulSet, PVC, and PV identities changed as
expected. Fixture data/settings reset was intentional; this proof makes no cross-recreate data
continuity claim. Exact-UID normal cleanup completed. Independent postflight found only the
original 15 infrastructure Pods, two infrastructure Deployments, five standard namespaces, and
no DB workload, Pod, PVC, PV, or active runner.

Review1 and review2 remain preserved failures. Review1 stopped before delete; the adapter's
canonical Pod-kind mismatch was reproduced offline but the original live cause is unproven.
Review2 recreated the target but failed before init intent; its RuntimeError detail was withheld.
The old RPC-host guard was reproduced offline against explicit split RPC/SQL advertisement flags
and corrected; that is the likely review2 cause, not a recovered live message. Review3 passed
after this correction. This is a bounded case recovery proof, not a full case workflow or solver
run, and it does not validate multi-node recovery or interrupted-reset resumption.

The current supported Python 3.12 full regression passed 1032 tests, skipped 2, and passed 38
subtests; see the external REPORT.md and CHECKPOINT.json for commands and exact logs.


## Startup helper extraction — 2026-10-20T07:01:21Z

`database_container`, `arguments`, and `flag_value` were moved to `karma.crdb.startup` and wired through thin wrappers in seven base-identical case clusters: readonly-audit, rollback-rehearsal, zone-config, monitoring-integration, version-check, initialize, and major-upgrade-finalize. Each wrapper injects that case's existing `UnsafeState` type. The extraction preserves the original function bodies after normalizing that injected error class; it changes no case lifecycle, recovery policy, YAML, task, or oracle. It is not a whole-case migration for initialize or major-upgrade-finalize.

Per-case focused tests, all including the shared seven-wrapper test, passed: readonly-audit 41, rollback 50, zone 67 (two existing datetime warnings), monitoring 30, version-check 83, initialize 19, major-upgrade-finalize 19. Exact logs and offline AST parity evidence are in the external `CONTINUATION.md` and `CHECKPOINT.json`. The 144-file original case baseline is now 10 changed, 134 unchanged, none missing or added. `git diff --check` passed. No broad suite or live proof was run for this pure extraction.


## P039 Service preservation component proof — 2026-10-20

The parent-reviewed opt-in `tls-service-preservation` proof passed on one cached v24.1.0 node with a 1Gi PVC. Evidence: `/private/tmp/karma-crdb-case-migration-20261019/certificate-rotation-service-preservation-1node-20261020-review1`; source-input snapshot and hashes: `/private/tmp/karma-crdb-case-migration-20261019/certificate-rotation-service-preservation-1node-20261020-review1-inputs`. The actual component check returned headless/public 4/0 before repair and 0/0 after applying the original rendered headless Service spec with only harness ownership metadata added. The headless Service UID was retained with its expected routing change; the public NodePort Service full spec, UID, and allocated nodePorts were unchanged.

TLS-only readiness failed before and passed after the transform; both HTTPS health endpoints returned 200. Cluster UUID/node ID, image/version, PVC/PV identities, certificate Secret fingerprints, and two-row witness hash were preserved. Pod UID changed as expected. UID-guarded normal cleanup completed, and independent postflight found no DB workloads, PVCs, or PVs. The task oracle and full shell/toolbox/CA/solver workflow were not run.

The focused harness suite reported **59 passed** in the parent-reviewed run; no separate transcript was retained. Earlier focused source/service validation remains **232 passed, 42 subtests** (`/private/tmp/karma-crdb-case-migration-20261019/p039-service-focused-20261020-r1.log`). The latest broad suite remains **1218 passed, 2 skipped, 42 subtests** (`/private/tmp/karma-crdb-case-migration-20261019/p039-service-broad-20261020-r1.log`); it predates the final harness-only tests, so it is not claimed to cover them. Original-case baseline remains 16 modified and 128 unchanged of 144, plus two new certificate-rotation helpers.

Next design only: a legacy-first TLS-only observed SQL-connection retry for the certificate-rotation oracle. Keep all cert fingerprint, CA, served-leaf, expiry, per-node retry, and task assertions unchanged; custom HTTP endpoint behavior remains outside the proposed first slice.


## Certificate-rotation Oracle SQL connection helper (P040, 2026-10-20)

The opt-in `oracle-sql-connection` proof passed once on one cached v24.1.0 TLS node: `/private/tmp/karma-crdb-case-migration-20261019/certificate-rotation-oracle-sql-connection-1node-20261020-review1`. Before explicit init, `secure_sql_result()` returned its original legacy secure-SQL failure and left lifecycle DEPLOYED. After one explicit init and after a normal UID-guarded Pod restart, it succeeded via the shared observed TLS endpoint (container `db`, `/cockroach/cockroach`, Pod DNS port 26258, `/root/.cockroach-certs`); no insecure retry was made. The controlled 128 MiB setting, accepted workload projection, two-row witness digest, and HTTPS health endpoints were preserved. Normal exact-UID cleanup and independent cluster postflight completed.

Focused: 75 passed (`/private/tmp/karma-crdb-case-migration-20261019/p040-oracle-connection-harness-focused-20261020-r1.log`). Broad: 1245 passed, 2 skipped, 42 subtests, with two existing datetime deprecation warnings (`/private/tmp/karma-crdb-case-migration-20261019/p040-oracle-connection-broad-20261020-r1.log`). Original case baseline: 17 modified, 127 unchanged of 144, plus two certificate-rotation helpers (`/private/tmp/karma-crdb-case-migration-20261019/baseline-verification-after-p040-oracle-sql-connection-20261020-r1.json`). Source snapshot and SHA-256 manifest: `/private/tmp/karma-crdb-case-migration-20261019/certificate-rotation-oracle-sql-connection-1node-20261020-review1-inputs`. This is a helper proof only; Oracle `main()`, task assertions, full workflow, solver, multi-node behavior, and other versions were not run.


## Initialize certificate-directory resolver (P041, 2026-10-20)

Initialize now shares the certificate-directory resolver between SQL client connection flags and preparation preflight. Explicit `--certs-dir` spelling remains unchanged in client arguments, while preflight uses the effective path for the existing mounted-Secret, HTTPS, and certificate-file checks. Root default, literal HOME, and relative paths are covered by focused tests; initialization, reset, and recovery policy are unchanged.

Focused validation passed **62 tests** in the parent-reviewed P041 run; a standalone transcript was not retained. AST parity against `352c0608` confirms `prepare.py` and `Cluster.client` match after normalizing only the new StatefulSet observation argument and effective-directory resolution. Artifacts: `/private/tmp/karma-crdb-case-migration-20261019/p041-initialize-ast-parity-20261020-r1.json` and `/private/tmp/karma-crdb-case-migration-20261019/baseline-verification-after-p041-initialize-certs-20261020-r1.json`.

The supported Python 3.12 broad suite passed **1259**, skipped **2**, and passed **42 subtests**, with two existing datetime deprecation warnings: `/private/tmp/karma-crdb-case-migration-20261019/p041-initialize-certdir-broad-20261020-r1.log`. The baseline contains 18 modified and 126 unchanged original case files of 144, no missing originals, and two new certificate-rotation helper files; all original case YAML remains unchanged.

This is focused/unit and AST evidence for the initialize certificate-path seam, not a live initialize/reset workflow proof. P040's live SQL-observer proof used the common resolver in a separate certificate-rotation helper; it does not validate the full initialize path. The current source-based 15-case inventory is `/private/tmp/karma-crdb-case-migration-20261019/CASE-INVENTORY-20261020-r1.md`.


## P042/P043 pure shared-measurement extractions — 2026-10-20

P042 centralizes identical connection-flag assembly in six wrappers; initialize remains distinct to preserve its explicit certificate-path client argument. Six-case AST parity: `/private/tmp/karma-crdb-case-migration-20261019/p042-six-case-connection-flags-parity-20261020-r1.json`. P043 centralizes the original `node_state()` HTTP readiness observation through the existing helper across all seven original wrappers, with caller error types and surrounding policy unchanged; parity: `/private/tmp/karma-crdb-case-migration-20261019/p043-seven-case-node-state-parity-20261020-r1.json`. Combined focused validation passed 224 (`/private/tmp/karma-crdb-case-migration-20261019/p043-seven-case-node-state-focused-20261020-r1.log`).

The supported Python 3.12 broad suite passed **1303**, skipped **2**, and passed **42 subtests**, with two existing datetime deprecation warnings: `/private/tmp/karma-crdb-case-migration-20261019/p042-p043-connection-flags-node-state-broad-20261020-r1.log`. Baseline: 18 modified and 126 unchanged of 144 original case files, no missing files, two added certificate-rotation helpers, and no original YAML changes: `/private/tmp/karma-crdb-case-migration-20261019/baseline-verification-after-p042-p043-20261020-r1.json`. These pure extractions had no live fixture or task-oracle run.

Next proposal is P044 mounted-Secret signature calculation extraction only; it awaits parent design review and has no source changes yet.

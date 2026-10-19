# CockroachDB common library experiment results

The standalone `karma.crdb` library passed one sequential live experiment on
2026-10-19 UTC using the cached `cockroachdb/cockroach:v24.1.0` image and a
single Kind worker. The insecure and TLS fixtures used separate namespaces
and PVCs; the next fixture started only after the previous one was fully
cleaned up.

| Check | Insecure fixture | TLS fixture |
| --- | --- | --- |
| Pre-init requirement | Satisfied as `DEPLOYED`; node remained uninitialized | Satisfied as `DEPLOYED`; node remained uninitialized |
| Explicit initialization | RPC listener `26258`; succeeded in 697 ms | RPC listener `26258`; succeeded in 671 ms |
| Initialized semantic readiness | Satisfied | Satisfied |
| SQL witness | Two rows; before/after digest matched | Two rows; before/after digest matched |
| `/health` and `/health?ready=1` | HTTP 200, healthy | HTTPS 200, healthy |
| Accepted-state reconcile | No-op; `changed_by_library=false` | No-op; `changed_by_library=false` |
| Probe preparation | HTTP `/health` and `/health?ready=1` handlers | HTTPS `/health` and `/health?ready=1` handlers |
| Preservation verification | Passed; unrelated-spec preservation hash unchanged | Passed; unrelated-spec preservation hash unchanged |
| Cleanup | UID-preconditioned normal cleanup completed | UID-preconditioned normal cleanup completed |

The row digest matched before and after the probe rollout in each fixture.
The test recorded the cluster UUID, node ID, SQL version, PVC and PV identity,
Service routing, and certificate fingerprints. The accepted-state check passed
after each mutation. TLS was preserved within the secure fixture; this test did
not transition an existing cluster between TLS modes. Raw certificate and key
bytes were never written to the evidence directory.

The proof used one node and one 1Gi PVC at a time. The fixture requested
100m CPU and 256Mi memory and was limited to 1 CPU and 1Gi memory. It used the
cached image with `imagePullPolicy: Never`; no image build or pull occurred.
Final cluster inventory showed only the original 15 infrastructure Pods and
no CockroachDB Pod, StatefulSet, PVC, or PV.

A separate diagnostic-only run on the same image and pod configuration showed
that the node reached Running, the original Kubernetes Ready wait passed in
6.46 seconds, and the deployed/uninitialized semantic probe passed both before
and after Ready. This contradicts the earlier attribution that the third old
failure occurred before Ready. The old run only recorded a generic bounded
`kubectl` failure, and its exact operation remains unattributed; no retrospective
root cause is claimed. The three original failed-run records remain preserved.

Full safe evidence, including per-phase operation timings and cleanup journals,
is under
`/private/tmp/karma-crdb-common-library-20261018/run-200511-23314/resume-20261019T0636Z/`:

- `live-diagnostic-20261019T0651Z/insecure-phase.json`
- `live-proof-20261019T0647Z/live-summary.json`
- `live-proof-20261019T0647Z/insecure-journal.json`
- `live-proof-20261019T0647Z/tls-journal.json`
- `cases-cockroachdb-final-verification.json`

The final focused suite ran 50 tests on Python 3.12. Existing regression runs
from the prior checkpoint recorded 702 passes and 2 skips; three localhost
bind tests passed when rerun with approved socket access. See the external
evidence report for the complete commands and historical outcomes.

This experiment does not establish multi-node behavior, general bootstrap,
version or topology changes, TLS-mode conversion, decommissioning, controller
integration, or durable operation journaling. Those features remain outside
the v1 library contract.

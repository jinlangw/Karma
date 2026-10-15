# Version check

The solver reports the **active feature version**, while every selected node runs
a newer binary family. It must not upgrade, finalize, or change the database.

Four units prepare the task:

1. `crdb_env_ready` reuses a healthy selected StatefulSet, supports inherited TLS
   and insecure mode, and repairs/recreates only selected exclusive stores when
   database failure is confirmed. Control-plane failures do not justify resets.
   On 26.1+, identity uses pinned, tested status API payloads and native node
   status instead of restricted internal SQL. Permission/capability failures
   never authorize a store reset. Secure status requests use native two-minute
   HTTP sessions cached only in memory; other sessions are never revoked. No
   unsafe-internals override is enabled.
   Fresh one/two-node stores receive matching built-in replication settings so
   real range health can converge (two replicas explicitly use one voter); healthy inherited zone settings are untouched.
2. `crdb_feature_version_gap_ready` reuses a coherent held gap; otherwise it
   establishes the hold **before** rolling to the next pinned release family.
   Mixed compatible binaries converge to the inherited newer patch. A finalized
   ceiling/unsupported release state uses fresh selected stores and the fallback
   pair. This expected regression loses selected-cluster data. Other clusters,
   namespace resources, TLS material, replicas and non-version workload
   configuration are preserved. Preparation records and reset markers resume
   interrupted work, including a leftover compatibility helper from the other
   source/target candidate; foreign helpers are preserved. Healthy peers are checked throughout rolling updates.
3. `crdb_version_report_absent` clears only the report for this cluster/run/stage.
4. `crdb_version_baseline_ready` refreshes an authenticated encrypted version-state
   snapshot before the first solver launch. All four units preserve the original
   frozen snapshot and submission on agent retries. The oracle compares the
   readable report and live held state with that snapshot. Completed plaintext
   version-preparation records are removed before the solver starts.

`from_version` accepts a release family or an exact source patch. `to_version`
selects the fallback newer binary; an effective fallback always crosses one
compatible release edge. Legacy same-family pairs remain accepted as bootstrap hints:
preparation chooses the next pinned family rather than creating a patch-only
challenge. Reusing a healthy inherited gap does not enforce either fallback
version. Healthy equal-family clusters advance to the next pinned release family,
preserving inherited data. This smallest step keeps older workflow preparers
within their adjacent rolling compatibility window. Explicit fallback pairs and
inherited gaps can use documented Regular-release skips. No active feature
version is downgraded in place.

The report parameter is a **prefix**. The prompt gives the exact formula for its
cluster/run/stage suffix. Reports and encrypted baselines from earlier stages are
preserved, including repeated audits of the same cluster with the same report key.

The pinned release graph includes historical workflow compatibility releases;
that does not assert current vendor support. See the dated
[official-source research](../../../docs/research/cockroachdb-version-check-supported-releases-20261015.md)
for all currently supported families, exact patches, registry ARM64/AMD64 checks,
upgrade rules and licensing requirements. Newly published images must be
intentionally qualified before changing these pins. The ceiling is deterministic,
not a floating `latest` tag. No license safeguards are bypassed.

Keys use the existing framework's process-memory stage-key support and trusted
stdin. This prevents disclosure through ordinary environment/artifact files;
it does not promise isolation from same-user process debugging in a local sandbox.
Losing the orchestrator's key causes verification to fail closed.

Final sweeps may report expected regressions when this setup advances a binary
asserted by an earlier upgrade stage, or when a later stage deliberately changes
the recorded version/hold/workload state. Stage-time and final-sweep outcomes
must be reported separately.

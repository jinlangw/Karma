# CockroachDB major-upgrade-finalize chainability

Research date: 2026-10-14. This note evaluates fixture design; it does not modify the case. Recommendations below are proposed Karma behavior, not CockroachDB guarantees.

## What the existing case requires

The local [test definition](../../cases/cockroachdb/major-upgrade-finalize/test.yaml) defaults to source release series `23.2` and target binary `24.1.0`. Its task requires upgrading binaries and then finalizing, with availability maintained. Some existing workflows instead configure `24.1` → `24.2.0`, for example [incident-then-upgrade](../../workflows/suite/cockroachdb-incident-then-upgrade.yaml). Setup currently skips on StatefulSet presence or any Running pod; its missing-environment apply deletes the namespace, creates source nodes, initializes them, and holds finalization. Neither existence nor a successful SQL query establishes the required source version or upgrade hold.

## Verified upstream rules

### Historical target releases

- The v24.1 guide lists production v23.2 releases as eligible sources. Earlier production releases are directed through subsequent major releases; a previous upgrade must be finalized before the next one. The page states no minimum v23.2 patch floor for this path. This establishes the documented major-release path, not a claim that every old patch is free of bugs. [v24.1 upgrade guide](https://docs.cockroachlabs.com/docs/v24.1/upgrade-cockroach-version#step-1-verify-that-you-can-upgrade)
- The v24.2 guide similarly lists production v24.1 releases and no minimum v24.1 patch floor. Its major-release transition is v24.1 → v24.2. Mixed binary versions are temporary during rolling upgrades; all nodes should be uniform before starting another upgrade. Dead, non-decommissioned or partially decommissioned nodes can block finalization. [v24.2 upgrade guide](https://docs.cockroachlabs.com/docs/v24.2/upgrade-cockroach-version)

These are version-specific rules. Do not apply a contemporary upgrade diagram or unrelated release's minimum patch requirement to the pinned historical targets. The current rendered historical pages contain newer licensing text; this note does not infer licensing requirements for `24.1.0` or `24.2.0` from that text.

### Binary version and logical cluster version are separate

All nodes can run v24.1 binaries while the logical cluster version remains `23.2`. Finalization runs migrations affecting system schemas, indexes, descriptors, and features; when complete, `SHOW CLUSTER SETTING version` advances. Setting `cluster.preserve_downgrade_option` to the current logical version holds this process; assigning another value is rejected. Resetting the hold re-enables finalization under the documented default policy. [v24.1 upgrade guide](https://docs.cockroachlabs.com/docs/v24.1/upgrade-cockroach-version#step-3-decide-how-the-upgrade-will-be-finalized)

The v24.1.0 source represents stable logical versions separately from transitional internal versions; a nonzero internal component identifies progress between stable releases. Scripts must parse this state rather than compare formatted strings lexicographically. [Pinned v24.1.0 version definitions](https://github.com/cockroachdb/cockroach/blob/v24.1.0/pkg/clusterversion/cockroach_versions.go)

### Rollback has a limited window

A v24.2 binary upgrade can roll back to v24.1 before major finalization, using one node at a time. The guide also permits rollback to an earlier patch within v24.2. After major finalization, rollback to the previous major release is unavailable. Equivalent v24.1 → v23.2 pre-finalization rollback is documented. [v24.2 rollback guide](https://docs.cockroachlabs.com/docs/v24.2/upgrade-cockroach-version#step-5-roll-back-the-upgrade-optional), [v24.1 rollback guide](https://docs.cockroachlabs.com/docs/v24.1/upgrade-cockroach-version#step-5-roll-back-the-upgrade-optional)

Pinned v24.1.0 validation rejects decreasing the logical cluster version. It also rejects a cluster version above the binary's supported maximum; the update-validation path treats incompatibility as fatal. Changing an image tag therefore does not undo persisted version state. [Pinned version validation](https://github.com/cockroachdb/cockroach/blob/v24.1.0/pkg/clusterversion/setting.go#L154-L230)

Current official guidance is stricter about the boundary: rollback is unavailable once finalization begins, not merely after completion. Treat an active migration or transitional logical version as outside the simple rollback path. [Current self-hosted upgrade guide](https://docs.cockroachlabs.com/docs/stable/upgrade-cockroach-version#perform-a-major-version-upgrade)

### Carryover can contain a second finalization hold

`cluster.auto_upgrade.enabled` already exists in v23.2.0 and defaults to true. [Pinned v23.2.0 setting](https://github.com/cockroachdb/cockroach/blob/v23.2.0/pkg/clusterversion/setting.go#L313-L323)

In v24.1.0, the automatic upgrader checks that flag separately from `cluster.preserve_downgrade_option`. Thus resetting preserve alone does not resume automatic finalization when `auto_upgrade.enabled=false`. [Pinned automatic upgrade logic](https://github.com/cockroachdb/cockroach/blob/v24.1.0/pkg/server/auto_upgrade.go#L131-L146)

Manual `SET CLUSTER SETTING version` follows the SQL upgrade path and version validator. That validator checks binary compatibility and the preserve hold, but not the automatic-upgrade flag. Consequently, after clearing preserve, manual finalization can proceed with automatic upgrades disabled, subject to the normal upgrade checks and migrations. This conclusion follows from the pinned code paths. [Pinned SQL setting path](https://github.com/cockroachdb/cockroach/blob/v24.1.0/pkg/sql/set_cluster_setting.go#L531-L579), [Pinned version validator](https://github.com/cockroachdb/cockroach/blob/v24.1.0/pkg/clusterversion/setting.go#L154-L189)

Current guidance explicitly offers manual finalization with automatic upgrading disabled and says either setting prevents automatic finalization. That is consistent with the historical source, although the current recommended interface differs from the case's preserve-based task. [Current finalization guidance](https://docs.cockroachlabs.com/docs/stable/upgrade-cockroach-version#disable-auto-finalization)

### Backup does not provide arbitrary downgrade

Cockroach Labs does not support restoring a newer-version backup into an older-version cluster. For example, a v23.2 backup is supported on v23.2/v24.1; a backup from finalized v24.1 is not a supported means to reconstruct v23.2. A compatible backup made before upgrading is a different recovery input. [Restore compatibility guide](https://docs.cockroachlabs.com/docs/v24.1/restoring-backups-across-versions)

### Kubernetes deletion does not imply fresh database storage

StatefulSet stable storage persists across Pod replacement. PVC retention defaults to `Retain`, including StatefulSet deletion or scaling; an explicit retention policy can alter that behavior. Merely deleting and recreating a StatefulSet can attach the same old database files. [StatefulSet stable storage](https://kubernetes.io/docs/concepts/workloads/controllers/statefulset/#stable-storage), [PVC retention](https://kubernetes.io/docs/concepts/workloads/controllers/statefulset/#persistentvolumeclaim-retention)

## Recommended Karma fixture

The user's direction is sound: reuse an adequate environment, deterministically normalize version, and recreate database state when an old-version rollback is unsupported. I recommend three units organized by achieved state, with upward and downward handling inside the second unit:

1. **`crdb_env_ready`**: identify only the configured namespace and cluster; require a coherent initialized database, live selected nodes, and usable SQL under its existing TLS/insecure mode. Create a missing deployment on the configured source release. Distinguish absent, waiting for initialization, unavailable, and unsupported states; arbitrary SQL failure must not authorize destruction.
2. **`crdb_source_version_ready`**: establish uniform supported source-series binaries and an exactly finalized source logical version. Compare to **`from_version`**, not the solver's `to_version`. Reuse suitable source patches; do not downgrade a newer patch within the same source series merely because it is numerically higher. Upgrade older release series through verified supported steps and finalize each prerequisite. For newer binaries with logical version still exactly at source and no migration started, use only a verified supported rollback. When logical state is already above source, reset the selected database's stores and initialize source binaries, preserving compatible Kubernetes configuration, topology, TLS material, and unrelated resources.
3. **`crdb_upgrade_hold_ready`**: verify the logical source version, set preserve to that value, and verify it from the selected cluster. Record/check `cluster.auto_upgrade.enabled`; to maintain the case's existing preserve-reset flow, normalize it to true **after** preserve is established. Verify both settings and ensure all actual source binaries are uniform before handing off.

Units remain dependent even when independently probed: the third must not mutate an environment whose source-state guard failed. Apply and verify should reread actual node versions, logical version, migrations, and holds; a stale StatefulSet image alone is insufficient. Record resumable progress and selected resource/store identities before mutations. A failed reset or rollout should not broaden cleanup or silently use a fresh fallback.

The order inside version normalization matters. If compatible newer binaries are already present but logical state is still source, establish a temporary hold before rolling anything; otherwise the background upgrader can remove the rollback window. Reapply the final hold in unit three. If a lower source is still completing its own upgrade, resolve that state deliberately; do not classify an internal transition as simply "less than" the desired source.

For a repeatable source → target task, a cluster finalized **exactly at target** needs reset too: it already satisfies the final result and has no major upgrade left. The rule is therefore not merely "higher than target means recreate." Lower/equal/higher must be evaluated against the intended **starting state** and both kinds of version.

Recreation intentionally loses selected database contents, users, settings, and cluster identity. That matches the user's accepted same-cluster regression semantics, but it must be stated in fixture behavior. Deleting the entire namespace is unnecessary and unsafe for unrelated clusters. Reusing old PVC contents with an older image does not constitute a fresh reinstall; stop all selected nodes, then explicitly clear verified exclusive selected stores or provision fresh stores before restarting old binaries. Compatible Services, ingress references, TLS Secrets, RBAC, and workload options should survive; settings or flags unsupported by source need an explicit supported policy rather than guesses. Foreign/shared storage, uncertain ownership, unsupported operators, or unrecognized deployment shapes should block preparation before destructive work.

Choose explicit, tested source patches when designing additional supported paths; do not resolve a floating "latest" release during preparation. Preserve valid inherited source patches for carryover. Validate the exact chosen releases in kind before implementing general upgrade traversal; the research supports the two historical adjacent paths, not an unrestricted universal downgrade/upgrade algorithm.

## Scope and next verification

No case behavior was edited during this research. Before implementation, agree on reset semantics, supported source deployment shapes, and the source patch policy. Live experiments should cover source reuse, an older finalized source, a target binary held on source, already-finalized target, a transitional version, inherited automatic-upgrade=false, TLS, an unrelated cluster, and retry after interrupted reset/rollout. Verify database identity preservation on supported upgrades/rollbacks and intentional identity replacement only on reset.

## Implementation follow-up: earlier hops and persisted storage

This follow-up was requested once implementation was authorized. It adds upstream evidence; it does not edit the case implementation.

### Earlier source-normalization hops

The v23.1 guide permits v22.2 production sources, and the v23.2 guide permits v23.1 production sources; neither eligibility list specifies a source patch floor. Both direct earlier versions through intervening major releases. For the proposed limited traversal, use finalized `22.2` → finalized `23.1` → finalized `23.2`, rather than replacing all nodes directly with `23.2`. Both guides require a live, uniform cluster with zero unavailable/under-replicated ranges before rolling. They recommend one node at a time, verifying SQL and waiting at least one minute before the next node. [v23.1 guide](https://docs.cockroachlabs.com/docs/v23.1/upgrade-cockroach-version), [v23.2 guide](https://docs.cockroachlabs.com/docs/v23.2/upgrade-cockroach-version)

Pinned source corroborates the data-version floors: v23.1.0 uses `V22_2`, while v23.2.0 uses `V23_1`. These floors describe logical persisted data compatibility, not exact required binary patch tags. [v23.1.0 version definitions](https://github.com/cockroachdb/cockroach/blob/v23.1.0/pkg/clusterversion/cockroach_versions.go#L996-L1010), [v23.2.0 version definitions](https://github.com/cockroachdb/cockroach/blob/v23.2.0/pkg/clusterversion/cockroach_versions.go#L925-L938)

The v23.1.0 automatic upgrader checks the preserve hold; that release's setting definitions contain no `cluster.auto_upgrade.enabled`. Do not issue SQL for that setting indiscriminately during earlier hops. Establish/clear preserve on the current logical version; inspect/use the additional automatic-upgrade setting only when present. [v23.1.0 automatic upgrader](https://github.com/cockroachdb/cockroach/blob/v23.1.0/pkg/server/auto_upgrade.go#L122-L206), [v23.1.0 settings](https://github.com/cockroachdb/cockroach/blob/v23.1.0/pkg/clusterversion/setting.go)

### Does merely running v24.1 make rollback stores incompatible?

For the pinned ordinary v23.2.0/v24.1.0 path, no such forced format advance appears in the inspected storage path. v24.1.0's Pebble-format map selects `FormatVirtualSSTables` at logical `23.2`, matching v23.2.0. The newer synthetic-prefix/suffix format is gated on a v24.1 upgrade version. Opening existing storage and `SetMinVersion` derive the required format from its persisted logical/store version, and ratchet only upward. [v24.1.0 storage opening](https://github.com/cockroachdb/cockroach/blob/v24.1.0/pkg/storage/pebble.go#L1256-L1367), [v24.1.0 format map and ratchet](https://github.com/cockroachdb/cockroach/blob/v24.1.0/pkg/storage/pebble.go#L2378-L2462), [v23.2.0 format ratchet](https://github.com/cockroachdb/cockroach/blob/v23.2.0/pkg/storage/pebble.go#L2431-L2508)

The practical conclusion is narrow: a verified hold keeping every node/store at stable logical `23.2` is consistent with the documented pre-finalization v24.1 → v23.2 binary rollback. It does not authorize rollback after an internal migration/fence version advanced, manually forced engine options, or arbitrary untested newer patches. Storage can ratchet during intermediate finalization stages before the final `24.1` value appears. The proposed adapter should only attempt a supported tested rollback, preferably to the recorded original source patch; otherwise use the explicit scoped-reset policy or block before mutation. This is implementation policy inferred from the sources, not a new upstream compatibility promise.

### What to read and what to guard

`cockroach version --build-tag` reports the particular local executable. `SELECT version()` returns the connected node's server version. Read node-local SQL against every selected gateway and the logical setting separately; also confirm actual container identity/image so a load-balanced response or a swapped executable cannot masquerade as a uniform rollout. [CLI version command](https://docs.cockroachlabs.com/docs/v23.2/cockroach-version), [SQL version function](https://docs.cockroachlabs.com/docs/v23.2/functions-and-operators#system-info-functions)

Pinned v23.2.0 `node status` provides `build`, `is_available`, `is_live`; `--ranges` adds unavailable/under-replicated ranges, and `--decommission` adds membership/draining. `--all` includes these columns. It reads gossip liveness/node tables and store-status metrics. A suitable adapter checks expected active nodes and permits fully decommissioned historical records, while blocking partially decommissioned or unexpectedly missing active nodes. [Pinned node-status implementation](https://github.com/cockroachdb/cockroach/blob/v23.2.0/pkg/cli/node.go#L89-L232)

Before version advancement, v24.1.0's first upgrade precondition checks `"".crdb_internal.invalid_objects`, attempts repairable catalog corruption, and rejects remaining invalid descriptors. Its manager invokes preconditions before fence/migration work and waits for existing migration jobs instead of assuming a tag update is completion. [First upgrade precondition](https://github.com/cockroachdb/cockroach/blob/v24.1.0/pkg/upgrade/upgrades/first_upgrade.go#L110-L212), [Upgrade manager](https://github.com/cockroachdb/cockroach/blob/v24.1.0/pkg/upgrade/upgrademanager/manager.go#L363-L545), [Existing migration jobs](https://github.com/cockroachdb/cockroach/blob/v24.1.0/pkg/upgrade/upgrademanager/manager.go#L659-L691)

A blanket "no pending jobs" check would reject legitimate long-running work such as changefeeds. Recommended fixture policy: separately inspect nonterminal migration/schema-change jobs, boundedly wait for genuine completion, and fail with evidence on stalls/corruption. Do not automatically cancel jobs, mutate descriptors, or erase data in response to those failures. Likewise, preflight the exact target/source executable's supported startup flags before an image downgrade, preserve compatible settings, and explicitly block unsupported custom engine/startup options. These are conservative Karma choices; the upstream checks are not a complete arbitrary-configuration downgrade validator.

## Live mixed-version liveness correction

The actual pinned22.2→23.1 kind experiment found an adapter error: a22.2 SQL
gateway reports a healthy23.1 node as `node status.is_live=false`, although both
client versions report it live when connected to the23.1 gateway. All physical
nodes served the witness row, were Ready and had zero unavailable/under-replicated
ranges. The error followed gateway version, not client version.

Pinned CLI base queries are identical. The SQL virtual table implementation is
different:22.2 `gossip_nodes.is_live` checks for a gossip-client key;23.1 checks
liveness heartbeat expiration. The newer node no longer satisfies the old
gossip-client-key heuristic. These facts are verified in the actual differential
probe and primary source, rather than inferred from Pod readiness alone.
[v22.2 SQL virtual tables](https://github.com/cockroachdb/cockroach/blob/v22.2.0/pkg/sql/crdb_internal.go),
[v23.1 SQL virtual tables](https://github.com/cockroachdb/cockroach/blob/v23.1.0/pkg/sql/crdb_internal.go).

The adapter now reads `kv_node_liveness` directly for heartbeat expiration,
membership and draining, matching exact selected node IDs. Both pinned sources
identify this table as fresh KV state; gossip tables do not guarantee freshness.
The existing SQL, Pod, topology, availability and zero-range-error checks remain.
A recorded real-data regression failed before the fix and passes afterward, with
expired, draining, partially decommissioned and unexpected-node controls rejected.
The original live mixed fixture also passes without recreating any stores.
Evidence: `/private/tmp/karma-major-upgrade-preconditions-20261014-k1a1ku_q/`.

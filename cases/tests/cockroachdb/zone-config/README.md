# CockroachDB zone-config

This case asks the solver to change four table zone values in the target schema
of `defaultdb`. Namespace, StatefulSet name, schemas and desired values are
parameters. TLS mode, SQL port, existing table names and node count are discovered.

Setup has four independently checked units:

1. `crdb_env_ready` reuses a usable selected cluster or creates it. Persistent
   database failures use the selected cluster's exclusive PVC stores for scoped,
   resumable recovery. API, permission and unsupported inspection failures do not
   authorize deleting data. Under-replication alone does not authorize recovery:
   inherited zone policies can cause it. Add only the nodes needed by the desired
   replication factor, retaining existing stores, version and configuration.
2. `crdb_zone_fixture_ready` adds missing tenant schemas and enough ordinary tables
   to have two in each schema. Existing names, rows, views and policies are reused.
3. `crdb_zone_change_ready` validates the desired policy in a rolled-back transaction.
   Before recording the baseline, repair only target-side voter or placement fields
   which prevent that policy. Preserve compatible constraints. If every target
   already matches, increase one table's GC TTL by one second; at the integer
   ceiling use a range-size mismatch instead. Existing unfinished work is reused.
4. `crdb_zone_baseline_ready` always refreshes a stage-bound, authenticated encrypted
   snapshot before the first solver attempt. A framework-only key arrives over
   trusted stdin. Frozen retries inspect the original snapshot and preserve solver
   progress instead of recreating the challenge. Baseline names combine namespace,
   cluster, run and stage identity.

The oracle parses supported `SHOW ZONE CONFIGURATION` YAML and compares exact
integers, then checks usable quorum and selected-node health. Inherited
under-replication outside the target policy does not fail this configuration task.
It preserves existing table descriptor identities, protected effective
policies, sparse shared-parent/index/partition policies, unrequested target fields,
workload configuration, store identities and mounted certificate material. A
protected table may already have a custom policy: it must remain unchanged.
Sparse overrides come from `SHOW ALL ZONE CONFIGURATIONS`; per-table `raw` YAML is
hydrated and cannot prove whether a field was explicitly configured.

When scaling TLS nodes, already-covered names need no certificate changes. If
names are missing, clone selected certificate material and extend the node leaf
under its existing signer where available. Without that signer, first roll all
selected nodes to a combined old/new CA trust bundle with the old node leaf, then
roll the new leaf and add nodes. Keep the old root client and original/shared
Secrets untouched. This can invalidate external clients which trust only the old
CA for the selected servers; this is an expected selected-cluster regression.
Full Secret-backed node/root certificate directories are required for extension;
unsupported split projections are rejected before changing the workload. Literal
single-store startup attributes and native node localities support placement
qualification; ambiguous layouts are never assumed unconstrained.

Requested policies must fit the selected cluster's available resources. Shared
parent or protected policy conflicts are not silently cleared. Later stages which
intentionally change the same cluster's zone values, workload, or certificates may
fail this stage's final regression oracle, even when each stage passed initially.

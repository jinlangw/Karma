# Rollback rehearsal

Inspect the selected live cluster, submit a rollback script, and leave the original
cluster unchanged. The oracle executes the script on a disposable target. Initial
scope is exactly two field types: `kv.snapshot_rebalance.max_rate`, and explicit
`gc.ttlseconds` overrides on non-system user DATABASE/TABLE zones. Other settings,
zone fields, data, version, workload, storage and TLS material are preserved.

Four independent units prepare a usable selected cluster, ensure meaningful
rollback targets, clear only this stage's script artifact, and capture an
authenticated encrypted snapshot. Artifact names hash namespace, cluster, run and
stage. Baselines refresh before the first solver starts and remain frozen for
retries/final sweeps, using existing trusted framework stdin keys. Malformed
script labels do not block cleanup of the reserved current-stage output name.

The targets unit reads the actual byte-setting default through
`crdb_internal.cluster_setting_encoded_default`, not a fixed default or a
nonexistent `default_value` column. It reads raw zone YAML to distinguish explicit
GC overrides from unrelated/inherited fields. All eligible user database parents
are reset first; selected table pins are then copied from the resulting parent.
`COPY FROM PARENT` copies its current numeric value; it does not establish dynamic
inheritance. A GC value already equal to RANGE default's effective TTL is outside
the required rollback list. The default range itself and system zones are not
rollback targets. If no targets exist, only one deterministic non-default snapshot
rate is introduced. Existing eligible work is never overwritten or expanded.
Current bytes come from the persisted setting (or the encoded default after
RESET). Human-readable SHOW output rounds and can hide a one-byte difference.
Source snapshots also retain exact persisted settings. The capabilities and
metadata forms were checked live on 22.2.0, 23.1.0, 23.2.0, 24.1.0 and 24.2.0.

The script accepts namespace and StatefulSet arguments and discovers the passed
target's connection mode/port. Relevant SQL object names are retained in the
fixture; Kubernetes names are random. The fixture uses the actual source pod0's
pinned official CockroachDB image, one node with ephemeral storage, fresh TLS
material when needed, and bounded resources. It reproduces rate/GC targets and
parent GC context. Unrelated range fields, another table's GC, and witness rows
act as sentinels. Placement constraints and replica topology are not copied from
the original cluster into a small fixture. A portable script must preserve the
passed target's unrelated configuration, not reconstruct it from source values.

The candidate runs in a separate non-root Pod with read-only root filesystem,
no host mounts or host credentials, a bounded deadline, and a namespaced
ServiceAccount. Kubernetes rights permit inspecting fixture pods/StatefulSets and
exec only into its database pod; source-namespace access is denied. The pinned
runner is alpine/k8s 1.32.1, including shell/kubectl/jq. This provides process,
filesystem and Kubernetes credential separation. It is not a claim of complete
network isolation on kind's default CNI; no unsupported NetworkPolicy protection
is assumed. The original cluster's full captured configuration is checked before
and after each oracle execution. Namespace cleanup verifies nonce labels and UID
and runs even when the candidate or fixture verification fails. No PVCs are used
by the disposable target.

Only the selected case's local copies of proven environment/recovery helpers are
used; no shared helper unification or other case changes are required. Recovery
retains exclusive-store and PVC/PKI identity guards. Framework key lifetime/local
same-user limits remain as documented for readonly-audit: lost process keys fail
closed rather than bypassing grading.

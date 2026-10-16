# CockroachDB zone-config chainability research

Date: 2026-10-15. Scope: SQL inspection, preservation, small topology, and certificate compatibility for the `zone-config` case. This is primary-source research, not a claim that every listed release or scenario has passed a live qualification. The implementation must retain the actual live results separately.

## Inspection route

Use public SQL statements rather than direct `system.zones`, protobuf conversion functions, or direct `crdb_internal` queries. Both the archived [23.2 SHOW ZONE documentation](https://www.cockroachlabs.com/docs/v23.2/show-zone-configurations) and [26.1 documentation](https://www.cockroachlabs.com/docs/v26.1/show-zone-configurations) expose per-table/database/range statements and the all-zone listing.

For one object, explicitly select the hidden YAML columns:

```sql
SELECT zone_id, subzone_id, target, raw_config_yaml, full_config_yaml
FROM [SHOW ZONE CONFIGURATION FOR TABLE defaultdb.tenant_b.orders];

SELECT zone_id, target, raw_config_yaml, full_config_yaml
FROM [SHOW ZONE CONFIGURATION FOR DATABASE defaultdb];

SELECT zone_id, target, raw_config_yaml, full_config_yaml
FROM [SHOW ZONE CONFIGURATION FOR RANGE default];
```

The columns have matching declarations in the tagged [23.2 implementation](https://github.com/cockroachdb/cockroach/blob/v23.2.0/pkg/sql/show_zone_config.go#L31), [24.1 implementation](https://github.com/cockroachdb/cockroach/blob/v24.1.0/pkg/sql/show_zone_config.go#L31), and [26.1 implementation](https://github.com/cockroachdb/cockroach/blob/v26.1.0/pkg/sql/show_zone_config.go#L27). Parse YAML as structured data; do not regex the four desired values out of pretty SQL and assume everything else remained unchanged. This is a version-pinned inspection contract: unknown future columns/semantics need qualification, not an unsafe-internals bypass.

**Important: per-object `raw_config_yaml` is already hydrated.** `getShowZoneConfigRow` calls `GetZoneConfigInTxn`, which completes inherited fields before producing the row. When the full-config argument is nil, the display function populates full YAML from that same object. Consequently `raw_config_yaml` versus `full_config_yaml` on this statement does not distinguish explicit overrides from inherited values. The returned `target`/`zone_id` identifies the applicable ancestor if the table lacks its own zone. See [26.1 inheritance completion](https://github.com/cockroachdb/cockroach/blob/v26.1.0/pkg/sql/zone_config.go#L192) and [display generation](https://github.com/cockroachdb/cockroach/blob/v26.1.0/pkg/sql/show_zone_config.go#L245).

```sql
SHOW ALL ZONE CONFIGURATIONS;
```

The all-zone statement has only `target` and `raw_config_sql` in its delegated output. It lists sparse stored overrides, including index and partition zones, and is a useful companion to effective per-object YAML. Do not try selecting the per-object hidden columns from the all-zone statement. [Tagged delegate](https://github.com/cockroachdb/cockroach/blob/v26.1.0/pkg/sql/delegate/show_zone_config.go).

On 26.1+, `crdb_internal.zones` and `crdb_internal.tables` are unsafe internals for direct queries; documented SHOW commands can internally access restricted data without changing the user's `allow_unsafe_internals` setting. Qualify the actual SHOW commands on the modern fixture; a denied or unsupported inspection must not be interpreted as a broken database or permission to reset stores. [Official internal-access guidance](https://www.cockroachlabs.com/docs/v26.1/crdb-internal).

## Table discovery and stable identity

`SHOW TABLES FROM defaultdb.tenant_a` / `.tenant_b` distinguishes ordinary tables, views and locality, but its documented columns do **not** include a descriptor/table ID. Filter to ordinary tables for this case; do not apply table zone statements to views or sequences. `SHOW CREATE TABLE` can record schema definitions but cannot alone detect drop-and-recreate with the same definition. [SHOW TABLES](https://www.cockroachlabs.com/docs/v26.1/show-tables).

Use the PostgreSQL-compatible catalog to record identity in a session connected to the selected database:

```sql
SELECT n.nspname AS schema_name, c.relname AS table_name,
       c.oid::INT8 AS table_id, c.relkind
FROM pg_catalog.pg_class AS c
JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
WHERE n.nspname IN ('tenant_a', 'tenant_b')
  AND c.relkind = 'r'
ORDER BY n.nspname, c.relname;
```

This is justified by CockroachDB's own implementation: `pg_class.oid` is built from `table.GetID()`, and schema OIDs from the parent schema descriptor; relkind distinguishes tables/views/sequences. [Tagged CockroachDB pg_catalog implementation](https://github.com/cockroachdb/cockroach/blob/v26.1.0/pkg/sql/pg_catalog.go#L788). Live-check the same query on legacy and modern fixtures. Scope the connection/database explicitly and SQL-quote configurable identifiers.

## Preservation contract

Zones inherit unset fields from the database and ultimately the default range. Explicitly assigning a field, even to its parent's current value, changes future inheritance. Index/partition overrides can supersede table settings. `USING DEFAULT` resets configurations; `DISCARD` removes overrides and resumes inheritance. Neither is an appropriate blanket preparation step for inherited tenants. [Replication inheritance](https://www.cockroachlabs.com/docs/stable/configure-replication-zones#how-zone-config-inheritance-works).

Recommended baseline:

- Exact table identity set for both schemas.
- Protected tables: both effective structured YAML and sparse explicit override representation.
- Shared parents: applicable database and default-range configurations.
- Target tables: all effective fields outside the four requested fields, plus sparse unrequested settings and descendant index/partition configurations.

The last requirement is an implementation inference from the documented inheritance rules. Compare canonical data structures and preserve sparse semantics where relevant; display formatting and field order are not configuration changes. The target may acquire explicit values for the requested four fields. Protected tables must not lose an existing custom configuration merely because the legacy oracle expected no explicit configuration.

## Validation, replicas, and placement

The tagged [23.2 validator](https://github.com/cockroachdb/cockroach/blob/v23.2.0/pkg/config/zonepb/zone.go#L350), [24.1 validator](https://github.com/cockroachdb/cockroach/blob/v24.1.0/pkg/config/zonepb/zone.go#L352), and [26.1 validator](https://github.com/cockroachdb/cockroach/blob/v26.1.0/pkg/config/zonepb/zone.go#L381) agree on the relevant constraints:

| Requested total replicas | Voter constraint |
| --- | --- |
| 1 | One voter is valid; inherited voters greater than one conflict. |
| 2 | An explicit positive voter count is required; use one voter, since two voters is rejected. |
| 3 | Default behavior is valid; explicit inherited voters must not exceed three. |
| 5 | Default behavior is valid; explicit inherited voters must not exceed five. |

The code rejects non-positive replicas/voters, voters greater than total replicas, and two voters. It does not generally require all voter counts to be odd. Do not invent an odd-only rule beyond documented recommendations. Per-replica constraints require explicit num_replicas, per-voter constraints require explicit num_voters, and both range-size bounds must be provided together.

Node count alone does not prove placement feasibility. Replicas use distinct eligible nodes; required/prohibited constraints, voter constraints and localities affect eligibility. Cloning a StatefulSet with the same locality cannot satisfy mutually exclusive location requirements. Desired replicas below inherited voters or per-replica constraint counts cannot be solved solely by adding nodes. Preserving arbitrary inherited placement settings while satisfying every possible requested replica count is not always mathematically possible. [Replication constraints and eligible nodes](https://www.cockroachlabs.com/docs/stable/configure-replication-zones#replication-constraints).

A focused preflight can execute the exact desired `ALTER TABLE ... CONFIGURE ZONE USING ...` in a transaction followed by `ROLLBACK`, then compare snapshots to prove no persistent change. The zone implementation writes through the current SQL transaction, including validation. [Tagged set-zone implementation](https://github.com/cockroachdb/cockroach/blob/v26.1.0/pkg/sql/set_zone_config.go#L714). This remains a live qualification requirement, not a generic guarantee for all DDL.

**Protect the trial from inherited session defaults.** Where the release supports it, explicitly disable `autocommit_before_ddl` in that session before BEGIN; otherwise an inherited enabled default can commit before a DDL statement. CockroachDB documents limitations on generic DDL transactions and this automatic-commit behavior. Test rollback after both valid and invalid trials. [Online schema changes and automatic commit](https://www.cockroachlabs.com/docs/v26.1/online-schema-changes#enable-automatic-commit-before-running-schema-changes-inside-transactions).

For meaningful work when all requested values already match, increasing only one target table's GC TTL is preferable to decreasing it: it avoids newly expiring historical data during preparation. The SQL validator requires TTL >= 1, represented as a signed 32-bit integer; choose a bounded distinct valid TTL, not an overflowing increment. The documented routinely tested window is 600 through 90000 seconds. The required target may be outside that routinely tested window yet SQL-valid; trial validation establishes acceptance. [TTL guidance](https://www.cockroachlabs.com/docs/stable/configure-replication-zones#replication-zone-variables), [26.1 zone validator](https://github.com/cockroachdb/cockroach/blob/v26.1.0/pkg/config/zonepb/zone.go#L444).

## TLS scaling without inventing new trust

Node certificates require CN=node, trusted signing CA, and SAN coverage for the addresses actually used. CockroachDB supports wildcard DNS SANs. Before scaling, compare proposed new Pod advertised/RPC/SQL names against the existing certificate SANs. A shared node certificate with matching headless-service wildcard can cover future ordinals without certificate mutation; a bare service SAN covers that service address, not arbitrary per-Pod DNS names. Validate the complete advertised naming pattern and certificate chain rather than assuming all names under one service match. [cockroach cert](https://www.cockroachlabs.com/docs/v26.1/cockroach-cert).

If new names are not covered, issuing an expanded certificate requires the original CA private key (or the external issuer). `ca.crt` plus existing node/client certificates cannot sign a new certificate. The original signer cannot expand the existing certificate when its key is absent. This does not prohibit a separately authorized trust migration: the two-phase selected-only procedure below introduces a new signing CA while preserving old trust. Do not silently switch to insecure mode, disable hostname validation, or overwrite shared TLS secrets. For externally signed deployments, server node certificates and client.node credentials can be split and have distinct requirements. [Custom PKI and split certificates](https://www.cockroachlabs.com/docs/v26.2/create-security-certificates-custom-ca).

## Minimum live qualification checklist

1. Legacy23.2/24.1 and modern26.1+: effective YAML, all-zone sparse output, catalog identity, ordinary-table/view distinction, unsafe internals left disabled.
2. Inherited protected custom table settings, database defaults, and target unrequested settings survive desired changes.
3. All-targets-already-correct triggers only one target TTL mutation; retry does not add repeated mutations; baseline freezes at solver launch.
4. Replica1/2/3 and inherited num_voters conflict; placement-ineligible topology; trial rollback leaves exact pre-trial sparse state.
5. Existing matching SAN scaleup; nonmatching SAN with unavailable CA key follows explicit compatibility handling without partial cluster mutation.

No cluster mutations or case/framework edits were performed for this research.


## Follow-up: exact constraint YAML and small-cluster eligibility

The tagged custom YAML serializer—not the protobuf field layout—determines the inspection format. Both `constraints` and `voter_constraints` use either a list of strings for all replicas or a mapping of comma-joined constraint strings to counts:

```yaml
# All replicas must match both tokens.
constraints: [+region=east, -ssd]
# Alternatively, per-group counts (not a list of protobuf structs):
constraints: {"+region=east,+ssd": 2, "+region=west": 1}
voter_constraints: {"+region=east": 1}
lease_preferences: [[+region=east], [+region=west]]
```

These are illustrative fragments, not one internally compatible complete policy. Empty/inherited constraint lists serialize as `[]`; this is another reason to preserve sparse SQL alongside effective YAML. [Tagged custom YAML serializer](https://github.com/cockroachdb/cockroach/blob/v24.1.0/pkg/config/zonepb/zone_yaml.go#L77).

A locality constraint `+key=value` matches an exact key/value in a node's locality tiers. An attribute constraint `+ssd` matches node attributes **or the selected store's attributes**. Negative constraints invert that match. Tokens within one comma group are ANDed; attribute values and locality values are case-sensitive. Do not combine attributes from different stores into a fictional eligible store. [Exact token matching](https://github.com/cockroachdb/cockroach/blob/v24.1.0/pkg/roachpb/span_config.go#L24).

Each positive map count is the required matching replica count for that conjunction. The validator bounds summed counts by total replicas (or voters). If their sum is smaller, remaining replicas can be unconstrained. The allocator counts a store toward every group it matches; independently checking group count requirements is not the same as requiring a disjoint group assignment. [Constraint analyzer](https://github.com/cockroachdb/cockroach/blob/v24.1.0/pkg/kv/kvserver/constraint/analyzer.go) and [allocator candidate validity](https://github.com/cockroachdb/cockroach/blob/v24.1.0/pkg/kv/kvserver/allocator/allocatorimpl/allocator_scorer.go#L2042).

For a bounded small selected cluster, a useful source-derived feasibility check is:

1. Read actual live, available, non-decommissioned node identities/localities using native node status. Correlate selected Pod/node identities, not merely cluster-wide node count. Derive node/store attributes from inspected selected startup flags when the command layout is known; mark unrecognized shell expansion, attribute flags, and multi-store syntax unresolved rather than assuming no attributes.
2. Enumerate candidate sets with the requested number of distinct nodes and one actual store choice per node.
3. For list constraints, every chosen store matches every token. For map constraints, each group's matching count is at least its count; if the sum covers every replica, every store also matches at least one group. If the sum is smaller, unmatched stores are permitted for the unconstrained remainder.
4. Enumerate a voter subset of the chosen replicas. Apply voter constraints to that subset, while retaining the overall constraint requirements. Voting candidates must satisfy both applicable sets; nonvoters need only the overall set.
5. A feasible set is evidence of placement eligibility for these inspected dimensions, not proof of current replica convergence, disk capacity, allocator success, or locality diversity. Verify actual native range health after applying requested policies. SQL trial validation remains authoritative for syntactic/tandem-field rules.

This is an implementation inference from tagged matcher/allocator behavior and needs live qualification, especially for overlapping groups. Simple per-group eligible-node counts alone can miss intersecting overall/voter constraints. Do not reset protected tables or shared parents when a target-side constraint blocks the requested RF. If the user's policy permits minimal target-only repair, freeze the baseline after that repair and record exactly which target fields changed.

## Follow-up: selected-only two-phase CA trust migration

The official [CA rotation procedure](https://www.cockroachlabs.com/docs/stable/rotate-certificates#rotate-the-ca-certificate) explicitly introduces combined new-and-old trust before rotating node/client leaves. The existing CA private key is not needed to generate a separate new CA. Retaining the original CA certificate is sufficient to keep validating existing old-CA-signed client certificates; the old private key is needed only to issue new leaves under that original signer.

For the standard multifunction `node.crt` layout, the proposed selected-only migration is consistent with that documented trust transition:

1. Clone the selected certificate Secret into a new test-owned Secret, preserving old node/client key material initially. Add a new CA certificate to the clone's `ca.crt` alongside the original trust bundle. Preserve unrelated original/shared Secrets byte-for-byte.
2. Repoint only the selected StatefulSet's certificate volume to that clone. Roll/reload **every existing selected node**, still using old node leaves. Verify each node actually loaded dual trust and that the selected cluster is healthy before phase two.
3. Issue a new `CN=node` leaf with serverAuth and clientAuth and all selected advertised/SQL/RPC DNS SANs; sign it with the new CA. Change the cloned Secret's node leaf/key and roll/reload the selected nodes individually, checking fresh authenticated TLS/RPC and SQL after each node. Every old and new node must already trust both roots.
4. Preserve old `client.root.crt`/key and retain the old root indefinitely for this case. The assistant's client must use combined trust to validate new server leaves. Old-CA-only external clients may now fail server validation: that is the explicitly accepted selected-cluster trust regression, not a guarantee of client transparency.

These steps are a source-derived operational design requiring live qualification and resumable phase checkpoints. The key TLS mechanics are verified in tagged source: `tls.Config.RootCAs` and `ClientCAs` load PEM pools, and the standard node certificate supplies outgoing node client identity when separate `client.node.crt` is absent. [Tagged TLS pools](https://github.com/cockroachdb/cockroach/blob/v24.1.0/pkg/security/tls.go#L15), [node-client certificate fallback](https://github.com/cockroachdb/cockroach/blob/v24.1.0/pkg/security/certificate_loader.go#L55).

Scope requirements: reject or explicitly support split `ca-client.crt`/`client.node.crt`/UI-CA layouts; preserving a separate old client CA without adding the new signer would reject new outgoing node certificates. Preserve existing root-client credentials and every original CA root, do not substitute a new root-client identity. Verify all relevant selected mounts, permission modes, init-copy behavior and `subPath` semantics. A Secret update alone is not proof every process loaded new trust. Kubernetes shared volumes or external clients outside the selected StatefulSet must not be silently repointed. Record new Secret ownership, original reference, old/new fingerprints, and completed node/phase checkpoints before irreversible trust changes. Do not remove old CA trust as part of this case.


### Unset voters: requested RF4/RF5

When effective `num_voters` is unset/null, **all requested replicas are voting replicas**; there is no automatic cap of three voters. `SpanConfig.GetNumVoters()` returns `NumReplicas` when `NumVoters` is zero. Thus RF4 means four desired voters and RF5 means five, unless an explicit inherited voter count overrides this. RF2 needs explicit one voter to pass validation. [Tagged zone definition](https://github.com/cockroachdb/cockroach/blob/v24.1.0/pkg/config/zonepb/zone.proto#L112), [effective voter count](https://github.com/cockroachdb/cockroach/blob/v24.1.0/pkg/roachpb/span_config.go#L109).

The allocator can temporarily reduce voter demand when the cluster has fewer nodes; reduced counts prefer odd quorums. It explicitly honors an even voter count when that exact count was requested and enough nodes exist. This availability adjustment does not justify assuming `min(3,RF)` when evaluating desired topology. [Tagged allocator count adjustment](https://github.com/cockroachdb/cockroach/blob/v24.1.0/pkg/kv/kvserver/allocator/allocatorimpl/allocator.go#L655).

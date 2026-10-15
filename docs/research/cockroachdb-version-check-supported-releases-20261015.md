# CockroachDB version-check release research

Checked online on **2026-10-15** for the `version-check` precondition redesign. This records first-party documentation and registry observations, not live database qualification. No cluster was changed during this research.

## Current vendor support

The official support table lists the following supported families and patch ranges. Assistance support remains vendor support even after maintenance ends. Earlier patches in a family can already be unsupported; family membership alone is insufficient. [Release support policy](https://docs.cockroachlabs.com/docs/releases/release-support-policy)

| Family | Supported patch ranges | Support ends | Latest stable patch in official release notes |
| --- | --- | --- | --- |
| 24.1 | 24.1.6+ LTS | 2026-10-21 | [24.1.33](https://docs.cockroachlabs.com/docs/releases/v24.1#v24-1-33) |
| 24.3 | 24.3.12+ LTS | 2027-05-05 | [24.3.36](https://docs.cockroachlabs.com/docs/releases/v24.3#v24-3-36) |
| 25.2 | 25.2.0–9 GA; 25.2.10+ LTS | GA 2026-11-12; LTS 2027-12-17 | [25.2.24](https://docs.cockroachlabs.com/docs/releases/v25.2#v25-2-24) |
| 25.4 | 25.4.0–9 GA; 25.4.10+ LTS | GA 2027-05-03; LTS 2028-05-03 | [25.4.17](https://docs.cockroachlabs.com/docs/releases/v25.4#v25-4-17) |
| 26.2 | 26.2.0–6 GA; 26.2.7+ LTS | GA 2027-10-27; LTS 2028-09-23 | [26.2.7](https://docs.cockroachlabs.com/docs/releases/v26.2#v26-2-7) |
| 26.3 | 26.3.0+ Innovation | 2027-02-19 | [26.3.2](https://docs.cockroachlabs.com/docs/releases/v26.3#v26-3-2) |

The policy places 22.2, 23.1, 23.2, 24.2, 25.1, 25.3, and 26.1 under unsupported releases. Keep any repository compatibility fixtures explicitly separate from current vendor support. The policy also warns that binaries/images can be unpublished four years after a family's GA date. [Support policy](https://docs.cockroachlabs.com/docs/releases/release-support-policy#unsupported-versions)

26.4 has only alpha/beta testing releases on the checked date. Exclude it from the production-release allowlist; the existence of a downloadable image does not make a release supported. [26.4 notes](https://docs.cockroachlabs.com/docs/releases/v26.4)

## Deterministic binary selection

Recommended pinned latest-patch map, with current supported families separately marked:

```text
22.2 -> 22.2.19    historical compatibility
23.1 -> 23.1.30    historical compatibility
23.2 -> 23.2.31    historical compatibility
24.1 -> 24.1.33    currently supported LTS
24.2 -> 24.2.10    historical compatibility / Innovation
24.3 -> 24.3.36    currently supported LTS
25.1 -> 25.1.10    historical compatibility / Innovation
25.2 -> 25.2.24    currently supported LTS
25.3 -> 25.3.7     historical compatibility / Innovation
25.4 -> 25.4.17    currently supported LTS
26.1 -> 26.1.8     historical compatibility / Innovation
26.2 -> 26.2.7     currently supported LTS
26.3 -> 26.3.2     currently supported Innovation
```

The current-family patches come from the release-note links above. Historical newer-family patches come from [23.2](https://docs.cockroachlabs.com/docs/releases/v23.2), [24.2](https://docs.cockroachlabs.com/docs/releases/v24.2), [25.1](https://docs.cockroachlabs.com/docs/releases/v25.1), [25.3](https://docs.cockroachlabs.com/docs/releases/v25.3), and [26.1](https://docs.cockroachlabs.com/docs/releases/v26.1) release notes. The historical 22.2/23.1 documentation pages were empty/too large through the browser extractor; their listed final stable patches were independently checked against the publisher's Docker Hub tag listings: [22.2 tags](https://hub.docker.com/v2/repositories/cockroachdb/cockroach/tags?page_size=100&name=v22.2.&ordering=last_updated), [23.1 tags](https://hub.docker.com/v2/repositories/cockroachdb/cockroach/tags?page_size=100&name=v23.1.&ordering=last_updated).

For **each of the 13 exact tags above**, a read-only request to `https://hub.docker.com/v2/repositories/cockroachdb/cockroach/tags/v{VERSION}` returned an active image with both `linux/amd64` and `linux/arm64` entries. This confirms published manifest metadata, not successful image startup or upgrade. Example first-party publisher records: [22.2.19](https://hub.docker.com/v2/repositories/cockroachdb/cockroach/tags/v22.2.19), [24.1.33](https://hub.docker.com/v2/repositories/cockroachdb/cockroach/tags/v24.1.33), [26.3.2](https://hub.docker.com/v2/repositories/cockroachdb/cockroach/tags/v26.3.2). Official release notes also describe multi-platform Intel/ARM images. [26.3 Docker image](https://docs.cockroachlabs.com/docs/releases/v26.3#docker-image)

## Upgrade graph and held gap

Official guidance permits the next major family. A Regular release can alternatively skip the following Innovation release; an Innovation release can advance only to the next Regular release. A patch change within one family does not create a distinct active feature family. [Upgrade compatibility](https://docs.cockroachlabs.com/docs/stable/upgrade-cockroach-version#compatible-versions)

Conservative graph: adjacent entries in the pinned map above are the candidate one-family edges. Explicit optional skip edges for the newer Regular families are `24.1 -> 24.3`, `24.3 -> 25.2`, `25.2 -> 25.4`, and `25.4 -> 26.2`. The case needs only **one compatible edge** to create a gap; it should not finalize intermediate families merely to reach a distant requested target. This last sentence is an implementation recommendation, not a vendor requirement.

Set `cluster.preserve_downgrade_option` to the **current active family before replacing binaries**. It blocks automatic and manual feature-version upgrades until reset. Official internal mixed-version tests use precisely this state: all nodes run the newer binary while the cluster version remains older. [Setting definition](https://github.com/cockroachdb/cockroach/blob/master/docs/generated/settings/settings.html#setting-cluster-preserve-downgrade-option), [Mixed-version framework](https://github.com/cockroachdb/cockroach/blob/master/pkg/cmd/roachtest/roachtestutil/mixedversion/README.md)

Modern docs recommend `cluster.auto_upgrade.enabled = false` instead; it was introduced in 23.2. Either setting prevents automatic finalization, but preserving the existing explicit downgrade hold gives this case a cross-version observable invariant. Once finalization begins, an older binary cannot be used to undo those migrations. Therefore a finalized highest-family cluster needs the user-authorized selected-store rebuild to recreate an older feature family. [Disable finalization and rollback](https://docs.cockroachlabs.com/docs/stable/upgrade-cockroach-version#disable-auto-finalization)

**Implementation recommendation:** inspect SQL-reported binaries on every selected live node, not just the StatefulSet image. Reuse a healthy held gap without forcing its binaries to the configured fallback target. If binaries are mixed because preparation was interrupted, retain the hold and finish the same compatible edge. Treat internal migration versions such as `X.Y-upgrading-to-...` as transient/incomplete preparation, not a stable completed gap. These are safety design recommendations requiring case tests.

## Licensing and validation limits

Current upgrade docs say major upgrades require a valid license; free/trial finalization additionally requires telemetry. A pinned image's existence does not demonstrate that a particular unlicensed held upgrade will work. Test actual behavior and retain an ordinary supported bootstrap/reset fallback; never forge license keys or use licensing bypass environment flags. [Upgrade license requirements](https://docs.cockroachlabs.com/docs/v26.2/upgrade-cockroach-version#ensure-you-have-a-valid-license-key)

The licensing FAQ documents a seven-day no-key grace period and then a limit of **five concurrent open SQL transactions**, not five connections. Development clusters started with `start-single-node` or `demo` are exempt from throttling; a one-replica StatefulSet using `start` should not automatically be assumed exempt. New licensing behavior starts at 23.1.29, 23.2.15, 24.1.7, 24.2.5, and 24.3.0. [Licensing FAQ](https://docs.cockroachlabs.com/docs/stable/licensing-faqs)

Release-note dates and registry push dates differ for some September 2026 patches; both observations predate this research date. Preserve the pinned snapshot and refresh intentionally, rather than selecting a different latest version on each workflow run. None of the newly researched release families is claimed live-tested by this note.

## Follow-up: v26.1+ access restrictions and safe inspection

The implementation's separate live experiment on 26.2.7 encountered SQLSTATE 42501 when querying direct `system`/`crdb_internal` objects. Official **v26.1** breaking changes explain this: access to most such objects is restricted by default through `allow_unsafe_internals`. This is an inspection incompatibility, not evidence that the database is broken. The case should not rebuild a healthy inherited cluster merely because its old inspection query was denied. [26.1 breaking changes](https://docs.cockroachlabs.com/docs/releases/v26.1#backward-incompatible-changes)

The current access-control documentation confirms that some `SHOW` statements and CockroachDB command-line tools intentionally keep functioning when direct access is disabled. Keep the setting off and use supported inspection surfaces; do not widen access as a setup side effect. [Internal schema access control](https://docs.cockroachlabs.com/docs/stable/crdb-internal#access-control)

`cockroach node status --all --format=csv --timeout=...` is a documented replacement for direct liveness/status tables. It exposes node ID, running `build`, `is_available`, `is_live`, range counts, unavailable/underreplicated ranges, and draining/decommissioning fields. Both availability and liveness matter. Parse column names, not fixed positions, and map the selected pods' actual node IDs before interpreting membership. The timeout is necessary because an unset timeout can hang. [Node command response and flags](https://docs.cockroachlabs.com/docs/stable/cockroach-node)

For cluster and per-pod identity, the official **v26.2.6** API definitions contain the routes and fields below. The parent implementation separately observed these endpoints working on 26.2.7. Source definitions establish existence and shape, not a stable public-API guarantee:

| Endpoint | Verified source definition | Intended use |
| --- | --- | --- |
| `GET /_admin/v1/cluster` | `ClusterResponse.cluster_id`, lines386–394; route lines1097–1102 | Compare real cluster UUID across selected pods and the frozen baseline. |
| `GET /_status/details/local` | `DetailsRequest.node_id` accepts `local`; `DetailsResponse.node_id`, `build_info`, `sql_address`, lines105–115; route lines2404–2408 | Associate each selected pod with its database node ID and actual build. |

Sources: [admin.proto at v26.2.6](https://github.com/cockroachdb/cockroach/blob/v26.2.6/pkg/server/serverpb/admin.proto#L386), [status.proto at v26.2.6](https://github.com/cockroachdb/cockroach/blob/v26.2.6/pkg/server/serverpb/status.proto#L105). These files were read from the official raw repository with the system HTTPS client; the browser extractor could not render those source URLs.

Do not invent `/api/v2/cluster` as a substitute: the official Cluster API resource list documents `/api/v2/nodes/` and `/api/v2/health/`, and does not list a cluster-identity endpoint. API v2 authentication uses sessions; secure-cluster transport requires trusted CA validation. Keep TLS verification and authentication correct rather than assuming that insecure fixture behavior transfers to TLS. [Cluster API resources and authentication](https://docs.cockroachlabs.com/docs/stable/cluster-api)

Public `SHOW DATABASES` plus SQL `SELECT 1` provide useful read-path/connection checks, but a successful cached catalog read alone is not proof that every KV range has quorum. Combine public SQL checks with native availability/liveness/range status. This is an implementation recommendation; preserve the older direct KV inspection only where that binary supports it, with permission denials distinguished from actual unhealthy state.

## Implemented selection policy

Automatic preparation chooses the next pinned release family, the smallest documented step. A live workflow and a direct check of the existing upgrade preparer showed that choosing `24.1 -> 24.3` leaves a valid CockroachDB gap that the older next-stage preparer rejects; `24.1 -> 24.2` stays inside its rolling compatibility window. Historical compatibility pins therefore remain separate from current vendor support. Explicit fallback pairs and inherited gaps can still use the documented Regular-release skip options. An existing coherent held gap is reused without replacing its binaries solely because support status changed. This section describes repository policy; live qualification results are recorded separately outside the repository.

## Live TLS authentication observation

On the pinned 26.3.2 fixture, a CA-verified HTTPS request with the root client certificate alone returned HTTP401 from the v1 identity endpoint. The installed official binary's `cockroach auth-session login --help` documents native admin-created cookies for noninteractive HTTP clients. A live `auth-session login root --only-cookie --expire-after=2m` using the existing certificate-authenticated SQL connection succeeded, and the same HTTPS identity request then returned200 with that cookie. The case caches the cookie only in process memory, keyed by pod UID, and allows natural expiration; it does not revoke other sessions or enable unsafe SQL internals. This is a dated live observation, not a promise of future API compatibility.

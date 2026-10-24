# Composition Failure Patterns

A field guide derived from a full re-run sweep of the example, short, long, and
error-prone workflow suites (138 runs). It catalogs the concrete ways a case
fails when it is *composed into a workflow* rather than run standalone, and the
fix for each. Read it alongside [adding-a-test-case.md](./adding-a-test-case.md):
that doc states the authoring principles; this one shows the failures that
motivate them, with the observed evidence.

Of 24 failed runs analyzed, roughly three quarters were **test or workflow
bugs**, not agent faults. The harness itself was clean (the single run with no
`run.json` was a correct fail-fast on a malformed adversary stage id). The
patterns below are ordered by how many runs they explain.

## Classification

When triaging a failure, classify it before fixing it:

- **TEST_BUG** — the precondition or oracle is wrong (races, hardcoded
  standalone assumptions, code bugs, too-short budgets).
- **WORKFLOW_BUG** — bad stage composition (an earlier stage left state that a
  later stage's precondition or oracle cannot reconcile).
- **AGENT_FAULT** — the agent genuinely failed or submitted early. Do **not**
  mask these with test changes.
- **INFRA/FLAKE** — transient cluster conditions (warm-up, image pull). Fix by
  adding retry, not by relaxing the assertion.

---

## Pattern 1 — Existence-gated preconditions skip problem-shape planting (dominant)

**This is the single most common composition failure.** A service's env-setup
unit (`mongo_env_ready`, `es_env_ready`, `crdb_env_ready`) gates its *entire*
`apply` behind `on_probe_fail: skip` with a probe that only asks "is a pod
Running?" or "does the namespace exist?". That `apply` does double duty: it
deploys the cluster **and** seeds the case-specific baseline / plants the fault /
creates the fixture the oracle checks.

In a workflow the cluster is already running from an earlier stage, so the probe
passes and the **whole apply is skipped** — the cluster persists correctly, but
the case's problem-shape is never established, while the oracle still grades the
post-change state relative to that never-planted baseline.

Observed:
- `mongodb/mongod-config-update`: oracle wants `verbosity=2`/`slowms=400`
  (seed+step); the baseline seed was skipped, the agent correctly computed `+1`
  from the cluster's *default* baseline, so the oracle is "off by one step."
- `mongodb/statefulset-customization`: oracle wants `monitoring=enabled`; the
  fault-planting that sets it `disabled` was skipped, so the label never existed
  (`got None`).
- `mongodb/password-rotation`: the fixture meant to grant `read@appdb` was
  skipped (user already existed from a prior stage), so the oracle's "reporting
  user reads `testdata`" check fails by design.
- `elasticsearch/safe-downscale-with-shard-migration` and
  `elasticsearch/snapshot-repo-setup`: marker file / `es-config` ConfigMap
  fixtures skipped, so the oracle demands artifacts the composed build never
  produced.

**Fix** (see [adding-a-test-case.md](./adding-a-test-case.md) "Reuse
Infrastructure, Replant the Problem"): split the monolithic env-setup into
independent units —

1. a **runtime unit** (`*_runtime_ready`) that checks only core health/identity
   and applies missing infrastructure idempotently (fine to skip when inherited);
2. a **problem unit** (`*_drift_ready` / `*_baseline_ready`) that probes the
   *exact* unsolved problem and replants it when a previous stage solved it.

The problem unit's probe must test the **capability/state the oracle checks**
(e.g. "can `reporting-user` read `appdb.testdata`?", "does the template carry
`monitoring`?", "is verbosity still the seeded baseline?"), not merely "does the
cluster/user exist?".

---

## Pattern 2 — `kubectl wait --for=condition=ready -l <label>` zero-match race

`kubectl apply` a StatefulSet, then within `sleep 1`:

```
kubectl wait --for=condition=ready pod -l app=es-cluster --timeout=600s
# error: no matching resources found   (rc=1, returns instantly)
```

`kubectl wait` with a label selector does **not** wait for objects to appear: if
zero pods match at invocation, it exits immediately with rc=1. The StatefulSet
controller has not created the pod objects within one second, so the selector
matches nothing. This is effectively deterministic on a busy/fresh cluster, and
it explained 5 of the failed runs (all Elasticsearch).

**Fixes** (defense in depth, all three are in place / recommended):
- Framework safety net: `"no matching resources found"` is in
  `_is_transient_apply_error()` (`karma/runtime/case.py`), so a racy apply unit
  retries the (idempotent, read-only) `wait` until the pods register.
- Preferred per-case form: wait at the controller level —
  `kubectl rollout status statefulset/<name> --timeout=600s` — which does not
  depend on pods already existing.
- Or guard with `kubectl wait --for=create pod -l <label>` before the readiness
  wait (requires a recent kubectl).

---

## Pattern 3 — Oracles encode standalone assumptions composition violates

An oracle hardcodes something that is only true for a standalone run:

- **Absolute targets from a relative prompt** — `mongodb/mongod-config-update`
  bakes in `verbosity=2` because the prompt says "increase by one level" against
  a seeded baseline of 1. In composition the baseline differs and the absolute
  target is wrong. Resolve targets from the *observed* pre-change state.
- **Global topology in a namespace that deliberately accumulates** —
  `elasticsearch/full-restart-upgrade-ha` sums *all* ES StatefulSets via
  `_cat/nodes` and got 7 where the prompt said 3, because prior stages spawned
  extra node sets. Scope the check to the *target* object (explicit param or
  label), never "sum everything in the namespace."
- **A standalone-only artifact, checked unconditionally** —
  `elasticsearch/snapshot-repo-setup`'s `check_configmap()` requires an
  `es-config` ConfigMap created only by its own `resource/`, which the chained
  build never applies. Gate such checks on the artifact's presence, or verify
  the *behavior* (no plaintext creds) rather than a named object.
- **The oracle's own client identity** — `mongodb/external-access-horizons`'s
  connectivity probe runs from a `mongo-client` pod that lacks the client cert
  the requireTLS members demand once a prior TLS stage ran; the agent's work was
  correct but the oracle's own connection was refused. Present a client cert (or
  probe from a member that holds one).

**Fix:** an oracle grades only (a) what the prompt promised and (b) the live
behavior of the *target* cluster — never a standalone seed, a polluted global
topology, or its own under-provisioned client.

---

## Pattern 4 — Under-specified prompt vs. exact-match oracle

The agent is graded on a literal it was never told. `safe-downscale` checks for a
marker file at an exact path (`pvc-gc-marker`) that the prompt never names, so
the agent invented a different filename and "failed." If the oracle hard-checks
a filename, count, or object name, that literal **must appear in the prompt** or
be seeded by the precondition — never left for the agent to guess.

---

## Pattern 5 — Missing flap-retry on transient-prone checks

`curl -> es-http.<svc>` flaked while pod-local access worked; some oracle/
precondition health checks are single-shot. `elasticsearch/secure-http-ingress`'s
oracle had no retry loop and failed on 1 of 1 attempt during ingress-controller
warm-up; `elasticsearch/rotate-elastic-password`'s precondition health gate used
a single `curl --max-time 5` and hit exit 28. **Fix:** wrap every reachability/
health check in the standard bounded re-evaluate loop (≈120s, `--max-time`
comfortably above the server-side `timeout=`). Sweep *all* such checks, don't
patch one.

---

## Pattern 6 — Fixed time/grace budgets calibrated standalone

Budgets that are fine for a clean standalone cluster time out for a loaded,
inherited, multi-stage one:
- `cockroachdb/version-check` precondition rollout wait capped at 300s.
- `cockroachdb/cluster-settings` oracle pod-drain `timeout=120s` (a graceful
  CockroachDB drain under accumulated state exceeds it).

**Fix:** budget for the worst case — rollout waits ≥600s; for a persistence
restart whose only goal is to bounce a node, use a short `--grace-period` (or
`--force --grace-period=0`) with the command timeout comfortably above it.

---

## Pattern 7 — Hardcoded image/version clobbers the workflow baseline

`cockroachdb/initialize`'s `resource/statefulset.yaml` pins `v24.1.0`. When its
skip-probe fails to match an agent-deployed cluster, its destructive apply runs
and redeploys at the hardcoded version, silently overwriting the v23.2.0 baseline
a prior stage established — making a later "downgrade" stage unsatisfiable.
**Fix:** parameterize every image/version/security-mode from case params
(`{{params.to_version}}`), and make skip-if-running probes authoritative (match
the StatefulSet or any Running pod, and require the deploy to carry canonical
labels) so destructive applies never run over inherited state.

---

## Pattern 8 — Static oracle bugs

`elasticsearch/rotate-http-certs/oracle.py` used `os.environ` without
`import os` — a 100% crash whenever the check was reached. **Fix:** a static
import/name-resolution scan over `cases/tests/**/oracle/*.py` catches this class for
free; run it before any sweep.

---

## Genuine agent faults (do not mask)

Three failures were real agent errors and must **not** be fixed by changing the
test:
- `elasticsearch/bootstrap-initial-master-nodes` — submitted mid rolling-restart
  with a node not yet rejoined (75s oracle grace exhausted).
- `cockroachdb/health-check-recovery` — submitted on a momentarily-healthy
  `podManagementPolicy: Parallel` cluster that then lost quorum.
- `cockroachdb/major-upgrade-finalize` (in the security workflow) — rebuilt the
  StatefulSet **insecure**, destroying the TLS posture earlier stages
  established.

---

## The one-line guideline

> **Preconditions probe by intent and seed additively; oracles grade the prompt
> against the live target.** Split runtime from problem-shape, replant the
> problem (don't reset infrastructure), resolve expectations from live state,
> retry transients, parameterize versions, and never grade a literal the prompt
> didn't promise.

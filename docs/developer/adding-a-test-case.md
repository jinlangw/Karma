# Adding A Test Case

This guide focuses on authoring canonical `cases/tests/**/test.yaml` cases that work
in both:

- Single-case mode
- Workflow chain mode

Use the current case schema:

- `prompt`
- `params`
- `namespace_contract`
- `preconditionUnits`
- `oracle.verify.commands`
- `metrics` and `decoys` when needed

Do not use legacy top-level command fields or case-level namespace cleanup
commands. The framework owns generated namespace lifecycle.

## Core Principle: Composition-Safe Preconditions

A case must establish the environment and the **unsolved problem** required for
its task. It should work standalone and compose into a workflow without
destroying useful carry-over state from earlier stages.

That means preconditions should use:

- `probe` to inspect one required concern
- `apply` only when that concern is not in the required state
- `verify` to confirm that concern after apply

There are two kinds of precondition state:

- **Infrastructure state**: the cluster, service, helper, or identity material
  required to attempt the task
- **Problem-shape state**: the fault, drift, old version, missing object, or
  other baseline the agent is expected to fix

Infrastructure should no-op when already correct. Problem-shape setup must not
silently accept a state where a prior stage already solved the current task.

## Chainability Rule: Reuse Infrastructure, Replant the Problem

If a case follows another stage that already created the core workload, do not
blindly reset that workload merely because one challenge-specific check fails.

Bad pattern:

- One probe checks workload readiness and challenge drift together.
- One failure triggers a full StatefulSet or Deployment re-apply.
- The re-apply overwrites valid carried-over versions, data, or configuration.

Better pattern:

- One unit owns core workload readiness.
- One unit owns helper resources.
- One unit owns the exact challenge-specific baseline.
- Each unit reconciles only its concern.

For example, creating a Deployment and planting an incorrect Deployment value
should normally be separate units. A repeated stage can then reuse the
Deployment while deliberately restoring the incorrect value the agent must
change.

Chain-safe does not mean preserving every previous value. It means preserving
unrelated valid state while intentionally restoring the current task's
starting condition.

## Example: Version-Agnostic Follow-Up Stage

For a follow-up stage such as TLS rotation, the case should usually be
version-agnostic:

- Verify that the cluster exists and is healthy.
- Verify or plant the certificate baseline required by the task.
- Do not require a specific application version unless version is part of the
  challenge.

Why:

- An earlier workflow stage may have upgraded the cluster.
- TLS rotation should operate on that valid carried-over version.
- Resetting the workload to a fixed image would erase useful workflow state.

Version-agnostic does not mean baseline-agnostic. If the current task requires
old or short-lived certificates, its problem-shape unit must ensure those
certificates are present even when the cluster itself is reused.

## Current Case Shape

A minimal canonical case looks like:

```yaml
prompt: |
  Update ConfigMap `demo-config` in ${BENCH_NAMESPACE}.
  Set `data.value` to `{{params.target_value}}`.

params:
  target_value:
    type: string
    default: x

namespace_contract:
  required_roles:
    - default

preconditionUnits:
  - name: configmap_ready
    probe:
      - command: "kubectl -n ${BENCH_NAMESPACE} get configmap demo-config"
        timeout_sec: 20
    apply:
      - command: "kubectl -n ${BENCH_NAMESPACE} apply -f cases/tests/demo/configmap-update/resource/config.yaml"
        timeout_sec: 20
    verify:
      - command: "kubectl -n ${BENCH_NAMESPACE} get configmap demo-config"
        timeout_sec: 20

oracle:
  verify:
    commands:
      - command: "python3 cases/tests/demo/configmap-update/oracle/oracle.py --expected-value {{params.target_value}}"
        timeout_sec: 20
```

Each precondition unit requires `name`, `probe`, `apply`, and `verify`.
Commands may be a single string, command object, or list of command objects.
Command objects support:

- `command`
- `timeout_sec`
- `sleep`

`verify` may also use the structured form with `commands`, `retries`, and
`interval_sec`.

## Practical Authoring Checklist

Before shipping a new case:

1. Standalone behavior:
   - Preconditions build the intended infrastructure.
   - Preconditions plant the intended unsolved problem.
   - A real solve action can satisfy the oracle.
2. Workflow behavior:
   - Valid carried-over infrastructure is reused.
   - Challenge-specific drift is restored when a previous stage solved it.
   - Unrelated versions, data, or configuration are not reset.
3. Identity and namespace:
   - Use `${BENCH_NAMESPACE}` or `${BENCH_NS_<ROLE>}`.
   - Declare the corresponding roles in `namespace_contract`.
   - Do not create or delete framework-managed namespaces.
4. Parameterization:
   - Parameters materially affect the task.
   - Prompt, setup helpers, manifests, and oracle use the same resolved values.
5. Oracle:
   - Verification is deterministic and observational by default.
   - Any active verification is necessary, scoped, and does not repair the
     task.
6. Validation:
   - Static validation passes.
   - Standalone Kind execution passes.
   - Same-parameter self-chain works.
   - Different-parameter self-chain works when the parameters are intended to
     support it.

## Designing Parameterization

Parameterization should make a case meaningfully reusable without turning
every implementation detail into public configuration.

### 1) Decide what should be a parameter

Parameterize values that materially change the task, identify its target, or
represent a meaningful transition:

- Workload identity used by the agent, such as `cluster_prefix`
- Version transitions such as `from_version` and `to_version`
- Replica or worker counts central to the requested operation
- Target values such as `setting_value` or `expected_body`
- Fault-shape controls such as an incorrect port or policy
- Task-relevant thresholds such as `min_rotated_validity_days`

Usually keep these as implementation details:

- Temporary helper-pod names
- Internal scratch ConfigMap names
- Report object names the agent never uses
- Generic command timeouts
- Filenames and setup-script internals

Do not parameterize a value merely because it could vary.

### 2) Use clear parameter names

Prefer explicit names tied to meaning and scope:

- Good: `target_version`, `worker_count`, `setting_name`, `setting_value`
- Bad: `value1`, `target`, `flag`, `config`

If a parameter is role-specific, encode the role in the name.

### 3) Set defaults to the canonical standalone baseline

Defaults should represent a normal standalone run. Workflow overrides should
change only the values relevant to that stage.

### 4) Wire each parameter end-to-end

The resolved value must be used consistently in:

- Prompt text
- Precondition probes
- Precondition applies
- Precondition verification
- Rendered manifests or setup helpers
- Oracle expectations

The framework substitutes `{{params.name}}` in the normalized case and exports
the same value as `BENCH_PARAM_NAME`.

After adding a parameter, search for hidden hardcoded copies of its default.

### 5) Keep parameters aligned with independent precondition units

Each unit should depend only on parameters relevant to its concern. Avoid one
broad parameter block that couples source and target clusters or infrastructure
and problem-shape setup.

### 6) Quick validation for parameterization

Before handoff:

1. Run with defaults.
2. Run with a meaningful non-default override.
3. Inspect the rendered prompt and `bundle/env.json`.
4. Confirm setup and oracle use the override.
5. Self-chain the case with two different values when that is a supported use.

### Example: Why independent parameterization helps chaining

Consider a blue/green workflow with two clusters. If one unit probes both
clusters and one side drifts, the combined apply may mutate both sides.

If source and target use independent units and explicit parameters, only the
drifted side reconciles. Valid carried-over state on the other side remains
untouched.

## Namespace Contract

Prefer framework-managed role namespaces:

```yaml
namespace_contract:
  required_roles:
    - source
    - target
```

At runtime:

- `BENCH_NS_SOURCE` contains the source namespace.
- `BENCH_NS_TARGET` contains the target namespace.
- `BENCH_NAMESPACE` contains the default role, or the first bound namespace
  when no explicit default role exists.
- Workflows can map logical roles to physical namespace identities with
  `namespace_binding`.

Rules:

- Do not hardcode a namespace for setup convenience.
- Do not delete and recreate a framework-managed namespace.
- Keep source and target concerns in separate precondition units.
- Fixed literal namespaces are acceptable only when task semantics genuinely
  require them. Such cases declare an empty required-role list and are harder
  to compose safely.

Ordinary resource files are not automatically rendered by the framework. If a
manifest contains runtime variables, render it explicitly before applying it.
Whitelist only the intended variables:

```bash
envsubst '${BENCH_NAMESPACE} ${BENCH_PARAM_TARGET_PORT}' \
  < cases/tests/service/case/resource/manifest.yaml |
  kubectl apply -f -
```

Bare `envsubst` may erase shell variables embedded in a manifest.

## Resource-First Setup

Keep stable Kubernetes definitions under the case's `resource/` directory and
apply them from the relevant precondition unit. Use Python or shell setup
helpers when procedural initialization is genuinely required.

Resource-first setup does not mean pre-creating the object the agent is asked
to create. The precondition should provide the required environment, not solve
the task.

Examples:

- A “patch ConfigMap value” case should create the ConfigMap baseline.
- A “create Service” case should not include that Service in its baseline.
- A “repair permissions” case may create users and clients, but should plant
  the incorrect permission state rather than the final permission.

The framework cleans generated namespaces after the workflow. Do not add a
case-level cleanup block. Oracle `after_commands` may remove temporary
verification helpers, but they are not a substitute for namespace cleanup.

## Oracle Independence For Full Sweep

Oracle design directly affects stage correctness and regression-sweep signal.

Use this contract:

1. Observational by default
   - Read cluster state and return a deterministic verdict.
   - Do not repair the workload or complete the task.
2. Same parameter contract as setup
   - Use `BENCH_NAMESPACE`, `BENCH_NS_*`, and `BENCH_PARAM_*`.
   - Avoid hidden hardcoded names, versions, and endpoints.
3. Independent assertions
   - Separate unrelated properties when doing so makes failures easier to
     diagnose.
4. Active verification only when justified
   - Mutation may be valid when it is intrinsic to proving the promised
     property.

### Why split assertions

Bundled checks reduce signal quality. If one combined command fails, it may be
unclear which property regressed.

Example:

- Better:
  - Pods exist.
  - Expected pod count is ready.
  - Service endpoint responds.
- Worse:
  - One opaque command checks all three and returns only one failure.

Small assertions are especially useful in a regression sweep because they
show which parts of an earlier outcome still hold.

### Active Verification Example: Persistence

Suppose the task promises that a CockroachDB setting persists after restart.
Reading the setting before restart does not prove persistence.

A valid oracle may:

1. Confirm the expected setting value.
2. Restart one pod.
3. Wait for the pod and cluster to recover.
4. Confirm the setting still holds.

This mutation is acceptable only because restart durability is part of the
task. The oracle must not set the value itself, repair a failed rollout, or
leave the cluster unstable.

### Verification Helpers

Some oracles need a temporary client pod. Use:

```yaml
oracle:
  verify:
    before_commands:
      - command: "kubectl -n ${BENCH_NAMESPACE} apply -f cases/common/rabbitmq/oracle-client.yaml"
    commands:
      - command: "python3 cases/tests/<service>/<case>/oracle/oracle.py"
    after_commands:
      - command: "kubectl -n ${BENCH_NAMESPACE} delete -f cases/common/rabbitmq/oracle-client.yaml --ignore-not-found=true"
    after_failure_mode: warn
```

`before_commands` prepare only the verification mechanism. They must not repair
the workload. `after_commands` run after core verification; set
`after_failure_mode: fail` only when helper cleanup is part of correctness.

## Case Studies: Why Independent Preconditions Matter

These examples show why each precondition unit should check one concern.

### Case Study 1: RabbitMQ Blue/Green Migration

Scenario:

- Blue is the source cluster.
- Green is the target cluster.
- Messages must move to green without unnecessarily mutating blue.

Bad setup:

- One unit checks both clusters.
- Green is missing one resource.
- The combined apply re-applies both blue and green.

What can go wrong:

- Blue's valid version or configuration is overwritten.
- Seed data or cluster membership is disturbed.
- Later workflow stages become order-sensitive.

Good setup:

- One unit checks source readiness.
- One unit checks target readiness.
- Separate units own seed data and migration-specific baseline.

Result:

- If only green drifts, only green changes.
- Blue remains available as valid carry-over state.

### Case Study 2: CockroachDB Monitoring Integration

Goal:

- Prometheus can scrape CockroachDB metrics.

A good precondition should distinguish:

- CockroachDB runtime readiness
- Monitoring infrastructure readiness
- Scrape-target readiness

Do not bundle installation of the database, monitoring components, and target
checks into one reset. If monitoring already works through a valid setup, the
probe may accept the outcome. If the task specifically requires one
implementation, the probe must check that implementation because it is part of
the problem contract.

Outcome probing is appropriate only when the task allows multiple solutions.

### Case Study 3: MongoDB Stage1 -> Stage2 RBAC Drift Setup

Scenario:

- Stage 1 leaves a healthy replica set and baseline users.
- Stage 2 requires a specific reporting-RBAC drift.

Bad setup:

- One large Stage 2 unit combines runtime, secrets, users, and drift.
- One RBAC mismatch triggers deletion and recreation of the core workload.

Good setup:

- Unit A: `mongodb_cluster_runtime_ready`
  - Probe core runtime and required authentication inputs.
  - Apply only missing infrastructure.
  - Verify replica-set health.
- Unit B: `custom_roles_setup_baseline_ready`
  - Probe only the exact RBAC problem shape.
  - Reconcile roles and users in place.
  - Verify the task remains unsolved in the intended way.

Result:

- Stage 2 runs standalone.
- Stage 2 can follow Stage 1.
- Core data survives while the challenge baseline is restored.

### Reference Pattern: Independent Runtime and Drift Units

Use this structure when a case needs both infrastructure and
challenge-specific state:

1. Runtime unit (`*_runtime_ready`)
   - Checks only core health and identity material.
   - Applies missing infrastructure idempotently.
   - Avoids destructive rebuilds unless they are unavoidable and justified.
2. Problem unit (`*_drift_ready` or `*_baseline_ready`)
   - Checks only the exact unsolved problem.
   - Replants that problem when a previous run solved it.
   - Does not rebuild unrelated infrastructure.

### Simple Rule

For every precondition unit:

- Probe: “Is this one concern in the exact state required before the task?”
- Apply: “What is the smallest reliable reconciliation for this concern?”
- Verify: “Did this concern reach the required state?”

If those questions have unrelated answers, split the unit.

## When To Split Preconditions

Split a large precondition when:

- One drift causes unrelated resources to re-apply.
- Infrastructure readiness and challenge baseline are mixed.
- Source and target clusters are coupled.
- A helper resource failure rebuilds the application.
- A solved task can pass the probe and silently skip the challenge.

A larger reset can be justified when:

- The task has multiple valid solutions and no smaller reset can reliably
  restore a known unsolved baseline.
- A downgrade or destructive transition inherently requires recreation.
- Reusing unknown carried-over state would make the task nondeterministic.

Document the reason and keep the reset scoped as narrowly as practical.

## Example: Two-Cluster Case (Blue/Green-Style)

For a case that uses source and target namespaces:

Bad:

- One unit probes source and target together.
- Target drift causes both sides to re-apply.

Good:

- `source_cluster_ready` owns only source.
- `target_cluster_ready` owns only target.
- Migration data and fault state have their own units.
- Workflow `namespace_binding` maps roles to physical identities.

This lets a workflow reverse direction or reuse one side without unnecessary
mutation.

## Validation Before Handoff

### Static Validation

Run:

```bash
python3 scripts/validate_ported_case.py SERVICE CASE
```

This checks case normalization, referenced files, Python compilation, YAML
parsing, and unresolved tokens in plainly applied manifests.

### Standalone Kind Validation

Run the case with a real solve action:

```bash
python3 orchestrator.py run-case SERVICE CASE \
  --agent AGENT \
  --param NAME=VALUE
```

Confirm:

- Setup establishes the unsolved task.
- The agent or test solver actually changes the cluster.
- The oracle passes.
- Generated namespaces are removed.

### Self-Chain Validation

Build a two-stage workflow containing the case twice.

Run:

- Same parameters in both stages.
- Different meaningful parameters when supported.
- `--final-sweep-mode full` when earlier outcomes are expected to survive.

Inspect stage 2's `precondition.log`:

- Infrastructure no-ops when valid.
- Problem-shape setup runs when needed.
- No solved state silently bypasses the task.
- No unrelated state is reset.

A passing self-chain is not sufficient by itself. Verify from logs and live
state that the second stage exercised the intended problem.

### Minimal Validation Matrix

Record one row per touched case:

| Check | Required evidence |
| --- | --- |
| Static case validation | `scripts/validate_ported_case.py` passes. |
| Standalone Kind run | Preconditions plant the unsolved task, a real solve runs, oracle passes. |
| Same-parameter self-chain | Stage 2 reuses valid infrastructure and replants the problem when needed. |
| Different-parameter self-chain | Non-default values are honored by setup, prompt, solver/agent action, and oracle. |
| Final regression sweep | Earlier outcomes still pass unless the new stage is intentionally destructive. |
| Namespace cleanup | Generated namespaces from the run are removed. |

### Self-Chain Workflow Skeleton

Use the same physical namespace when checking whether a case can chain against
itself. Change only meaningful parameters in the varied stage.

```yaml
metadata:
  id: SERVICE-CASE-self-chain
spec:
  prompt_mode: progressive
  stages:
    - id: default_first
      service: SERVICE
      case: CASE
      namespaces: [cluster_a]
      namespace_binding: { default: cluster_a }
    - id: default_second
      service: SERVICE
      case: CASE
      namespaces: [cluster_a]
      namespace_binding: { default: cluster_a }
    - id: varied_parameters
      service: SERVICE
      case: CASE
      namespaces: [cluster_a]
      namespace_binding: { default: cluster_a }
      param_overrides:
        meaningful_param: non_default_value
```

Run with full sweep when earlier outcomes should survive:

```bash
python3 orchestrator.py run-workflow workflows/path/to/self-chain.yaml \
  --final-sweep-mode full
```

### Varied-Parameter Decision Rules

Different-parameter self-chain is required when the parameter is meant to make
the case reusable in one workflow namespace. It is not automatically required
when the parameter changes object identity in a way that intentionally replaces
the previous stage's target.

If a varied stage cannot preserve the previous stage's regression oracle, make
that explicit in the case review. Either bind it to a different namespace,
vary an outer identity such as `cluster_prefix`, or document why the transition
is destructive and should skip regression compatibility.

### Deterministic Solver Validation

A deterministic solver script can be used for case validation when agent
quality is not the thing being tested. The solver must perform the same kind of
operator action the prompt asks for.

Do not let a validation solver:

- call the oracle
- edit preconditions
- create framework namespaces
- delete unrelated workflow state
- rely on hardcoded defaults that ignore `BENCH_PARAM_*`

The best solver scripts are small, parameter-aware, and leave a normal
submission artifact when the harness expects one.

### Evidence To Inspect

For every failed or suspicious chain run, inspect:

- `bundle/env.json` for effective namespace and parameter values.
- Stage 2 `precondition.log` for no-op versus replant behavior.
- `oracle.json` for the authoritative verdict.
- Regression-sweep oracle artifacts for broken earlier outcomes.
- Live Kubernetes state when logs and oracle disagree.

## Brainstorm: State Compatibility Contracts

Self-chain validation is necessary, but it cannot prove that a case can follow
every valid state produced by earlier workflow stages. Avoid the anti-pattern of
adding one-off precondition patches only after a specific workflow breaks.

Potential direction: each case should declare and honor a state compatibility
contract:

- Required input state: what must exist before the task can be attempted.
- Accepted variance: versions, replica counts, extra resources, or prior data
  that should be preserved.
- Required exact state: values that must be exact because the task depends on
  them.
- Normalization policy: preserve, expand only, safe decommission, or justified
  broad reset.
- Forbidden mutation: state the case must not change, such as data, unrelated
  versions, or unrelated Services.
- Output guarantee: what the case promises remains true after a solve.

Design probes against the semantic contract, not the default setup shape. For
example, if a CockroachDB case only needs a healthy SQL cluster, it should not
reject a valid six-node cluster merely because the standalone default is three.
If a case truly requires exactly three nodes, the normalization policy must be
explicit and safe, such as decommissioning rather than raw scale-down.

Open ideas to explore later:

- Add service-level normalizers for dangerous operations such as CockroachDB
  decommission, MongoDB member removal, and Elasticsearch master downscale.
- Add compatibility-envelope validation: run a case against generic valid
  predecessor-like states such as larger topology, different supported version,
  extra unrelated resources, and prior solved state.
- Treat workflow-combination failures as evidence that the case contract was
  incomplete, not as an invitation to add workflow-specific setup hacks.

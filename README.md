<div align="center">

<p align="center">
  <img src="./docs/images/KARMA.jpg" alt="KARMA" width="760">
</p>

# KARMA

**Kubernetes Agent Runtime Measurement Architecture**

Modular Framework for Evaluating AI Agents in
Kubernetes

📺 <a href="https://youtu.be/_KY-T6U31Is"><b>Watch the 2-minute demo screencast</b></a>

<p align="center">
  <a href="#about"><b>About</b></a> |
  <a href="#why-karma"><b>Why KARMA</b></a> |
  <a href="#roadmap"><b>Roadmap</b></a> |
  <a href="#quick-start"><b>Quick Start</b></a> |
  <a href="#repo-map"><b>Repo Map</b></a> |
  <a href="#profiles"><b>Profiles</b></a> |
  <a href="#developer-guide"><b>Developer Guide</b></a> |
  <a href="#license"><b>License</b></a>
</p>

</div>

## About

KARMA is a framework for evaluating AI agents on realistic Kubernetes operations tasks.

Instead of treating each benchmark as a one-off script, KARMA models tasks as reusable stages that can be assembled into multi-stage workflows. Each stage prepares the environment, lets the agent act on the live system, verifies the result, and records artifacts for later analysis.

The point is simple: isolated tasks only tell part of the story. Real operations work is stateful. Changes stack up. Fixes in one step can quietly break something earlier. KARMA is built to evaluate agents in that setting.

The suite ships **92 composable cases** and **38 reversible adversary scenarios** across **eight systems** — RabbitMQ, MongoDB, CockroachDB, Elasticsearch, Nginx, Ray, Spark, and a demo service — which recombine into hundreds of example workflows.

## Why KARMA

KARMA is built around a few ideas that matter in practice:

- **Reusable building blocks.** A testcase defines one operational task with setup, prompt, verification, and cleanup.
- **Stateful workflows.** Stages run in sequence against preserved system state, so later actions can help or hurt earlier outcomes.
- **Deterministic correctness checks.** Each stage has explicit verification, with optional workflow-level regression sweeps to catch cross-stage breakage.
- **Probe/apply/verify setup.** Testcases are broken into smaller resource-level precondition units, each with its own `probe`, `apply`, and `verify` cycle. That makes cases much more chainable because a later workflow stage can reuse the parts of the environment that are already correct instead of replaying a full reset.
- **Trajectory capture.** Runs produce logs, traces, snapshots, and optional judge artifacts so you can inspect how the agent behaved, not just whether it passed.

This makes KARMA useful for long-horizon evaluation, regression analysis, and safety-oriented agent testing in real infrastructure environments.

## Roadmap

KARMA already supports **horizontal composition**: building longer workflows from reusable stages.

But many hard real-world tasks are not just longer workflows. They are a base task plus environmental adversaries such as drift, permission constraints, and competing controllers.

That is the next direction for KARMA:

- [ ] Extend KARMA beyond Kubernetes
- [ ] Add layered environmental adversaries to workflows

## Quick Start

### Prerequisites

- Python 3.11+
- `kubectl` on your `PATH`, pointing at a reachable cluster (a local [kind](https://kind.sigs.k8s.io/) cluster works)
- a kubeconfig at `~/.kube/config` (or set `KUBECONFIG`)

Some case setup scripts use `envsubst` (from GNU gettext) to fill in parameterized Kubernetes manifests. Install it before running those cases:

- macOS: `brew install gettext`; if `envsubst` is not on your `PATH`, run `export PATH="$(brew --prefix gettext)/bin:$PATH"`.
- Debian/Ubuntu: `sudo apt-get install gettext-base`.
- Fedora: `sudo dnf install gettext-envsubst`.

### Install and launch the web UI

```bash
pip install -e .
python3 main.py
```

Then open:

```text
http://localhost:8080
```

The UI is the easiest way to browse services, inspect workflows, run cases, and generate the equivalent CLI commands.

### Bootstrap a local cluster

```bash
./scripts/setup-cluster.sh --provider kind
```

### Run from the CLI

Run a single case:

```bash
python3 orchestrator.py run-case demo configmap-update \
  --agent cli_runner --sandbox local
```

Run a multi-stage workflow:

```bash
python3 orchestrator.py run-workflow workflows/suite/workflow-demo.yaml \
  --agent cli_runner
```

Judge a completed run (LLM-as-Judge):

```bash
python3 orchestrator.py judge runs/<run_id>
```

List the available agents:

```bash
python3 orchestrator.py info --agents
```

For a local debug run that should reuse a specific namespace, a workflow can
declare a debug-only alias mapping:

```yaml
spec:
  debug:
    namespace_overrides:
      default: cockroachdb
```

Activate it with `python3 orchestrator.py run-workflow <workflow.yaml> --debug`.
The mapping key is a workflow namespace alias (for example, `default`), and the
value is the Kubernetes namespace name. Without `--debug`, KARMA continues to
use its normal per-run namespaces. KARMA does not role-label or role-delete the
overridden namespace; however, the case's own setup commands still run and may
modify or recreate resources there, so use it with a cluster/namespace intended
for testing.

### Run the tests

```bash
pip install -e ".[dev]"    # installs pytest and the test dependencies
pytest tests/unit          # fast, no cluster required
pytest tests/integration   # requires a reachable cluster
```

## Repo Map

- `main.py`
  HTTP server and web UI (served at `http://localhost:8080`).

- `orchestrator.py`
  Headless CLI entrypoint for `run-case`, `run-workflow`, `run-batch`, `judge`, and `info`.

- `karma/`
  The framework package: case/workflow/prompt **definitions**, the Kubernetes **environment** and **transport** (kubectl proxy), the **adversary** lifecycle, the **runtime** execution core, the **oracle** and **evidence** collection, and the LLM-as-**judge** pipeline.

- `karma/agents/`
  Agent adapters and container definitions (`cli_runner`, `react`, `claude_code`, `codex`, `copilot`, `api`).

- `cases/`
  Benchmark corpus. Each testcase lives under `cases/<service>/<case>/test.yaml`.

- `workflows/`
  Multi-stage workflow definitions built from reusable testcases.

- `adversaries/`
  Adversary scenarios (drift, permission constraints, competing controllers) injected into workflows.

- `webui/`
  The browser UI — plain HTML/CSS/JS with no build step.

- `docs/`
  Developer runbooks, prompt templates, and design notes.

- `tests/`
  `tests/unit` (fast, no cluster) and `tests/integration` (require a live cluster).

## Profiles

A **profile** is a reusable YAML preset of run flags (agent, sandbox, timeout, params, …) so you don't have to repeat them on every invocation. Pass one with `--profile` to `run-case`, `run-workflow`, or `run-batch`:

```bash
python3 orchestrator.py run-workflow workflows/suite/workflow-demo.yaml \
  --profile my-profile.yaml
```

Note: the LLM-as-Judge also uses rubric overlays (e.g. `judge_base.yaml`), which are a separate concept — they tune scoring, not execution.

## Developer Guide

If you want to understand or extend the repo, start here:

- `docs/developer/adding-a-test-case.md`
  How to author reusable, workflow-safe testcases.

- `docs/developer/kind-cluster-setup.md`
  Setting up a local Kind cluster.

- `docs/developer/persistent-agent-sessions.md`
  How an agent session persists across stages of a workflow.

- `docs/developer/composition-failure-patterns.md`
  Common failure classes in long, composed workflows.

If you are new to the codebase, a good path is:

1. Skim the Repo Map above and the guides in `docs/developer/`.
2. Open a workflow in `workflows/` and a testcase in `cases/<service>/<case>/test.yaml`.
3. Trace `orchestrator.py` into `karma/interfaces/cli/main.py` and `karma/runtime/workflow.py`.
4. Run a workflow and inspect the artifacts under `runs/`.

## License

KARMA is released under the [MIT License](LICENSE).

## Citation

If you use KARMA in your research, please cite:

```bibtex
@unpublished{karma2026,
  title  = {KARMA: A Composable Framework for Evaluating LLM Agents on
            Stateful Kubernetes Operations},
  author = {Ouyang, Junhan and Liu, Shaw and Wang, Jinlang and Zhou, Jiawei},
  year   = {2026},
  note   = {Under review at EMNLP 2026 System Demonstrations}
}
```

<!-- TODO: swap to the published @inproceedings entry (venue, pages, DOI) once the paper is accepted. -->

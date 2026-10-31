#!/usr/bin/env python3
"""Oracle for spark/spark_streaming_autoscale.

Verifies the operator actively scaled the cluster through the traffic phases:
  - the Spark cluster is up (master ready, >= 1 worker),
  - spark-worker was scaled through the prompt's phase targets (up to the
    Phase-3 peak of 20, via the Phase-2 step of 10, then back to the baseline
    of 5), graded from the DURABLE scale history the resource records itself
    (the deployment controller's ScalingReplicaSet events + the live spec),
    corroborated by the metrics-server watch log, and
  - the traffic generator is running or has completed.

O46: the scale outcome is graded from the deployment's own recorded history,
not solely from a fixed-interval helper-pod watch log — that lossy sampler
misses transitions under adversary pod-churn, zeroing a flawless agent.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

from cases.common.spark.oracle_lib import (  # noqa: E402
    bench_namespace,
    deployment_ready_replicas,
    deployment_spec_replicas,
    kubectl_json,
    run,
)

NAMESPACE = bench_namespace("spark-streaming")
WORKER = "spark-worker"
BASELINE = 5           # Phase 1 / Phase 4 cooldown target
PHASE2_TARGET = 10     # Phase 2 (2x spike)
PHASE3_TARGET = 20     # Phase 3 (5x spike) — the peak


def fail(message: str) -> int:
    print(f"spark_streaming_autoscale oracle failed: {message}")
    return 1


def pod_logs(selector: str) -> str:
    proc = run(
        ["kubectl", "-n", NAMESPACE, "logs", "-l", selector, "--tail=-1", "--prefix=true"],
        check=False,
    )
    return proc.stdout or ""


def check_cluster() -> int:
    master_ready = deployment_ready_replicas(NAMESPACE, "spark-master")
    if master_ready < 1:
        return fail(f"deployment/spark-master readyReplicas={master_ready}, expected >= 1")
    worker_ready = deployment_ready_replicas(NAMESPACE, WORKER)
    if worker_ready < 1:
        return fail(f"deployment/{WORKER} readyReplicas={worker_ready}, expected >= 1")
    return 0


def _event_scale_sequence() -> list[int]:
    """Ordered replica targets from the deployment's ScalingReplicaSet events.

    The deployment controller records every `kubectl scale` as a durable event
    ("Scaled up/down replica set ... to N") on the Deployment object — a signal
    that survives pod-churn, unlike the sampled watch log. Ordered by timestamp.
    """
    try:
        payload = kubectl_json(NAMESPACE, ["get", "events"])
    except Exception:
        return []
    items = payload.get("items", []) or []
    scaled: list[tuple[str, int]] = []
    for ev in items:
        involved = ev.get("involvedObject", {}) or {}
        if involved.get("kind") != "Deployment" or involved.get("name") != WORKER:
            continue
        if ev.get("reason") != "ScalingReplicaSet":
            continue
        match = re.search(r"\bto (\d+)\b", str(ev.get("message") or ""))
        if not match:
            continue
        ts = str(ev.get("lastTimestamp") or ev.get("eventTime")
                 or (ev.get("metadata", {}) or {}).get("creationTimestamp") or "")
        scaled.append((ts, int(match.group(1))))
    scaled.sort(key=lambda pair: pair[0])
    return [count for _, count in scaled]


def _log_scale_sequence() -> list[int]:
    """Replica targets from the metrics-server watch log (corroborating only)."""
    logs = pod_logs("app=metrics-server")
    return [int(n) for n in re.findall(r"->\s*(\d+)", logs)]


def check_scaling_events() -> int:
    """Grade the scale-through against the phase targets from durable history."""
    events = _event_scale_sequence()
    log_seq = _log_scale_sequence()
    # Union for peak/target detection; the events sequence is authoritative for
    # ordering (the log is a lossy corroborator, kept per O46's guidance).
    observed = set(events) | set(log_seq)
    current = deployment_spec_replicas(NAMESPACE, WORKER)
    observed.add(current)

    peak = max(observed) if observed else current
    if peak < PHASE3_TARGET:
        return fail(
            f"{WORKER} peak replicas={peak}, expected the Phase-3 target "
            f"of {PHASE3_TARGET} to be reached (events={events}, log={log_seq})"
        )
    if PHASE2_TARGET not in observed:
        return fail(
            f"{WORKER} never scaled through the Phase-2 target of {PHASE2_TARGET} "
            f"(observed={sorted(observed)})"
        )
    # Phase-4 cooldown: the durable end-state must return to baseline, or a
    # scale-down back to baseline must be the last recorded transition. (The
    # creation event is itself a "to 5", so membership in `observed` is not
    # evidence of a cooldown — require the live spec or the final transition.)
    returned = current <= BASELINE or (bool(events) and events[-1] <= BASELINE)
    if not returned:
        return fail(
            f"{WORKER} did not return to the baseline of {BASELINE} after the "
            f"spike (current={current}, events={events})"
        )
    return 0


def check_traffic_generator() -> int:
    proc = run(
        [
            "kubectl",
            "-n",
            NAMESPACE,
            "get",
            "deployment",
            "traffic-generator",
            "-o",
            "jsonpath={.status.availableReplicas}",
        ],
        check=False,
    )
    if proc.returncode != 0:
        return fail("deployment/traffic-generator not found")
    raw = (proc.stdout or "").strip()
    try:
        available = int(raw or "0")
    except ValueError:
        available = 0
    logs = pod_logs("app=traffic-generator")
    if available < 1 and "TRAFFIC GENERATION COMPLETE" not in logs:
        return fail("traffic-generator is neither running nor completed")
    return 0


def main() -> int:
    for check in (check_cluster, check_scaling_events, check_traffic_generator):
        rc = check()
        if rc != 0:
            return rc
    print(
        "spark_streaming_autoscale verified: cluster up, worker scaled through "
        "the phase targets (10 -> 20 -> baseline), traffic active"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

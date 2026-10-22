#!/usr/bin/env python3
import argparse
import os
import sys
from pathlib import Path

from cases.common.rabbitmq.setup_check_utils import (  # noqa: E402
    expect_pod_ready,
    expect_pods_ready,
    list_pods,
    pod_is_ready,
    run_json,
    run,
    split_lines,
)

BLUE_CLUSTER_PREFIX = os.environ.get("BENCH_PARAM_BLUE_CLUSTER_PREFIX", "rabbitmq-blue")
GREEN_CLUSTER_PREFIX = os.environ.get("BENCH_PARAM_GREEN_CLUSTER_PREFIX", "rabbitmq-green")
SOURCE_NAMESPACE = os.environ.get("BENCH_NS_SOURCE")
TARGET_NAMESPACE = os.environ.get("BENCH_NS_TARGET")


def _check_cluster_bootstrap(ns, cluster_prefix, label, errors):
    pod0 = f"{cluster_prefix}-0"
    try:
        queues = run(
            [
                "kubectl",
                "-n",
                ns,
                "exec",
                pod0,
                "--",
                "rabbitmqctl",
                "-q",
                "list_queues",
                "-p",
                "/app",
                "name",
            ]
        )
        if "app-queue" not in set(split_lines(queues)):
            errors.append(f"{label}: app-queue missing from /app")
    except Exception as exc:
        errors.append(f"{label}: failed to inspect bootstrap queue state: {exc}")


def _check_seed_state(source_ns, source_prefix, required_messages, errors):
    try:
        queue_out = run(
            [
                "kubectl",
                "-n",
                source_ns,
                "exec",
                f"{source_prefix}-0",
                "--",
                "rabbitmqctl",
                "-q",
                "list_queues",
                "-p",
                "/app",
                "name",
                "messages",
            ]
        )
        for line in split_lines(queue_out):
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "app-queue":
                try:
                    if int(parts[1]) >= required_messages:
                        return
                except ValueError:
                    pass
                break
        errors.append(f"source: app-queue has fewer than {required_messages} message(s)")
    except Exception as exc:
        errors.append(f"source: failed to inspect seed queue state: {exc}")


def _read_seed_count(namespace, label, errors):
    try:
        cm = run_json(["kubectl", "-n", namespace, "get", "configmap", "migration-seed", "-o", "json"])
    except Exception as exc:
        errors.append(f"{label}: migration-seed configmap missing: {exc}")
        return None

    raw = str(((cm.get("data") or {}).get("seed_count") or "")).strip()
    if not raw:
        errors.append(f"{label}: migration-seed.seed_count missing")
        return None
    try:
        seed_count = int(raw)
    except ValueError:
        errors.append(f"{label}: migration-seed.seed_count is not an integer ({raw!r})")
        return None
    if seed_count <= 0:
        errors.append(f"{label}: migration-seed.seed_count must be > 0 (got {seed_count})")
        return None
    return seed_count


def _expect_labeled_pod_ready(namespace, label, errors, name_hint):
    pods = list_pods(namespace, label=label)
    if not pods:
        errors.append(f"{name_hint}: no pods found")
        return
    if not any(pod_is_ready(p) for p in pods):
        errors.append(f"{name_hint}: no ready pod found")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--namespace", default=os.environ.get("BENCH_NAMESPACE", "rabbitmq"))
    parser.add_argument("--source-namespace", default=SOURCE_NAMESPACE)
    parser.add_argument("--target-namespace", default=TARGET_NAMESPACE)
    parser.add_argument("--min-ready", type=int, default=1)
    parser.add_argument("--bootstrap-only", action="store_true")
    parser.add_argument("--seed-only", action="store_true")
    args = parser.parse_args()

    source_ns = args.source_namespace or args.namespace
    target_ns = args.target_namespace or args.namespace
    errors = []

    expect_pods_ready(source_ns, f"app={BLUE_CLUSTER_PREFIX}", 3, errors, BLUE_CLUSTER_PREFIX)
    expect_pods_ready(target_ns, f"app={GREEN_CLUSTER_PREFIX}", 3, errors, GREEN_CLUSTER_PREFIX)
    _check_cluster_bootstrap(source_ns, BLUE_CLUSTER_PREFIX, "source", errors)
    _check_cluster_bootstrap(target_ns, GREEN_CLUSTER_PREFIX, "target", errors)

    if args.bootstrap_only:
        if errors:
            print("setup-precondition-check: failed")
            for err in errors:
                print(f" - {err}")
            return 1
        print("setup-precondition-check: ok")
        return 0

    source_seed_count = _read_seed_count(source_ns, "source", errors)
    target_seed_count = _read_seed_count(target_ns, "target", errors)
    if (
        source_seed_count is not None
        and target_seed_count is not None
        and source_seed_count != target_seed_count
    ):
        errors.append(
            f"seed_count mismatch between source ({source_seed_count}) and target ({target_seed_count})"
        )

    required_seed_messages = source_seed_count if source_seed_count is not None else 1
    _check_seed_state(source_ns, BLUE_CLUSTER_PREFIX, required_seed_messages, errors)

    if args.seed_only:
        if errors:
            print("setup-precondition-check: failed")
            for err in errors:
                print(f" - {err}")
            return 1
        print("setup-precondition-check: ok")
        return 0

    _expect_labeled_pod_ready(target_ns, "app=curl-test", errors, "curl-test")

    deploys = run_json(
        ["kubectl", "-n", source_ns, "get", "deploy", "-l", "app=blue-producer", "-o", "json"]
    ).get("items", [])
    if not deploys:
        errors.append("blue-producer deployment missing")
    else:
        if not any((((d.get("status") or {}).get("readyReplicas") or 0) >= 1) for d in deploys):
            errors.append("blue-producer is not Ready")

    if errors:
        print("setup-precondition-check: failed")
        for err in errors:
            print(f" - {err}")
        return 1
    print("setup-precondition-check: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
import argparse
import os
import sys
from pathlib import Path

from cases.common.rabbitmq.setup_check_utils import (  # noqa: E402
    expect_pod_ready,
    expect_pods_ready,
    run,
    split_lines,
)

def _check_bootstrap_state(ns, cluster_prefix, errors):
    try:
        queue_out = run(
            [
                "kubectl",
                "-n",
                ns,
                "exec",
                f"{cluster_prefix}-0",
                "--",
                "rabbitmqctl",
                "-q",
                "list_queues",
                "-p",
                "/app",
                "name",
                "type",
            ]
        )
        found = False
        for line in split_lines(queue_out):
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "app-queue":
                found = True
                if parts[1] != "classic":
                    errors.append(f"app-queue expected classic, got {parts[1]}")
        if not found:
            errors.append("app-queue missing from /app")
    except Exception as exc:
        errors.append(f"failed to inspect bootstrap /app queues: {exc}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--namespace", default=os.environ.get("BENCH_NAMESPACE", "rabbitmq"))
    parser.add_argument("--min-ready", type=int, default=1)
    parser.add_argument("--bootstrap-only", action="store_true")
    args = parser.parse_args()
    ns = args.namespace
    cluster_prefix = os.environ.get("BENCH_PARAM_CLUSTER_PREFIX", "rabbitmq")
    errors = []

    expect_pods_ready(ns, f"app={cluster_prefix}", 3, errors, cluster_prefix)
    _check_bootstrap_state(ns, cluster_prefix, errors)

    if args.bootstrap_only:
        if errors:
            print("setup-precondition-check: failed")
            for err in errors:
                print(f" - {err}")
            return 1
        print("setup-precondition-check: ok")
        return 0

    expect_pods_ready(ns, "app=curl-test", 1, errors, "curl-test")

    try:
        policies = run(
            [
                "kubectl",
                "-n",
                ns,
                "exec",
                f"{cluster_prefix}-0",
                "--",
                "rabbitmqctl",
                "-q",
                "list_policies",
                "-p",
                "/app",
            ]
        )
        if "ha-all" in policies:
            errors.append("ha-all already exists in /app (precondition should be unsynced)")
    except Exception as exc:
        errors.append(f"failed to inspect policies: {exc}")

    if errors:
        print("setup-precondition-check: failed")
        for err in errors:
            print(f" - {err}")
        return 1
    print("setup-precondition-check: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

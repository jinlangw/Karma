#!/usr/bin/env python3
import argparse
import os
import sys
from pathlib import Path

from cases.common.rabbitmq.setup_check_utils import (  # noqa: E402
    expect_pod_ready,
    expect_pods_ready,
    run,
    run_json,
    split_lines,
)

def _check_seeded_queue_state(ns, cluster_prefix, errors):
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
                "messages",
            ]
        )
        found = False
        for line in split_lines(queue_out):
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "app-queue":
                found = True
                try:
                    messages = int(parts[1])
                except ValueError:
                    messages = 0
                if messages < 1:
                    errors.append("app-queue has no messages")
                break
        if not found:
            errors.append("app-queue missing from /app")
    except Exception as exc:
        errors.append(f"failed to inspect queue state: {exc}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--namespace", default=os.environ.get("BENCH_NAMESPACE", "rabbitmq"))
    parser.add_argument("--min-ready", type=int, default=1)
    parser.add_argument(
        "--cluster-prefix",
        default=os.environ.get("BENCH_PARAM_CLUSTER_PREFIX", "rabbitmq"),
    )
    parser.add_argument(
        "--from-version",
        default=os.environ.get("BENCH_PARAM_FROM_VERSION", "3.9"),
    )
    parser.add_argument("--bootstrap-only", action="store_true")
    args = parser.parse_args()
    ns = args.namespace
    cluster_prefix = args.cluster_prefix
    errors = []

    expect_pods_ready(ns, f"app={cluster_prefix}", 3, errors, cluster_prefix)
    _check_seeded_queue_state(ns, cluster_prefix, errors)

    if not args.bootstrap_only:
        expect_pods_ready(ns, "app=curl-test", 1, errors, "curl-test")
    else:
        if errors:
            print("setup-precondition-check: failed")
            for err in errors:
                print(f" - {err}")
            return 1
        print("setup-precondition-check: ok")
        return 0

    sts = run_json(["kubectl", "-n", ns, "get", "sts", cluster_prefix, "-o", "json"])
    image = (
        ((sts.get("spec") or {}).get("template") or {})
        .get("spec", {})
        .get("containers", [{}])[0]
        .get("image", "")
    )
    expected_image_prefix = f"rabbitmq:{args.from_version}"
    if expected_image_prefix not in image:
        errors.append(
            f"expected baseline image prefix {expected_image_prefix!r} before upgrade, got {image}"
        )

    if errors:
        print("setup-precondition-check: failed")
        for err in errors:
            print(f" - {err}")
        return 1
    print("setup-precondition-check: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

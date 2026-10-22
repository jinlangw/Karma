#!/usr/bin/env python3
import argparse
import os
import sys
from pathlib import Path

from cases.common.rabbitmq.setup_check_utils import (  # noqa: E402
    BAD_WAITING_REASONS,
    expect_pod_ready,
    expect_pods_ready,
    list_pods,
    pod_is_ready,
    pod_name,
    pod_waiting_reason,
    run,
    split_lines,
)

def _check_bootstrap_state(ns, cluster_prefix, errors):
    pod = f"{cluster_prefix}-0"
    try:
        vhosts_out = run(
            ["kubectl", "-n", ns, "exec", pod, "--", "rabbitmqctl", "-q", "list_vhosts"]
        )
        vhosts = {line.strip() for line in split_lines(vhosts_out)}
        if "/app" not in vhosts:
            errors.append("vhost /app missing")
    except Exception as exc:
        errors.append(f"failed to inspect vhosts: {exc}")

    try:
        perms_out = run(
            ["kubectl", "-n", ns, "exec", pod, "--", "rabbitmqctl", "-q", "list_permissions", "-p", "/app"]
        )
        if not any(line.split() and line.split()[0] == "app-user" for line in split_lines(perms_out)):
            errors.append("app-user permissions for /app missing")
    except Exception as exc:
        errors.append(f"failed to inspect /app permissions: {exc}")

    # Policy state is part of the challenge baseline, but the setup job currently
    # does not fail if management API writes are rejected. Keep bootstrap checks
    # focused on durable cluster bootstrap semantics (vhost + user permissions)
    # so the precondition remains carryover-safe without becoming flaky.


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

    producer_pods = list_pods(ns, label="app=app-producer")
    if len(producer_pods) < 1:
        errors.append("app-producer pod missing")
    else:
        broken = False
        for pod in producer_pods:
            reason = pod_waiting_reason(pod)
            if not pod_is_ready(pod):
                broken = True
            if reason in BAD_WAITING_REASONS:
                broken = True
        if not broken:
            names = ",".join(pod_name(p) for p in producer_pods)
            errors.append(f"app-producer is unexpectedly healthy ({names})")

    if errors:
        print("setup-precondition-check: failed")
        for err in errors:
            print(f" - {err}")
        return 1
    print("setup-precondition-check: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

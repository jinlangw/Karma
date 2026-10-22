#!/usr/bin/env python3
import argparse
import os
import re
import sys
from pathlib import Path

from cases.common.rabbitmq.setup_check_utils import (  # noqa: E402
    BAD_WAITING_REASONS,
    expect_pod_ready,
    expect_pods_ready,
    list_pods,
    pod_is_ready,
    pod_waiting_reason,
    run,
    split_lines,
)


def _parse_permissions_table(raw_text):
    rows = {}
    for line in split_lines(raw_text):
        if not line.strip():
            continue
        if "\t" in line:
            cols = [c.strip() for c in line.split("\t")]
        else:
            cols = [c.strip() for c in re.split(r"\s{2,}", line.strip())]
        if not cols:
            continue
        if cols[0] == "user":
            continue
        while len(cols) < 4:
            cols.append("")
        user, configure, write, read = cols[:4]
        rows[user] = {"configure": configure, "write": write, "read": read}
    return rows


def _parse_user_names(raw_text):
    users = set()
    for line in split_lines(raw_text):
        text = line.strip()
        if not text:
            continue
        if text.startswith("Listing users"):
            continue
        if text.startswith("user\t") or text == "user":
            continue
        if "\t" in text:
            user = text.split("\t", 1)[0].strip()
        else:
            user = text.split(None, 1)[0].strip()
        if user:
            users.add(user)
    return users


def _is_intentionally_broken_configure(configure_value):
    return configure_value in ("", '""', "^$", '"^$"')


def _has_any_permission(perm):
    """True if a parsed permission row grants any configure/write/read access."""
    if not perm:
        return False
    for value in (perm.get("configure", ""), perm.get("write", ""), perm.get("read", "")):
        if value not in ("", '""', "^$", '"^$"'):
            return True
    return False


def _check_ops_scenario(ns, cluster_prefix, errors):
    """Verify the ops-user mis-permission scenario is planted on the cluster.

    The setup-job intentionally grants ops-user permissions on /app (the wrong
    vhost) and leaves ops-user WITHOUT access on /ops, so ops-client crashes.
    This gate makes the ``setup_job_completed`` probe fail whenever an inherited
    cluster is already in a healthy/fixed state, so the idempotent setup-job
    re-establishes the scenario additively (no namespace/cluster reset).
    """
    try:
        app_perms = _parse_permissions_table(
            run([
                "kubectl", "-n", ns, "exec", f"{cluster_prefix}-0", "--",
                "rabbitmqctl", "-q", "list_permissions", "-p", "/app",
            ])
        )
    except Exception as exc:
        errors.append(f"failed to inspect /app permissions for ops-user: {exc}")
        return
    if not _has_any_permission(app_perms.get("ops-user")):
        errors.append("ops-user mis-grant on /app is not planted")

    try:
        ops_perms = _parse_permissions_table(
            run([
                "kubectl", "-n", ns, "exec", f"{cluster_prefix}-0", "--",
                "rabbitmqctl", "-q", "list_permissions", "-p", "/ops",
            ])
        )
    except Exception as exc:
        errors.append(f"failed to inspect /ops permissions for ops-user: {exc}")
        return
    if _has_any_permission(ops_perms.get("ops-user")):
        errors.append("ops-user already has access on /ops (scenario not broken)")


def _deployment_expected_broken(namespace, label, errors):
    pods = list_pods(namespace, label=label)
    if not pods:
        errors.append(f"{label}: no pods found")
        return
    broken = False
    for pod in pods:
        if not pod_is_ready(pod):
            broken = True
        reason = pod_waiting_reason(pod)
        if reason in BAD_WAITING_REASONS:
            broken = True
    if not broken:
        errors.append(f"{label}: unexpectedly healthy")


def _check_bootstrap_state(ns, cluster_prefix, errors):
    try:
        vhosts = run(
            [
                "kubectl",
                "-n",
                ns,
                "exec",
                f"{cluster_prefix}-0",
                "--",
                "rabbitmqctl",
                "-q",
                "list_vhosts",
                "name",
            ]
        )
        lines = set(split_lines(vhosts))
        for vhost in ("/app", "/ops"):
            if vhost not in lines:
                errors.append(f"missing vhost {vhost}")
    except Exception as exc:
        errors.append(f"failed to inspect vhosts: {exc}")

    try:
        users = run(
            [
                "kubectl",
                "-n",
                ns,
                "exec",
                f"{cluster_prefix}-0",
                "--",
                "rabbitmqctl",
                "-q",
                "list_users",
            ]
        )
        user_lines = _parse_user_names(users)
        for user in ("app-user", "ops-user"):
            if user not in user_lines:
                errors.append(f"missing user {user}")
    except Exception as exc:
        errors.append(f"failed to inspect users: {exc}")

    for vhost, queue_name in (("/app", "app-queue"), ("/ops", "ops-queue")):
        try:
            queues = run(
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
                    vhost,
                    "name",
                ]
            )
            if queue_name not in set(split_lines(queues)):
                errors.append(f"{queue_name} missing from {vhost}")
        except Exception as exc:
            errors.append(f"failed to inspect queues in {vhost}: {exc}")


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

    if not args.bootstrap_only:
        expect_pods_ready(ns, "app=curl-test", 1, errors, "curl-test")
        _deployment_expected_broken(ns, "app=app-client", errors)
        _deployment_expected_broken(ns, "app=ops-client", errors)

    try:
        perms = run(
            [
                "kubectl",
                "-n",
                ns,
                "exec",
                f"{cluster_prefix}-0",
                "--",
                "rabbitmqctl",
                "-q",
                "list_permissions",
                "-p",
                "/app",
            ]
        )
        parsed = _parse_permissions_table(perms)
        app_perm = parsed.get("app-user")
        if not app_perm:
            users = ",".join(sorted(parsed.keys())) if parsed else "<none>"
            errors.append(f"app-user permissions missing on /app (parsed users: {users})")
        elif not _is_intentionally_broken_configure(app_perm["configure"]):
            errors.append(
                "app-user configure permission on /app is not intentionally broken "
                f"(value={app_perm['configure']!r})"
            )
    except Exception as exc:
        errors.append(f"failed to inspect /app permissions: {exc}")

    # Gate the setup-job on the ops-user scenario too: if an inherited cluster
    # left ops-user healthy (access on /ops, no /app mis-grant), the bootstrap
    # probe must fail so the idempotent setup-job re-plants the broken scenario.
    _check_ops_scenario(ns, cluster_prefix, errors)

    if args.bootstrap_only:
        if errors:
            print("setup-precondition-check: failed")
            for err in errors:
                print(f" - {err}")
            return 1
        print("setup-precondition-check: ok")
        return 0

    if errors:
        print("setup-precondition-check: failed")
        for err in errors:
            print(f" - {err}")
        return 1
    print("setup-precondition-check: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

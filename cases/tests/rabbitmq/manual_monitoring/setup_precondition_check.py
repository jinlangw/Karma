#!/usr/bin/env python3
import argparse
import os
import json
import sys
from pathlib import Path

from cases.common.rabbitmq.setup_check_utils import expect_pod_ready, expect_pods_ready, run  # noqa: E402


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--namespace", default=os.environ.get("BENCH_NAMESPACE", "rabbitmq"))
    parser.add_argument("--min-ready", type=int, default=1)
    args = parser.parse_args()
    ns = args.namespace
    cluster_prefix = os.environ.get("BENCH_PARAM_CLUSTER_PREFIX", "rabbitmq")
    errors = []

    expect_pods_ready(ns, f"app={cluster_prefix}", 3, errors, cluster_prefix)
    expect_pods_ready(ns, "app=prometheus", 1, errors, "prometheus")
    expect_pods_ready(ns, "app=curl-test", 1, errors, "curl-test")

    try:
        curl_pod = run(
            [
                "kubectl",
                "-n",
                ns,
                "get",
                "pods",
                "-l",
                "app=curl-test",
                "-o",
                "jsonpath={.items[0].metadata.name}",
            ]
        ).strip()
        targets_raw = run(
            [
                "kubectl",
                "-n",
                ns,
                "exec",
                curl_pod,
                "--",
                "curl",
                "-s",
                "--max-time",
                "5",
                f"http://prometheus.{ns}.svc.cluster.local:8000/api/v1/targets",
            ]
        )
        targets = json.loads(targets_raw)
        rabbit = [
            t
            for t in ((targets.get("data") or {}).get("activeTargets") or [])
            if ((t.get("labels") or {}).get("job") == "rabbitmq")
        ]
        if len(rabbit) >= 3:
            errors.append("monitoring precondition missing: rabbitmq targets already >= 3")
    except Exception as exc:
        errors.append(f"failed to query Prometheus targets: {exc}")

    if errors:
        print("setup-precondition-check: failed")
        for err in errors:
            print(f" - {err}")
        return 1
    print("setup-precondition-check: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
import argparse
import os
import base64
import sys
from pathlib import Path

from cases.common.rabbitmq.setup_check_utils import expect_pod_ready, expect_pods_ready, run_json  # noqa: E402


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--namespace", default=os.environ.get("BENCH_NAMESPACE", "rabbitmq"))
    parser.add_argument("--min-ready", type=int, default=1)
    args = parser.parse_args()
    ns = args.namespace
    cluster_prefix = os.environ.get("BENCH_PARAM_CLUSTER_PREFIX", "rabbitmq")
    errors = []

    expect_pods_ready(ns, f"app={cluster_prefix}", 3, errors, cluster_prefix)
    expect_pods_ready(ns, "app=curl-test", 1, errors, "curl-test")

    try:
        sec = run_json(
            ["kubectl", "-n", ns, "get", "secret", f"{cluster_prefix}-cookie-perpod", "-o", "json"]
        )
        data = sec.get("data") or {}
        keys = tuple(f"{cluster_prefix}-{i}" for i in range(3))
        missing = [k for k in keys if k not in data]
        if missing:
            errors.append(f"cookie secret missing keys: {','.join(missing)}")
        else:
            values = [base64.b64decode(data[k]).decode().strip() for k in keys]
            if len(set(values)) == 1:
                errors.append("cookie drift precondition missing (all node cookies equal)")
    except Exception as exc:
        errors.append(f"failed to validate {cluster_prefix}-cookie-perpod: {exc}")

    if errors:
        print("setup-precondition-check: failed")
        for err in errors:
            print(f" - {err}")
        return 1
    print("setup-precondition-check: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

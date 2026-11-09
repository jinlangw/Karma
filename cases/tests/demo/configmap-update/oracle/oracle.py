#!/usr/bin/env python3
"""
Oracle for demo/configmap-update.

Reads demo-config from the assigned namespace and checks that
data.value matches the --expected-value argument.

Exit codes:
  0  value matches
  1  mismatch, kubectl error, or parse failure
"""

import argparse
import json
import os
import subprocess
import sys


def _read_configmap(namespace: str, name: str) -> dict | None:
    """Fetch a ConfigMap from the cluster and return its parsed JSON, or None on error."""
    cmd = ["kubectl", "-n", namespace, "get", "configmap", name, "-o", "json"]
    proc = subprocess.run(cmd, text=True, capture_output=True)
    if proc.returncode != 0:
        print(proc.stderr.strip() or f"failed to read configmap {name}")
        return None
    try:
        return json.loads(proc.stdout or "{}")
    except Exception as exc:
        print(f"failed to parse kubectl output: {exc}")
        return None


def main() -> int:
    """Parse arguments, fetch the ConfigMap, and verify the expected value."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--configmap", default="demo-config")
    parser.add_argument("--key", default="value")
    parser.add_argument("--expected-value", required=True)
    parser.add_argument("--namespace", default=os.environ.get("BENCH_NAMESPACE", "default"))
    args = parser.parse_args()

    payload = _read_configmap(args.namespace, args.configmap)
    if payload is None:
        return 1

    actual = str((payload.get("data") or {}).get(args.key, ""))
    expected = str(args.expected_value)

    if actual != expected:
        print(
            f"FAIL namespace={args.namespace} configmap={args.configmap} "
            f"key={args.key} expected={expected!r} actual={actual!r}"
        )
        return 1

    print(
        f"PASS namespace={args.namespace} configmap={args.configmap} "
        f"key={args.key} value={expected!r}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

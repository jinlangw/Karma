#!/usr/bin/env python3
"""
Oracle for demo/configmap-update-two-ns.

Supports two subcommands:
  check-value    Read demo-config from one namespace and assert data.value
                 matches --expected-value. Prints PASS or FAIL with role/ns info.
  check-distinct Assert that --source-namespace and --target-namespace are not
                 the same string. Prints PASS or FAIL.

Exit codes:
  0  assertion passed
  1  assertion failed, kubectl error, or parse failure
"""

import argparse
import json
import os
import subprocess
import sys


def _read_configmap_value(namespace: str, configmap: str, key: str) -> str:
    """Fetch *key* from *configmap* in *namespace* and return its string value.

    Raises RuntimeError on kubectl failure or JSON parse error.
    """
    cmd = ["kubectl", "-n", namespace, "get", "configmap", configmap, "-o", "json"]
    proc = subprocess.run(cmd, text=True, capture_output=True)
    if proc.returncode != 0:
        msg = proc.stderr.strip() or proc.stdout.strip() or f"failed to read configmap {configmap}"
        raise RuntimeError(msg)
    try:
        payload = json.loads(proc.stdout or "{}")
    except Exception as exc:
        raise RuntimeError(f"failed to parse kubectl output: {exc}") from exc
    return str((payload.get("data") or {}).get(key, ""))


def _check_value(args: argparse.Namespace) -> int:
    """Assert the named ConfigMap key equals --expected-value in one namespace."""
    actual = _read_configmap_value(args.namespace, args.configmap, args.key)
    expected = str(args.expected_value)
    role_tag = f" role={args.role}" if getattr(args, "role", None) else ""
    if actual != expected:
        print(
            f"FAIL{role_tag} namespace={args.namespace} configmap={args.configmap} "
            f"key={args.key} expected={expected!r} actual={actual!r}"
        )
        return 1
    print(
        f"PASS{role_tag} namespace={args.namespace} configmap={args.configmap} "
        f"key={args.key} value={expected!r}"
    )
    return 0


def _check_distinct(args: argparse.Namespace) -> int:
    """Assert source and target namespace bindings resolve to different namespaces."""
    source_ns = str(args.source_namespace)
    target_ns = str(args.target_namespace)
    if not source_ns or not target_ns:
        print("FAIL source and target namespaces are required")
        return 1
    if source_ns == target_ns:
        print(f"FAIL source and target namespaces are identical ({source_ns!r})")
        return 1
    print(f"PASS source_namespace={source_ns} target_namespace={target_ns} distinct=true")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    """Return the argument parser with check-value and check-distinct subcommands."""
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="subcommand")

    value = sub.add_parser("check-value", help="Check configmap key value in one namespace.")
    value.add_argument("--configmap", default="demo-config")
    value.add_argument("--key", default="value")
    value.add_argument("--expected-value", required=True)
    value.add_argument("--namespace", required=True)
    value.add_argument("--role", choices=["source", "target"])

    distinct = sub.add_parser(
        "check-distinct",
        help="Assert source and target namespace bindings are distinct.",
    )
    distinct.add_argument("--source-namespace", required=True)
    distinct.add_argument("--target-namespace", required=True)

    return parser


def main() -> int:
    """Dispatch to the selected subcommand and return an exit code."""
    parser = _build_parser()
    args = parser.parse_args()
    if args.subcommand is None:
        parser.print_help()
        return 1
    try:
        if args.subcommand == "check-distinct":
            return _check_distinct(args)
        return _check_value(args)
    except RuntimeError as exc:
        print(str(exc))
        return 1


if __name__ == "__main__":
    sys.exit(main())

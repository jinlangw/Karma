#!/usr/bin/env python3
import argparse
import os
import base64
import datetime as dt
import subprocess
import sys
from pathlib import Path

from cases.common.rabbitmq.setup_check_utils import expect_pod_ready, expect_pods_ready, run_json  # noqa: E402


def _fp_sha256(pem_bytes):
    out = subprocess.check_output(
        ["openssl", "x509", "-noout", "-fingerprint", "-sha256"],
        input=pem_bytes,
        stderr=subprocess.STDOUT,
    ).decode()
    return out.strip().split("=", 1)[-1]


def _not_after(pem_bytes):
    out = subprocess.check_output(
        ["openssl", "x509", "-noout", "-enddate"],
        input=pem_bytes,
        stderr=subprocess.STDOUT,
    ).decode()
    raw = out.strip().split("=", 1)[-1]
    return dt.datetime.strptime(raw, "%b %d %H:%M:%S %Y %Z")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--namespace", default=os.environ.get("BENCH_NAMESPACE", "rabbitmq"))
    parser.add_argument("--min-ready", type=int, default=1)
    parser.add_argument(
        "--baseline-max-leaf-validity-days",
        type=int,
        default=int(os.environ.get("BENCH_PARAM_BASELINE_MAX_LEAF_VALIDITY_DAYS", "10")),
    )
    parser.add_argument("--tls-material-only", action="store_true")
    parser.add_argument("--tls-statefulset-only", action="store_true")
    args = parser.parse_args()
    ns = args.namespace
    cluster_prefix = os.environ.get("BENCH_PARAM_CLUSTER_PREFIX", "rabbitmq")
    errors = []

    if args.tls_statefulset_only:
        try:
            sts = run_json(["kubectl", "-n", ns, "get", "sts", cluster_prefix, "-o", "json"])
        except Exception as exc:
            print("setup-precondition-check: failed")
            print(f" - failed to read {cluster_prefix} statefulset: {exc}")
            return 1

        spec = (((sts.get("spec") or {}).get("template") or {}).get("spec") or {})
        containers = spec.get("containers") or []
        rabbit = next((c for c in containers if c.get("name") == "rabbitmq"), None)
        if not rabbit:
            errors.append("statefulset is missing rabbitmq container")
        else:
            mounts = rabbit.get("volumeMounts") or []
            tls_mount = next((m for m in mounts if m.get("name") == "tls-secret"), None)
            if not tls_mount:
                errors.append("statefulset rabbitmq container missing tls-secret volume mount")
            else:
                if tls_mount.get("mountPath") != "/etc/rabbitmq/tls":
                    errors.append(
                        "tls-secret mountPath mismatch "
                        f"({tls_mount.get('mountPath')!r} != '/etc/rabbitmq/tls')"
                    )
            conf_mount = next(
                (m for m in mounts if m.get("name") == "config" and m.get("subPath") == "rabbitmq.conf"),
                None,
            )
            if not conf_mount:
                errors.append("statefulset rabbitmq container missing rabbitmq.conf config mount")
            elif conf_mount.get("mountPath") != "/etc/rabbitmq/rabbitmq.conf":
                errors.append(
                    "rabbitmq.conf mountPath mismatch "
                    f"({conf_mount.get('mountPath')!r} != '/etc/rabbitmq/rabbitmq.conf')"
                )

        volumes = spec.get("volumes") or []
        tls_vol = next((v for v in volumes if v.get("name") == "tls-secret"), None)
        if not tls_vol:
            errors.append("statefulset template missing tls-secret volume")
        else:
            secret_name = ((tls_vol.get("secret") or {}).get("secretName") or "").strip()
            expected_secret = f"{cluster_prefix}-tls"
            if secret_name != expected_secret:
                errors.append(
                    f"tls-secret volume secretName mismatch ({secret_name!r} != {expected_secret!r})"
                )

        if errors:
            print("setup-precondition-check: failed")
            for err in errors:
                print(f" - {err}")
            return 1
        print("setup-precondition-check: ok")
        return 0

    if not args.tls_material_only:
        expect_pods_ready(ns, f"app={cluster_prefix}", 3, errors, cluster_prefix)
        expect_pods_ready(ns, "app=openssl-toolbox", 1, errors, "openssl-toolbox")

    try:
        tls_secret = f"{cluster_prefix}-tls"
        secret = run_json(["kubectl", "-n", ns, "get", "secret", tls_secret, "-o", "json"])
        ca_pem = base64.b64decode((secret.get("data") or {}).get("ca.crt", ""))
        leaf_pem = base64.b64decode((secret.get("data") or {}).get("tls.crt", ""))
        if not ca_pem or not leaf_pem:
            errors.append(f"{tls_secret} is missing ca.crt or tls.crt")
    except Exception as exc:
        errors.append(f"failed to read {tls_secret} secret: {exc}")
        ca_pem = b""
        leaf_pem = b""

    try:
        old_cm = f"{cluster_prefix}-tls-old"
        old = run_json(["kubectl", "-n", ns, "get", "configmap", old_cm, "-o", "json"])
        old_ca_fp = ((old.get("data") or {}).get("ca_fingerprint_sha256") or "").strip()
        old_leaf_fp = ((old.get("data") or {}).get("leaf_fingerprint_sha256") or "").strip()
        if not old_ca_fp or not old_leaf_fp:
            errors.append(f"{old_cm} missing stored fingerprints")
    except Exception as exc:
        errors.append(f"failed to read {old_cm} configmap: {exc}")
        old_ca_fp = ""
        old_leaf_fp = ""

    if ca_pem and leaf_pem and old_ca_fp and old_leaf_fp:
        try:
            now_ca_fp = _fp_sha256(ca_pem)
            now_leaf_fp = _fp_sha256(leaf_pem)
            if now_ca_fp != old_ca_fp:
                errors.append("CA fingerprint mismatch from recorded baseline")
            if now_leaf_fp != old_leaf_fp:
                errors.append("leaf certificate already rotated in setup baseline")
            days_left = (_not_after(leaf_pem) - dt.datetime.utcnow()).days
            if days_left > args.baseline_max_leaf_validity_days:
                errors.append(
                    "leaf certificate is not near expiry baseline "
                    f"(days_left={days_left}, max={args.baseline_max_leaf_validity_days})"
                )
        except Exception as exc:
            errors.append(f"failed to inspect certificate material: {exc}")

    if errors:
        print("setup-precondition-check: failed")
        for err in errors:
            print(f" - {err}")
        return 1
    print("setup-precondition-check: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

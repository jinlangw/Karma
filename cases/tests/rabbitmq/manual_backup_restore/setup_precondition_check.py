#!/usr/bin/env python3
import argparse
import os
import sys
from pathlib import Path

from cases.common.rabbitmq.setup_check_utils import (  # noqa: E402
    expect_pods_ready,
    list_pods,
    pod_is_ready,
    run,
    run_json,
    split_lines,
)


def _pvc_phase(namespace, name):
    pvc = run_json(["kubectl", "-n", namespace, "get", "pvc", name, "-o", "json"])
    return ((pvc.get("status") or {}).get("phase") or "Unknown")


def _validate_restore_pvc_phases(pvc_phases):
    errors = []

    cluster_prefix = pvc_phases.get("__cluster_prefix__", "rabbitmq")
    backup_name = f"{cluster_prefix}-backup"
    data_name = f"data-{cluster_prefix}-0"
    backup_phase = pvc_phases.get(backup_name, "Unknown")
    if backup_phase != "Bound":
        errors.append(f"PVC {backup_name} is not Bound (phase={backup_phase})")

    data_phase = pvc_phases.get(data_name, "Unknown")
    # With WaitForFirstConsumer storage classes, this can legitimately remain Pending
    # until a restore pod mounts it.
    if data_phase not in {"Pending", "Bound"}:
        errors.append(
            f"PVC {data_name} is not restorable "
            f"(phase={data_phase}, expected Pending or Bound)"
        )

    return errors


def _seed_queue_ready(namespace, cluster_prefix, errors):
    try:
        out = run(
            [
                "kubectl",
                "-n",
                namespace,
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
        for line in split_lines(out):
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "app-backup":
                found = True
                try:
                    messages = int(parts[1])
                except ValueError:
                    messages = 0
                if messages < 20:
                    errors.append("app-backup does not have expected seeded messages (>=20)")
                break
        if not found:
            errors.append("app-backup queue not found in /app")
    except Exception as exc:
        errors.append(f"failed to inspect seeded queue state: {exc}")


def _backup_archive_present(namespace, cluster_prefix, errors):
    pod_name = f"{cluster_prefix}-backup-probe"
    manifest = f"""apiVersion: v1
kind: Pod
metadata:
  name: {pod_name}
spec:
  restartPolicy: Never
  containers:
    - name: check
      image: busybox:1.36
      command: [\"/bin/sh\", \"-c\", \"test -s /backup/{cluster_prefix}-0.tgz\"]
      volumeMounts:
        - name: backup
          mountPath: /backup
  volumes:
    - name: backup
      persistentVolumeClaim:
        claimName: {cluster_prefix}-backup
"""
    try:
        run(["kubectl", "-n", namespace, "delete", "pod", pod_name, "--ignore-not-found=true"])
        run(["kubectl", "-n", namespace, "apply", "-f", "-"], input_data=manifest)
        run(
            [
                "kubectl",
                "-n",
                namespace,
                "wait",
                f"pod/{pod_name}",
                "--for=jsonpath={.status.phase}=Succeeded",
                "--timeout=60s",
            ]
        )
    except Exception as exc:
        errors.append(f"backup archive missing or unreadable: {exc}")
    finally:
        try:
            run(["kubectl", "-n", namespace, "delete", "pod", pod_name, "--ignore-not-found=true"])
        except Exception:
            pass


def _check_seed_material_mode(ns, cluster_prefix):
    errors = []
    try:
        sts = run_json(["kubectl", "-n", ns, "get", "sts", cluster_prefix, "-o", "json"])
        replicas = ((sts.get("spec") or {}).get("replicas") or 0)
        if replicas < 1:
            errors.append(f"{cluster_prefix} statefulset replicas expected >=1, got {replicas}")
    except Exception as exc:
        errors.append(f"failed to read {cluster_prefix} statefulset: {exc}")
    _seed_queue_ready(ns, cluster_prefix, errors)
    return errors


def _check_backup_snapshot_mode(ns, cluster_prefix):
    errors = []
    try:
        sts = run_json(["kubectl", "-n", ns, "get", "sts", cluster_prefix, "-o", "json"])
        replicas = ((sts.get("spec") or {}).get("replicas") or 0)
        if replicas != 0:
            errors.append(f"{cluster_prefix} statefulset replicas expected 0, got {replicas}")
    except Exception as exc:
        errors.append(f"failed to read {cluster_prefix} statefulset: {exc}")
    try:
        phase = _pvc_phase(ns, f"{cluster_prefix}-backup")
        if phase != "Bound":
            errors.append(f"PVC {cluster_prefix}-backup is not Bound (phase={phase})")
    except Exception as exc:
        errors.append(f"failed to read backup PVC: {exc}")
    _backup_archive_present(ns, cluster_prefix, errors)
    return errors


def _restore_target_wiped(namespace, cluster_prefix, errors):
    """Assert the data-loss fault is PLANTED: data-0 holds no broker data.

    A Bound data-0 PVC is NOT evidence the wipe ran -- after seed+snapshot the
    PVC is Bound WITH data on every run, so a phase-only probe skips the wipe
    and the fault is never planted (P3/P28). Mount the restore-target PVC in a
    short-lived probe pod and require the mnesia directory to be absent; a
    restored (or never-wiped) PVC fails this, so a second scheduling re-plants
    the wipe (break-then-fix, C8).
    """
    pod_name = f"{cluster_prefix}-restore-probe"
    manifest = f"""apiVersion: v1
kind: Pod
metadata:
  name: {pod_name}
spec:
  restartPolicy: Never
  containers:
    - name: check
      image: busybox:1.36
      command: [\"/bin/sh\", \"-c\", \"test ! -e /data/mnesia\"]
      volumeMounts:
        - name: data
          mountPath: /data
  volumes:
    - name: data
      persistentVolumeClaim:
        claimName: data-{cluster_prefix}-0
"""
    try:
        run(["kubectl", "-n", namespace, "delete", "pod", pod_name, "--ignore-not-found=true"])
        run(["kubectl", "-n", namespace, "apply", "-f", "-"], input_data=manifest)
        run(
            [
                "kubectl",
                "-n",
                namespace,
                "wait",
                f"pod/{pod_name}",
                "--for=jsonpath={.status.phase}=Succeeded",
                "--timeout=90s",
            ]
        )
    except Exception as exc:
        errors.append(
            f"restore target data-{cluster_prefix}-0 still holds broker data "
            f"(mnesia present) or is unreadable -- data-loss fault not planted: {exc}"
        )
    finally:
        try:
            run(["kubectl", "-n", namespace, "delete", "pod", pod_name, "--ignore-not-found=true"])
        except Exception:
            pass


def _check_restore_pvc_mode(ns, cluster_prefix):
    errors = []
    pvc_phases = {"__cluster_prefix__": cluster_prefix}
    for pvc in (f"{cluster_prefix}-backup", f"data-{cluster_prefix}-0"):
        try:
            pvc_phases[pvc] = _pvc_phase(ns, pvc)
        except Exception as exc:
            errors.append(f"failed to read PVC {pvc}: {exc}")
    errors.extend(_validate_restore_pvc_phases(pvc_phases))
    # Only probe emptiness when the PVCs themselves are readable; the phase
    # errors above already fail the mode.
    if not errors:
        _restore_target_wiped(ns, cluster_prefix, errors)
    return errors


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--namespace", default=os.environ.get("BENCH_NAMESPACE", "rabbitmq"))
    # Keep for backward compatibility with existing test invocations.
    parser.add_argument("--min-ready", type=int, default=1)
    parser.add_argument(
        "--mode",
        choices=["full", "seed-material", "backup-snapshot", "restore-pvc"],
        default="full",
    )
    args = parser.parse_args()
    ns = args.namespace
    cluster_prefix = os.environ.get("BENCH_PARAM_CLUSTER_PREFIX", "rabbitmq")
    errors = []

    if args.mode == "seed-material":
        errors.extend(_check_seed_material_mode(ns, cluster_prefix))
    elif args.mode == "backup-snapshot":
        errors.extend(_check_backup_snapshot_mode(ns, cluster_prefix))
    elif args.mode == "restore-pvc":
        errors.extend(_check_restore_pvc_mode(ns, cluster_prefix))
    else:
        expect_pods_ready(ns, "app=curl-test", 1, errors, "curl-test")

        try:
            sts = run_json(["kubectl", "-n", ns, "get", "sts", cluster_prefix, "-o", "json"])
            replicas = ((sts.get("spec") or {}).get("replicas") or 0)
            if replicas != 0:
                errors.append(f"{cluster_prefix} statefulset replicas expected 0, got {replicas}")
        except Exception as exc:
            errors.append(f"failed to read {cluster_prefix} statefulset: {exc}")

        rabbit_pods = list_pods(ns, label=f"app={cluster_prefix}")
        ready_count = sum(1 for p in rabbit_pods if pod_is_ready(p))
        if ready_count > 0:
            errors.append(f"expected no ready {cluster_prefix} pods, got {ready_count}")

        errors.extend(_check_restore_pvc_mode(ns, cluster_prefix))
        # Final degraded baseline should include a usable backup archive, independent of job provenance.
        errors.extend(_check_backup_snapshot_mode(ns, cluster_prefix))

    if errors:
        print("setup-precondition-check: failed")
        for err in errors:
            print(f" - {err}")
        return 1
    print("setup-precondition-check: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

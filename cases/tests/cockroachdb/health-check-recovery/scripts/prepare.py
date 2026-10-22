#!/usr/bin/env python3
"""Prepare a healthy CockroachDB fixture and the case-local health fault."""
import argparse
import subprocess
import sys

from cluster import FAULT_MARKER, Cluster, UnsafeState, database_container
from fault import Fault
from cases.common.cockroachdb import CrdbLibrary, KubectlAdapter, Lifecycle, ProbeStatus, Requirement, WorkloadRef
from cases.common.cockroachdb.types import (
    AuthenticationError,
    InvalidRequirementError,
    KubernetesAccessError,
    MissingResourceError,
    PreservationMismatchError,
    StaleIdentityError,
    UnsupportedLayoutError,
)


HEALTH_RECOVERY_MINIMUM_NODES = 3


def _recovery_assessment_ready(assessment, minimum_nodes):
    pods = assessment.workload.pods
    return (
        assessment.status is ProbeStatus.SATISFIED
        and len(pods) >= minimum_nodes
        and all(pod.phase == "Running" and pod.pod_ready for pod in pods)
    )


def prepare_cluster_unit(cluster, fault, library, mode):
    """Run shared readiness while preserving the case's recovery policy.

    An active owned fault remains on the local readiness path so retries never
    normalize its probes or replace the saved starting configuration. Other
    existing apply targets use the case's bounded, data-preserving recovery
    before shared readiness. A missing workload is bootstrapped only by this
    case's explicit, guarded fresh-fixture policy.
    """
    if mode not in {"probe", "apply", "verify"}:
        raise ValueError("mode must be probe, apply, or verify")

    sts = cluster.get("statefulset", cluster.name)
    baseline = fault.load() if sts is not None else None
    if baseline is not None and fault.configured(baseline, sts):
        cluster.wait(fault.environment_ready, 90 if mode in {"probe", "apply"} else 30)
        return True

    if sts is None:
        if mode != "apply":
            raise MissingResourceError(f"StatefulSet {cluster.namespace}/{cluster.name} is missing")
        if cluster.get("configmap", fault.baseline_name) is not None:
            raise UnsafeState("health baseline exists without its selected StatefulSet; refusing fresh bootstrap")
        # This is an explicit case policy for a new, empty fixture. Cluster.bootstrap
        # checks for leftover target Pods/PVCs before creating or initializing it.
        cluster.bootstrap()
    elif any(
        FAULT_MARKER.strip() in part
        for part in database_container(sts["spec"]["template"]).get("command", [])
    ):
        raise UnsafeState("unrecognized case fault; refusing generic recovery")

    ref = WorkloadRef(cluster.namespace, cluster.name)
    requirement = Requirement(Lifecycle.INITIALIZED, minimum_nodes=HEALTH_RECOVERY_MINIMUM_NODES)
    if sts is not None and mode == "apply":
        def shared_ready():
            result = library.probe(ref, requirement, per_node_timeout=5)
            return _recovery_assessment_ready(result, HEALTH_RECOVERY_MINIMUM_NODES)

        # Preserve the case's original bounded missing-Service and unready-Pod
        # recovery. Typed API, identity, authentication, and unsupported-layout
        # failures remain errors; they are not evidence that a Pod needs restart.
        cluster.recover(
            readiness_check=shared_ready,
            propagate=(
                AuthenticationError,
                InvalidRequirementError,
                KubernetesAccessError,
                MissingResourceError,
                PreservationMismatchError,
                StaleIdentityError,
                UnsupportedLayoutError,
            ),
        )
    if mode == "probe":
        assessment = library.probe(ref, requirement, per_node_timeout=5)
    else:
        timeout = 120 if mode == "apply" else 90
        result = library.reconcile(
            ref,
            requirement,
            timeout=timeout,
            poll_interval=2,
            per_node_timeout=5,
        )
        assessment = result.assessment

    if assessment.status is not ProbeStatus.SATISFIED:
        reason = "; ".join(assessment.reasons) or "CockroachDB did not satisfy the requested lifecycle"
        raise RuntimeError(reason)
    if not CrdbLibrary.health_recovery_probes_prepared(assessment.workload):
        if mode == "apply":
            library.prepare_health_recovery_probes(
                ref,
                timeout=180,
                poll_interval=2,
                per_node_timeout=5,
            )
        else:
            raise RuntimeError("health probes need explicit preparation")
    cluster.wait(fault.environment_ready, 90 if mode in {"probe", "apply"} else 30)
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("unit", choices=("cluster", "fault"))
    parser.add_argument("mode", choices=("probe", "apply", "verify"))
    args = parser.parse_args()
    cluster = Cluster()
    fault = Fault(cluster)
    if args.unit == "cluster":
        prepare_cluster_unit(cluster, fault, CrdbLibrary(KubectlAdapter()), args.mode)
    else:
        # Karma may evaluate later units after an earlier failure. Never mutate
        # a fault target until the selected environment passes its dependency.
        cluster.wait(fault.environment_ready, 30)
        fault.apply() if args.mode == "apply" else cluster.wait(fault.active, 15)
    print(f"{args.unit} {args.mode}: ready", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, ValueError, KeyError, OSError, subprocess.TimeoutExpired) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)

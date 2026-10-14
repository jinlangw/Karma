#!/usr/bin/env python3
"""Separate healthy-environment preparation and verified fault injection."""
import argparse
import subprocess
import sys

from cluster import Cluster, UnsafeState, database_container
from fault import Fault


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("unit", choices=("cluster", "fault"))
    parser.add_argument("mode", choices=("probe", "apply", "verify"))
    args = parser.parse_args()
    cluster = Cluster()
    fault = Fault(cluster)
    if args.unit == "cluster":
        if args.mode == "apply":
            sts = cluster.get("statefulset", cluster.name)
            baseline = fault.load() if sts else None
            if sts and fault.configured(baseline, sts):
                cluster.wait(fault.environment_ready, 90)
            else:
                if sts and any("karma-health-probe-fault" in part for part in database_container(sts["spec"]["template"]).get("command", [])):
                    raise UnsafeState("unrecognized case fault; refusing generic recovery")
                cluster.recover()
                cluster.wait(fault.environment_ready, 90)
        else:
            if cluster.get("statefulset", cluster.name) is None:
                raise RuntimeError("selected StatefulSet is absent")
            cluster.wait(fault.environment_ready, 90 if args.mode == "probe" else 30)
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

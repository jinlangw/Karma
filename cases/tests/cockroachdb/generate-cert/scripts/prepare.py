#!/usr/bin/env python3
"""Independent database/toolbox readiness and selected TLS/CA reset units."""
import argparse
import subprocess
import sys

from cluster import Cluster, TOOLBOX, UnsafeState
from pki import Reset, toolbox_ready


def prepare_toolbox(cluster):
    pod = cluster.get("pod", TOOLBOX)
    if pod is not None:
        try:
            cluster.wait(lambda: toolbox_ready(cluster), 30)
            return
        except RuntimeError:
            pass
        latest = cluster.get("pod", TOOLBOX)
        if latest is not None and any(c["type"] == "Ready" and c["status"] == "True" for c in latest.get("status", {}).get("conditions", [])):
            raise UnsafeState("ready toolbox cannot execute OpenSSL; refusing replacement on an exec/API failure")
        labels = pod["metadata"].get("labels", {})
        if labels.get("karma.dev/fixture") != "cert-toolbox" or labels.get("app.kubernetes.io/instance") != cluster.name:
            raise UnsafeState("unusable toolbox is not owned by this case and cluster")
        if pod["metadata"].get("ownerReferences"):
            raise UnsafeState("toolbox is managed by another controller")
        Reset(cluster).inventory(inspect_toolbox=False)
        cluster.delete(pod)
    cluster.create(cluster.template("openssl-toolbox.yaml")[0])
    cluster.wait(lambda: toolbox_ready(cluster), 150)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("unit", choices=("cluster", "toolbox", "tls"))
    parser.add_argument("mode", choices=("probe", "apply", "verify"))
    args = parser.parse_args()
    cluster = Cluster()
    if args.unit != "cluster":
        # The framework evaluates subsequent units even after a unit fails.
        # Guard dependencies in every mode before shared material can change.
        cluster.wait(cluster.ready, 30)
    if args.unit == "tls":
        toolbox_ready(cluster)
    if args.unit == "cluster":
        if args.mode == "apply":
            cluster.recover()
        else:
            if cluster.get("statefulset", cluster.name) is None:
                raise RuntimeError("selected StatefulSet is absent")
            cluster.wait(cluster.ready, 90 if args.mode == "probe" else 30)
    elif args.unit == "toolbox":
        prepare_toolbox(cluster) if args.mode == "apply" else toolbox_ready(cluster)
    else:
        Reset(cluster).apply() if args.mode == "apply" else Reset(cluster).absent()
    print(f"{args.unit} {args.mode}: ready", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, ValueError, KeyError, OSError, subprocess.TimeoutExpired) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)

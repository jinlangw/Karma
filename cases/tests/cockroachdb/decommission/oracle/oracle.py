#!/usr/bin/env python3
"""Verify exact prepared identities and data, not historical pod addresses."""
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from cluster import Cluster


def evaluate(cluster, baseline):
    sts = cluster.sts()
    if sts["metadata"]["uid"] != baseline["statefulset_uid"]:
        raise RuntimeError("selected StatefulSet was replaced")
    if cluster.count() != cluster.target:
        raise RuntimeError(f"expected {cluster.target} StatefulSet replicas")
    members = cluster.members(cluster.target)
    for pod, node_id in members.items():
        if baseline["node_ids"].get(pod) != node_id:
            raise RuntimeError(f"surviving identity changed for {pod}")
    for ordinal in range(cluster.target):
        for name in cluster.pvc_names(ordinal, sts):
            if cluster.obj("pvc", name)["metadata"]["uid"] != baseline["pvc_uids"].get(name):
                raise RuntimeError(f"surviving storage was replaced: {name}")
    if cluster.connection_flag() != baseline["connection_flag"]:
        raise RuntimeError("cluster security mode changed")
    removed = [baseline["node_ids"][cluster.pod(ordinal)]
               for ordinal in range(cluster.target, cluster.source)]
    if not cluster.removed(removed):
        raise RuntimeError("prepared removed nodes are not fully decommissioned or still own current replicas")
    for ordinal in range(cluster.target, cluster.source):
        pod = cluster.pod(ordinal)
        result = cluster.kubectl("get", "pod", pod, "-o", "json")
        if result.returncode == 0:
            raise RuntimeError(f"removed pod {pod} still exists")
        if "NotFound" not in result.stderr:
            raise RuntimeError(result.stderr.strip())
    if cluster.data() != baseline["seed_data"] or baseline["seed_data"]["rows"] < 3:
        raise RuntimeError("seeded data was lost or changed")
    return True


def main():
    cluster = Cluster()
    baseline = json.loads(cluster.obj("configmap", cluster.baseline_name)["data"]["baseline.json"])
    expected = {"namespace": cluster.namespace, "cluster": cluster.name,
                "source_nodes": cluster.source, "target_nodes": cluster.target,
                "seed_table": cluster.table}
    if any(baseline.get(key) != value for key, value in expected.items()):
        raise RuntimeError("Oracle baseline does not match selected namespace/cluster/parameters")
    # Gossip, pod termination, and SQL readiness settle asynchronously. Every
    # retry retains the same target assertions and frozen baseline.
    cluster.wait("safe decommission outcome", lambda: evaluate(cluster, baseline), 90)
    print("Decommission verification passed")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, ValueError, KeyError) as error:
        print(f"Decommission verification failed: {error}", file=sys.stderr)
        sys.exit(1)

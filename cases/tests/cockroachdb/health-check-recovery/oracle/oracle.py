#!/usr/bin/env python3
"""Verify actual health recovery, SQL, topology, storage and retained TLS."""
import csv
import io
import json
from pathlib import Path
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from cluster import FAULT_MARKER, Cluster, UnsafeState, database_container, flag_value, health_probes
from fault import Fault, POD_VARIABLE


def evaluate():
    cluster = Cluster()
    try:
        sts = cluster.statefulset()
        fault = Fault(cluster)
        baseline = fault.load()
        if baseline is None:
            raise RuntimeError("health fault preparation baseline is missing")
        fault.preserved(baseline, sts)
        original_strategy = json.loads(baseline["data"]["original_update_strategy"])
        if sts["spec"].get("updateStrategy", {"type": "RollingUpdate"}) != original_strategy:
            raise RuntimeError("original StatefulSet update strategy has not been restored")
        for template in [sts["spec"]["template"], *({"spec": p["spec"]} for p in cluster.pods(sts))]:
            container = database_container(template)
            if any(FAULT_MARKER.strip() in part for part in container.get("command", [])) or any(e["name"] == POD_VARIABLE for e in container.get("env", [])):
                raise RuntimeError("injected health wrapper or environment is still present")
            probes = health_probes(container)
            if probes[0]["scheme"] != ("http" if cluster.connection_flag() == "--insecure" else "https"):
                raise RuntimeError("health probe protocol no longer matches security mode")
        cluster.ready(functional_health=True)
        container = database_container(sts["spec"]["template"])
        host = f"{cluster.name}-0.{cluster.name}.{cluster.namespace}.svc.cluster.local"
        result = cluster.kubectl("exec", cluster.name + "-0", "-c", container["name"], "--", "./cockroach", "node", "status",
            cluster.connection_flag(), "--host=" + host, "--port=" + flag_value(container, "--port", "26257"), "--format=csv", timeout=15)
        rows = list(csv.DictReader(io.StringIO(cluster.require(result))))
        if not rows or "is_live" not in rows[0]:
            raise RuntimeError("node status does not contain live-node information")
        live = sum(row["is_live"].strip().lower() in ("true", "t", "1") for row in rows)
        if live != int(baseline["data"]["replicas"]):
            raise RuntimeError(f"expected {baseline['data']['replicas']} live nodes, found {live}")
        return []
    except (RuntimeError, ValueError, KeyError, OSError, subprocess.TimeoutExpired) as error:
        return [str(error)]


def main():
    deadline = time.monotonic() + 150
    errors = evaluate()
    while errors and time.monotonic() < deadline:
        time.sleep(5)
        errors = evaluate()
    if errors:
        print("Health recovery verification failed: " + "; ".join(errors), file=sys.stderr)
        return 1
    print("All original nodes recovered: health endpoints, enabled probes and SQL work; storage, identity, TLS and update strategy preserved")
    return 0


if __name__ == "__main__":
    sys.exit(main())

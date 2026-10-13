#!/usr/bin/env python3
"""Establish an empty native CockroachDB target and its existing RBAC contract.

Resetting the selected target intentionally discards its database. Namespace,
RBAC, and resources belonging to other targets are never part of that reset.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

import yaml


RESOURCES = {
    "StatefulSet": "statefulsets.apps",
    "Deployment": "deployments.apps",
    "DaemonSet": "daemonsets.apps",
    "ReplicaSet": "replicasets.apps",
    "CronJob": "cronjobs.batch",
    "Job": "jobs.batch",
    "Pod": "pods",
    "Service": "services",
    "Endpoints": "endpoints",
    "EndpointSlice": "endpointslices.discovery.k8s.io",
    "PersistentVolumeClaim": "persistentvolumeclaims",
    "PodDisruptionBudget": "poddisruptionbudgets.policy",
    "ConfigMap": "configmaps",
    "Secret": "secrets",
    "Ingress": "ingresses.networking.k8s.io",
    "NetworkPolicy": "networkpolicies.networking.k8s.io",
    "ControllerRevision": "controllerrevisions.apps",
}
CONTROLLERS = {"StatefulSet", "Deployment", "DaemonSet", "ReplicaSet", "CronJob", "Job"}


class Preparation:
    def __init__(self):
        self.namespace = os.environ["BENCH_NAMESPACE"]
        self.name = os.environ.get("BENCH_PARAM_CLUSTER_NAME", "crdb-cluster")
        for value in (self.namespace, self.name):
            if not re.fullmatch(r"[a-z0-9]([-a-z0-9]*[a-z0-9])?", value):
                raise ValueError("namespace and cluster_name must be DNS labels")
        self.labels = {"app.kubernetes.io/name": "cockroachdb",
                       "app.kubernetes.io/instance": self.name}

    def kubectl(self, *args, input_text=None, timeout=30):
        result = subprocess.run(
            ["kubectl", "-n", self.namespace, f"--request-timeout={timeout}s", *args],
            input=input_text, text=True, capture_output=True, timeout=timeout + 5,
        )
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "kubectl failed")
        return result.stdout

    def has_identity(self, labels):
        return all(labels.get(key) == value for key, value in self.labels.items())

    def targets(self):
        # Successful list operations distinguish actual absence from API errors.
        items = json.loads(self.kubectl("get", ",".join(RESOURCES.values()), "-o", "json"))["items"]
        selected = {}
        claim_templates = {"datadir"}
        for item in items:
            if item["kind"] == "StatefulSet" and item["metadata"]["name"] == self.name:
                claim_templates.update(claim["metadata"]["name"]
                                       for claim in item.get("spec", {}).get("volumeClaimTemplates", []))

        def matches(item):
            kind, metadata = item["kind"], item["metadata"]
            name, spec = metadata["name"], item.get("spec", {})
            if self.has_identity(metadata.get("labels", {})):
                return True
            if kind == "StatefulSet" and name == self.name:
                return True
            if kind in {"Service", "Endpoints"} and name in {self.name, f"{self.name}-public"}:
                return True
            if kind == "Pod" and (re.fullmatch(re.escape(self.name) + r"-\d+", name)
                                  or name == f"{self.name}-curl-test"):
                return True
            if kind == "PersistentVolumeClaim":
                return any(re.fullmatch(re.escape(f"{template}-{self.name}-") + r"\d+", name)
                           for template in claim_templates)
            if kind == "EndpointSlice":
                return metadata.get("labels", {}).get("kubernetes.io/service-name") in {
                    self.name, f"{self.name}-public"}
            selector = spec.get("podSelector" if kind == "NetworkPolicy" else "selector", {})
            return self.has_identity(selector.get("matchLabels", {}))

        # Owner references also identify unlabelled children of selected objects.
        while True:
            previous = len(selected)
            for item in items:
                uid = item["metadata"]["uid"]
                owners = item["metadata"].get("ownerReferences", [])
                if matches(item) or any(owner["uid"] in selected for owner in owners):
                    labels = item["metadata"].get("labels", {})
                    if any(key in labels and labels[key] != value for key, value in self.labels.items()):
                        raise RuntimeError(f"conflicting identity on {item['kind']}/{item['metadata']['name']}")
                    selected[uid] = item
            if len(selected) == previous:
                break

        # Never fight an operator or remove a child controlled by another target.
        existing_uids = {item["metadata"]["uid"] for item in items}
        for item in selected.values():
            for owner in item["metadata"].get("ownerReferences", []):
                if owner.get("controller") and owner["uid"] not in selected and (
                    owner["kind"] not in RESOURCES or owner["uid"] in existing_uids
                ):
                    raise RuntimeError(f"{item['kind']}/{item['metadata']['name']} has an external controller")
        dependencies = {kind: {item["metadata"]["name"] for item in selected.values()
                               if item["kind"] == kind}
                        for kind in ("PersistentVolumeClaim", "Secret", "ConfigMap")}
        for item in items:
            if item["kind"] != "Pod" or item["metadata"]["uid"] in selected:
                continue
            for volume in item.get("spec", {}).get("volumes", []):
                for field, kind, key in (("persistentVolumeClaim", "PersistentVolumeClaim", "claimName"),
                                         ("secret", "Secret", "secretName"),
                                         ("configMap", "ConfigMap", "name")):
                    if volume.get(field, {}).get(key) in dependencies[kind]:
                        raise RuntimeError(f"selected {kind} is also used by unrelated pod {item['metadata']['name']}")
        return list(selected.values())

    def absent(self):
        remaining = self.targets()
        if remaining:
            names = ", ".join(f"{obj['kind']}/{obj['metadata']['name']}" for obj in remaining)
            raise RuntimeError(f"selected target still exists: {names}")

    def reset(self):
        # Discover and validate the complete deletion set before mutating it.
        remaining = self.targets()
        deadline = time.monotonic() + 600
        # Stop reconcilers and their pods before removing storage or dependencies.
        remaining.sort(key=lambda obj: (0 if obj["kind"] in CONTROLLERS else
                                        1 if obj["kind"] == "Pod" else 2))
        for item in remaining:
            kind, name = item["kind"], item["metadata"]["name"]
            seconds = min(180, int(deadline - time.monotonic()))
            if seconds <= 0:
                raise RuntimeError("timed out deleting selected target")
            # Foreground deletion waits for dependent pods, including PVC users.
            print(self.kubectl("delete", RESOURCES[kind], name, "--ignore-not-found=true",
                               "--cascade=foreground", "--wait=true", f"--timeout={seconds}s",
                               timeout=seconds), end="", flush=True)
        self.absent()

    def rbac_fixture(self):
        path = Path(__file__).resolve().parents[1] / "resource" / "rbac.yaml"
        text = path.read_text().replace("${BENCH_NAMESPACE}", self.namespace)
        text = text.replace("${BENCH_PARAM_CLUSTER_NAME}", self.name)
        return list(yaml.safe_load_all(text))

    def rbac_ready(self):
        for expected in self.rbac_fixture():
            kind, name = expected["kind"], expected["metadata"]["name"]
            raw = self.kubectl("get", kind, name, "--ignore-not-found=true", "-o", "json")
            if not raw.strip():
                raise RuntimeError(f"missing {kind}/{name}")
            actual = json.loads(raw)
            if not self.has_identity(actual["metadata"].get("labels", {})):
                raise RuntimeError(f"incorrect labels on {kind}/{name}")
            for field in ("rules", "roleRef", "subjects"):
                if field in expected and actual.get(field) != expected[field]:
                    raise RuntimeError(f"incorrect {field} on {kind}/{name}")

    def prepare_rbac(self):
        expected = self.rbac_fixture()
        binding = next(obj for obj in expected if obj["kind"] == "RoleBinding")
        name = binding["metadata"]["name"]
        raw = self.kubectl("get", "rolebinding", name, "--ignore-not-found=true", "-o", "json")
        # Kubernetes forbids changing roleRef in place. Repair only this binding.
        if raw.strip() and json.loads(raw).get("roleRef") != binding["roleRef"]:
            self.kubectl("delete", "rolebinding", name, "--wait=true", "--timeout=20s")
        print(self.kubectl("apply", "-f", "-", input_text=json.dumps({
            "apiVersion": "v1", "kind": "List", "items": expected,
        })), end="", flush=True)
        self.rbac_ready()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("unit", choices=("absent", "rbac"))
    parser.add_argument("mode", choices=("probe", "apply", "verify"))
    args = parser.parse_args()
    preparation = Preparation()
    if args.unit == "absent":
        preparation.reset() if args.mode == "apply" else preparation.absent()
    else:
        preparation.prepare_rbac() if args.mode == "apply" else preparation.rbac_ready()
    print(f"{args.unit} {args.mode}: ready", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)

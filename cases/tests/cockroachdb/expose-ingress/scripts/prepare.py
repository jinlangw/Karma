#!/usr/bin/env python3
"""Four independently probed preparation units; shared state is retained."""
import argparse
import subprocess
import sys

import yaml

from cluster import Cluster
from routes import CONTROLLER, NGINX_NAMESPACE, Routes, argument

INSTALL_URL = "https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.10.1/deploy/static/provider/kind/deploy.yaml"


def controller_ready(cluster):
    deployment, _ = Routes(cluster).class_ready()
    if deployment.get("status", {}).get("observedGeneration", 0) < deployment["metadata"].get("generation", 1):
        raise RuntimeError("controller has not observed its current configuration")
    if deployment.get("status", {}).get("availableReplicas", 0) < 1:
        raise RuntimeError("shared controller has no available replicas")
    service = cluster.get("service", CONTROLLER, namespace=NGINX_NAMESPACE)
    if not service or not any(p["port"] == 443 for p in service["spec"].get("ports", [])):
        raise RuntimeError("controller HTTPS Service is missing")
    endpoints = cluster.get("endpoints", CONTROLLER, namespace=NGINX_NAMESPACE)
    if not endpoints or not any(s.get("addresses") for s in endpoints.get("subsets", [])):
        raise RuntimeError("controller HTTPS Service has no ready endpoints")
    return True


def prepare_controller(cluster):
    deployment = cluster.get("deployment", CONTROLLER, namespace=NGINX_NAMESPACE)
    if deployment is None:
        # Preserve every existing object. A missing controller is provisioned
        # with the same pinned release previously used by this case.
        # Use the host's verified TLS transport; Python installations may not
        # share the OS trust store used by kubectl/curl on macOS.
        download = subprocess.run(["curl", "--fail", "--silent", "--show-error", "--location", INSTALL_URL],
                                  capture_output=True, text=True, timeout=45)
        manifests = list(yaml.safe_load_all(cluster.require(download)))
        nodes = cluster.get("nodes", namespace="")["items"]
        ingress_ready = any(n["metadata"].get("labels", {}).get("ingress-ready") == "true" for n in nodes)
        missing = []
        for obj in manifests:
            if obj["kind"] == "IngressClass":
                obj["metadata"]["name"] = cluster.ingress_class
            if obj["kind"] == "Deployment":
                spec = obj["spec"]["template"]["spec"]
                if not ingress_ready:
                    # Ordinary kind clusters lack this optional provider label.
                    # Adjust only the newly created Deployment, not node labels
                    # or an inherited controller's scheduling configuration.
                    spec["nodeSelector"].pop("ingress-ready", None)
                args = spec["containers"][0]["args"]
                args[:] = ["--watch-ingress-without-class=false" if a.startswith("--watch-ingress-without-class=") else
                           "--ingress-class=" + cluster.ingress_class if a.startswith("--ingress-class=") else a for a in args]
            namespace = obj["metadata"].get("namespace", "")
            existing = cluster.get(obj["kind"], obj["metadata"]["name"], namespace=namespace)
            if existing is not None:
                if obj["kind"] == "Namespace":
                    continue
                if obj["kind"] == "IngressClass":
                    if existing["spec"].get("controller") != obj["spec"]["controller"]:
                        raise RuntimeError("existing IngressClass belongs to a different controller")
                elif existing["metadata"].get("labels", {}).get("app.kubernetes.io/name") != "ingress-nginx":
                    raise RuntimeError(f"existing {obj['kind']}/{obj['metadata']['name']} is not owned by ingress-nginx")
                continue
            missing.append(obj)
        # Ownership checks above all finish before provisioning any objects.
        for obj in missing:
            cluster.create(obj)
        for name in ("ingress-nginx-admission-create", "ingress-nginx-admission-patch"):
            cluster.require(cluster.kubectl("wait", "--for=condition=Complete", "job/" + name,
                "--timeout=240s", namespace=NGINX_NAMESPACE, timeout=245))
    _, args = Routes(cluster).controller()
    controller_class = argument(args, "--controller-class", "k8s.io/ingress-nginx")
    ingress_class = cluster.get("ingressclass", cluster.ingress_class, namespace="")
    if ingress_class is None:
        cluster.create({"apiVersion": "networking.k8s.io/v1", "kind": "IngressClass",
                        "metadata": {"name": cluster.ingress_class}, "spec": {"controller": controller_class}})
    elif ingress_class["spec"].get("controller") != controller_class:
        raise RuntimeError("requested IngressClass belongs to another controller")
    # An inherited unavailable/incompatible controller is never reinstalled or
    # reset. Give its rollout time to settle, then fail if still unusable.
    cluster.wait(lambda: controller_ready(cluster), 300)


def probe_ready(cluster):
    pod = cluster.get("pod", cluster.name + "-curl-test")
    if pod is None:
        raise RuntimeError("curl helper is missing")
    if not any(c["type"] == "Ready" and c["status"] == "True" for c in pod.get("status", {}).get("conditions", [])):
        raise RuntimeError("curl helper is not ready")
    cluster.require(cluster.kubectl("exec", pod["metadata"]["name"], "--", "curl", "--version", timeout=10))
    return True


def prepare_probe(cluster):
    name = cluster.name + "-curl-test"
    pod = cluster.get("pod", name)
    if pod is not None:
        expected = {"app.kubernetes.io/name": "curl", "app.kubernetes.io/instance": cluster.name,
                    "karma.dev/fixture": "ingress-probe"}
        if not all(pod["metadata"].get("labels", {}).get(k) == v for k, v in expected.items()):
            raise RuntimeError("unusable curl helper name is occupied by a resource without fixture ownership")
        if pod["metadata"].get("ownerReferences"):
            raise RuntimeError("curl helper is owned by another controller")
        # Pending startup can settle without a replacement; terminal/broken
        # helpers are replaceable independently of controller and DB readiness.
        if pod.get("status", {}).get("phase") not in ("Failed", "Succeeded"):
            try:
                cluster.wait(lambda: probe_ready(cluster), 30)
                return
            except RuntimeError:
                pass
        cluster.delete_object(pod)
    cluster.create(cluster.template("curl-test.yaml")[0])
    cluster.wait(lambda: probe_ready(cluster), 120)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("unit", choices=("cluster", "controller", "probe", "routes"))
    parser.add_argument("mode", choices=("probe", "apply", "verify"))
    args = parser.parse_args()
    cluster = Cluster()
    apply = args.mode == "apply"
    # The framework continues evaluating units after a failed unit. Dependencies
    # must therefore be rechecked before later units can mutate shared routes.
    if args.unit != "cluster":
        cluster.wait(cluster.ready, 30)
    if args.unit in ("probe", "routes"):
        controller_ready(cluster)
    if args.unit == "routes":
        probe_ready(cluster)
    if args.unit == "cluster":
        if apply:
            cluster.recover()
        else:
            if cluster.get("statefulset", cluster.name) is None:
                raise RuntimeError("selected StatefulSet is absent")
            cluster.wait(cluster.ready, 90 if args.mode == "probe" else 30)
    elif args.unit == "controller":
        prepare_controller(cluster) if apply else controller_ready(cluster)
    elif args.unit == "probe":
        prepare_probe(cluster) if apply else probe_ready(cluster)
    else:
        Routes(cluster).reset() if apply else Routes(cluster).absent()
    print(f"{args.unit} {args.mode}: ready", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, ValueError, KeyError, OSError, subprocess.TimeoutExpired) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)

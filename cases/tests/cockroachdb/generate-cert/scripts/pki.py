"""Reset only selected PKI, after a verified transition to insecure SQL."""
import base64
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from cluster import CERT_DIR, TOOLBOX, WORKSPACE, UnsafeState, certificate_directory, database_container, insecure_template

MATERIAL = ("ca.key", "ca.crt", "ca.srl", "node.key", "node.crt", "node.csr", "client.root.key", "client.root.crt", "client.root.csr")


def fingerprint(pem):
    with tempfile.TemporaryDirectory(prefix="karma-ca-public-") as directory:
        path = Path(directory) / "ca.crt"
        path.write_bytes(pem)
        result = subprocess.run(["openssl", "x509", "-in", str(path), "-outform", "DER"], capture_output=True, timeout=10)
        if result.returncode:
            return None
        return hashlib.sha256(result.stdout).hexdigest()


def secret_ca(secret):
    try:
        return fingerprint(base64.b64decode(secret["data"]["ca.crt"], validate=True))
    except (KeyError, ValueError):
        return None


def secret_references(spec):
    names = set()
    for volume in spec.get("volumes", []):
        if "secret" in volume:
            names.add(volume["secret"]["secretName"])
        for source in volume.get("projected", {}).get("sources", []):
            if "secret" in source:
                names.add(source["secret"]["name"])
    for container in spec.get("containers", []) + spec.get("initContainers", []):
        for env in container.get("env", []):
            ref = env.get("valueFrom", {}).get("secretKeyRef", {})
            if ref.get("name"):
                names.add(ref["name"])
        for env in container.get("envFrom", []):
            if "secretRef" in env:
                names.add(env["secretRef"]["name"])
    return names


def is_database(spec):
    try:
        database_container({"spec": spec})
        return True
    except UnsafeState:
        return False


def toolbox_ready(cluster):
    pod = cluster.get("pod", TOOLBOX)
    if pod is None or not any(c["type"] == "Ready" and c["status"] == "True" for c in pod.get("status", {}).get("conditions", [])):
        raise RuntimeError("OpenSSL toolbox is missing or not Ready")
    cluster.require(cluster.kubectl("exec", TOOLBOX, "--", "openssl", "version", timeout=10))
    return True


def toolbox_material(cluster):
    # Only public certificates and filenames leave the helper. Never print keys.
    script = 'for f in "$@"; do if test -e "/tmp/certs/$f"; then printf "%s\\n" "$f"; fi; done'
    raw = cluster.require(cluster.kubectl("exec", TOOLBOX, "--", "sh", "-c", script, "sh", *MATERIAL, timeout=10))
    files = raw.splitlines()
    ca, node = None, ""
    if "ca.crt" in files:
        result = cluster.kubectl("exec", TOOLBOX, "--", "cat", WORKSPACE + "/ca.crt", timeout=10)
        ca = fingerprint(cluster.require(result).encode())
    if "node.crt" in files:
        result = cluster.kubectl("exec", TOOLBOX, "--", "openssl", "x509", "-in", WORKSPACE + "/node.crt", "-noout", "-ext", "subjectAltName", timeout=10)
        node = result.stdout if result.returncode == 0 else ""
    return {"files": files, "ca_fingerprint": ca, "node_san": node}


class Reset:
    def __init__(self, cluster):
        self.cluster = cluster
        self.baseline_name = cluster.name + "-cert-reset-baseline"

    def inventory(self, inspect_toolbox=True):
        cluster = self.cluster
        sts = cluster.statefulset()
        cluster.pods(sts)
        baseline = cluster.get("configmap", self.baseline_name)
        if baseline is not None:
            labels = baseline["metadata"].get("labels", {})
            if labels.get("karma.dev/fixture") != "cert-reset-baseline" or labels.get("app.kubernetes.io/instance") != cluster.name:
                raise UnsafeState("certificate baseline name belongs to another resource")
            if baseline.get("data", {}).get("statefulset_uid") != sts["metadata"]["uid"]:
                raise UnsafeState("certificate baseline belongs to a different database incarnation")
        secrets = {obj["metadata"]["name"]: obj for obj in cluster.get("secrets")["items"]}
        names = {cluster.secret}
        names |= set(json.loads((baseline or {}).get("data", {}).get("material_secret_names", "[]")))
        container = database_container(sts["spec"]["template"])
        directory = certificate_directory(container)
        mounted = {m["name"] for m in container.get("volumeMounts", []) if m["mountPath"] in (directory, CERT_DIR)}
        for volume in sts["spec"]["template"]["spec"].get("volumes", []):
            if volume["name"] in mounted:
                names |= secret_references({"volumes": [volume]})
        # Include explicitly selected standalone CA Secrets, preserving all
        # unrelated Secrets even when their filenames resemble certificate keys.
        for name, secret in secrets.items():
            if secret["metadata"].get("labels", {}).get("app.kubernetes.io/instance") == cluster.name and "ca.crt" in secret.get("data", {}):
                names.add(name)
        selected = [secrets[name] for name in sorted(names) if name in secrets]
        for secret in selected:
            labels = secret["metadata"].get("labels", {})
            if labels.get("app.kubernetes.io/instance", cluster.name) != cluster.name:
                raise UnsafeState("selected certificate Secret belongs to another cluster")
            if not any(key in secret.get("data", {}) for key in ("ca.crt", "node.crt", "node.key", "client.root.crt", "client.root.key")):
                raise UnsafeState("certificate Secret name or mount is occupied by unrelated material")
        material = toolbox_material(cluster) if inspect_toolbox else {"files": [], "ca_fingerprint": None, "node_san": ""}
        ca_fingerprints = {fp for fp in [*(secret_ca(secret) for secret in selected), material["ca_fingerprint"]] if fp}
        # Non-server consumers of selected PKI are same-cluster clients: their
        # old trust is deliberately invalidated. Another database is protected.
        foreign_refs = set()
        for other in cluster.get("statefulsets")["items"]:
            if other["metadata"]["uid"] != sts["metadata"]["uid"] and is_database(other["spec"]["template"]["spec"]):
                foreign_refs |= secret_references(other["spec"]["template"]["spec"])
        for pod in cluster.get("pods")["items"]:
            owned = any(ref.get("uid") == sts["metadata"]["uid"] for ref in pod["metadata"].get("ownerReferences", []))
            instance = pod["metadata"].get("labels", {}).get("app.kubernetes.io/instance")
            if not owned and secret_references(pod["spec"]) & names and instance and instance != cluster.name:
                raise UnsafeState("an unrelated workload uses selected certificate material")
            if not owned and is_database(pod["spec"]):
                foreign_refs |= secret_references(pod["spec"])
        if foreign_refs & names:
            raise UnsafeState("another CockroachDB cluster uses selected certificate material")
        if any(secret_ca(secrets[name]) in ca_fingerprints for name in foreign_refs if name in secrets):
            raise UnsafeState("selected CA is shared with another CockroachDB cluster")
        if material["files"]:
            pod = cluster.get("pod", TOOLBOX)
            marked = pod["metadata"].get("labels", {}).get("app.kubernetes.io/instance") == cluster.name
            matches = material["ca_fingerprint"] and any(secret_ca(secret) == material["ca_fingerprint"] for secret in selected)
            host = f"{cluster.name}-0.{cluster.name}.{cluster.namespace}.svc.cluster.local"
            if not (marked or matches or ("DNS:" + host) in material["node_san"]):
                raise UnsafeState("toolbox certificate files cannot be attributed to the selected cluster")
        return {"sts": sts, "names": names, "secrets": selected, "material": material,
                "ca_fingerprints": ca_fingerprints, "baseline": baseline}

    def record_baseline(self, inventory):
        cluster = self.cluster
        baseline = inventory["baseline"]
        data = {"statefulset_uid": inventory["sts"]["metadata"]["uid"], "cluster_id": cluster.cluster_id(),
                "old_ca_fingerprints": json.dumps(sorted(inventory["ca_fingerprints"])),
                "material_secret_names": json.dumps(sorted(inventory["names"]))}
        if baseline is None:
            cluster.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": self.baseline_name,
                "namespace": cluster.namespace, "labels": {**cluster.labels, "karma.dev/fixture": "cert-reset-baseline"}}, "data": data})
        else:
            if baseline["data"]["cluster_id"] != data["cluster_id"]:
                raise UnsafeState("database cluster identity changed during preparation")
            previous = set(json.loads(baseline["data"].get("old_ca_fingerprints", "[]")))
            combined = json.dumps(sorted(previous | inventory["ca_fingerprints"]))
            if combined != baseline["data"]["old_ca_fingerprints"] or data["material_secret_names"] != baseline["data"].get("material_secret_names"):
                patch = [{"op": "test", "path": "/metadata/resourceVersion", "value": baseline["metadata"]["resourceVersion"]},
                         {"op": "replace", "path": "/data/old_ca_fingerprints", "value": combined},
                         {"op": "add", "path": "/data/material_secret_names", "value": data["material_secret_names"]}]
                cluster.require(cluster.kubectl("patch", "configmap", self.baseline_name, "--type=json", "-p", json.dumps(patch)))

    def absent(self):
        inventory = self.inventory()
        cluster = self.cluster
        if cluster.connection_flag() != "--insecure":
            raise RuntimeError("selected database still uses TLS")
        template = inventory["sts"]["spec"]["template"]
        if insecure_template(template, inventory["names"]) != template:
            raise RuntimeError("selected workload still has certificate mounts or TLS configuration")
        if inventory["secrets"] or inventory["material"]["files"]:
            raise RuntimeError("selected certificate or CA material still exists")
        if inventory["baseline"] is None:
            raise RuntimeError("certificate generation baseline is missing")
        cluster.ready()
        return True

    def apply(self):
        cluster = self.cluster
        inventory = self.inventory()  # All ownership checks precede mutations.
        cluster.durable(inventory["sts"])
        template = inventory["sts"]["spec"]["template"]
        updated = insecure_template(template, inventory["names"])
        self.record_baseline(inventory)
        if updated != template:
            old = inventory["sts"]
            strategy = copy.deepcopy(old["spec"].get("updateStrategy", {"type": "RollingUpdate"}))
            pods = cluster.pods(old)
            # Switching security mode needs a coordinated restart: ordinary
            # rolling readiness can stall while old/new nodes cannot communicate.
            cluster.patch_spec(old, {"template": updated, "updateStrategy": {"type": "OnDelete"}})
            try:
                for pod in pods:
                    cluster.delete(pod, wait=False)
                for pod in pods:
                    meta = pod["metadata"]
                    cluster.wait(lambda meta=meta: (cluster.get("pod", meta["name"]) or {}).get("metadata", {}).get("uid") != meta["uid"], 120)
                cluster.flag = None
                cluster.wait(cluster.ready, 300)
                if cluster.connection_flag() != "--insecure":
                    raise RuntimeError("database did not become insecure")
            finally:
                latest = cluster.statefulset()
                if latest["metadata"]["uid"] != old["metadata"]["uid"] or latest["spec"].get("updateStrategy") != {"type": "OnDelete"}:
                    raise UnsafeState("workload ownership or restart strategy changed concurrently")
                cluster.patch_spec(latest, {"updateStrategy": strategy})
        cluster.flag = None
        cluster.wait(cluster.ready, 90)
        if cluster.connection_flag() != "--insecure":
            raise RuntimeError("refusing certificate deletion while database still needs TLS")
        # Recheck consumers after the restart, before removing any signing keys.
        fresh = self.inventory()
        for secret in fresh["secrets"]:
            cluster.delete(secret)
        if fresh["material"]["files"]:
            script = 'for f in "$@"; do rm -f -- "/tmp/certs/$f"; done'
            cluster.require(cluster.kubectl("exec", TOOLBOX, "--", "sh", "-c", script, "sh", *MATERIAL, timeout=15))
        self.absent()

"""Case-local database readiness and health probes that preserve inherited state."""
import csv
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import time

import yaml
from cases.common.cockroachdb.cluster_backend import ClusterBackend
from cases.common.cockroachdb.connections import select_sql_readiness_flag

FAULT_MARKER = "# karma-health-probe-fault-v1\n"
SERVER_MARKER = "# karma-health-probe-server\n"
CERT_DIR = "/cockroach/cockroach-certs"


class UnsafeState(RuntimeError):
    """Waiting or rebuilding cannot safely resolve this configuration."""


def database_container(template):
    candidates = [c for c in template["spec"]["containers"]
                  if "cockroach" in (c.get("image", "") + " ".join(c.get("command", []) + c.get("args", [])))
                  and re.search(r"\bstart(?:-single-node)?\b", " ".join(c.get("command", []) + c.get("args", [])))]
    if len(candidates) != 1:
        raise UnsafeState("cannot identify exactly one CockroachDB server container")
    return candidates[0]


def shell_body(container):
    command = container.get("command", [])
    if len(command) == 3 and command[0] in ("/bin/bash", "/bin/sh", "bash", "sh") and command[1] in ("-c", "-ec"):
        body = command[2]
        if body.startswith(FAULT_MARKER):
            if SERVER_MARKER not in body:
                raise UnsafeState("incomplete health fault wrapper")
            body = body.split(SERVER_MARKER, 1)[1]
        syntax = shlex.shlex(body, posix=True, punctuation_chars=";&|<>")
        syntax.whitespace_split = True
        if any(re.fullmatch(r"[;&|<>]+", word) for word in syntax):
            raise UnsafeState("compound server startup cannot be modified safely")
        return body
    return None


def arguments(container):
    body = shell_body(container)
    return (shlex.split(body) if body is not None else container.get("command", [])) + container.get("args", [])


def flag_value(container, name, default):
    tokens = arguments(container)
    values = [token.split("=", 1)[1] for token in tokens if token.startswith(name + "=")]
    values += [tokens[i + 1] for i, token in enumerate(tokens[:-1]) if token == name]
    if len(values) > 1:
        raise UnsafeState("ambiguous server flag: " + name)
    return values[0] if values else default


def pod_ready(pod):
    return bool(pod and not pod["metadata"].get("deletionTimestamp") and pod.get("status", {}).get("phase") == "Running"
                and any(c.get("type") == "Ready" and c.get("status") == "True" for c in pod.get("status", {}).get("conditions", [])))


def health_probes(container):
    ports = {p["name"]: p["containerPort"] for p in container.get("ports", []) if "name" in p}
    result = []
    for kind, path in (("livenessProbe", "/health"), ("readinessProbe", "/health?ready=1")):
        probe = container.get(kind, {}).get("httpGet")
        if not probe or probe.get("host") or probe.get("path") != path:
            raise UnsafeState("case requires HTTP liveness /health and readiness /health?ready=1 probes on the pod address")
        port = ports.get(probe["port"], probe["port"])
        scheme = probe.get("scheme", "HTTP")
        if not isinstance(port, int) or not 1 <= port <= 65535 or scheme not in ("HTTP", "HTTPS"):
            raise UnsafeState("invalid health probe port or scheme")
        result.append({"port": port, "scheme": scheme.lower(), "path": path, "headers": probe.get("httpHeaders", [])})
    if len({p["port"] for p in result}) != 1 or len({p["scheme"] for p in result}) != 1:
        raise UnsafeState("health probes must use the same listener and protocol")
    return result


class Cluster:
    kubectl = ClusterBackend.kubectl
    require = staticmethod(ClusterBackend.require)
    get = ClusterBackend.get
    patch_spec = ClusterBackend.patch_spec

    def __init__(self):
        self.namespace = os.environ["BENCH_NAMESPACE"]
        self.name = os.environ.get("BENCH_PARAM_CLUSTER_NAME", "crdb-cluster")
        for value in (self.namespace, self.name):
            if len(value) > 63 or not re.fullmatch(r"[a-z0-9]([-a-z0-9]*[a-z0-9])?", value):
                raise ValueError("namespace and cluster_name must be DNS labels")
        if len(self.name) > 56:
            raise ValueError("cluster_name must leave room for the related Service suffix")
        self.labels = {"app.kubernetes.io/name": "cockroachdb", "app.kubernetes.io/instance": self.name}
        self.resources = Path(__file__).resolve().parents[1] / "resource"
        self.flag = None

    def create(self, obj):
        self.require(self.kubectl("create", "-f", "-", namespace=obj["metadata"].get("namespace", ""), input_text=json.dumps(obj)))
        print(f"Created {obj['kind']}/{obj['metadata']['name']}", flush=True)

    def template(self, name):
        text = (self.resources / name).read_text()
        for key, value in (("BENCH_NAMESPACE", self.namespace), ("BENCH_PARAM_CLUSTER_NAME", self.name)):
            text = text.replace("${" + key + "}", value)
        return list(yaml.safe_load_all(text))

    def identity(self, obj):
        labels = obj["metadata"].get("labels", {})
        if any(key in labels and labels[key] != value for key, value in self.labels.items()):
            raise UnsafeState("selected resource has conflicting cluster identity")
        if any(ref.get("controller") for ref in obj["metadata"].get("ownerReferences", [])):
            raise UnsafeState("selected resource is managed by another controller")

    def statefulset(self):
        sts = self.get("statefulset", self.name)
        if sts is None:
            raise RuntimeError("selected StatefulSet is absent")
        self.identity(sts)
        if int(sts["spec"].get("ordinals", {}).get("start", 0)) != 0:
            raise UnsafeState("case requires zero-based pod ordinals")
        return sts

    def pods(self, sts, optional=()):
        count = int(sts["spec"].get("replicas", 1))
        if count < 1:
            raise UnsafeState("selected StatefulSet has no replicas")
        items = {p["metadata"]["name"]: p for p in self.get("pods")["items"]}
        pods = []
        for ordinal in range(count):
            pod = items.get(f"{self.name}-{ordinal}")
            if pod is None and ordinal not in optional:
                raise RuntimeError("selected database pod is missing")
            if pod and not any(r.get("uid") == sts["metadata"]["uid"] for r in pod["metadata"].get("ownerReferences", [])):
                raise UnsafeState("database pod belongs to another workload")
            pods.append(pod)
        return pods

    def sql(self, query, ordinal=0, flag=None, timeout=10):
        container = database_container(self.statefulset()["spec"]["template"])
        flag = flag or self.connection_flag()
        port = flag_value(container, "--port", "26257")
        host = f"{self.name}-{ordinal}.{self.name}.{self.namespace}.svc.cluster.local"
        return self.kubectl("exec", f"{self.name}-{ordinal}", "-c", container["name"], "--", "./cockroach", "sql", flag,
                            "--host=" + host, "--port=" + port, "--format=csv", "-e", query, timeout=timeout)

    def connection_flag(self):
        if self.flag is None:
            container = database_container(self.statefulset()["spec"]["template"])
            directory = flag_value(container, "--certs-dir", CERT_DIR)
            self.flag = select_sql_readiness_flag(
                dict.fromkeys(("--certs-dir=" + directory, "--certs-dir=" + CERT_DIR, "--insecure")),
                lambda query, flag: self.sql(query, flag=flag),
                unavailable_message="selected database has no working TLS or insecure SQL connection",
            )
        return self.flag

    def cluster_id(self, ordinal=0):
        rows = list(csv.reader(io.StringIO(self.require(self.sql("SELECT crdb_internal.cluster_id();", ordinal)))))
        if len(rows) != 2 or not re.fullmatch(r"[0-9a-fA-F-]{36}", rows[1][0]):
            raise RuntimeError("database did not return a cluster identity")
        return rows[1][0]

    def services_ready(self, sts):
        for name in (self.name, self.name + "-public"):
            service = self.get("service", name)
            if service is None:
                raise RuntimeError("selected database Service is missing")
            selector = service["spec"].get("selector", {})
            labels = sts["spec"]["template"]["metadata"].get("labels", {})
            if not selector or any(labels.get(k) != v for k, v in selector.items()):
                raise UnsafeState("database Service does not select the selected workload")
            for pod in self.get("pods")["items"]:
                if all(pod["metadata"].get("labels", {}).get(k) == v for k, v in selector.items()) and not any(
                    ref.get("uid") == sts["metadata"]["uid"] for ref in pod["metadata"].get("ownerReferences", [])):
                    raise UnsafeState("database Service also selects another workload")

    def ready(self, omit=(), functional_health=False):
        sts = self.statefulset()
        identity = self.cluster_id()
        for ordinal, pod in enumerate(self.pods(sts, optional=omit)):
            if ordinal in omit:
                continue
            if not pod_ready(pod):
                raise RuntimeError("selected database pod is not Ready")
            if self.cluster_id(ordinal) != identity:
                raise UnsafeState("selected pods belong to different database clusters")
            if functional_health:
                self.health(pod)
        self.services_ready(sts)
        return True

    def health_request(self, pod, probe):
        address = ipaddress.ip_address(pod["status"]["podIP"])
        host = f"[{address}]" if address.version == 6 else str(address)
        container = database_container(self.statefulset()["spec"]["template"])
        args = ["exec", self.name + "-0", "-c", container["name"], "--", "curl", "--fail", "--silent", "--show-error", "--connect-timeout", "2", "--max-time", "3"]
        if probe["scheme"] == "https":
            # Match kubelet HTTP probes: health availability, without changing
            # the cluster's trust material. Verified SQL checks TLS credentials.
            args += ["--insecure"]
        for header in probe["headers"]:
            args += ["--header", header["name"] + ": " + header["value"]]
        return self.kubectl(*args, f"{probe['scheme']}://{host}:{probe['port']}{probe['path']}", timeout=8)

    def health(self, pod):
        container = database_container({"spec": pod["spec"]})
        for probe in health_probes(container):
            self.require(self.health_request(pod, probe))

    def wait(self, check, seconds, *, propagate=()):
        deadline = time.monotonic() + seconds
        last = "not ready"
        while time.monotonic() < deadline:
            try:
                if check():
                    return
            except propagate:
                raise
            except (RuntimeError, ValueError) as error:
                if isinstance(error, UnsafeState):
                    raise
                last = str(error)
            time.sleep(3)
        raise RuntimeError(last)

    def delete_pod(self, pod, wait=True):
        meta = pod["metadata"]
        options = {"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": meta["uid"]}}
        self.require(self.kubectl("delete", "--raw=" + f"/api/v1/namespaces/{self.namespace}/pods/{meta['name']}", "-f", "-", input_text=json.dumps(options)))
        if wait:
            self.wait(lambda: (self.get("pod", meta["name"]) or {}).get("metadata", {}).get("uid") != meta["uid"], 120)

    def durable(self, sts):
        container = database_container(sts["spec"]["template"])
        tokens = arguments(container)
        stores = [t.split("=", 1)[1] for t in tokens if t.startswith(("--store=", "-s="))]
        stores += [t[2:] for t in tokens if t.startswith("-s") and t != "-s" and not t.startswith("-s=")]
        stores += [tokens[i + 1] for i, t in enumerate(tokens[:-1]) if t in ("--store", "-s")]
        volumes = {v["metadata"]["name"] for v in sts["spec"].get("volumeClaimTemplates", [])}
        volumes |= {v["name"] for v in sts["spec"]["template"]["spec"].get("volumes", []) if "persistentVolumeClaim" in v}
        for store in stores or ["/cockroach/cockroach-data"]:
            options = dict(part.split("=", 1) for part in store.split(",") if "=" in part)
            path = options.get("path", store.split(",", 1)[0])
            mounts = sorted((m for m in container.get("volumeMounts", []) if path == m["mountPath"].rstrip("/") or path.startswith(m["mountPath"].rstrip("/") + "/")),
                            key=lambda m: len(m["mountPath"]), reverse=True)
            if options.get("type") == "mem" or not path.startswith("/") or not mounts or mounts[0]["name"] not in volumes:
                raise UnsafeState("health fault restart requires PVC-backed database stores")

    def pvc_identity(self, sts):
        names = {v["persistentVolumeClaim"]["claimName"] for pod in self.pods(sts) for v in pod["spec"].get("volumes", []) if "persistentVolumeClaim" in v}
        result = {}
        for name in sorted(names):
            pvc = self.get("pvc", name)
            if pvc is None or pvc["metadata"].get("deletionTimestamp") or pvc.get("status", {}).get("phase") != "Bound":
                raise UnsafeState("selected database storage is missing or not Bound")
            result[name] = pvc["metadata"]["uid"]
        if not result:
            raise UnsafeState("selected database has no persistent storage")
        return result

    def bootstrap(self):
        if self.get("namespace", self.namespace, namespace="") is None:
            raise RuntimeError("framework-managed namespace is missing")
        for kind, prefix in (("pods", ""), ("pvc", "datadir-")):
            for item in self.get(kind)["items"]:
                if all(item["metadata"].get("labels", {}).get(k) == v for k, v in self.labels.items()) or re.fullmatch(re.escape(prefix + self.name) + r"-\d+", item["metadata"]["name"]):
                    raise UnsafeState("selected workload is absent but inherited pods/storage remain")
        for file in ("rbac.yaml", "services.yaml"):
            for obj in self.template(file):
                existing = self.get(obj["kind"], obj["metadata"]["name"])
                if existing is None:
                    self.create(obj)
                else:
                    self.identity(existing)
                    for key in ("rules", "roleRef", "subjects"):
                        if key in obj and existing.get(key) != obj[key]:
                            raise UnsafeState("existing bootstrap RBAC is incompatible")
                    if obj["kind"] == "Service" and existing["spec"].get("selector") != obj["spec"]["selector"]:
                        raise UnsafeState("existing bootstrap Service belongs to another target")
        self.create(self.template("statefulset.yaml")[0])
        host = f"{self.name}-0.{self.name}.{self.namespace}.svc.cluster.local"
        def initialize():
            return self.sql("SELECT 1;", flag="--insecure").returncode == 0 or self.kubectl("exec", self.name + "-0", "--", "./cockroach", "init", "--insecure", "--host=" + host, timeout=15).returncode == 0
        self.wait(initialize, 300)
        self.wait(self.ready, 300)

    def recover(self, readiness_check=None, propagate=()):
        """Restore the original data-preserving health recovery policy.

        Missing Services are recreated from the case manifest, then readiness
        is given the original grace period. If the selected workload remains
        unhealthy, only Running, unready Pods are restarted after verifying
        their stores are PVC-backed. ``readiness_check`` lets the shared CRDB
        observer participate in those same bounded checks without changing
        the case's repair policy.
        """
        if self.get("statefulset", self.name) is None:
            self.bootstrap()
            return
        sts = self.statefulset()
        for service in self.template("services.yaml"):
            if self.get("service", service["metadata"]["name"]) is None:
                service["spec"]["selector"] = sts["spec"]["selector"].get("matchLabels", {})
                if not service["spec"]["selector"]:
                    raise UnsafeState("cannot infer missing Service selector")
                self.create(service)

        def ready():
            return readiness_check() if readiness_check is not None else self.ready()

        try:
            self.wait(ready, 20, propagate=propagate)
            return
        except propagate:
            raise
        except UnsafeState:
            raise
        except RuntimeError:
            pass
        self.durable(sts)
        for pod in self.pods(sts):
            if pod.get("status", {}).get("phase") == "Running" and not pod_ready(pod):
                self.delete_pod(pod)
                self.wait(lambda: self.get("pod", pod["metadata"]["name"]) is not None, 120)
        self.flag = None
        self.wait(ready, 180, propagate=propagate)

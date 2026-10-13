"""Selected database operations; readiness never grants permission to erase data."""
import copy
import csv
import io
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import time

import yaml

CERT_DIR = "/cockroach/cockroach-certs"
TOOLBOX = "openssl-toolbox"
WORKSPACE = "/tmp/certs"


class UnsafeState(RuntimeError):
    """Ownership or configuration cannot be repaired by waiting."""


def database_container(template):
    containers = [c for c in template["spec"]["containers"]
                  if "cockroach" in (c.get("image", "") + " ".join(c.get("command", []) + c.get("args", [])))
                  and re.search(r"\bstart(?:-single-node)?\b", " ".join(c.get("command", []) + c.get("args", [])))]
    if len(containers) != 1:
        raise UnsafeState("cannot identify exactly one CockroachDB server container")
    return containers[0]


def server_arguments(container):
    command = container.get("command", [])
    if len(command) == 3 and command[0] in ("/bin/bash", "/bin/sh", "bash", "sh") and command[1] in ("-c", "-ec"):
        tokens = shlex.split(command[2])
        syntax = shlex.shlex(command[2], posix=True, punctuation_chars=";&|<>")
        syntax.whitespace_split = True
        if any(re.fullmatch(r"[;&|<>]+", token) for token in syntax):
            raise UnsafeState("compound server startup requires explicit security-mode configuration")
        return tokens + container.get("args", [])
    return command + container.get("args", [])


def certificate_directory(container):
    tokens = server_arguments(container)
    for index, token in enumerate(tokens):
        if token.startswith("--certs-dir="):
            return token.split("=", 1)[1]
        if token == "--certs-dir" and index + 1 < len(tokens):
            return tokens[index + 1]
    return CERT_DIR


def insecure_template(template, secret_names):
    """Change only server security flags, certificate mounts, and HTTP probes."""
    updated = copy.deepcopy(template)
    container = database_container(updated)
    directory = certificate_directory(container)
    def strip(tokens):
        result = []
        index = 0
        while index < len(tokens):
            token = tokens[index]
            if token in ("--certs-dir", "--accept-sql-without-tls"):
                index += 2 if token == "--certs-dir" else 1
                continue
            if token == "--insecure" or token.startswith(("--certs-dir=", "--insecure=", "--accept-sql-without-tls=")):
                index += 1
                continue
            result.append(token)
            index += 1
        return result
    command = container.get("command", [])
    arguments = server_arguments(container)
    change_flags = not any(t in ("--insecure", "--insecure=true") for t in arguments) or any(
        t == "--certs-dir" or t.startswith(("--certs-dir=", "--accept-sql-without-tls")) for t in arguments)
    if not change_flags:
        pass
    elif len(command) == 3 and command[0] in ("/bin/bash", "/bin/sh", "bash", "sh") and command[1] in ("-c", "-ec"):
        body = command[2]
        # Preserve quoting and expansion of every unrelated startup argument.
        body = re.sub(r"(?<!\S)--certs-dir(?:=\S+|\s+\S+)(?=\s|$)", "", body)
        body = re.sub(r"(?<!\S)--(?:insecure|accept-sql-without-tls)(?:=\S+)?(?=\s|$)", "", body)
        wanted = strip(shlex.split(command[2]))
        if shlex.split(body) != wanted:
            raise UnsafeState("cannot safely edit quoted security arguments")
        container["command"][2] = body.rstrip() + " --insecure"
        if "args" in container:
            container["args"] = strip(container["args"])
    else:
        if "command" in container:
            container["command"] = strip(container["command"])
        if "args" in container:
            container["args"] = strip(container["args"]) + ["--insecure"]
        else:
            container["command"] = strip(container.get("command", [])) + ["--insecure"]
    def refs(volume):
        return {volume["secret"]["secretName"]} if "secret" in volume else {
            source["secret"]["name"] for source in volume.get("projected", {}).get("sources", []) if "secret" in source}
    removed = {volume["name"] for volume in updated["spec"].get("volumes", []) if refs(volume) & secret_names}
    removed |= {mount["name"] for mount in container.get("volumeMounts", []) if mount["mountPath"] in (directory, CERT_DIR)}
    for volume in updated["spec"].get("volumes", []):
        if volume["name"] in removed and (not refs(volume) or refs(volume) - secret_names or any(
            "secret" not in source for source in volume.get("projected", {}).get("sources", []))):
            raise UnsafeState("certificate volume includes unrelated sources or non-Secret storage")
    # A shared volume used at an unrelated path cannot be removed implicitly.
    for other in updated["spec"].get("containers", []) + updated["spec"].get("initContainers", []):
        if other is not container and any(m["name"] in removed for m in other.get("volumeMounts", [])):
            raise UnsafeState("another container uses the database certificate volume")
    if "volumeMounts" in container:
        container["volumeMounts"] = [m for m in container["volumeMounts"] if m["name"] not in removed]
    if "volumes" in updated["spec"]:
        updated["spec"]["volumes"] = [v for v in updated["spec"]["volumes"] if v["name"] not in removed]
    for key in ("livenessProbe", "readinessProbe", "startupProbe"):
        probe = container.get(key, {})
        if "httpGet" in probe and probe["httpGet"].get("scheme") == "HTTPS":
            probe["httpGet"]["scheme"] = "HTTP"
        if "exec" in probe and any("--certs-dir" in arg for arg in probe["exec"]["command"]):
            raise UnsafeState("certificate-based exec health probe requires explicit mode conversion")
    return updated


class Cluster:
    def __init__(self):
        self.namespace = os.environ["BENCH_NAMESPACE"]
        self.name = os.environ.get("BENCH_PARAM_CLUSTER_NAME", "crdb-cluster")
        self.secret = os.environ.get("BENCH_PARAM_CERT_SECRET_NAME", "crdb-cluster-certs")
        for value in (self.namespace, self.name):
            if len(value) > 63 or not re.fullmatch(r"[a-z0-9]([-a-z0-9]*[a-z0-9])?", value):
                raise ValueError("namespace and cluster_name must be DNS labels")
        if len(self.name) > 56 or len(self.secret) > 253 or not re.fullmatch(r"[a-z0-9]([a-z0-9.-]*[a-z0-9])?", self.secret):
            raise ValueError("cluster_name prefix or certificate Secret name is invalid")
        self.labels = {"app.kubernetes.io/name": "cockroachdb", "app.kubernetes.io/instance": self.name}
        self.resources = Path(__file__).resolve().parents[1] / "resource"
        self.flag = None
        self.sql_container = None

    def kubectl(self, *args, timeout=25, namespace=None, input_text=None):
        namespace = self.namespace if namespace is None else namespace
        command = ["kubectl", f"--request-timeout={timeout}s"] + (["-n", namespace] if namespace else []) + list(args)
        try:
            return subprocess.run(command, input=input_text, text=True, capture_output=True, timeout=timeout + 5)
        except subprocess.TimeoutExpired:
            return subprocess.CompletedProcess(command, 124, "", "kubectl timed out")

    @staticmethod
    def require(result):
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or "kubectl failed")
        return result.stdout

    def get(self, kind, name=None, namespace=None):
        args = ["get", kind] + ([name, "--ignore-not-found=true"] if name is not None else [])
        raw = self.require(self.kubectl(*args, "-o", "json", namespace=namespace))
        return json.loads(raw) if raw.strip() else None

    def create(self, obj):
        self.require(self.kubectl("create", "-f", "-", input_text=json.dumps(obj), namespace=obj["metadata"].get("namespace", "")))
        print(f"Created {obj['kind']}/{obj['metadata']['name']}", flush=True)

    def template(self, file):
        text = (self.resources / file).read_text()
        for key, value in (("BENCH_NAMESPACE", self.namespace), ("BENCH_PARAM_CLUSTER_NAME", self.name)):
            text = text.replace("${" + key + "}", value)
        return list(yaml.safe_load_all(text))

    def identity(self, obj):
        labels = obj["metadata"].get("labels", {})
        if any(key in labels and labels[key] != value for key, value in self.labels.items()):
            raise UnsafeState("selected resource has conflicting cluster identity")
        if any(ref.get("controller") for ref in obj["metadata"].get("ownerReferences", [])):
            raise UnsafeState("selected StatefulSet is managed by another controller")

    def statefulset(self):
        sts = self.get("statefulset", self.name)
        if sts is None:
            raise RuntimeError("selected StatefulSet is absent")
        self.identity(sts)
        if int(sts["spec"].get("ordinals", {}).get("start", 0)) != 0:
            raise UnsafeState("this case requires zero-based CockroachDB pod ordinals")
        return sts

    def pods(self, sts):
        count = int(sts["spec"].get("replicas", 1))
        if count < 1:
            raise UnsafeState("selected StatefulSet has no running replicas")
        items = {p["metadata"]["name"]: p for p in self.get("pods")["items"]}
        result = []
        for ordinal in range(count):
            pod = items.get(f"{self.name}-{ordinal}")
            if pod is None:
                raise RuntimeError("selected database pod is missing")
            if not any(r.get("uid") == sts["metadata"]["uid"] for r in pod["metadata"].get("ownerReferences", [])):
                raise UnsafeState("database pod belongs to another workload")
            result.append(pod)
        return result

    def sql(self, query, ordinal=0, flag=None, timeout=10):
        flag = flag or self.connection_flag()
        if self.sql_container is None:
            self.sql_container = database_container(self.statefulset()["spec"]["template"])["name"]
        host = f"{self.name}-{ordinal}.{self.name}.{self.namespace}.svc.cluster.local"
        return self.kubectl("exec", f"{self.name}-{ordinal}", "-c", self.sql_container, "--", "./cockroach", "sql", flag,
                            "--host=" + host, "--format=csv", "-e", query, timeout=timeout)

    def connection_flag(self):
        if self.flag is None:
            directory = certificate_directory(database_container(self.statefulset()["spec"]["template"]))
            for flag in dict.fromkeys(("--certs-dir=" + directory, "--certs-dir=" + CERT_DIR, "--insecure")):
                if self.sql("SELECT 1;", flag=flag).returncode == 0:
                    self.flag = flag
                    break
            if self.flag is None:
                raise RuntimeError("selected database has no working TLS or insecure SQL connection")
        return self.flag

    def cluster_id(self):
        rows = list(csv.reader(io.StringIO(self.require(self.sql("SELECT crdb_internal.cluster_id();")))))
        if len(rows) != 2 or not re.fullmatch(r"[0-9a-fA-F-]{36}", rows[1][0]):
            raise RuntimeError("database did not return a cluster identity")
        return rows[1][0]

    def ready(self):
        sts = self.statefulset()
        pods = self.pods(sts)
        for ordinal in range(len(pods)):
            self.require(self.sql("SELECT 1;", ordinal=ordinal))
        for name in (self.name, self.name + "-public"):
            svc = self.get("service", name)
            if svc is None:
                raise RuntimeError("selected database Service is missing")
            selector = svc["spec"].get("selector", {})
            labels = sts["spec"]["template"]["metadata"].get("labels", {})
            if not selector or any(labels.get(k) != v for k, v in selector.items()):
                raise UnsafeState("database Service does not select the selected workload")
            for pod in self.get("pods")["items"]:
                if all(pod["metadata"].get("labels", {}).get(k) == v for k, v in selector.items()) and not any(
                    ref.get("uid") == sts["metadata"]["uid"] for ref in pod["metadata"].get("ownerReferences", [])):
                    raise UnsafeState("database Service also selects another workload")
            if not {26257, 8080} <= {p["port"] for p in svc["spec"].get("ports", [])}:
                raise UnsafeState("database Services must expose SQL 26257 and console 8080")
        return True

    def wait(self, check, seconds):
        deadline = time.monotonic() + seconds
        last = "not ready"
        while time.monotonic() < deadline:
            try:
                if check():
                    return
            except (RuntimeError, ValueError) as error:
                if isinstance(error, UnsafeState):
                    raise
                last = str(error)
            time.sleep(3)
        raise RuntimeError(last)

    def delete(self, obj, wait=True):
        plural = {"Pod": "pods", "Secret": "secrets"}[obj["kind"]]
        meta = obj["metadata"]
        path = f"/api/v1/namespaces/{meta['namespace']}/{plural}/{meta['name']}"
        options = {"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": meta["uid"]}}
        if obj["kind"] == "Secret":
            options["preconditions"]["resourceVersion"] = meta["resourceVersion"]
        self.require(self.kubectl("delete", "--raw=" + path, "-f", "-", input_text=json.dumps(options)))
        if wait:
            self.wait(lambda: (self.get(obj["kind"], meta["name"]) or {}).get("metadata", {}).get("uid") != meta["uid"], 120)

    def patch_spec(self, obj, fields):
        patch = [{"op": "test", "path": "/metadata/uid", "value": obj["metadata"]["uid"]},
                 {"op": "test", "path": "/metadata/resourceVersion", "value": obj["metadata"]["resourceVersion"]}]
        for key, value in fields.items():
            patch.append({"op": "add", "path": "/spec/" + key, "value": value})
        self.require(self.kubectl("patch", "statefulset", self.name, "--type=json", "-p", json.dumps(patch)))

    def durable(self, sts):
        container = database_container(sts["spec"]["template"])
        arguments = server_arguments(container)
        stores = [value.split("=", 1)[1] for value in arguments if value.startswith(("--store=", "-s="))]
        stores += [value[2:] for value in arguments if value.startswith("-s") and value != "-s" and not value.startswith("-s=")]
        stores += [arguments[i + 1] for i, value in enumerate(arguments[:-1]) if value in ("--store", "-s")]
        stores = stores or ["/cockroach/cockroach-data"]
        volumes = {v["metadata"]["name"] for v in sts["spec"].get("volumeClaimTemplates", [])}
        volumes |= {v["name"] for v in sts["spec"]["template"]["spec"].get("volumes", []) if "persistentVolumeClaim" in v}
        mounts = container.get("volumeMounts", [])
        for store in stores:
            options = dict(part.split("=", 1) for part in store.split(",") if "=" in part)
            path = options.get("path", store.split(",", 1)[0])
            covering = sorted((m for m in mounts if path == m["mountPath"].rstrip("/") or path.startswith(m["mountPath"].rstrip("/") + "/")),
                              key=lambda m: len(m["mountPath"]), reverse=True)
            if options.get("type") == "mem" or not path.startswith("/") or not covering or covering[0]["name"] not in volumes:
                raise UnsafeState("security-mode restart requires PVC-backed database stores")

    def bootstrap(self):
        if self.get("namespace", self.namespace, namespace="") is None:
            raise RuntimeError("framework-managed namespace is missing")
        for kind, prefix in (("pods", ""), ("pvc", "datadir-")):
            for obj in self.get(kind)["items"]:
                if all(obj["metadata"].get("labels", {}).get(k) == v for k, v in self.labels.items()) or re.fullmatch(
                    re.escape(prefix + self.name) + r"-\d+", obj["metadata"]["name"]):
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
            if self.sql("SELECT 1;", flag="--insecure").returncode == 0:
                return True
            return self.kubectl("exec", self.name + "-0", "--", "./cockroach", "init", "--insecure", "--host=" + host,
                                timeout=15).returncode == 0
        self.wait(initialize, 300)
        self.require(self.kubectl("rollout", "status", "statefulset/" + self.name, "--timeout=300s", timeout=305))
        self.wait(self.ready, 120)

    def recover(self):
        if self.get("statefulset", self.name) is None:
            self.bootstrap()
            return
        sts = self.statefulset()
        for svc in self.template("services.yaml"):
            if self.get("service", svc["metadata"]["name"]) is None:
                svc["spec"]["selector"] = sts["spec"]["selector"].get("matchLabels", {})
                if not svc["spec"]["selector"]:
                    raise UnsafeState("cannot infer missing Service selector")
                self.create(svc)
        try:
            self.wait(self.ready, 30)
            return
        except UnsafeState:
            raise
        except RuntimeError:
            pass
        for pod in self.pods(sts):
            if pod.get("status", {}).get("phase") == "Running" and not any(
                c["type"] == "Ready" and c["status"] == "True" for c in pod.get("status", {}).get("conditions", [])):
                self.durable(sts)
                self.delete(pod)
                self.wait(lambda: self.get("pod", pod["metadata"]["name"]) is not None, 120)
        self.flag = None
        self.wait(self.ready, 180)

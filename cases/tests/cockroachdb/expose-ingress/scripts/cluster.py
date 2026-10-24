"""Selected-cluster operations that preserve inherited workload and storage."""
import base64
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from cases.common.cockroachdb.cluster_backend import ClusterBackend
from cases.common.cockroachdb.connections import select_sql_readiness_flag


class UnsafeState(RuntimeError):
    """An ownership/configuration conflict that waiting cannot safely repair."""


class Cluster(ClusterBackend):
    error_type = UnsafeState

    def __init__(self):
        self.namespace = os.environ["BENCH_NAMESPACE"]
        self.name = os.environ.get("BENCH_PARAM_CLUSTER_NAME", "crdb-cluster")
        self.ui_host = os.environ.get("BENCH_PARAM_UI_HOST", "crdb-ui.example.com")
        self.sql_port = os.environ.get("BENCH_PARAM_SQL_PORT", "26257")
        self.ingress_class = os.environ.get("BENCH_PARAM_INGRESS_CLASS_NAME", "nginx")
        for value in (self.namespace, self.name, self.ingress_class):
            if len(value) > 63 or not re.fullmatch(r"[a-z0-9]([-a-z0-9]*[a-z0-9])?", value):
                raise ValueError("namespace, cluster_name and ingress_class_name must be DNS labels")
        if not re.fullmatch(r"[a-z0-9]([a-z0-9.-]*[a-z0-9])?", self.ui_host):
            raise ValueError("ui_host must be a DNS hostname")
        if not self.sql_port.isdigit() or not 1 <= int(self.sql_port) <= 65535 or int(self.sql_port) in (80, 443):
            raise ValueError("sql_port must be a TCP port other than the controller's HTTP/HTTPS ports")
        self.sql_port = str(int(self.sql_port))
        self.labels = {"app.kubernetes.io/name": "cockroachdb", "app.kubernetes.io/instance": self.name}
        self.resources = Path(__file__).resolve().parents[1] / "resource"
        self.flag = None

    def kubectl(self, *args, namespace=None, timeout=25, input_text=None):
        return super().kubectl(*args, timeout=timeout, namespace=namespace, input_text=input_text)

    def create(self, obj):
        self.require(self.kubectl("create", "-f", "-", namespace=obj["metadata"].get("namespace", ""),
                                  input_text=json.dumps(obj)))
        print(f"Created {obj['kind']}/{obj['metadata']['name']}", flush=True)

    def get_all_ingresses(self):
        return json.loads(self.require(self.kubectl("get", "ingresses", "-A", "-o", "json", namespace="")))["items"]

    def delete_object(self, obj):
        metadata = obj["metadata"]
        resources = {"Ingress": "/apis/networking.k8s.io/v1", "Pod": "/api/v1"}
        plural = {"Ingress": "ingresses", "Pod": "pods"}
        path = (f"{resources[obj['kind']]}/namespaces/{metadata['namespace']}/"
                f"{plural[obj['kind']]}/{metadata['name']}")
        options = {"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {
            "uid": metadata["uid"], "resourceVersion": metadata["resourceVersion"]}}
        self.require(self.kubectl("delete", "--raw=" + path, "-f", "-", input_text=json.dumps(options)))
        self.wait(lambda: self.get(obj["kind"], metadata["name"], namespace=metadata["namespace"]) is None, 120)

    def identity(self, obj):
        labels = obj["metadata"].get("labels", {})
        if any(key in labels and labels[key] != value for key, value in self.labels.items()):
            raise UnsafeState(f"conflicting identity on {obj['kind']}/{obj['metadata']['name']}")
        if any(ref.get("controller") for ref in obj["metadata"].get("ownerReferences", [])):
            raise UnsafeState("selected StatefulSet is managed by another controller")

    def sql(self, query, ordinal=0, flag=None, timeout=10, through_ingress=False):
        pod = f"{self.name}-{ordinal}"
        host = f"{pod}.{self.name}.{self.namespace}.svc.cluster.local"
        flag = flag or self.connection_flag()
        args = ["exec", pod, "--", "./cockroach", "sql", "--format=csv"]
        if through_ingress:
            host = "ingress-nginx-controller.ingress-nginx.svc"
            if flag != "--insecure":
                url = (f"postgresql://root@{host}:{self.sql_port}/?sslmode=require"
                       "&sslcert=/cockroach/cockroach-certs/client.root.crt"
                       "&sslkey=/cockroach/cockroach-certs/client.root.key")
                args += ["--url", url]
            else:
                args += [flag, f"--host={host}", f"--port={self.sql_port}"]
        else:
            args += [flag, f"--host={host}"]
        return self.kubectl(*args, "-e", query, timeout=timeout)

    def connection_flag(self):
        if self.flag is None:
            candidates = ("--certs-dir=/cockroach/cockroach-certs", "--insecure")
            self.flag = select_sql_readiness_flag(
                candidates,
                lambda query, flag: self.sql(query, flag=flag),
                unavailable_message="selected database is not SQL-ready with TLS or insecure credentials",
            )
        return self.flag

    def service_ready(self, sts):
        service = self.get("service", self.name + "-public")
        if service is None:
            raise RuntimeError("selected public Service is missing")
        selector = service.get("spec", {}).get("selector", {})
        labels = sts["spec"]["template"]["metadata"].get("labels", {})
        if not selector or any(labels.get(key) != value for key, value in selector.items()):
            raise UnsafeState("public Service does not select the selected StatefulSet")
        pods = self.get("pods")["items"]
        selected = [pod for pod in pods if all(pod["metadata"].get("labels", {}).get(k) == v
                                               for k, v in selector.items())]
        uid = sts["metadata"]["uid"]
        if not selected or any(not any(ref.get("uid") == uid for ref in pod["metadata"].get("ownerReferences", []))
                               for pod in selected):
            raise UnsafeState("public Service also selects pods outside the selected StatefulSet")
        ports = {port["port"] for port in service["spec"].get("ports", [])}
        if not {26257, 8080} <= ports:
            raise UnsafeState("public Service must expose SQL 26257 and console 8080")

    def ready(self):
        sts = self.get("statefulset", self.name)
        if sts is None:
            raise RuntimeError("selected StatefulSet is absent")
        self.identity(sts)
        replicas = int(sts["spec"].get("replicas", 1))
        if replicas < 1:
            raise RuntimeError("selected StatefulSet has no running replicas")
        self.connection_flag()
        for ordinal in range(replicas):
            self.require(self.sql("SELECT 1;", ordinal=ordinal))
        self.service_ready(sts)
        return True

    def certificates(self):
        """Generate only a missing target's material; never rotate inherited keys."""
        name = self.name + "-certs"
        if self.get("secret", name) is not None:
            # Leave existing material intact; bootstrap will verify it via SQL.
            return
        with tempfile.TemporaryDirectory(prefix="karma-ingress-certs-") as directory:
            root = Path(directory)
            def openssl(*args):
                result = subprocess.run(["openssl", *args], cwd=root, capture_output=True, text=True, timeout=30)
                if result.returncode:
                    raise RuntimeError("certificate generation failed: " + result.stderr)
            openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.crt",
                    "-subj", "/CN=CockroachDB CA", "-days", "3650")
            names = ["localhost", self.name, self.name + "-public"]
            names += [f"{name}.{self.namespace}.svc.cluster.local" for name in (self.name, self.name + "-public")]
            names += [f"*.{self.name}.{self.namespace}.svc.cluster.local"]
            names += [f"{self.name}-{i}.{self.name}.{self.namespace}.svc.cluster.local" for i in range(3)]
            (root / "node.ext").write_text("keyUsage=critical,digitalSignature,keyEncipherment\n"
                "extendedKeyUsage=serverAuth,clientAuth\nsubjectAltName="
                + ",".join("DNS:" + host for host in names) + ",IP:127.0.0.1\n")
            for stem, subject in (("node", "node"), ("client.root", "root")):
                openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", stem + ".key", "-out", stem + ".csr",
                        "-subj", "/CN=" + subject)
                extra = ["-extfile", "node.ext"] if stem == "node" else []
                openssl("x509", "-req", "-in", stem + ".csr", "-CA", "ca.crt", "-CAkey", "ca.key",
                        "-CAcreateserial", "-out", stem + ".crt", "-days", "365", *extra)
            files = ("ca.crt", "node.crt", "node.key", "client.root.crt", "client.root.key")
            self.create({"apiVersion": "v1", "kind": "Secret", "type": "Opaque", "metadata": {
                "name": name, "namespace": self.namespace, "labels": self.labels},
                "data": {file: base64.b64encode((root / file).read_bytes()).decode() for file in files}})

    def bootstrap(self):
        # Orphan storage is inherited state, not permission to initialize a new DB.
        for kind in ("pods", "persistentvolumeclaims"):
            for item in self.get(kind)["items"]:
                labels, name = item["metadata"].get("labels", {}), item["metadata"]["name"]
                if all(labels.get(k) == v for k, v in self.labels.items()) or re.fullmatch(
                    ("datadir-" if kind == "persistentvolumeclaims" else "") + re.escape(self.name) + r"-\d+", name
                ):
                    raise RuntimeError("selected workload is absent but inherited pods/storage remain; refusing a fresh bootstrap")
        for file in ("rbac.yaml", "services.yaml"):
            for obj in self.template(file):
                existing = self.get(obj["kind"], obj["metadata"]["name"])
                if existing is None:
                    self.create(obj)
                else:
                    for field in ("rules", "roleRef", "subjects", "spec"):
                        if field in obj and field != "spec" and existing.get(field) != obj[field]:
                            raise RuntimeError("existing bootstrap RBAC is incompatible")
                    if obj["kind"] == "Service" and existing["spec"].get("selector") != obj["spec"]["selector"]:
                        raise RuntimeError("existing bootstrap Service belongs to another target")
        self.certificates()
        self.create(self.template("statefulset.yaml")[0])
        host = f"{self.name}-0.{self.name}.{self.namespace}.svc.cluster.local"
        def initialize():
            if self.sql("SELECT 1;", flag="--certs-dir=/cockroach/cockroach-certs").returncode == 0:
                return True
            return self.kubectl("exec", self.name + "-0", "--", "./cockroach", "init",
                                "--certs-dir=/cockroach/cockroach-certs", f"--host={host}", timeout=15).returncode == 0
        self.wait(initialize, 300)
        self.require(self.kubectl("rollout", "status", "statefulset/" + self.name,
                                  "--timeout=300s", timeout=305))
        self.wait(self.ready, 90)

    def recover(self):
        sts = self.get("statefulset", self.name)
        if sts is None:
            self.bootstrap()
            return
        self.identity(sts)
        for service in self.template("services.yaml"):
            if self.get("service", service["metadata"]["name"]) is None:
                selector = sts["spec"].get("selector", {}).get("matchLabels", {})
                if not selector:
                    raise UnsafeState("cannot infer missing Services' selected workload labels")
                service["spec"]["selector"] = selector
                self.create(service)
        try:
            self.wait(self.ready, 15)
            return
        except UnsafeState:
            raise
        except RuntimeError:
            pass
        # Recover unready running pods one at a time, retaining PVCs and config.
        # Credential, API, and network failures on ready pods do not justify wiping.
        for ordinal in range(int(sts["spec"].get("replicas", 1))):
            pod = self.get("pod", f"{self.name}-{ordinal}")
            if pod is None or pod["status"].get("phase") != "Running":
                continue
            ready = any(c["type"] == "Ready" and c["status"] == "True" for c in pod["status"].get("conditions", []))
            if not ready:
                if not any(r.get("uid") == sts["metadata"]["uid"] for r in pod["metadata"].get("ownerReferences", [])):
                    raise RuntimeError("unready pod belongs to another workload")
                self.require(self.kubectl("delete", "pod", pod["metadata"]["name"], "--wait=true", "--timeout=90s", timeout=95))
                try:
                    self.wait(self.ready, 120)
                    return
                except RuntimeError:
                    pass
        self.wait(self.ready, 120)

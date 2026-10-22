"""Inspect and reset only this host/target's routes on the shared controller."""
import copy
import fnmatch
import json

NGINX_NAMESPACE = "ingress-nginx"
CONTROLLER = "ingress-nginx-controller"
CONTROLLER_HOST = f"{CONTROLLER}.{NGINX_NAMESPACE}.svc"


def argument(args, flag, default=None):
    values = []
    for index, arg in enumerate(args):
        if arg.startswith(flag + "="):
            values.append(arg.split("=", 1)[1])
        elif arg == flag and index + 1 < len(args):
            values.append(args[index + 1])
    if len(set(values)) > 1:
        raise RuntimeError(f"ambiguous controller argument {flag}")
    return values[-1] if values else default


def service_backend(path):
    backend = path.get("backend", path)
    service = backend.get("service", {})
    return service.get("name", backend.get("serviceName")), service.get("port", {}).get("number",
        service.get("port", {}).get("name", backend.get("servicePort")))


class Routes:
    def __init__(self, cluster):
        self.cluster = cluster

    def controller(self):
        deployment = self.cluster.get("deployment", CONTROLLER, namespace=NGINX_NAMESPACE)
        if deployment is None:
            raise RuntimeError("ingress-nginx controller is missing")
        containers = deployment["spec"]["template"]["spec"]["containers"]
        controller = next((c for c in containers if c["name"] == "controller"), None)
        if controller is None:
            raise RuntimeError("expected ingress-nginx controller container is missing")
        return deployment, controller.get("args", [])

    def class_ready(self):
        deployment, args = self.controller()
        expected = argument(args, "--controller-class", "k8s.io/ingress-nginx")
        obj = self.cluster.get("ingressclass", self.cluster.ingress_class, namespace="")
        if obj is None or obj["spec"].get("controller") != expected:
            raise RuntimeError("requested IngressClass is missing or incompatible with the shared controller")
        watched = argument(args, "--watch-namespace")
        if watched and self.cluster.namespace not in watched.split(","):
            raise RuntimeError("shared controller does not watch the application namespace")
        if argument(args, "--watch-namespace-selector"):
            raise RuntimeError("namespace-selector controller scope requires explicit compatibility configuration")
        return deployment, args

    def tcp_config(self):
        _, args = self.controller()
        ref = argument(args, "--tcp-services-configmap", f"{NGINX_NAMESPACE}/tcp-services")
        ref = ref.replace("$(POD_NAMESPACE)", NGINX_NAMESPACE).replace("${POD_NAMESPACE}", NGINX_NAMESPACE)
        parts = ref.split("/")
        if len(parts) != 2 or not all(parts):
            raise RuntimeError("invalid TCP ConfigMap reference on shared controller")
        return parts[0], parts[1], self.cluster.get("configmap", parts[1], namespace=parts[0])

    def target_service(self, namespace, name):
        return namespace == self.cluster.namespace and name in (self.cluster.name, self.cluster.name + "-public")

    def target_mapping(self, value):
        if not isinstance(value, str):
            return False
        pieces = value.split(":")
        backend = pieces[0].split("/")
        return len(pieces) >= 2 and len(backend) == 2 and self.target_service(*backend)

    def inspect(self):
        # Validate every possible conflict before deleting any route.
        self.class_ready()
        patches = []
        for obj in self.cluster.get_all_ingresses():
            namespace = obj["metadata"]["namespace"]
            aliases = obj["metadata"].get("annotations", {}).get("nginx.ingress.kubernetes.io/server-alias", "")
            if any(fnmatch.fnmatch(self.cluster.ui_host, alias.strip()) for alias in aliases.split(",") if alias.strip()):
                raise RuntimeError("requested UI host overlaps a server-alias; explicit route ownership is required")
            updated = copy.deepcopy(obj["spec"])
            rules = []
            changed = False
            for rule in obj["spec"].get("rules", []):
                host = rule.get("host", "")
                if host != self.cluster.ui_host and not (host.startswith("*.") and fnmatch.fnmatch(self.cluster.ui_host, host)):
                    rules.append(rule)
                    continue
                paths = []
                for path in rule.get("http", {}).get("paths", []):
                    name, _ = service_backend(path)
                    if self.target_service(namespace, name):
                        if host != self.cluster.ui_host:
                            raise RuntimeError("selected UI host is covered by a wildcard route; refusing to alter other hostnames")
                        changed = True
                    else:
                        if path.get("path", "/") == "/":
                            raise RuntimeError(f"UI hostname {self.cluster.ui_host} is owned by another backend")
                        paths.append(path)
                if paths:
                    replacement = copy.deepcopy(rule)
                    replacement["http"]["paths"] = paths
                    rules.append(replacement)
            if changed:
                updated["rules"] = rules
                if not any(rule.get("host") == self.cluster.ui_host for rule in rules):
                    tls = []
                    for entry in updated.get("tls", []):
                        entry = copy.deepcopy(entry)
                        hosts = entry.get("hosts", [])
                        if self.cluster.ui_host in hosts:
                            entry["hosts"] = [host for host in hosts if host != self.cluster.ui_host]
                            if not entry["hosts"]:
                                continue
                        tls.append(entry)
                    updated["tls"] = tls
                patches.append((obj, updated))
        namespace, name, configmap = self.tcp_config()
        mapping = (configmap or {}).get("data", {}).get(self.cluster.sql_port)
        if mapping is not None and not self.target_mapping(mapping):
            raise RuntimeError(f"SQL port {self.cluster.sql_port} is owned by another backend: {mapping}")
        return patches, (namespace, name, configmap, mapping)

    def absent(self):
        patches, tcp = self.inspect()
        if patches or tcp[3] is not None:
            raise RuntimeError("selected UI or SQL route still exists")
        return True

    def reset(self):
        patches, (namespace, name, configmap, mapping) = self.inspect()
        for obj, spec in patches:
            metadata = obj["metadata"]
            # JSON Patch version tests refuse concurrent modification instead of
            # replacing a shared object's latest rules with an older snapshot.
            patch = [{"op": "test", "path": "/metadata/resourceVersion", "value": metadata["resourceVersion"]}]
            if spec.get("rules") or spec.get("defaultBackend"):
                patch.append({"op": "replace", "path": "/spec", "value": spec})
                self.cluster.require(self.cluster.kubectl("patch", "ingress", metadata["name"], "--type=json", "-p", json.dumps(patch),
                    namespace=metadata["namespace"]))
            else:
                # Delete only an entirely selected route, with UID/version
                # preconditions. Referenced certificates remain untouched.
                self.cluster.delete_object(obj)
        if mapping is not None:
            path = "/data/" + self.cluster.sql_port
            patch = [{"op": "test", "path": "/metadata/resourceVersion", "value": configmap["metadata"]["resourceVersion"]},
                     {"op": "test", "path": path, "value": mapping}, {"op": "remove", "path": path}]
            self.cluster.require(self.cluster.kubectl("patch", "configmap", name, "--type=json", "-p", json.dumps(patch), namespace=namespace))
        self.absent()

    def configured(self):
        cluster = self.cluster
        self.class_ready()
        found = False
        for obj in cluster.get_all_ingresses():
            matches = False
            effective_class = obj["spec"].get("ingressClassName", obj["metadata"].get("annotations", {}).get("kubernetes.io/ingress.class"))
            if effective_class != cluster.ingress_class or obj["metadata"]["namespace"] != cluster.namespace:
                continue
            for rule in obj["spec"].get("rules", []):
                if rule.get("host") != cluster.ui_host:
                    continue
                for path in rule.get("http", {}).get("paths", []):
                    name, port = service_backend(path)
                    if path.get("path", "/") == "/" and self.target_service(cluster.namespace, name) and str(port) in ("8080", "http"):
                        matches = True
            tls = [entry for entry in obj["spec"].get("tls", []) if cluster.ui_host in entry.get("hosts", [])]
            if matches and not any(entry.get("secretName") and cluster.get("secret", entry["secretName"]) for entry in tls):
                raise RuntimeError("UI route has no available TLS Secret for the requested hostname")
            found |= matches
        if not found:
            raise RuntimeError("UI route does not target this cluster with the requested ingress class")
        _, args = self.controller()
        if argument(args, "--tcp-services-configmap") is None:
            raise RuntimeError("controller is not configured for TCP forwarding")
        _, _, configmap = self.tcp_config()
        value = (configmap or {}).get("data", {}).get(cluster.sql_port, "")
        if not value or not self.target_mapping(value) or value.split(":")[1] not in ("26257", "grpc"):
            raise RuntimeError("SQL mapping does not target the selected cluster's SQL Service port")
        service = cluster.get("service", CONTROLLER, namespace=NGINX_NAMESPACE)
        if not service or not any(str(p["port"]) == cluster.sql_port and p.get("protocol", "TCP") == "TCP"
                                   for p in service["spec"].get("ports", [])):
            raise RuntimeError("controller Service does not expose the requested SQL port")

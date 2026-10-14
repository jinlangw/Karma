"""Owned single-pod health fault, resumable without normalizing inherited state."""
import copy
import hashlib
import json
import re
import shlex

from cluster import FAULT_MARKER, SERVER_MARKER, Cluster, UnsafeState, arguments, database_container, flag_value, health_probes, pod_ready, shell_body

POD_VARIABLE = "KARMA_HEALTH_PROBE_POD_NAME"
HTTP_VARIABLE = "KARMA_HEALTH_PROBE_HTTP_ADDR"


def signature(secret):
    return {"uid": secret["metadata"]["uid"], "data_sha256": hashlib.sha256(json.dumps(secret.get("data", {}), sort_keys=True).encode()).hexdigest()}


def secret_names(template):
    spec = template["spec"]
    names = set()
    for volume in spec.get("volumes", []):
        if "secret" in volume:
            names.add(volume["secret"]["secretName"])
        names |= {s["secret"]["name"] for s in volume.get("projected", {}).get("sources", []) if "secret" in s}
    for container in spec.get("containers", []) + spec.get("initContainers", []):
        names |= {e["valueFrom"]["secretKeyRef"]["name"] for e in container.get("env", []) if "secretKeyRef" in e.get("valueFrom", {})}
        names |= {e["secretRef"]["name"] for e in container.get("envFrom", []) if "secretRef" in e}
    return names


def serving_secrets(cluster, template):
    return {name: signature(secret) if (secret := cluster.get("secret", name)) else None for name in sorted(secret_names(template))}


def fault_template(template, target):
    result = copy.deepcopy(template)
    container = database_container(result)
    if any(e["name"] in (POD_VARIABLE, HTTP_VARIABLE) for e in container.get("env", [])):
        raise UnsafeState("health fault environment names are already occupied")
    tokens = arguments(container)
    if any(FAULT_MARKER.strip() in part for part in container.get("command", [])):
        raise UnsafeState("existing fault wrapper requires its owned baseline")
    address = flag_value(container, "--http-addr", "0.0.0.0:8080")
    probes = health_probes(container)
    if not re.fullmatch(r"(?:[a-zA-Z0-9.-]*|\[[0-9a-fA-F:]+\]):[0-9]+", address) or int(address.rsplit(":", 1)[1]) != probes[0]["port"]:
        raise UnsafeState("cannot safely identify the health listener address")
    port = probes[0]["port"]
    variable = '"${' + HTTP_VARIABLE + '}"'
    def without_http(parts):
        remaining = []
        index = 0
        while index < len(parts):
            if parts[index] == "--http-addr":
                index += 2
            elif parts[index].startswith("--http-addr="):
                index += 1
            else:
                remaining.append(parts[index]); index += 1
        return remaining
    body = shell_body(container)
    if body is not None:
        pattern = r'''(?<!\S)--http-addr(?:=(?:'[^']*'|"[^"]*"|\S+)|\s+(?:'[^']*'|"[^"]*"|\S+))(?=\s|$)'''
        updated, count = re.subn(pattern, lambda _: "--http-addr=" + variable, body)
        if count == 0:
            if any(t.startswith("--http-addr") for t in container.get("args", [])):
                raise UnsafeState("health flag in shell positional arguments cannot be rewritten safely")
            updated = body.rstrip() + " --http-addr=" + variable
        if count > 1 or without_http(shlex.split(updated)) != without_http(shlex.split(body)):
            raise UnsafeState("cannot preserve unrelated shell startup arguments")
    else:
        updated = "exec " + " ".join(shlex.quote(t) for t in without_http(tokens)) + " --http-addr=" + variable
        container.pop("args", None)
        container["command"] = ["/bin/sh", "-ec", ""]
    prefix = (FAULT_MARKER + f'if [ "${{{POD_VARIABLE}}}" = "{target}" ]; then\n'
              + f"  {HTTP_VARIABLE}=127.0.0.1:{port}\nelse\n  {HTTP_VARIABLE}=" + shlex.quote(address) + "\nfi\n" + SERVER_MARKER)
    container["command"][2] = prefix + updated
    container.setdefault("env", []).append({"name": POD_VARIABLE, "valueFrom": {"fieldRef": {"apiVersion": "v1", "fieldPath": "metadata.name"}}})
    return result


class Fault:
    def __init__(self, cluster):
        self.cluster = cluster
        self.target = cluster.name + "-1"
        self.baseline_name = cluster.name + "-health-recovery-baseline"

    def load(self):
        cluster = self.cluster
        baseline = cluster.get("configmap", self.baseline_name)
        if baseline is None:
            return None
        labels = baseline["metadata"].get("labels", {})
        if labels.get("karma.dev/fixture") != "health-recovery-baseline" or labels.get("app.kubernetes.io/instance") != cluster.name:
            raise UnsafeState("health baseline name belongs to another resource")
        data = baseline["data"]
        if data["statefulset_uid"] != cluster.statefulset()["metadata"]["uid"]:
            raise UnsafeState("health baseline belongs to another database incarnation")
        return baseline

    def configured(self, baseline, sts):
        return bool(baseline and sts["spec"]["template"] == json.loads(baseline["data"]["fault_template"])
                    and sts["spec"].get("updateStrategy") == {"type": "OnDelete"})

    def preserved(self, baseline, sts):
        cluster = self.cluster
        data = baseline["data"]
        if int(sts["spec"].get("replicas", 1)) != int(data["replicas"]):
            raise UnsafeState("health task must preserve the starting replica count")
        if cluster.cluster_id() != data["cluster_id"]:
            raise UnsafeState("database identity changed during the health task")
        if cluster.connection_flag() != data["connection_flag"]:
            raise UnsafeState("database security mode changed during the health task")
        # Storage and PKI survive restarts; no private material is logged.
        if cluster.pvc_identity(sts) != json.loads(data["pvc_uids"]):
            raise UnsafeState("database persistent storage changed during the health task")
        if serving_secrets(cluster, json.loads(data["original_template"])) != json.loads(data["secret_signatures"]):
            raise UnsafeState("inherited Secret material changed during the health task")

    def environment_ready(self):
        cluster = self.cluster
        sts = cluster.statefulset()
        baseline = self.load()
        if self.configured(baseline, sts):
            # A retry can see this case's intentional unhealthy target. Its
            # peers must still work; readiness must not undo or rebuild it.
            self.preserved(baseline, sts)
            cluster.ready(omit=(1,), functional_health=True)
            return True
        if any(FAULT_MARKER.strip() in part for part in database_container(sts["spec"]["template"]).get("command", [])):
            raise UnsafeState("unrecognized health fault or concurrently changed restart strategy")
        return cluster.ready(functional_health=True)

    def active(self):
        cluster = self.cluster
        sts = cluster.statefulset()
        baseline = self.load()
        if not self.configured(baseline, sts):
            raise RuntimeError("selected workload does not have this case's health fault")
        self.preserved(baseline, sts)
        cluster.ready(omit=(1,), functional_health=True)
        pod = cluster.pods(sts)[1]
        if pod.get("status", {}).get("phase") != "Running" or not pod.get("status", {}).get("podIP"):
            raise RuntimeError("fault target is still starting")
        expected = database_container(json.loads(baseline["data"]["fault_template"]))
        actual = database_container({"spec": pod["spec"]})
        if actual.get("command") != expected["command"] or actual.get("args", []) != expected.get("args", []) or actual.get("env", []) != expected.get("env", []):
            raise RuntimeError("target has not restarted with the health fault")
        if pod["metadata"]["uid"] == json.loads(baseline["data"]["pod_uids"])[self.target] or pod_ready(pod):
            raise RuntimeError("target has not become unready after injection")
        for probe in health_probes(actual):
            result = cluster.health_request(pod, probe)
            if result.returncode == 0:
                raise RuntimeError("faulted health endpoint is still reachable")
            if not re.search(r"curl: \((7|28)\)", result.stderr):
                raise RuntimeError("health request failed for a reason other than the planted listener fault: " + result.stderr.strip())
        return True

    def preflight(self, sts):
        cluster = self.cluster
        if int(sts["spec"].get("replicas", 1)) < 3:
            raise UnsafeState("single-pod health injection requires at least three healthy nodes")
        if sts["spec"].get("updateStrategy", {}).get("type", "RollingUpdate") not in ("RollingUpdate", "OnDelete"):
            raise UnsafeState("unsupported inherited StatefulSet update strategy")
        cluster.durable(sts)
        cluster.ready(functional_health=True)
        container = database_container(sts["spec"]["template"])
        probes = health_probes(container)
        flag = cluster.connection_flag()
        if probes[0]["scheme"] != ("http" if flag == "--insecure" else "https"):
            raise UnsafeState("health probe protocol does not match actual SQL security mode")
        if flag != "--insecure":
            directory = flag.split("=", 1)[1]
            mounts = sorted((m for m in container.get("volumeMounts", []) if directory == m["mountPath"].rstrip("/") or directory.startswith(m["mountPath"].rstrip("/") + "/")),
                            key=lambda m: len(m["mountPath"]), reverse=True)
            volumes = {v["name"]: v for v in sts["spec"]["template"]["spec"].get("volumes", [])}
            claims = {v["metadata"]["name"] for v in sts["spec"].get("volumeClaimTemplates", [])}
            if not mounts or not (mounts[0]["name"] in claims or any(k in volumes.get(mounts[0]["name"], {}) for k in ("secret", "projected", "persistentVolumeClaim"))):
                raise UnsafeState("TLS restart requires persistent or Secret-backed certificate material")
        return fault_template(sts["spec"]["template"], self.target)

    def record(self, baseline, sts, updated):
        cluster = self.cluster
        data = {"statefulset_uid": sts["metadata"]["uid"], "cluster_id": cluster.cluster_id(),
                "replicas": str(sts["spec"].get("replicas", 1)), "connection_flag": cluster.connection_flag(),
                "original_template": json.dumps(sts["spec"]["template"], sort_keys=True),
                "original_update_strategy": json.dumps(sts["spec"].get("updateStrategy", {"type": "RollingUpdate"}), sort_keys=True),
                "fault_template": json.dumps(updated, sort_keys=True), "pvc_uids": json.dumps(cluster.pvc_identity(sts), sort_keys=True),
                "secret_signatures": json.dumps(serving_secrets(cluster, sts["spec"]["template"]), sort_keys=True),
                "pod_uids": json.dumps({p["metadata"]["name"]: p["metadata"]["uid"] for p in cluster.pods(sts)}, sort_keys=True)}
        if baseline is None:
            cluster.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": self.baseline_name,
                "namespace": cluster.namespace, "labels": {**cluster.labels, "karma.dev/fixture": "health-recovery-baseline"}}, "data": data})
        else:
            if data["cluster_id"] != baseline["data"]["cluster_id"]:
                raise UnsafeState("database identity no longer matches the existing baseline")
            patch = [{"op": "test", "path": "/metadata/uid", "value": baseline["metadata"]["uid"]},
                     {"op": "test", "path": "/metadata/resourceVersion", "value": baseline["metadata"]["resourceVersion"]},
                     {"op": "replace", "path": "/data", "value": data}]
            cluster.require(cluster.kubectl("patch", "configmap", self.baseline_name, "--type=json", "-p", json.dumps(patch)))
        return cluster.get("configmap", self.baseline_name)

    def apply(self):
        cluster = self.cluster
        sts = cluster.statefulset()
        baseline = self.load()
        if not self.configured(baseline, sts):
            updated = self.preflight(sts)  # Every safety check precedes mutation.
            baseline = self.record(baseline, sts, updated)
            cluster.patch_spec(sts, {"template": updated, "updateStrategy": {"type": "OnDelete"}})
        else:
            self.environment_ready()
        # OnDelete remains in force throughout the task: restoring RollingUpdate
        # while the fault template is active would also roll healthy peer pods.
        pod = cluster.get("pod", self.target)
        if pod:
            expected = database_container(json.loads(baseline["data"]["fault_template"]))
            actual = database_container({"spec": pod["spec"]})
            if actual.get("command") != expected["command"] or actual.get("args", []) != expected.get("args", []) or actual.get("env", []) != expected.get("env", []):
                if not any(ref.get("uid") == sts["metadata"]["uid"] for ref in pod["metadata"].get("ownerReferences", [])):
                    raise UnsafeState("fault target belongs to another workload")
                cluster.delete_pod(pod)
        cluster.flag = None
        cluster.wait(self.active, 180)

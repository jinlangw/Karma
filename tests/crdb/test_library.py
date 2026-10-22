from __future__ import annotations

import copy
import contextlib
from dataclasses import replace
import hashlib
import io
import json
import subprocess
import tempfile
import traceback
import unittest
from typing import Any
from unittest.mock import patch

from cases.common.cockroachdb import CrdbLibrary, HTTPTransport, KubectlAdapter, Lifecycle, ProbeStatus, Requirement, TLSMode, WorkloadRef
from cases.common.cockroachdb.adapter import HttpHealthResponse
from cases.common.cockroachdb.types import (
    AuthenticationError,
    ConnectionError,
    ErrorCode,
    InvalidRequirementError,
    KubernetesAccessError,
    PreservationMismatchError,
    RolloutInProgressError,
    StaleIdentityError,
    TransientError,
    UninitializedError,
    UnsupportedLayoutError,
)


_CLUSTER_ID = "a2506905-9598-4967-92a5-1e45668f9c67"


def fixture_resources(*, tls: bool = False, replicas: int = 2, custom_ports: bool = True):
    namespace, name, uid, service = "crdb-fixture", "db", "sts-db-uid", "db"
    labels = {"app": "cockroach", "instance": name}
    sql_port = 26270 if custom_ports else 26257
    rpc_port = 26300 if custom_ports else 26257
    http_port = 8082 if custom_ports else 8080
    command_script = " ".join(
        [
            "exec /cockroach/cockroach start",
            f"--advertise-host=$(POD_NAME).{service}.$(POD_NAMESPACE).svc.cluster.local",
            f"--sql-addr=0.0.0.0:{sql_port}",
            f"--listen-addr=0.0.0.0:{rpc_port}",
            f"--http-addr=0.0.0.0:{http_port}",
            f"--port={sql_port}",
            f"--join={name}-0.{service}.$(POD_NAMESPACE).svc.cluster.local:{sql_port},{name}-1.{service}.$(POD_NAMESPACE).svc.cluster.local:{sql_port}",
            "--certs-dir=/cockroach/cockroach-certs" if tls else "--insecure",
        ]
    )
    container = {
        "name": "db",
        "image": "cockroachdb/cockroach:v24.1.4",
        "command": ["/bin/bash", "-ec", command_script],
        "env": [
            {"name": "POD_NAME", "valueFrom": {"fieldRef": {"fieldPath": "metadata.name"}}},
            {"name": "POD_NAMESPACE", "valueFrom": {"fieldRef": {"fieldPath": "metadata.namespace"}}},
        ],
        "ports": [
            {"name": "sql", "containerPort": sql_port, "protocol": "TCP"},
            {"name": "grpc", "containerPort": rpc_port, "protocol": "TCP"},
            {"name": "http", "containerPort": http_port, "protocol": "TCP"},
        ],
        "volumeMounts": [{"name": "data", "mountPath": "/cockroach/cockroach-data"}],
        "resources": {"requests": {"cpu": "100m", "memory": "256Mi"}},
        "livenessProbe": {
            "httpGet": {"path": "/healthz", "port": "http", "scheme": "HTTP"},
            "initialDelaySeconds": 17,
            "periodSeconds": 9,
            "timeoutSeconds": 4,
            "failureThreshold": 5,
        },
        "readinessProbe": {
            "tcpSocket": {"port": "sql"},
            "initialDelaySeconds": 8,
            "periodSeconds": 4,
            "timeoutSeconds": 4,
            "failureThreshold": 3,
        },
    }
    volumes = []
    secrets = {}
    if tls:
        container["volumeMounts"].append(
            {"name": "certs", "mountPath": "/cockroach/cockroach-certs", "readOnly": True}
        )
        volumes.append({"name": "certs", "secret": {"secretName": "db-certs"}})
        secrets["db-certs"] = {
            "metadata": {"name": "db-certs", "uid": "secret-uid", "resourceVersion": "31"},
            "data": {
                key: hashlib.sha256(key.encode()).hexdigest()
                for key in ("ca.crt", "node.crt", "node.key", "client.root.crt", "client.root.key")
            },
        }
    template_spec = {"containers": [container], "volumes": volumes}
    spec = {
        "serviceName": service,
        "replicas": replicas,
        "selector": {"matchLabels": labels},
        "template": {"metadata": {"labels": labels}, "spec": template_spec},
        "volumeClaimTemplates": [{"metadata": {"name": "data"}, "spec": {"resources": {"requests": {"storage": "1Gi"}}}}],
        "updateStrategy": {"type": "RollingUpdate", "rollingUpdate": {"partition": 0}},
    }
    sts = {
        "metadata": {
            "name": name,
            "namespace": namespace,
            "uid": uid,
            "resourceVersion": "10",
            "generation": 1,
            "ownerReferences": [],
        },
        "spec": spec,
        "status": {
            "observedGeneration": 1,
            "readyReplicas": replicas,
            "updatedReplicas": replicas,
            "currentRevision": "rev1",
            "updateRevision": "rev1",
        },
    }
    pods = []
    pvcs = []
    for ordinal in range(replicas):
        pod_name = f"{name}-{ordinal}"
        pod_spec = copy.deepcopy(template_spec)
        pod_spec["volumes"].append(
            {"name": "data", "persistentVolumeClaim": {"claimName": f"data-{name}-{ordinal}"}}
        )
        pods.append(
            {
                "metadata": {
                    "name": pod_name,
                    "namespace": namespace,
                    "uid": f"pod-{ordinal}",
                    "labels": {**labels, "controller-revision-hash": "rev1"},
                    "ownerReferences": [{"uid": uid, "controller": True}],
                },
                "spec": pod_spec,
                "status": {
                    "phase": "Running",
                    "containerStatuses": [{"name": "db", "ready": True, "state": {"running": {}}}],
                    "conditions": [{"type": "Ready", "status": "True"}],
                },
            }
        )
        pvcs.append(
            {
                "metadata": {
                    "name": f"data-{name}-{ordinal}",
                    "namespace": namespace,
                    "uid": f"pvc-{ordinal}",
                    "resourceVersion": "8",
                },
                "spec": {"volumeName": f"pv-{ordinal}"},
                "status": {"phase": "Bound"},
            }
        )
    services = [
        {
            "metadata": {"name": "db", "namespace": namespace, "uid": "svc-headless", "resourceVersion": "3"},
            "spec": {
                "clusterIP": "None",
                "selector": labels,
                "ports": [
                    {"name": "sql", "port": sql_port, "targetPort": "sql"},
                    {"name": "grpc", "port": rpc_port, "targetPort": "grpc"},
                ],
            },
        },
        {
            "metadata": {"name": "db-client", "namespace": namespace, "uid": "svc-client", "resourceVersion": "4"},
            "spec": {"clusterIP": "10.0.0.9", "selector": labels, "ports": [{"name": "sql", "port": sql_port, "targetPort": "sql"}]},
        },
    ]
    return namespace, name, sts, pods, services, pvcs, secrets


def add_standard_service_account_projection(pod, suffix: str):
    name = "kube-api-access-" + suffix
    pod["spec"]["containers"][0]["volumeMounts"].append(
        {
            "name": name,
            "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount",
            "readOnly": True,
        }
    )
    pod["spec"]["volumes"].append(
        {
            "name": name,
            "projected": {
                "defaultMode": 420,
                "sources": [
                    {"serviceAccountToken": {"expirationSeconds": 3607, "path": "token"}},
                    {"configMap": {"name": "kube-root-ca.crt", "items": [{"key": "ca.crt", "path": "ca.crt"}]}},
                    {"downwardAPI": {"items": [{"path": "namespace", "fieldRef": {"apiVersion": "v1", "fieldPath": "metadata.namespace"}}]}},
                ],
            },
        }
    )


class MemoryAdapter:
    def __init__(self, *, tls: bool = False, replicas: int = 2, custom_ports: bool = True, initialized: bool = True):
        self.namespace, self.name, self.sts, self.pods, self.services, self.pvcs, self.secrets = fixture_resources(
            tls=tls, replicas=replicas, custom_ports=custom_ports
        )
        self.initialized = initialized
        self.query_error: Exception | None = None
        self.http_status = {"/health": 200, "/health?ready=1": 200}
        self.http_body = {"/health": "ignored", "/health?ready=1": "ignored"}
        self.http_calls: list[dict[str, Any]] = []
        self.http_error: Exception | None = None
        self.patch_calls: list[list[dict[str, Any]]] = []
        self.get_count = 0
        self.pod_get_count = 0
        self.pod_get_error: Exception | None = None
        self.list_calls: list[str] = []
        self.replace_sts_uid_on_second_read: str | None = None
        self.replace_pod_uid_on_second_read: str | None = None
        self.fingerprint_calls: list[str] = []
        self.fingerprint_error: Exception | None = None
        self.select_one_error: Exception | None = None
        self.queried_sql_hosts: list[str] = []
        self.node_status_calls: list[dict[str, Any]] = []
        self.liveness_query_calls: list[dict[str, Any]] = []
        self.node_status_output = (
            "id,is_available,ranges_unavailable,ranges_underreplicated\n"
            "1,true,0,0\n"
            "2,true,0,0\n"
        )
        self.server_versions = ["CockroachDB CCL v24.1.4"] * replicas
        self.query_sql_calls: list[dict[str, Any]] = []
        self.native_identity_calls: list[dict[str, Any]] = []
        self.native_identity_error: Exception | None = None
        self.node_liveness_output = (
            "node_id,membership,draining,is_live\n"
            "1,active,false,true\n"
            "2,active,false,true\n"
        )
        self.node_status_error: Exception | None = None
        self.node_status_transient_once = False
        self.mutate_before_second_sts_read = False
        self.rollout_once = False
        self.transient_query_once = False
        self.pending_pod_set_once = False

    def get_resource(self, kind: str, namespace: str, name: str):
        if namespace != self.namespace:
            return None
        if kind == "statefulset" and name == self.name:
            self.get_count += 1
            if self.get_count == 2 and self.replace_sts_uid_on_second_read:
                self.sts["metadata"]["uid"] = self.replace_sts_uid_on_second_read
            if self.mutate_before_second_sts_read and self.get_count == 2:
                self.sts["metadata"]["resourceVersion"] = "stale"
            if self.rollout_once:
                self.rollout_once = False
                self.sts["status"]["observedGeneration"] = 0
            elif self.sts["status"]["observedGeneration"] < self.sts["metadata"]["generation"]:
                self.sts["status"]["observedGeneration"] = self.sts["metadata"]["generation"]
            return copy.deepcopy(self.sts)
        if kind == "pod" and name.startswith(f"{self.name}-"):
            self.pod_get_count += 1
            if self.pod_get_error is not None:
                raise self.pod_get_error
            pod = next((item for item in self.pods if item["metadata"].get("name") == name), None)
            if pod is None:
                return None
            if self.pod_get_count == 2 and self.replace_pod_uid_on_second_read:
                pod["metadata"]["uid"] = self.replace_pod_uid_on_second_read
            return copy.deepcopy(pod)
        return None

    def list_resources(self, kind: str, namespace: str):
        self.list_calls.append(kind)
        if kind == "pod" and self.pending_pod_set_once:
            self.pending_pod_set_once = False
            return self.pods[1:]
        return {
            "pod": self.pods,
            "service": self.services,
            "pvc": self.pvcs,
        }.get(kind, ())

    def secret_fingerprint(self, namespace: str, name: str):
        from cases.common.cockroachdb.types import SecretFingerprint, MissingResourceError

        self.fingerprint_calls.append(name)
        if self.fingerprint_error is not None:
            raise self.fingerprint_error
        secret = self.secrets.get(name)
        if secret is None:
            raise MissingResourceError("missing test Secret")
        return SecretFingerprint(
            name=name,
            uid=secret["metadata"]["uid"],
            resource_version=secret["metadata"]["resourceVersion"],
            keys=tuple(sorted(secret["data"])),
            sha256_by_key=tuple(
                sorted((key, hashlib.sha256(value.encode()).hexdigest()) for key, value in secret["data"].items())
            ),
        )

    def query_sql(self, **kwargs):
        if kwargs["sql"] != "SELECT version() AS version;":
            self.queried_sql_hosts.append(kwargs["sql_host"])
        self.query_sql_calls.append(copy.deepcopy(kwargs))
        if kwargs["sql"] == "SELECT 1;":
            if self.select_one_error is not None:
                raise self.select_one_error
            return "1\n"
        if "crdb_internal.kv_node_liveness" in kwargs["sql"]:
            self.liveness_query_calls.append(copy.deepcopy(kwargs))
            return self.node_liveness_output
        if self.transient_query_once:
            self.transient_query_once = False
            raise TransientError("test node is rolling")
        if self.query_error:
            raise self.query_error
        if not self.initialized:
            raise UninitializedError("test node is not initialized")
        ordinal = int(kwargs["pod_name"].rsplit("-", 1)[1])
        if kwargs["sql"] == "SELECT version() AS version;":
            version = self.server_versions[min(ordinal, len(self.server_versions) - 1)]
            return f'version\n"{version}"\n'
        version = self.server_versions[min(ordinal, len(self.server_versions) - 1)].split()[-1]
        return f"cluster_id,node_id,version\n{_CLUSTER_ID},{ordinal + 1},{version}\n"

    def native_identity(self, **kwargs):
        self.native_identity_calls.append(copy.deepcopy(kwargs))
        if self.native_identity_error:
            raise self.native_identity_error
        ordinal = int(kwargs["pod_name"].rsplit("-", 1)[1])
        return ordinal + 1, _CLUSTER_ID

    def node_status(self, **kwargs):
        self.node_status_calls.append(copy.deepcopy(kwargs))
        if self.node_status_transient_once:
            self.node_status_transient_once = False
            raise TransientError("test SQL connection is being restarted")
        if self.node_status_error:
            raise self.node_status_error
        return self.node_status_output

    def health_http(self, **kwargs):
        self.http_calls.append(copy.deepcopy(kwargs))
        if self.http_error:
            raise self.http_error
        return HttpHealthResponse(
            status=self.http_status[kwargs["path"]], body=self.http_body[kwargs["path"]]
        )

    def patch_statefulset_json(self, *, namespace, name, uid, resource_version, operations, timeout):
        if self.sts["metadata"]["uid"] != uid or self.sts["metadata"]["resourceVersion"] != resource_version:
            raise StaleIdentityError("fake identity mismatch")
        if operations[0]["op"] != "test" or operations[1]["op"] != "test":
            raise StaleIdentityError("missing fake guards")
        self.patch_calls.append(copy.deepcopy(list(operations)))
        for operation in operations[2:]:
            pointer = [part.replace("~1", "/").replace("~0", "~") for part in operation["path"].lstrip("/").split("/")]
            target: Any = self.sts
            for part in pointer[:-1]:
                target = target[int(part)] if isinstance(target, list) else target[part]
            key = pointer[-1]
            if operation["op"] == "remove":
                if isinstance(target, list):
                    target.pop(int(key))
                else:
                    del target[key]
            elif operation["op"] == "add":
                target[key] = copy.deepcopy(operation["value"])
            else:
                raise AssertionError(f"unexpected JSON Patch op {operation['op']}")
        self.sts["metadata"]["resourceVersion"] = "11"
        self.sts["metadata"]["generation"] = 2
        self.sts["status"].update({"observedGeneration": 2, "currentRevision": "rev2", "updateRevision": "rev2"})
        for pod in self.pods:
            pod["spec"]["containers"] = copy.deepcopy(self.sts["spec"]["template"]["spec"]["containers"])
            pod["metadata"]["labels"]["controller-revision-hash"] = "rev2"
        return copy.deepcopy(self.sts)


class LibraryTests(unittest.TestCase):
    def test_gateway_connection_uses_selected_live_pod_without_peer_or_service_gate(self):
        adapter = MemoryAdapter(tls=True, replicas=3)
        adapter.pods = adapter.pods[:1]
        adapter.services = []
        adapter.pvcs = []
        desired_container = adapter.sts["spec"]["template"]["spec"]["containers"][0]
        desired_container["command"][2] = desired_container["command"][2].replace(
            "--sql-addr=0.0.0.0:26270", "--sql-addr=0.0.0.0:26271"
        )
        desired_container["ports"][0]["containerPort"] = 26271
        adapter.sts["metadata"]["generation"] = 2
        adapter.sts["status"]["observedGeneration"] = 1

        connection = CrdbLibrary(adapter).inspect_sql_connection(
            WorkloadRef(adapter.namespace, adapter.name), ordinal=0
        )

        self.assertEqual(connection.workload_uid, "sts-db-uid")
        self.assertEqual((connection.pod_name, connection.pod_uid), ("db-0", "pod-0"))
        self.assertEqual(connection.container_name, "db")
        self.assertEqual(connection.image, "cockroachdb/cockroach:v24.1.4")
        self.assertEqual(connection.sql_binary, "/cockroach/cockroach")
        self.assertEqual(connection.sql_host, "db-0.db.crdb-fixture.svc.cluster.local")
        self.assertEqual((connection.sql_port, connection.rpc_port), (26270, 26300))
        self.assertEqual(connection.tls_mode, TLSMode.TLS)
        self.assertEqual(connection.certs_dir, "/cockroach/cockroach-certs")
        self.assertEqual(adapter.list_calls, [])
        self.assertEqual(adapter.fingerprint_calls, [])
        self.assertEqual(
            adapter.query_sql(
                namespace=connection.namespace,
                pod_name=connection.pod_name,
                container_name=connection.container_name,
                binary=connection.sql_binary,
                sql_host=connection.sql_host,
                sql_port=connection.sql_port,
                tls_mode=connection.tls_mode.value,
                certs_dir=connection.certs_dir,
                sql="SELECT 1;",
                timeout=5,
            ),
            "1\n",
        )
        self.assertEqual(len(adapter.query_sql_calls), 1)

    def test_gateway_connection_uses_live_tls_mode_and_custom_ports(self):
        for tls in (False, True):
            with self.subTest(tls=tls):
                adapter = MemoryAdapter(tls=tls, replicas=1, custom_ports=True)
                connection = CrdbLibrary(adapter).inspect_sql_connection(
                    WorkloadRef(adapter.namespace, adapter.name)
                )
                self.assertEqual(connection.tls_mode, TLSMode.TLS if tls else TLSMode.INSECURE)
                self.assertEqual(connection.certs_dir, "/cockroach/cockroach-certs" if tls else None)
                self.assertEqual((connection.sql_port, connection.rpc_port), (26270, 26300))

    def test_gateway_connection_falls_back_to_listen_addr_for_sql_port(self):
        adapter = MemoryAdapter(tls=False, replicas=1, custom_ports=True)
        pod_container = adapter.pods[0]["spec"]["containers"][0]
        script = pod_container["command"][2]
        pod_container["command"][2] = " ".join(
            token for token in script.split() if not token.startswith(("--sql-addr=", "--port="))
        )

        connection = CrdbLibrary(adapter).inspect_sql_connection(
            WorkloadRef(adapter.namespace, adapter.name)
        )

        self.assertEqual(connection.sql_port, 26300)

    def test_inspector_resolves_relative_certificate_directory_against_working_dir(self):
        adapter = MemoryAdapter(tls=True, replicas=1)
        template_container = adapter.sts["spec"]["template"]["spec"]["containers"][0]
        template_container["command"][2] = template_container["command"][2].replace(
            "--certs-dir=/cockroach/cockroach-certs", "--certs-dir=certificates"
        )
        script = template_container["command"][2]
        template_container["command"] = ["/bin/sh", "-e", "-c", script]
        template_container["workingDir"] = "/work/db"
        template_container["volumeMounts"][1]["mountPath"] = "/work/db/certificates"
        for pod in adapter.pods:
            container = pod["spec"]["containers"][0]
            container["command"] = copy.deepcopy(template_container["command"])
            container["workingDir"] = "/work/db"
            container["volumeMounts"][1]["mountPath"] = "/work/db/certificates"

        observation = CrdbLibrary(adapter).inspect(WorkloadRef(adapter.namespace, adapter.name))

        self.assertEqual(observation.tls_mode, TLSMode.TLS)
        self.assertEqual(observation.certs_dir, "/work/db/certificates")
        self.assertEqual(adapter.fingerprint_calls, ["db-certs"])

    def test_inspector_resolves_implicit_home_and_official_root_certificate_directories(self):
        for home, expected in (("/var/lib/cockroach", "/var/lib/cockroach/.cockroach-certs"), (None, "/root/.cockroach-certs")):
            with self.subTest(home=home):
                adapter = MemoryAdapter(tls=True, replicas=1)
                template_container = adapter.sts["spec"]["template"]["spec"]["containers"][0]
                template_container["command"][2] = template_container["command"][2].replace(
                    " --certs-dir=/cockroach/cockroach-certs", ""
                )
                template_container["volumeMounts"][1]["mountPath"] = expected
                if home is not None:
                    template_container["env"].append({"name": "HOME", "value": home})
                for pod in adapter.pods:
                    container = pod["spec"]["containers"][0]
                    container["command"] = copy.deepcopy(template_container["command"])
                    container["volumeMounts"][1]["mountPath"] = expected
                    container["env"] = copy.deepcopy(template_container["env"])

                observation = CrdbLibrary(adapter).inspect(WorkloadRef(adapter.namespace, adapter.name))

                self.assertEqual(observation.tls_mode, TLSMode.TLS)
                self.assertEqual(observation.certs_dir, expected)
                self.assertEqual(adapter.fingerprint_calls, ["db-certs"])

    def test_sql_only_certificate_resolution_does_not_fetch_secret_material(self):
        adapter = MemoryAdapter(tls=True, replicas=1)
        template_container = adapter.sts["spec"]["template"]["spec"]["containers"][0]
        template_container["command"][2] = template_container["command"][2].replace(
            " --certs-dir=/cockroach/cockroach-certs", ""
        )
        template_container["volumeMounts"][1]["mountPath"] = "/root/.cockroach-certs"
        for pod in adapter.pods:
            container = pod["spec"]["containers"][0]
            container["command"] = copy.deepcopy(template_container["command"])
            container["volumeMounts"][1]["mountPath"] = "/root/.cockroach-certs"

        connection = CrdbLibrary(adapter).inspect_sql_connection(
            WorkloadRef(adapter.namespace, adapter.name)
        )

        self.assertEqual(connection.tls_mode, TLSMode.TLS)
        self.assertEqual(connection.certs_dir, "/root/.cockroach-certs")
        self.assertEqual(adapter.fingerprint_calls, [])

    def test_inspector_rejects_unresolved_default_certificate_directory_without_secret_reads(self):
        for run_as_user, env_from in ((1000, False), (None, True)):
            with self.subTest(run_as_user=run_as_user, env_from=env_from):
                adapter = MemoryAdapter(tls=True, replicas=1)
                template_spec = adapter.sts["spec"]["template"]["spec"]
                container = template_spec["containers"][0]
                container["command"][2] = container["command"][2].replace(
                    " --certs-dir=/cockroach/cockroach-certs", ""
                )
                if env_from:
                    container["envFrom"] = [{"configMapRef": {"name": "startup-env"}}]
                elif run_as_user is not None:
                    template_spec["securityContext"] = {"runAsUser": run_as_user}
                for pod in adapter.pods:
                    pod_container = pod["spec"]["containers"][0]
                    pod_container["command"] = copy.deepcopy(container["command"])
                    if env_from:
                        pod_container["envFrom"] = copy.deepcopy(container["envFrom"])
                    elif run_as_user is not None:
                        pod["spec"]["securityContext"] = {"runAsUser": run_as_user}

                with self.assertRaises(UnsupportedLayoutError):
                    CrdbLibrary(adapter).inspect(WorkloadRef(adapter.namespace, adapter.name))
                self.assertEqual(adapter.fingerprint_calls, [])

    def test_gateway_connection_observes_rpc_and_sql_advertisements_independently(self):
        for rpc_service, sql_service in (("db", "db"), ("rpc", "sql")):
            with self.subTest(rpc_service=rpc_service, sql_service=sql_service):
                adapter = MemoryAdapter(tls=True, replicas=1)
                container = adapter.sts["spec"]["template"]["spec"]["containers"][0]
                container["command"][2] = container["command"][2].replace(
                    "--advertise-host=$(POD_NAME).db.$(POD_NAMESPACE).svc.cluster.local",
                    f"--advertise-addr=$(POD_NAME).{rpc_service}.$(POD_NAMESPACE).svc.cluster.local:26300 "
                    f"--advertise-sql-addr=$(POD_NAME).{sql_service}.$(POD_NAMESPACE).svc.cluster.local:26270",
                )
                for pod in adapter.pods:
                    pod["spec"]["containers"][0]["command"] = copy.deepcopy(container["command"])

                connection = CrdbLibrary(adapter).inspect_sql_connection(
                    WorkloadRef(adapter.namespace, adapter.name), ordinal=0
                )

                self.assertEqual(connection.sql_host, f"db-0.{sql_service}.crdb-fixture.svc.cluster.local")
                self.assertEqual(connection.rpc_host, f"db-0.{rpc_service}.crdb-fixture.svc.cluster.local")
                self.assertEqual((connection.sql_port, connection.rpc_port), (26270, 26300))

        # Do not pair an advertised RPC host with a listener port when the
        # startup configuration explicitly advertises a different port.
        adapter = MemoryAdapter(tls=True, replicas=1)
        container = adapter.sts["spec"]["template"]["spec"]["containers"][0]
        container["command"][2] = container["command"][2].replace(
            "--advertise-host=$(POD_NAME).db.$(POD_NAMESPACE).svc.cluster.local",
            "--advertise-addr=$(POD_NAME).rpc.$(POD_NAMESPACE).svc.cluster.local:26301",
        )
        for pod in adapter.pods:
            pod["spec"]["containers"][0]["command"] = copy.deepcopy(container["command"])
        connection = CrdbLibrary(adapter).inspect_sql_connection(
            WorkloadRef(adapter.namespace, adapter.name), ordinal=0
        )
        self.assertIsNone(connection.rpc_host)

        # A separate SQL advertise address must not make SQL-only inspection
        # fail when the startup configuration does not expose a safe RPC host.
        adapter = MemoryAdapter(tls=True, replicas=1)
        container = adapter.sts["spec"]["template"]["spec"]["containers"][0]
        container["command"][2] = container["command"][2].replace(
            "--advertise-host=$(POD_NAME).db.$(POD_NAMESPACE).svc.cluster.local",
            "--advertise-sql-addr=$(POD_NAME).sql.$(POD_NAMESPACE).svc.cluster.local:26270",
        )
        for pod in adapter.pods:
            pod["spec"]["containers"][0]["command"] = copy.deepcopy(container["command"])

        connection = CrdbLibrary(adapter).inspect_sql_connection(
            WorkloadRef(adapter.namespace, adapter.name), ordinal=0
        )
        self.assertEqual(connection.sql_host, "db-0.sql.crdb-fixture.svc.cluster.local")
        self.assertIsNone(connection.rpc_host)

        # An unparseable optional RPC address likewise must not block a valid
        # SQL-specific address used by the readiness observer.
        adapter = MemoryAdapter(tls=True, replicas=1)
        container = adapter.sts["spec"]["template"]["spec"]["containers"][0]
        container["command"][2] = container["command"][2].replace(
            "--advertise-host=$(POD_NAME).db.$(POD_NAMESPACE).svc.cluster.local",
            "--advertise-addr=rpc.example:not-a-port "
            "--advertise-sql-addr=$(POD_NAME).sql.$(POD_NAMESPACE).svc.cluster.local:26270",
        )
        for pod in adapter.pods:
            pod["spec"]["containers"][0]["command"] = copy.deepcopy(container["command"])

        connection = CrdbLibrary(adapter).inspect_sql_connection(
            WorkloadRef(adapter.namespace, adapter.name), ordinal=0
        )
        self.assertEqual(connection.sql_host, "db-0.sql.crdb-fixture.svc.cluster.local")
        self.assertIsNone(connection.rpc_host)

    def test_gateway_sql_connection_does_not_require_secret_read_access(self):
        adapter = MemoryAdapter(tls=True, replicas=1)
        adapter.fingerprint_error = KubernetesAccessError("Secret get is forbidden")
        library = CrdbLibrary(adapter)
        ref = WorkloadRef(adapter.namespace, adapter.name)

        connection = library.inspect_sql_connection(ref)

        self.assertEqual(connection.tls_mode, TLSMode.TLS)
        self.assertEqual(connection.certs_dir, "/cockroach/cockroach-certs")
        self.assertEqual(adapter.fingerprint_calls, [])
        self.assertEqual(
            adapter.query_sql(
                namespace=connection.namespace,
                pod_name=connection.pod_name,
                container_name=connection.container_name,
                binary=connection.sql_binary,
                sql_host=connection.sql_host,
                sql_port=connection.sql_port,
                tls_mode=connection.tls_mode.value,
                certs_dir=connection.certs_dir,
                sql="SELECT 1;",
                timeout=5,
            ),
            "1\n",
        )

        adapter.select_one_error = AuthenticationError("SQL rejected its credentials")
        with self.assertRaises(AuthenticationError):
            adapter.query_sql(
                namespace=connection.namespace,
                pod_name=connection.pod_name,
                container_name=connection.container_name,
                binary=connection.sql_binary,
                sql_host=connection.sql_host,
                sql_port=connection.sql_port,
                tls_mode=connection.tls_mode.value,
                certs_dir=connection.certs_dir,
                sql="SELECT 1;",
                timeout=5,
            )

        with self.assertRaises(KubernetesAccessError):
            library.inspect(ref)
        self.assertEqual(adapter.fingerprint_calls, ["db-certs"])

    def test_gateway_connection_does_not_apply_unrelated_http_listener_validation(self):
        for description, update in (
            ("unsupported HTTP port alias", lambda script: f"{script} --http-port=8181"),
            ("localhost HTTP flag with wildcard bind", lambda script: f"{script} --unencrypted-localhost-http"),
        ):
            with self.subTest(layout=description):
                adapter = MemoryAdapter()
                containers = [adapter.sts["spec"]["template"]["spec"]["containers"][0]] + [
                    pod["spec"]["containers"][0] for pod in adapter.pods
                ]
                for container in containers:
                    container["command"][2] = update(container["command"][2])

                connection = CrdbLibrary(adapter).inspect_sql_connection(
                    WorkloadRef(adapter.namespace, adapter.name)
                )

                self.assertEqual(connection.sql_port, 26270)
                with self.assertRaises(UnsupportedLayoutError):
                    CrdbLibrary(adapter).inspect(WorkloadRef(adapter.namespace, adapter.name))

    def test_gateway_connection_rejects_missing_or_foreign_pod(self):
        ref_adapter = MemoryAdapter()
        ref = WorkloadRef(ref_adapter.namespace, ref_adapter.name)
        ref_adapter.pods = ref_adapter.pods[1:]
        with self.assertRaises(RolloutInProgressError):
            CrdbLibrary(ref_adapter).inspect_sql_connection(ref)

        foreign_adapter = MemoryAdapter()
        foreign_adapter.pods[0]["metadata"]["ownerReferences"][0]["uid"] = "other-statefulset"
        with self.assertRaises(UnsupportedLayoutError):
            CrdbLibrary(foreign_adapter).inspect_sql_connection(
                WorkloadRef(foreign_adapter.namespace, foreign_adapter.name)
            )

    def test_gateway_connection_propagates_api_and_auth_errors(self):
        for error in (KubernetesAccessError("denied"), AuthenticationError("auth denied")):
            with self.subTest(error=type(error).__name__):
                adapter = MemoryAdapter()
                adapter.pod_get_error = error
                with self.assertRaises(type(error)):
                    CrdbLibrary(adapter).inspect_sql_connection(
                        WorkloadRef(adapter.namespace, adapter.name)
                    )

    def test_gateway_connection_rechecks_statefulset_and_pod_uids(self):
        ref = WorkloadRef("crdb-fixture", "db")
        statefulset_adapter = MemoryAdapter()
        statefulset_adapter.replace_sts_uid_on_second_read = "replacement-sts-uid"
        with self.assertRaises(RolloutInProgressError):
            CrdbLibrary(statefulset_adapter).inspect_sql_connection(ref)

        pod_adapter = MemoryAdapter()
        pod_adapter.replace_pod_uid_on_second_read = "replacement-pod-uid"
        with self.assertRaises(RolloutInProgressError):
            CrdbLibrary(pod_adapter).inspect_sql_connection(ref)

    def test_gateway_connection_rejects_out_of_range_ordinal(self):
        adapter = MemoryAdapter()
        with self.assertRaises(InvalidRequirementError):
            CrdbLibrary(adapter).inspect_sql_connection(
                WorkloadRef(adapter.namespace, adapter.name), ordinal=True
            )
        with self.assertRaises(RolloutInProgressError):
            CrdbLibrary(adapter).inspect_sql_connection(
                WorkloadRef(adapter.namespace, adapter.name), ordinal=3
            )
        with self.assertRaises(RolloutInProgressError):
            CrdbLibrary(adapter).inspect_sql_connection(
                WorkloadRef(adapter.namespace, adapter.name), ordinal=10000
            )

    def test_inspects_bash_downward_api_and_actual_named_ports(self):
        adapter = MemoryAdapter()
        observation = CrdbLibrary(adapter).inspect(WorkloadRef(adapter.namespace, adapter.name))
        self.assertEqual(observation.tls_mode, TLSMode.INSECURE)
        self.assertEqual(observation.http_transport, HTTPTransport.HTTP)
        self.assertEqual((observation.sql_port, observation.rpc_port, observation.http_port), (26270, 26300, 8082))
        self.assertEqual((observation.sql_port_name, observation.rpc_port_name, observation.http_port_name), ("sql", "grpc", "http"))
        self.assertEqual(observation.desired_replicas, 2)
        self.assertEqual(len(observation.pvcs), 2)
        self.assertTrue(observation.workload_spec_hash)
        self.assertTrue(observation.probe_preservation_hash)
        self.assertEqual(
            observation.advertised_sql_host_template,
            "$(POD_NAME).db.$(POD_NAMESPACE).svc.cluster.local",
        )
        self.assertEqual(
            tuple(pod.sql_host for pod in observation.pods),
            ("db-0.db.crdb-fixture.svc.cluster.local", "db-1.db.crdb-fixture.svc.cluster.local"),
        )

    def test_standard_kubernetes_service_account_projection_is_accepted(self):
        adapter = MemoryAdapter()
        for ordinal, pod in enumerate(adapter.pods):
            add_standard_service_account_projection(pod, f"a{ordinal}bc1")
        result = CrdbLibrary(adapter).probe(
            WorkloadRef(adapter.namespace, adapter.name), Requirement(Lifecycle.INITIALIZED)
        )
        self.assertEqual(result.status, ProbeStatus.SATISFIED)
        self.assertEqual(len(adapter.queried_sql_hosts), 2)

    def test_unexpected_service_account_mount_source_is_rejected_before_sql(self):
        adapter = MemoryAdapter()
        pod = adapter.pods[0]
        mount_name = "kube-api-access-a0bc1"
        pod["spec"]["containers"][0]["volumeMounts"].append(
            {
                "name": mount_name,
                "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount",
                "readOnly": True,
            }
        )
        pod["spec"]["volumes"].append(
            {"name": mount_name, "secret": {"secretName": "unrelated-credentials"}}
        )
        with self.assertRaises(RolloutInProgressError) as raised:
            CrdbLibrary(adapter).probe(
                WorkloadRef(adapter.namespace, adapter.name), Requirement(Lifecycle.INITIALIZED)
            )
        self.assertIn("volumeMounts", str(raised.exception))
        self.assertNotIn("unrelated-credentials", str(raised.exception))
        self.assertEqual(adapter.queried_sql_hosts, [])

    def test_probe_uses_only_resolved_per_pod_advertised_sql_hosts(self):
        adapter = MemoryAdapter()
        result = CrdbLibrary(adapter).probe(
            WorkloadRef(adapter.namespace, adapter.name), Requirement(Lifecycle.INITIALIZED)
        )
        self.assertEqual(result.status, ProbeStatus.SATISFIED)
        self.assertEqual(
            adapter.queried_sql_hosts,
            ["db-0.db.crdb-fixture.svc.cluster.local", "db-1.db.crdb-fixture.svc.cluster.local"],
        )

    def test_unmodeled_deprecated_http_port_fails_before_http_or_sql_io(self):
        adapter = MemoryAdapter()
        container = adapter.sts["spec"]["template"]["spec"]["containers"][0]
        container["command"][2] = container["command"][2].replace(
            "--http-addr=0.0.0.0:8082", "--http-port=9999"
        )
        for pod in adapter.pods:
            pod["spec"]["containers"][0]["command"] = copy.deepcopy(container["command"])

        with self.assertRaises(UnsupportedLayoutError) as raised:
            CrdbLibrary(adapter).probe(
                WorkloadRef(adapter.namespace, adapter.name),
                Requirement(Lifecycle.INITIALIZED),
            )

        self.assertIn("--http-port", str(raised.exception))
        self.assertEqual(adapter.http_calls, [])
        self.assertEqual(adapter.query_sql_calls, [])
        self.assertEqual(adapter.native_identity_calls, [])
        self.assertEqual(adapter.patch_calls, [])

    def test_full_health_joins_selected_sql_nodes_to_active_live_status(self):
        adapter = MemoryAdapter()
        result = CrdbLibrary(adapter).probe_full_health(WorkloadRef(adapter.namespace, adapter.name))

        self.assertEqual(result.status, ProbeStatus.SATISFIED)
        self.assertEqual(result.pod_node_ids, (("db-0", 1), ("db-1", 2)))
        self.assertEqual(tuple(node.node_id for node in result.node_status), (1, 2))
        self.assertIsNone(result.node_status[0].membership)
        self.assertEqual(tuple(node.node_id for node in result.node_liveness), (1, 2))
        self.assertEqual(len(adapter.node_status_calls), 1)
        self.assertEqual(adapter.node_status_calls[0]["sql_port"], 26270)
        self.assertEqual(adapter.node_status_calls[0]["pod_name"], "db-0")
        self.assertEqual(len(adapter.liveness_query_calls), 1)
        self.assertEqual(adapter.liveness_query_calls[0]["sql_port"], 26270)
        self.assertEqual(adapter.liveness_query_calls[0]["tls_mode"], "insecure")

    def test_native_identity_path_uses_fixed_version_query_and_node_status_liveness(self):
        adapter = MemoryAdapter(tls=True)
        adapter.server_versions = ["CockroachDB CCL v26.1.8"] * 2
        adapter.node_status_output = (
            "id,membership,is_draining,is_available,ranges_unavailable,ranges_underreplicated,is_live\n"
            "1,active,false,true,0,0,true\n"
            "2,active,false,true,0,0,true\n"
        )

        result = CrdbLibrary(adapter).probe_full_health(WorkloadRef(adapter.namespace, adapter.name))

        self.assertEqual(result.status, ProbeStatus.SATISFIED)
        self.assertEqual(tuple(call["sql"] for call in adapter.query_sql_calls), (
            "SELECT version() AS version;", "SELECT version() AS version;",
        ))
        self.assertEqual(tuple(call["pod_name"] for call in adapter.native_identity_calls), ("db-0", "db-1"))
        self.assertTrue(all(call["tls_mode"] == "tls" for call in adapter.native_identity_calls))
        self.assertEqual(adapter.liveness_query_calls, [])
        self.assertEqual(tuple(node.is_live for node in result.node_status), (True, True))

    def test_mixed_versions_choose_identity_per_observed_pod_version(self):
        adapter = MemoryAdapter()
        adapter.server_versions = ["CockroachDB CCL v24.1.4", "CockroachDB CCL v26.1.8"]
        adapter.node_status_output = (
            "id,membership,is_draining,is_available,ranges_unavailable,ranges_underreplicated,is_live\n"
            "1,active,false,true,0,0,true\n"
            "2,active,false,true,0,0,true\n"
        )

        assessment = CrdbLibrary(adapter).probe_full_health(WorkloadRef(adapter.namespace, adapter.name))

        self.assertEqual(assessment.status, ProbeStatus.SATISFIED)
        self.assertEqual(tuple(call["pod_name"] for call in adapter.native_identity_calls), ("db-1",))
        self.assertEqual(
            tuple((call["pod_name"], call["sql"]) for call in adapter.query_sql_calls),
            (
                ("db-0", "SELECT version() AS version;"),
                ("db-1", "SELECT version() AS version;"),
                (
                    "db-0",
                    "SELECT crdb_internal.cluster_id() AS cluster_id, "
                    "crdb_internal.node_id() AS node_id, version() AS version;",
                ),
            ),
        )
        self.assertEqual(len(adapter.node_status_calls), 1)
        self.assertEqual(adapter.liveness_query_calls, [])

    def test_native_identity_failure_does_not_fall_back_to_internal_sql(self):
        adapter = MemoryAdapter()
        adapter.server_versions = ["CockroachDB CCL v26.1.8"] * 2
        adapter.native_identity_error = AuthenticationError("native auth failed")

        with self.assertRaises(AuthenticationError):
            CrdbLibrary(adapter).probe(
                WorkloadRef(adapter.namespace, adapter.name), Requirement(Lifecycle.INITIALIZED)
            )

        self.assertEqual(len(adapter.native_identity_calls), 1)
        self.assertTrue(all(call["sql"] == "SELECT version() AS version;" for call in adapter.query_sql_calls))

    def test_image_only_rollout_is_health_observable_but_public_inspection_is_strict(self):
        adapter = MemoryAdapter()
        container = adapter.sts["spec"]["template"]["spec"]["containers"][0]
        container["image"] = "cockroachdb/cockroach:v26.1.8"
        adapter.sts["status"].update({"currentRevision": "rev1", "updateRevision": "rev2"})
        adapter.pods[0]["metadata"]["labels"]["controller-revision-hash"] = "rev1"
        adapter.pods[0]["spec"]["containers"][0]["image"] = "cockroachdb/cockroach:v24.1.4"
        adapter.pods[1]["metadata"]["labels"]["controller-revision-hash"] = "rev2"
        adapter.pods[1]["spec"]["containers"][0]["image"] = "cockroachdb/cockroach:v26.1.8"
        adapter.server_versions = ["CockroachDB CCL v24.1.4", "CockroachDB CCL v26.1.8"]
        adapter.node_status_output = (
            "id,membership,is_draining,is_available,ranges_unavailable,ranges_underreplicated,is_live\n"
            "1,active,false,true,0,0,true\n"
            "2,active,false,true,0,0,true\n"
        )
        library = CrdbLibrary(adapter)
        ref = WorkloadRef(adapter.namespace, adapter.name)

        with self.assertRaises(RolloutInProgressError):
            library.inspect(ref)
        health = library.probe_full_health(ref)
        self.assertEqual(health.status, ProbeStatus.SATISFIED)
        self.assertEqual(tuple(pod.image for pod in health.assessment.workload.pods), (
            "cockroachdb/cockroach:v24.1.4", "cockroachdb/cockroach:v26.1.8",
        ))
        self.assertEqual(tuple(pod.revision for pod in health.assessment.workload.pods), ("rev1", "rev2"))
        self.assertFalse(health.assessment.workload.pods[0].startup_matches_template)
        with self.assertRaises(InvalidRequirementError):
            library.accepted_state(health.assessment)

    def test_full_health_observes_completed_ondelete_rollout_when_current_revision_lags(self):
        def completed_rollout() -> MemoryAdapter:
            adapter = MemoryAdapter(tls=True, replicas=3, custom_ports=False)
            new_image = "cockroachdb/cockroach:v24.2.10"
            adapter.sts["metadata"]["generation"] = 2
            adapter.sts["status"].update(
                {
                    "observedGeneration": 2,
                    "currentRevision": "rev-old",
                    "updateRevision": "rev-new",
                    "updatedReplicas": 3,
                    "readyReplicas": 3,
                }
            )
            adapter.sts["spec"]["updateStrategy"] = {"type": "OnDelete"}
            adapter.sts["spec"]["template"]["spec"]["containers"][0]["image"] = new_image
            for pod in adapter.pods:
                pod["metadata"]["labels"]["controller-revision-hash"] = "rev-new"
                pod["spec"]["containers"][0]["image"] = new_image
            adapter.server_versions = ["CockroachDB CCL v24.2.10"] * 3
            adapter.node_status_output = (
                "id,is_available,ranges_unavailable,ranges_underreplicated\n"
                "1,true,0,0\n2,true,0,0\n3,true,0,0\n"
            )
            adapter.node_liveness_output = (
                "node_id,membership,draining,is_live\n"
                "1,active,false,true\n2,active,false,true\n3,active,false,true\n"
            )
            return adapter

        adapter = completed_rollout()
        result = CrdbLibrary(adapter).probe_full_health(WorkloadRef(adapter.namespace, adapter.name))

        self.assertEqual(result.status, ProbeStatus.SATISFIED)
        self.assertEqual(tuple(pod.revision for pod in result.assessment.workload.pods), ("rev-new",) * 3)
        self.assertEqual(len(adapter.node_status_calls), 1)
        self.assertEqual(len(adapter.liveness_query_calls), 1)
        self.assertEqual(
            tuple(call["pod_name"] for call in adapter.query_sql_calls if "SELECT version()" in call["sql"]),
            ("db-0", "db-1", "db-2"),
        )

    def test_read_only_health_does_not_accept_incomplete_ondelete_rollout_status(self):
        def completed_rollout() -> MemoryAdapter:
            adapter = MemoryAdapter(replicas=3, custom_ports=False)
            new_image = "cockroachdb/cockroach:v24.2.10"
            adapter.sts["metadata"]["generation"] = 2
            adapter.sts["status"].update(
                {
                    "observedGeneration": 2,
                    "currentRevision": "rev-old",
                    "updateRevision": "rev-new",
                    "updatedReplicas": 3,
                }
            )
            adapter.sts["spec"]["template"]["spec"]["containers"][0]["image"] = new_image
            for pod in adapter.pods:
                pod["metadata"]["labels"]["controller-revision-hash"] = "rev-new"
                pod["spec"]["containers"][0]["image"] = new_image
            adapter.server_versions = ["CockroachDB CCL v24.2.10"] * 3
            return adapter

        partial_count = completed_rollout()
        partial_count.sts["status"]["updatedReplicas"] = 2
        with self.assertRaises(RolloutInProgressError):
            CrdbLibrary(partial_count).probe_full_health(
                WorkloadRef(partial_count.namespace, partial_count.name)
            )
        self.assertEqual(partial_count.query_sql_calls, [])

        partial_revision = completed_rollout()
        partial_revision.pods[-1]["metadata"]["labels"]["controller-revision-hash"] = "rev-old"
        with self.assertRaises(RolloutInProgressError):
            CrdbLibrary(partial_revision).probe_full_health(
                WorkloadRef(partial_revision.namespace, partial_revision.name)
            )
        self.assertEqual(partial_revision.query_sql_calls, [])

        stale_generation = completed_rollout()
        stale_generation.sts["metadata"]["generation"] = 3
        stale_generation.sts["status"]["observedGeneration"] = 2
        stale_generation.rollout_once = True
        with self.assertRaises(RolloutInProgressError):
            CrdbLibrary(stale_generation).probe_full_health(
                WorkloadRef(stale_generation.namespace, stale_generation.name)
            )
        self.assertEqual(stale_generation.query_sql_calls, [])

    def test_probe_preparation_stays_strict_and_never_patches_during_image_rollout(self):
        adapter = MemoryAdapter()
        container = adapter.sts["spec"]["template"]["spec"]["containers"][0]
        container["image"] = "cockroachdb/cockroach:v26.1.8"
        adapter.sts["status"].update({"currentRevision": "rev1", "updateRevision": "rev2"})
        adapter.pods[0]["metadata"]["labels"]["controller-revision-hash"] = "rev1"
        adapter.pods[0]["spec"]["containers"][0]["image"] = "cockroachdb/cockroach:v24.1.4"
        adapter.pods[1]["metadata"]["labels"]["controller-revision-hash"] = "rev2"
        adapter.pods[1]["spec"]["containers"][0]["image"] = "cockroachdb/cockroach:v26.1.8"

        with self.assertRaises(RolloutInProgressError):
            CrdbLibrary(adapter).prepare_health_recovery_probes(
                WorkloadRef(adapter.namespace, adapter.name), timeout=0.01
            )
        self.assertEqual(adapter.patch_calls, [])

    def test_same_revision_pod_image_mismatch_is_rejected_by_all_public_paths(self):
        for operation in ("inspect", "probe", "prepare"):
            with self.subTest(operation=operation):
                adapter = MemoryAdapter()
                adapter.sts["spec"]["template"]["spec"]["containers"][0]["image"] = (
                    "cockroachdb/cockroach:v26.1.8"
                )
                adapter.sts["status"].update({"currentRevision": "rev1", "updateRevision": "rev1"})
                adapter.pods[0]["spec"]["containers"][0]["image"] = "cockroachdb/cockroach:v24.1.4"
                adapter.pods[1]["spec"]["containers"][0]["image"] = "cockroachdb/cockroach:v26.1.8"
                library = CrdbLibrary(adapter)
                ref = WorkloadRef(adapter.namespace, adapter.name)

                with self.assertRaises(RolloutInProgressError):
                    if operation == "inspect":
                        library.inspect(ref)
                    elif operation == "probe":
                        library.probe(ref, Requirement(Lifecycle.INITIALIZED))
                    elif operation == "prepare":
                        library.prepare_health_recovery_probes(ref, timeout=0.01)

                self.assertEqual(adapter.query_sql_calls, [])
                self.assertEqual(adapter.native_identity_calls, [])
                self.assertEqual(adapter.patch_calls, [])

    def test_read_only_health_observes_same_revision_image_change_by_actual_versions(self):
        adapter = MemoryAdapter()
        adapter.sts["spec"]["template"]["spec"]["containers"][0]["image"] = (
            "cockroachdb/cockroach:v26.1.8"
        )
        adapter.sts["status"].update({"currentRevision": "rev1", "updateRevision": "rev1"})
        adapter.pods[0]["spec"]["containers"][0]["image"] = "cockroachdb/cockroach:v24.1.4"
        adapter.pods[1]["spec"]["containers"][0]["image"] = "cockroachdb/cockroach:v26.1.8"
        adapter.server_versions = ["CockroachDB CCL v24.1.4", "CockroachDB CCL v26.1.8"]
        adapter.node_status_output = (
            "id,membership,is_draining,is_available,ranges_unavailable,ranges_underreplicated,is_live\n"
            "1,active,false,true,0,0,true\n"
            "2,active,false,true,0,0,true\n"
        )

        result = CrdbLibrary(adapter).probe_full_health(WorkloadRef(adapter.namespace, adapter.name))

        self.assertEqual(result.status, ProbeStatus.SATISFIED)
        self.assertEqual(result.assessment.health.sql_versions, tuple(adapter.server_versions))
        self.assertEqual(tuple(call["pod_name"] for call in adapter.native_identity_calls), ("db-1",))
        self.assertEqual(
            tuple(call["pod_name"] for call in adapter.query_sql_calls if "cluster_id()" in call["sql"]),
            ("db-0",),
        )

    def test_read_only_health_rejects_image_change_on_unknown_revision(self):
        adapter = MemoryAdapter()
        adapter.sts["spec"]["template"]["spec"]["containers"][0]["image"] = (
            "cockroachdb/cockroach:v26.1.8"
        )
        adapter.sts["status"].update({"currentRevision": "rev1", "updateRevision": "rev1"})
        adapter.pods[0]["spec"]["containers"][0]["image"] = "cockroachdb/cockroach:v24.1.4"
        adapter.pods[0]["metadata"]["labels"]["controller-revision-hash"] = "unexpected-rev"

        with self.assertRaises(RolloutInProgressError):
            CrdbLibrary(adapter).probe_full_health(WorkloadRef(adapter.namespace, adapter.name))
        self.assertEqual(adapter.query_sql_calls, [])
        self.assertEqual(adapter.native_identity_calls, [])

    def test_image_rollout_health_path_rejects_non_image_spec_mismatches(self):
        mutations = {
            "startup args": lambda pod: pod["spec"]["containers"][0].update(args=["different args"]),
            "container resources": lambda pod: pod["spec"]["containers"][0].update(
                resources={"requests": {"cpu": "200m", "memory": "256Mi"}}
            ),
            "container security context": lambda pod: pod["spec"]["containers"][0].update(
                securityContext={"runAsNonRoot": True}
            ),
            "probe handler": lambda pod: pod["spec"]["containers"][0].update(
                readinessProbe={"exec": {"command": ["true"]}}
            ),
            "volume source": lambda pod: pod["spec"]["volumes"][-1]["persistentVolumeClaim"].update(
                claimName="unexpected-claim"
            ),
            "pod security context": lambda pod: pod["spec"].update(
                securityContext={"runAsNonRoot": True}
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                adapter = MemoryAdapter()
                container = adapter.sts["spec"]["template"]["spec"]["containers"][0]
                container["image"] = "cockroachdb/cockroach:v26.1.8"
                adapter.sts["status"].update({"currentRevision": "rev1", "updateRevision": "rev2"})
                adapter.pods[0]["metadata"]["labels"]["controller-revision-hash"] = "rev1"
                adapter.pods[0]["spec"]["containers"][0]["image"] = "cockroachdb/cockroach:v24.1.4"
                adapter.pods[1]["metadata"]["labels"]["controller-revision-hash"] = "rev2"
                adapter.pods[1]["spec"]["containers"][0]["image"] = "cockroachdb/cockroach:v26.1.8"
                mutate(adapter.pods[0])

                with self.assertRaises(RolloutInProgressError):
                    CrdbLibrary(adapter).probe_full_health(WorkloadRef(adapter.namespace, adapter.name))
                self.assertEqual(adapter.query_sql_calls, [])
                self.assertEqual(adapter.native_identity_calls, [])

    def test_unencrypted_localhost_http_is_independent_of_sql_tls(self):
        adapter = MemoryAdapter(tls=True)
        container = adapter.sts["spec"]["template"]["spec"]["containers"][0]
        container["command"][2] = container["command"][2].replace(
            "--http-addr=0.0.0.0:8082", "--http-addr=localhost:8082"
        ) + " --unencrypted-localhost-http"
        for pod in adapter.pods:
            pod["spec"]["containers"][0]["command"] = copy.deepcopy(container["command"])
        library = CrdbLibrary(adapter)
        ref = WorkloadRef(adapter.namespace, adapter.name)

        observed = library.inspect(ref)
        result = library.probe(ref, Requirement(Lifecycle.INITIALIZED))
        self.assertEqual(observed.tls_mode, TLSMode.TLS)
        self.assertEqual(observed.http_transport, HTTPTransport.HTTP)
        self.assertEqual(observed.http_bind_host, "localhost")
        self.assertEqual(result.status, ProbeStatus.SATISFIED)
        self.assertTrue(all(call["http_transport"] == "http" for call in adapter.http_calls))
        self.assertTrue(all(call["tls_mode"] == "tls" for call in adapter.query_sql_calls))
        adapter.http_calls.clear()
        with self.assertRaises(UnsupportedLayoutError):
            library.prepare_health_recovery_probes(ref, timeout=0.01)
        self.assertEqual(adapter.patch_calls, [])
        self.assertEqual(len(adapter.http_calls), len(adapter.pods))
        self.assertTrue(all(call["path"] == "/health?ready=1" for call in adapter.http_calls))
        local_http_probes = replace(
            observed,
            liveness_probe=replace(
                observed.liveness_probe,
                handler="httpGet", path="/health", port="http", scheme="HTTP", host=None,
            ),
            readiness_probe=replace(
                observed.readiness_probe,
                handler="httpGet", path="/health?ready=1", port="http", scheme="HTTP", host=None,
            ),
        )
        self.assertFalse(CrdbLibrary.health_recovery_probes_prepared(local_http_probes))

    def test_localhost_http_validation_uses_effective_rpc_host_and_rejects_ambiguous_aliases(self):
        def configured(*, http_addr="0.0.0.0:8082", listen_addr="0.0.0.0:26300", http_host=None, local_http=True):
            adapter = MemoryAdapter(tls=True)
            template_container = adapter.sts["spec"]["template"]["spec"]["containers"][0]
            tokens = template_container["command"][2].split()
            tokens = [
                token for token in tokens
                if not token.startswith(("--http-addr=", "--listen-addr="))
            ]
            if http_addr is not None:
                tokens.append(f"--http-addr={http_addr}")
            if listen_addr is not None:
                tokens.append(f"--listen-addr={listen_addr}")
            if http_host is not None:
                tokens.append(f"--http-host={http_host}")
            if local_http:
                tokens.append("--unencrypted-localhost-http")
            template_container["command"][2] = " ".join(tokens)
            for pod in adapter.pods:
                pod["spec"]["containers"][0]["command"] = copy.deepcopy(template_container["command"])
            return adapter

        cases = (
            ("explicit localhost HTTP overrides wildcard RPC", {"http_addr": "localhost:8082"}, True, "localhost"),
            ("empty HTTP inherits wildcard RPC", {"http_addr": ":8082"}, False, None),
            ("empty HTTP inherits localhost RPC", {"http_addr": ":8082", "listen_addr": "localhost:26300"}, True, "localhost"),
            ("omitted HTTP address is forced local", {"http_addr": None}, True, "localhost"),
            ("empty HTTP alias inherits wildcard RPC", {"http_addr": None, "http_host": ""}, False, None),
            ("empty HTTP alias inherits localhost RPC", {"http_addr": None, "http_host": "", "listen_addr": "localhost:26300"}, True, "localhost"),
            ("HTTP address and alias are ambiguous", {"http_addr": "localhost:8082", "http_host": "localhost"}, False, None),
            ("without localhost-only flag, wildcard HTTP is unchanged", {"http_addr": "0.0.0.0:8082", "local_http": False}, True, "0.0.0.0"),
        )
        for label, options, accepted, expected_host in cases:
            with self.subTest(label=label):
                local_http = options.get("local_http", True)
                configure_options = {key: value for key, value in options.items() if key != "local_http"}
                adapter = configured(local_http=local_http, **configure_options)
                library = CrdbLibrary(adapter)
                ref = WorkloadRef(adapter.namespace, adapter.name)
                if accepted:
                    observation = library.inspect(ref)
                    self.assertEqual(observation.http_bind_host, expected_host)
                    self.assertEqual(
                        observation.http_transport,
                        HTTPTransport.HTTP if local_http else HTTPTransport.HTTPS,
                    )
                else:
                    with self.assertRaises(UnsupportedLayoutError):
                        library.probe(ref, Requirement(Lifecycle.INITIALIZED))
                    self.assertEqual(adapter.query_sql_calls, [])
                    self.assertEqual(adapter.native_identity_calls, [])
                    self.assertEqual(adapter.http_calls, [])

    def test_unencrypted_localhost_http_rejects_explicit_wildcard_before_probe_io(self):
        for explicit_host in ("--http-addr=0.0.0.0:8082", "--http-host=127.0.0.1"):
            with self.subTest(explicit_host=explicit_host):
                adapter = MemoryAdapter(tls=True)
                container = adapter.sts["spec"]["template"]["spec"]["containers"][0]
                if explicit_host.startswith("--http-addr="):
                    container["command"][2] += " --unencrypted-localhost-http"
                else:
                    container["command"][2] = container["command"][2].replace(
                        "--http-addr=0.0.0.0:8082", "--http-addr=:8082"
                    ) + " " + explicit_host + " --unencrypted-localhost-http"
                for pod in adapter.pods:
                    pod["spec"]["containers"][0]["command"] = copy.deepcopy(container["command"])

                with self.assertRaises(UnsupportedLayoutError):
                    CrdbLibrary(adapter).probe(
                        WorkloadRef(adapter.namespace, adapter.name),
                        Requirement(Lifecycle.INITIALIZED),
                    )

                self.assertEqual(adapter.query_sql_calls, [])
                self.assertEqual(adapter.native_identity_calls, [])
                self.assertEqual(adapter.http_calls, [])

    def test_full_health_requires_exact_active_node_mapping_and_healthy_ranges(self):
        adapter = MemoryAdapter()
        adapter.node_status_output = (
            "id,membership,is_draining,is_available,ranges_unavailable,ranges_underreplicated\n"
            "1,active,false,true,0,0\n"
            "3,active,false,true,0,0\n"
        )
        result = CrdbLibrary(adapter).probe_full_health(WorkloadRef(adapter.namespace, adapter.name))
        self.assertEqual(result.status, ProbeStatus.UNSATISFIED)
        self.assertIn("does not cover every selected StatefulSet replica", " ".join(result.reasons))

        adapter = MemoryAdapter()
        adapter.node_status_output = (
            "id,membership,is_draining,is_available,ranges_unavailable,ranges_underreplicated\n"
            "1,active,false,true,0,0\n"
            "2,active,false,true,1,0\n"
        )
        result = CrdbLibrary(adapter).probe_full_health(WorkloadRef(adapter.namespace, adapter.name))
        self.assertEqual(result.status, ProbeStatus.UNSATISFIED)
        self.assertIn("unavailable or under-replicated ranges", " ".join(result.reasons))

    def test_serving_health_allows_underreplication_but_full_health_does_not(self):
        adapter = MemoryAdapter()
        adapter.node_status_output = (
            "id,is_available,ranges_unavailable,ranges_underreplicated\n"
            "1,true,0,1\n"
            "2,true,0,1\n"
        )

        full = CrdbLibrary(adapter).probe_full_health(WorkloadRef(adapter.namespace, adapter.name))
        serving = CrdbLibrary(adapter).probe_serving_health(WorkloadRef(adapter.namespace, adapter.name))

        self.assertEqual(full.status, ProbeStatus.UNSATISFIED)
        self.assertEqual(serving.status, ProbeStatus.SATISFIED)
        self.assertEqual(tuple(node.ranges_underreplicated for node in serving.node_status), (1, 1))
        self.assertEqual(len(adapter.node_status_calls), 2)

    def test_serving_health_still_rejects_unavailable_ranges(self):
        adapter = MemoryAdapter()
        adapter.node_status_output = (
            "id,is_available,ranges_unavailable,ranges_underreplicated\n"
            "1,true,1,0\n"
            "2,true,0,0\n"
        )

        result = CrdbLibrary(adapter).probe_serving_health(WorkloadRef(adapter.namespace, adapter.name))

        self.assertEqual(result.status, ProbeStatus.UNSATISFIED)
        self.assertTrue(any("unavailable" in reason for reason in result.reasons))

    def test_serving_health_keeps_exact_node_and_liveness_guards(self):
        adapter = MemoryAdapter()
        adapter.node_status_output = (
            "id,is_available,ranges_unavailable,ranges_underreplicated\n"
            "1,true,0,1\n"
            "3,true,0,1\n"
        )
        result = CrdbLibrary(adapter).probe_serving_health(WorkloadRef(adapter.namespace, adapter.name))
        self.assertEqual(result.status, ProbeStatus.UNSATISFIED)
        self.assertIn("does not cover every selected StatefulSet replica", " ".join(result.reasons))

        adapter = MemoryAdapter()
        adapter.node_liveness_output = (
            "node_id,membership,draining,is_live\n"
            "1,active,false,true\n"
            "2,active,false,false\n"
        )
        result = CrdbLibrary(adapter).probe_serving_health(WorkloadRef(adapter.namespace, adapter.name))
        self.assertEqual(result.status, ProbeStatus.UNSATISFIED)
        self.assertIn("expired liveness heartbeat", " ".join(result.reasons))

    def test_serving_health_wait_retries_transient_but_not_api_failures(self):
        adapter = MemoryAdapter()
        adapter.node_status_transient_once = True
        result = CrdbLibrary(adapter).wait_for_serving_health(
            WorkloadRef(adapter.namespace, adapter.name), timeout=0.2, poll_interval=0.001
        )
        self.assertEqual(result.status, ProbeStatus.SATISFIED)
        self.assertEqual(result.attempts, 2)

        adapter = MemoryAdapter()
        adapter.node_status_error = KubernetesAccessError("node status read denied")
        with self.assertRaises(KubernetesAccessError):
            CrdbLibrary(adapter).wait_for_serving_health(
                WorkloadRef(adapter.namespace, adapter.name), timeout=0.2, poll_interval=0.001
            )
        self.assertEqual(len(adapter.node_status_calls), 1)

    def test_full_health_uses_liveness_to_validate_decommissioned_history(self):
        adapter = MemoryAdapter()
        adapter.node_status_output = (
            "id,membership,is_draining,is_available,ranges_unavailable,ranges_underreplicated\n"
            "1,active,false,true,0,0\n"
            "2,active,false,true,0,0\n"
            "3,decommissioned,false,true,0,0\n"
        )
        adapter.node_liveness_output += "3,decommissioned,false,false\n"
        result = CrdbLibrary(adapter).probe_full_health(WorkloadRef(adapter.namespace, adapter.name))
        self.assertEqual(result.status, ProbeStatus.SATISFIED)

        adapter = MemoryAdapter()
        adapter.node_status_output = (
            "id,membership,is_draining,is_available,ranges_unavailable,ranges_underreplicated\n"
            "1,active,false,true,0,0\n"
            "2,active,false,true,0,0\n"
            "3,active,false,true,0,0\n"
        )
        adapter.node_liveness_output += "3,decommissioned,false,false\n"
        result = CrdbLibrary(adapter).probe_full_health(WorkloadRef(adapter.namespace, adapter.name))
        self.assertEqual(result.status, ProbeStatus.UNSATISFIED)
        self.assertIn("outside the selected active cluster", " ".join(result.reasons))

    def test_full_health_rejects_malformed_node_status_output(self):
        adapter = MemoryAdapter()
        adapter.node_status_output = "id,membership\n1,active\n"
        with self.assertRaises(UnsupportedLayoutError):
            CrdbLibrary(adapter).probe_full_health(WorkloadRef(adapter.namespace, adapter.name))

    def test_full_health_retries_only_transient_observation_errors(self):
        adapter = MemoryAdapter()
        adapter.node_status_transient_once = True
        result = CrdbLibrary(adapter).wait_for_full_health(
            WorkloadRef(adapter.namespace, adapter.name), timeout=0.2, poll_interval=0.001
        )
        self.assertEqual(result.status, ProbeStatus.SATISFIED)
        self.assertEqual(result.attempts, 2)

        adapter = MemoryAdapter()
        adapter.node_status_error = KubernetesAccessError("node status read denied")
        with self.assertRaises(KubernetesAccessError):
            CrdbLibrary(adapter).wait_for_full_health(
                WorkloadRef(adapter.namespace, adapter.name), timeout=0.2, poll_interval=0.001
            )
        self.assertEqual(len(adapter.node_status_calls), 1)

    def test_exact_health_sentinel_means_deployed_before_sql(self):
        adapter = MemoryAdapter(initialized=False)
        adapter.query_error = TransientError("SQL is not accepting connections yet")
        adapter.http_status["/health?ready=1"] = 503
        adapter.http_body["/health?ready=1"] = json.dumps(
            {"error": "node is waiting for cluster initialization"}
        )
        result = CrdbLibrary(adapter).probe(
            WorkloadRef(adapter.namespace, adapter.name), Requirement(Lifecycle.DEPLOYED)
        )
        self.assertEqual(result.status, ProbeStatus.SATISFIED)
        self.assertEqual(result.health.lifecycle, Lifecycle.DEPLOYED)
        self.assertEqual(result.health.uninitialized_pods, ("db-0", "db-1"))
        self.assertEqual(
            [call["path"] for call in adapter.http_calls],
            ["/health?ready=1", "/health?ready=1"],
        )
        self.assertEqual(adapter.queried_sql_hosts, [])

    def test_unrelated_http_503_remains_transient_error(self):
        adapter = MemoryAdapter(initialized=False)
        adapter.query_error = TransientError("SQL is not accepting connections yet")
        adapter.http_status["/health?ready=1"] = 503
        adapter.http_body["/health?ready=1"] = json.dumps({"error": "some other failure"})
        with self.assertRaises(TransientError):
            CrdbLibrary(adapter).probe(
                WorkloadRef(adapter.namespace, adapter.name), Requirement(Lifecycle.DEPLOYED)
            )
        self.assertEqual(adapter.queried_sql_hosts, [])

    def test_http_api_error_before_sql_propagates(self):
        adapter = MemoryAdapter(initialized=False)
        adapter.query_error = TransientError("SQL is not accepting connections yet")
        adapter.http_error = KubernetesAccessError("health exec denied")
        with self.assertRaises(KubernetesAccessError):
            CrdbLibrary(adapter).probe(
                WorkloadRef(adapter.namespace, adapter.name), Requirement(Lifecycle.DEPLOYED)
            )
        self.assertEqual(adapter.queried_sql_hosts, [])

    def test_http_authentication_status_is_not_treated_as_preinit(self):
        adapter = MemoryAdapter(initialized=False)
        adapter.http_status["/health?ready=1"] = 403
        with self.assertRaises(AuthenticationError):
            CrdbLibrary(adapter).probe(
                WorkloadRef(adapter.namespace, adapter.name), Requirement(Lifecycle.DEPLOYED)
            )
        self.assertEqual(adapter.queried_sql_hosts, [])

    def test_unexpected_readiness_status_is_a_typed_redacted_connection_error(self):
        adapter = MemoryAdapter(initialized=False)
        adapter.http_status["/health?ready=1"] = 400
        adapter.http_body["/health?ready=1"] = '{"secret":"http-body-sentinel"}'

        with self.assertRaises(ConnectionError) as raised:
            CrdbLibrary(adapter).probe(
                WorkloadRef(adapter.namespace, adapter.name), Requirement(Lifecycle.DEPLOYED)
            )

        self.assertEqual(raised.exception.code, ErrorCode.CONNECTION)
        self.assertNotIn("http-body-sentinel", "".join(traceback.format_exception(raised.exception)))
        self.assertEqual(adapter.queried_sql_hosts, [])

    def test_malformed_read_only_witness_is_a_typed_redacted_connection_error(self):
        adapter = MemoryAdapter()
        secret = "malformed-witness-secret-sentinel"
        original_query = adapter.query_sql

        def query_sql(**kwargs):
            if "crdb_internal.cluster_id()" in kwargs["sql"]:
                return f"unexpected_header\n{secret}\n"
            return original_query(**kwargs)

        with patch.object(adapter, "query_sql", side_effect=query_sql):
            with self.assertRaises(ConnectionError) as raised:
                CrdbLibrary(adapter).probe(
                    WorkloadRef(adapter.namespace, adapter.name), Requirement(Lifecycle.INITIALIZED)
                )

        self.assertEqual(raised.exception.code, ErrorCode.CONNECTION)
        self.assertNotIn(secret, "".join(traceback.format_exception(raised.exception)))

    def test_advertise_addr_and_sql_specific_address_patterns_are_supported(self):
        adapter = MemoryAdapter()
        container = adapter.sts["spec"]["template"]["spec"]["containers"][0]
        command = container["command"][2].replace(
            "--advertise-host=$(POD_NAME).db.$(POD_NAMESPACE).svc.cluster.local",
            "--advertise-addr=$(POD_NAME).db.$(POD_NAMESPACE).svc.cluster.local:26300",
        )
        container["command"][2] = command
        for pod in adapter.pods:
            pod["spec"]["containers"][0]["command"] = copy.deepcopy(container["command"])
        assessment = CrdbLibrary(adapter).probe(
            WorkloadRef(adapter.namespace, adapter.name), Requirement(Lifecycle.INITIALIZED)
        )
        self.assertEqual(assessment.status, ProbeStatus.SATISFIED)
        self.assertEqual(adapter.queried_sql_hosts[0], "db-0.db.crdb-fixture.svc.cluster.local")

        adapter = MemoryAdapter()
        container = adapter.sts["spec"]["template"]["spec"]["containers"][0]
        container["command"][2] += " --advertise-sql-addr=$(POD_NAME).sql.$(POD_NAMESPACE).svc.cluster.local:26270"
        adapter.services.append(
            {
                "metadata": {
                    "name": "sql",
                    "namespace": adapter.namespace,
                    "uid": "svc-sql",
                    "resourceVersion": "5",
                },
                "spec": {
                    "clusterIP": "None",
                    "selector": {"app": "cockroach", "instance": adapter.name},
                    "ports": [{"name": "sql", "port": 26270, "targetPort": "sql"}],
                },
            }
        )
        for pod in adapter.pods:
            pod["spec"]["containers"][0]["command"] = copy.deepcopy(container["command"])
        assessment = CrdbLibrary(adapter).probe(
            WorkloadRef(adapter.namespace, adapter.name), Requirement(Lifecycle.INITIALIZED)
        )
        self.assertEqual(assessment.status, ProbeStatus.SATISFIED)
        self.assertEqual(adapter.queried_sql_hosts[0], "db-0.sql.crdb-fixture.svc.cluster.local")

    def test_literal_advertised_dns_is_supported_only_for_a_singleton(self):
        adapter = MemoryAdapter(replicas=1)
        container = adapter.sts["spec"]["template"]["spec"]["containers"][0]
        container["command"][2] = container["command"][2].replace(
            "--advertise-host=$(POD_NAME).db.$(POD_NAMESPACE).svc.cluster.local",
            "--advertise-host=db.crdb-fixture.svc.cluster.local",
        )
        for pod in adapter.pods:
            pod["spec"]["containers"][0]["command"] = copy.deepcopy(container["command"])
        assessment = CrdbLibrary(adapter).probe(
            WorkloadRef(adapter.namespace, adapter.name), Requirement(Lifecycle.INITIALIZED)
        )
        self.assertEqual(assessment.status, ProbeStatus.SATISFIED)
        self.assertEqual(adapter.queried_sql_hosts, ["db.crdb-fixture.svc.cluster.local"])

        adapter = MemoryAdapter(replicas=2)
        container = adapter.sts["spec"]["template"]["spec"]["containers"][0]
        container["command"][2] = container["command"][2].replace(
            "--advertise-host=$(POD_NAME).db.$(POD_NAMESPACE).svc.cluster.local",
            "--advertise-host=db.crdb-fixture.svc.cluster.local",
        )
        for pod in adapter.pods:
            pod["spec"]["containers"][0]["command"] = copy.deepcopy(container["command"])
        with self.assertRaises(UnsupportedLayoutError):
            CrdbLibrary(adapter).probe(
                WorkloadRef(adapter.namespace, adapter.name), Requirement(Lifecycle.INITIALIZED)
            )
        self.assertEqual(adapter.queried_sql_hosts, [])

    def test_sql_probe_refuses_unknown_advertised_host_without_querying(self):
        adapter = MemoryAdapter()
        container = adapter.sts["spec"]["template"]["spec"]["containers"][0]
        container["command"][2] = " ".join(
            token for token in container["command"][2].split() if not token.startswith("--advertise-host=")
        )
        for pod in adapter.pods:
            pod["spec"]["containers"][0]["command"] = copy.deepcopy(container["command"])
        with self.assertRaises(UnsupportedLayoutError):
            CrdbLibrary(adapter).probe(
                WorkloadRef(adapter.namespace, adapter.name), Requirement(Lifecycle.INITIALIZED)
            )
        self.assertEqual(adapter.queried_sql_hosts, [])

    def test_declared_ports_do_not_override_native_listener_defaults(self):
        adapter = MemoryAdapter(custom_ports=False)
        container = adapter.sts["spec"]["template"]["spec"]["containers"][0]
        command_script = container["command"][2]
        command_script = " ".join(
            token
            for token in command_script.split()
            if not token.startswith(("--sql-addr=", "--listen-addr=", "--http-addr=", "--port="))
        )
        container["command"][2] = command_script
        container["ports"] = [
            {"name": "sql", "containerPort": 9991},
            {"name": "grpc", "containerPort": 9992},
            {"name": "http", "containerPort": 9993},
        ]
        for pod in adapter.pods:
            pod["spec"]["containers"][0]["command"] = copy.deepcopy(container["command"])
            pod["spec"]["containers"][0]["ports"] = copy.deepcopy(container["ports"])
        observation = CrdbLibrary(adapter).inspect(WorkloadRef(adapter.namespace, adapter.name))
        self.assertEqual((observation.sql_port, observation.rpc_port, observation.http_port), (26257, 26257, 8080))
        self.assertEqual((observation.sql_port_name, observation.rpc_port_name, observation.http_port_name), (None, None, None))

    def test_sql_addr_and_listen_addr_resolve_separately(self):
        adapter = MemoryAdapter()
        observation = CrdbLibrary(adapter).inspect(WorkloadRef(adapter.namespace, adapter.name))
        self.assertEqual(observation.sql_port, 26270)
        self.assertEqual(observation.rpc_port, 26300)

    def test_uninitialized_cluster_meets_deployed_without_implicit_initialization(self):
        adapter = MemoryAdapter(initialized=False)
        library = CrdbLibrary(adapter)
        deployed = library.probe(WorkloadRef(adapter.namespace, adapter.name), Requirement(Lifecycle.DEPLOYED))
        initialized = library.probe(WorkloadRef(adapter.namespace, adapter.name), Requirement(Lifecycle.INITIALIZED))
        self.assertEqual(deployed.status, ProbeStatus.SATISFIED)
        self.assertEqual(initialized.status, ProbeStatus.UNSATISFIED)
        self.assertEqual(initialized.health.uninitialized_pods, ("db-0", "db-1"))
        self.assertEqual(adapter.patch_calls, [])

    def test_insecure_inspection_does_not_fetch_unrelated_secret_environment(self):
        adapter = MemoryAdapter()
        container = adapter.sts["spec"]["template"]["spec"]["containers"][0]
        container["env"].append(
            {"name": "DB_PASSWORD", "valueFrom": {"secretKeyRef": {"name": "unrelated", "key": "password"}}}
        )
        for pod in adapter.pods:
            pod["spec"]["containers"][0]["env"] = copy.deepcopy(container["env"])
        observation = CrdbLibrary(adapter).inspect(WorkloadRef(adapter.namespace, adapter.name))
        self.assertEqual(observation.secrets, ())
        self.assertEqual(adapter.fingerprint_calls, [])
        self.assertTrue(any(item.secret_name == "unrelated" for item in observation.env_references))

    def test_projected_tls_secret_is_supported_but_subpath_is_not(self):
        adapter = MemoryAdapter(tls=True)
        sts_volumes = adapter.sts["spec"]["template"]["spec"]["volumes"]
        sts_volumes[0] = {"name": "certs", "projected": {"sources": [{"secret": {"name": "db-certs"}}]}}
        for pod in adapter.pods:
            pod["spec"]["volumes"][0] = copy.deepcopy(sts_volumes[0])
        observation = CrdbLibrary(adapter).inspect(WorkloadRef(adapter.namespace, adapter.name))
        self.assertEqual(observation.tls_mode, TLSMode.TLS)
        self.assertEqual(adapter.fingerprint_calls, ["db-certs"])
        adapter.sts["spec"]["template"]["spec"]["containers"][0]["volumeMounts"][1]["subPath"] = "node.crt"
        for pod in adapter.pods:
            pod["spec"]["containers"][0]["volumeMounts"][1]["subPath"] = "node.crt"
        with self.assertRaises(UnsupportedLayoutError):
            CrdbLibrary(adapter).inspect(WorkloadRef(adapter.namespace, adapter.name))

    def test_startup_newline_is_not_misread_as_a_continued_flag_list(self):
        adapter = MemoryAdapter()
        container = adapter.sts["spec"]["template"]["spec"]["containers"][0]
        container["command"][2] = "exec /cockroach/cockroach start\n--insecure"
        for pod in adapter.pods:
            pod["spec"]["containers"][0]["command"] = copy.deepcopy(container["command"])
        with self.assertRaises(UnsupportedLayoutError):
            CrdbLibrary(adapter).inspect(WorkloadRef(adapter.namespace, adapter.name))

    def test_unknown_tls_and_ambiguous_cert_mounts_fail_closed(self):
        adapter = MemoryAdapter(tls=True)
        container = adapter.sts["spec"]["template"]["spec"]["containers"][0]
        container["command"][2] = container["command"][2].replace("--certs-dir=/cockroach/cockroach-certs", "")
        for pod in adapter.pods:
            pod["spec"]["containers"][0]["command"] = copy.deepcopy(container["command"])
        with self.assertRaises(UnsupportedLayoutError):
            CrdbLibrary(adapter).probe(WorkloadRef(adapter.namespace, adapter.name), Requirement(Lifecycle.DEPLOYED))
        adapter = MemoryAdapter(tls=True)
        container = adapter.sts["spec"]["template"]["spec"]["containers"][0]
        container["volumeMounts"].append(copy.deepcopy(container["volumeMounts"][1]))
        for pod in adapter.pods:
            pod["spec"]["containers"][0]["volumeMounts"] = copy.deepcopy(container["volumeMounts"])
        with self.assertRaises(UnsupportedLayoutError):
            CrdbLibrary(adapter).inspect(WorkloadRef(adapter.namespace, adapter.name))

    def test_accepted_snapshot_and_scoped_http_probe_preparation(self):
        adapter = MemoryAdapter()
        library = CrdbLibrary(adapter)
        ref = WorkloadRef(adapter.namespace, adapter.name)
        before = library.capture_accepted_state(ref)
        result = library.prepare_health_recovery_probes(ref, timeout=1, poll_interval=0.01)
        self.assertTrue(result.changed)
        self.assertEqual(len(adapter.patch_calls), 1)
        patch_ops = adapter.patch_calls[0]
        self.assertEqual(patch_ops[0], {"op": "test", "path": "/metadata/uid", "value": "sts-db-uid"})
        self.assertEqual(patch_ops[1], {"op": "test", "path": "/metadata/resourceVersion", "value": "10"})
        self.assertTrue(any(operation["path"].endswith("/httpGet") and operation["op"] == "add" for operation in patch_ops[2:]))
        self.assertEqual(result.after.liveness_probe.path, "/health")
        self.assertEqual(result.after.readiness_probe.path, "/health?ready=1")
        self.assertEqual(result.after.liveness_probe.port, "http")
        self.assertEqual(result.after.liveness_probe.scheme, "HTTP")
        self.assertEqual(result.after.liveness_probe.initial_delay_seconds, 17)
        self.assertEqual(result.after.readiness_probe.period_seconds, 4)
        after = library.capture_accepted_state(ref)
        self.assertNotEqual(before.workload_spec_hash, after.workload_spec_hash)
        self.assertEqual(before.cluster_id, after.cluster_id)
        self.assertEqual(before.node_ids, after.node_ids)
        self.assertEqual(before.pvc_identities, after.pvc_identities)
        self.assertEqual(before.service_routing, after.service_routing)
        self.assertEqual(before.certificate_fingerprints, after.certificate_fingerprints)
        self.assertEqual(len(library.verify_accepted_state(ref, after).health.node_ids), 2)

    def test_secure_probe_preparation_preserves_tls_with_https_handlers(self):
        adapter = MemoryAdapter(tls=True)
        result = CrdbLibrary(adapter).prepare_health_recovery_probes(
            WorkloadRef(adapter.namespace, adapter.name), timeout=1, poll_interval=0.01
        )
        self.assertEqual(result.after.tls_mode, TLSMode.TLS)
        self.assertEqual(result.after.liveness_probe.scheme, "HTTPS")
        self.assertEqual(result.after.readiness_probe.scheme, "HTTPS")
        self.assertEqual(result.after.certs_dir, "/cockroach/cockroach-certs")

    def test_preparation_preflights_both_http_endpoints_before_patch(self):
        adapter = MemoryAdapter()
        adapter.http_status["/health?ready=1"] = 503
        with self.assertRaises(Exception):
            CrdbLibrary(adapter).prepare_health_recovery_probes(
                WorkloadRef(adapter.namespace, adapter.name), timeout=0.2
            )
        self.assertEqual(adapter.patch_calls, [])

    def test_already_prepared_handlers_are_a_noop(self):
        adapter = MemoryAdapter()
        for container in [adapter.sts["spec"]["template"]["spec"]["containers"][0]] + [
            pod["spec"]["containers"][0] for pod in adapter.pods
        ]:
            container["livenessProbe"]["httpGet"] = {"path": "/health", "port": "http", "scheme": "HTTP"}
            container["readinessProbe"] = {
                **{key: value for key, value in container["readinessProbe"].items() if key != "tcpSocket"},
                "httpGet": {"path": "/health?ready=1", "port": "http", "scheme": "HTTP"},
            }
        result = CrdbLibrary(adapter).prepare_health_recovery_probes(
            WorkloadRef(adapter.namespace, adapter.name), timeout=0.2
        )
        self.assertFalse(result.changed)
        self.assertEqual(adapter.patch_calls, [])
        self.assertEqual(result.accepted_before, result.accepted_after)

    def test_semantically_equivalent_http_probe_ports_and_defaults_are_noop(self):
        for port in (8082, "http"):
            with self.subTest(port=port):
                adapter = MemoryAdapter()
                containers = [adapter.sts["spec"]["template"]["spec"]["containers"][0]] + [
                    pod["spec"]["containers"][0] for pod in adapter.pods
                ]
                for container in containers:
                    container["livenessProbe"]["httpGet"] = {
                        "path": "/health",
                        "port": port,
                        "host": "",
                        "httpHeaders": [],
                    }
                    container["readinessProbe"] = {
                        **{key: value for key, value in container["readinessProbe"].items() if key != "tcpSocket"},
                        "httpGet": {
                            "path": "/health?ready=1",
                            "port": port,
                            "host": "",
                            "httpHeaders": [],
                        },
                    }
                original_spec = copy.deepcopy(adapter.sts["spec"])

                result = CrdbLibrary(adapter).prepare_health_recovery_probes(
                    WorkloadRef(adapter.namespace, adapter.name), timeout=0.2
                )

                self.assertFalse(result.changed)
                self.assertEqual(adapter.patch_calls, [])
                self.assertEqual(adapter.sts["spec"], original_spec)
                self.assertTrue(CrdbLibrary.health_recovery_probes_prepared(result.after))

    def test_semantically_equivalent_https_numeric_probe_port_is_noop(self):
        adapter = MemoryAdapter(tls=True)
        containers = [adapter.sts["spec"]["template"]["spec"]["containers"][0]] + [
            pod["spec"]["containers"][0] for pod in adapter.pods
        ]
        for container in containers:
            container["livenessProbe"]["httpGet"] = {
                "path": "/health", "port": 8082, "scheme": "HTTPS"
            }
            container["readinessProbe"] = {
                **{key: value for key, value in container["readinessProbe"].items() if key != "tcpSocket"},
                "httpGet": {"path": "/health?ready=1", "port": 8082, "scheme": "HTTPS"},
            }
        original_spec = copy.deepcopy(adapter.sts["spec"])

        result = CrdbLibrary(adapter).prepare_health_recovery_probes(
            WorkloadRef(adapter.namespace, adapter.name), timeout=0.2
        )

        self.assertFalse(result.changed)
        self.assertEqual(adapter.patch_calls, [])
        self.assertEqual(adapter.sts["spec"], original_spec)
        self.assertTrue(CrdbLibrary.health_recovery_probes_prepared(result.after))

    def test_health_recovery_probe_predicate_is_read_only_and_checks_actual_handlers(self):
        adapter = MemoryAdapter()
        library = CrdbLibrary(adapter)
        ref = WorkloadRef(adapter.namespace, adapter.name)
        observed = library.inspect(ref)
        self.assertFalse(CrdbLibrary.health_recovery_probes_prepared(observed))

        prepared = replace(
            observed,
            liveness_probe=replace(
                observed.liveness_probe,
                handler="httpGet", path="/health", port="http", scheme="HTTP", host=None,
            ),
            readiness_probe=replace(
                observed.readiness_probe,
                handler="httpGet", path="/health?ready=1", port="http", scheme="HTTP", host=None,
            ),
        )
        self.assertTrue(CrdbLibrary.health_recovery_probes_prepared(prepared))

        tcp = replace(prepared, readiness_probe=replace(prepared.readiness_probe, handler="tcpSocket"))
        self.assertFalse(CrdbLibrary.health_recovery_probes_prepared(tcp))
        custom_header = replace(
            prepared, liveness_probe=replace(prepared.liveness_probe, has_custom_headers=True)
        )
        self.assertFalse(CrdbLibrary.health_recovery_probes_prepared(custom_header))
        unknown_tls = replace(prepared, tls_mode=TLSMode.UNKNOWN)
        self.assertFalse(CrdbLibrary.health_recovery_probes_prepared(unknown_tls))
        unknown_http_port = replace(prepared, http_port=None)
        self.assertFalse(CrdbLibrary.health_recovery_probes_prepared(unknown_http_port))
        unknown_http_transport = replace(prepared, http_transport=HTTPTransport.UNKNOWN)
        self.assertFalse(CrdbLibrary.health_recovery_probes_prepared(unknown_http_transport))
        self.assertEqual(adapter.patch_calls, [])

        secure_adapter = MemoryAdapter(tls=True)
        secure_observation = CrdbLibrary(secure_adapter).inspect(
            WorkloadRef(secure_adapter.namespace, secure_adapter.name)
        )
        secure_prepared = replace(
            secure_observation,
            liveness_probe=replace(
                secure_observation.liveness_probe,
                handler="httpGet", path="/health", port="http", scheme="HTTPS", host=None,
            ),
            readiness_probe=replace(
                secure_observation.readiness_probe,
                handler="httpGet", path="/health?ready=1", port="http", scheme="HTTPS", host=None,
            ),
        )
        self.assertTrue(CrdbLibrary.health_recovery_probes_prepared(secure_prepared))
        self.assertEqual(secure_adapter.patch_calls, [])

    def test_authentication_failure_never_falls_back_to_mutation(self):
        adapter = MemoryAdapter()
        adapter.query_error = AuthenticationError("test auth failure")
        with self.assertRaises(AuthenticationError):
            CrdbLibrary(adapter).prepare_health_recovery_probes(WorkloadRef(adapter.namespace, adapter.name), timeout=0.2)
        self.assertEqual(adapter.patch_calls, [])

    def test_stale_statefulset_identity_is_rejected_before_mutation(self):
        adapter = MemoryAdapter()
        adapter.mutate_before_second_sts_read = True
        with self.assertRaises(StaleIdentityError):
            CrdbLibrary(adapter).prepare_health_recovery_probes(WorkloadRef(adapter.namespace, adapter.name), timeout=0.2)
        self.assertEqual(adapter.patch_calls, [])

    def test_full_accepted_spec_detects_unrelated_template_change(self):
        adapter = MemoryAdapter()
        library = CrdbLibrary(adapter)
        ref = WorkloadRef(adapter.namespace, adapter.name)
        accepted = library.capture_accepted_state(ref)
        adapter.sts["spec"]["template"]["spec"]["containers"][0]["resources"]["requests"]["cpu"] = "200m"
        for pod in adapter.pods:
            pod["spec"]["containers"][0]["resources"]["requests"]["cpu"] = "200m"
        with self.assertRaises(PreservationMismatchError):
            library.verify_accepted_state(ref, accepted)

    def test_full_accepted_spec_detects_probe_change_and_noop_reconcile_preserves_state(self):
        adapter = MemoryAdapter()
        library = CrdbLibrary(adapter)
        ref = WorkloadRef(adapter.namespace, adapter.name)
        accepted = library.capture_accepted_state(ref)
        no_op = library.reconcile(
            ref, Requirement(Lifecycle.INITIALIZED), accepted_state=accepted, timeout=0.1
        )
        self.assertEqual(no_op.assessment.status, ProbeStatus.SATISFIED)
        self.assertFalse(no_op.changed_by_library)
        self.assertEqual(adapter.patch_calls, [])
        self.assertEqual(library.inspect(ref).workload_spec_hash, accepted.workload_spec_hash)
        probe = adapter.sts["spec"]["template"]["spec"]["containers"][0]["readinessProbe"]
        probe["tcpSocket"] = {"port": "grpc"}
        for pod in adapter.pods:
            pod["spec"]["containers"][0]["readinessProbe"] = copy.deepcopy(probe)
        with self.assertRaises(PreservationMismatchError):
            library.verify_accepted_state(ref, accepted)

    def test_controller_owned_ondelete_and_partitioned_workloads_are_not_mutated(self):
        for mutation in (
            lambda adapter: adapter.sts["metadata"].update({"ownerReferences": [{"uid": "owner", "controller": True}]}),
            lambda adapter: adapter.sts["spec"].update({"updateStrategy": {"type": "OnDelete"}}),
            lambda adapter: adapter.sts["spec"].update({"updateStrategy": {"type": "RollingUpdate", "rollingUpdate": {"partition": 1}}}),
        ):
            adapter = MemoryAdapter()
            mutation(adapter)
            with self.assertRaises(UnsupportedLayoutError):
                CrdbLibrary(adapter).prepare_health_recovery_probes(
                    WorkloadRef(adapter.namespace, adapter.name), timeout=0.2
                )
            self.assertEqual(adapter.patch_calls, [])

    def test_requirement_types_and_dns_identities_are_validated(self):
        from cases.common.cockroachdb.types import InvalidRequirementError

        with self.assertRaises(InvalidRequirementError):
            Requirement(Lifecycle.DEPLOYED, minimum_nodes=True)
        with self.assertRaises(InvalidRequirementError):
            WorkloadRef("-bad", "db")
        with self.assertRaises(InvalidRequirementError):
            Requirement("deployed")

    def test_observation_and_cli_never_expose_startup_or_multiline_env_secrets(self):
        from cases.common.cockroachdb.cli import main

        adapter = MemoryAdapter()
        container = adapter.sts["spec"]["template"]["spec"]["containers"][0]
        container["command"][2] += " --password private-value --token 'quoted private token'"
        private_key = "-----BEGIN PRIVATE KEY-----\nprivate-key-body-91c0\n-----END PRIVATE KEY-----"
        container["env"].append({"name": "PRIVATE_KEY", "value": private_key})
        for pod in adapter.pods:
            pod["spec"]["containers"][0]["command"] = copy.deepcopy(container["command"])
            pod["spec"]["containers"][0]["env"] = copy.deepcopy(container["env"])
        observation = CrdbLibrary(adapter).inspect(WorkloadRef(adapter.namespace, adapter.name))
        self.assertNotIn("private-value", repr(observation))
        self.assertNotIn("quoted private token", repr(observation))
        self.assertNotIn("private-key-body-91c0", repr(observation))
        cli_out = io.StringIO()
        with patch("cases.common.cockroachdb.cli.KubectlAdapter", return_value=adapter), contextlib.redirect_stdout(cli_out):
            self.assertEqual(main(["inspect", "--namespace", adapter.namespace, "--statefulset", adapter.name]), 0)
        self.assertNotIn("private-value", cli_out.getvalue())
        self.assertNotIn("quoted private token", cli_out.getvalue())
        self.assertNotIn("private-key-body-91c0", cli_out.getvalue())

    def test_probe_sql_interface_rejects_arbitrary_statements(self):
        from cases.common.cockroachdb.types import InvalidRequirementError

        adapter = KubectlAdapter()
        with self.assertRaises(UnsupportedLayoutError):
            adapter.query_sql(
                namespace="ns", pod_name="db-0", container_name="db", binary="cockroach",
                sql_host="db-0.db.ns.svc.cluster.local", sql_port=26257, tls_mode="insecure", certs_dir=None,
                sql="SELECT 1; RESET CLUSTER SETTING sql.defaults.distsql",
                timeout=1,
            )

    def test_read_only_witness_has_stable_csv_aliases(self):
        from cases.common.cockroachdb.adapter import _READ_ONLY_SQL
        from cases.common.cockroachdb.library import _WITNESS_SQL, _parse_witness

        self.assertEqual(_WITNESS_SQL, _READ_ONLY_SQL)
        self.assertEqual(
            _parse_witness("cluster_id,node_id,version\na2506905-9598-4967-92a5-1e45668f9c67,1,v24.1.4\n"),
            (_CLUSTER_ID, 1, "v24.1.4"),
        )
        adapter = KubectlAdapter()
        success = subprocess.CompletedProcess(args=[], returncode=0, stdout="cluster_id,node_id,version\n", stderr="")
        with patch.object(adapter, "_exec", return_value=success) as run:
            adapter.query_sql(
                namespace="ns", pod_name="db-0", container_name="db", binary="cockroach",
                sql_host="db-0.db.ns.svc.cluster.local", sql_port=26257, tls_mode="insecure", certs_dir=None,
                sql=_READ_ONLY_SQL, timeout=1,
            )
        self.assertEqual(run.call_args.args[3][-1], _READ_ONLY_SQL)


class CliTests(unittest.TestCase):
    def test_cli_capture_verify_roundtrip_and_exit_codes(self):
        from cases.common.cockroachdb.cli import main

        adapter = MemoryAdapter()
        with patch("cases.common.cockroachdb.cli.KubectlAdapter", return_value=adapter):
            with tempfile.TemporaryDirectory() as tempdir:
                state_file = f"{tempdir}/accepted.json"
                capture_out = io.StringIO()
                with contextlib.redirect_stdout(capture_out):
                    self.assertEqual(main(["capture", "--namespace", adapter.namespace, "--statefulset", adapter.name]), 0)
                with open(state_file, "w", encoding="utf-8") as stream:
                    stream.write(capture_out.getvalue())
                verify_out = io.StringIO()
                with contextlib.redirect_stdout(verify_out):
                    self.assertEqual(
                        main(["verify", "--namespace", adapter.namespace, "--statefulset", adapter.name, "--accepted-state", state_file]),
                        0,
                    )
            adapter.initialized = False
            unsatisfied = io.StringIO()
            with contextlib.redirect_stdout(unsatisfied):
                self.assertEqual(
                    main(["reconcile", "--namespace", adapter.namespace, "--statefulset", adapter.name,
                          "--lifecycle", "initialized", "--timeout", "0"]),
                    1,
                )
            adapter.query_error = AuthenticationError("test")
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(
                    main(["probe", "--namespace", adapter.namespace, "--statefulset", adapter.name]),
                    2,
                )

    def test_reconcile_retries_bounded_rollout_observation(self):
        adapter = MemoryAdapter()
        adapter.rollout_once = True
        result = CrdbLibrary(adapter).reconcile(
            WorkloadRef(adapter.namespace, adapter.name),
            Requirement(Lifecycle.INITIALIZED),
            timeout=1,
            poll_interval=0.01,
        )
        self.assertEqual(result.assessment.status, ProbeStatus.SATISFIED)
        self.assertGreaterEqual(result.attempts, 1)

    def test_reconcile_retries_pending_pod_set_and_one_sql_transport_failure(self):
        adapter = MemoryAdapter()
        adapter.pending_pod_set_once = True
        adapter.transient_query_once = True
        result = CrdbLibrary(adapter).reconcile(
            WorkloadRef(adapter.namespace, adapter.name),
            Requirement(Lifecycle.INITIALIZED),
            timeout=0.2,
            poll_interval=0.001,
        )
        self.assertEqual(result.assessment.status, ProbeStatus.SATISFIED)
        self.assertGreaterEqual(result.attempts, 3)


class KubectlAdapterTests(unittest.TestCase):
    def test_connection_classifier_retries_only_rollout_network_failures(self):
        self.assertIsInstance(
            KubectlAdapter._connection_error(
                'Error from server (NotFound): pods "db-0" not found', command_name="cockroach"
            ),
            TransientError,
        )
        self.assertIsInstance(
            KubectlAdapter._connection_error(
                "dial tcp: lookup db-0.db.ns.svc: no such host", command_name="cockroach"
            ),
            TransientError,
        )
        self.assertIsInstance(
            KubectlAdapter._connection_error("certificate authentication failed", command_name="cockroach"),
            AuthenticationError,
        )
        self.assertIsInstance(
            KubectlAdapter._connection_error("hint: TLS is disabled with --insecure", command_name="cockroach"),
            ConnectionError,
        )
        self.assertNotEqual(
            str(KubectlAdapter._connection_error("hint: TLS is disabled with --insecure", command_name="cockroach")),
            "CockroachDB TLS connection failed",
        )

    def test_sql_diagnostics_are_bounded_and_redacted(self):
        insecure = KubectlAdapter._connection_error(
            "ERROR: startup TLS hint; password=do-not-log\n"
            "-----BEGIN PRIVATE KEY-----\nprivate-material\n-----END PRIVATE KEY-----",
            command_name="cockroach",
            tls_mode="insecure",
            endpoint="db-0.db.ns.svc.cluster.local:26257",
        )
        self.assertIn("startup TLS hint", str(insecure))
        self.assertIn("db-0.db.ns.svc.cluster.local:26257", str(insecure))
        self.assertNotIn("do-not-log", str(insecure))
        self.assertNotIn("private-material", str(insecure))
        self.assertLessEqual(len(str(insecure)), 650)

        secure = KubectlAdapter._connection_error(
            "x509: certificate signed by unknown authority; private-material",
            command_name="cockroach",
            tls_mode="tls",
            endpoint="db-0.db.ns.svc.cluster.local:26257",
        )
        self.assertIn("certificate validation", str(secure))
        self.assertNotIn("private-material", str(secure))

    def test_sql_command_uses_explicit_insecure_endpoint_and_fixed_read_only_query(self):
        from cases.common.cockroachdb.adapter import _READ_ONLY_SQL

        adapter = KubectlAdapter()
        success = subprocess.CompletedProcess(args=[], returncode=0, stdout="cluster_id,node_id,version\n", stderr="")
        with patch.object(adapter, "_exec", return_value=success) as run:
            adapter.query_sql(
                namespace="ns", pod_name="db-0", container_name="db", binary="/cockroach/cockroach",
                sql_host="db-0.db.ns.svc.cluster.local", sql_port=26257, tls_mode="insecure", certs_dir=None,
                sql=_READ_ONLY_SQL, timeout=2.5,
            )
        argv = run.call_args.args[3]
        self.assertEqual(
            argv,
            [
                "/cockroach/cockroach", "sql", "--insecure",
                "--host=db-0.db.ns.svc.cluster.local", "--port=26257", "--format=csv",
                "-e", _READ_ONLY_SQL,
            ],
        )

    def test_full_health_adapter_uses_sql_port_for_fixed_status_and_liveness_reads(self):
        from cases.common.cockroachdb.adapter import _READ_ONLY_LIVENESS_SQL

        adapter = KubectlAdapter()
        success = subprocess.CompletedProcess(args=[], returncode=0, stdout="id,membership\n", stderr="")
        common = {
            "namespace": "ns",
            "pod_name": "db-0",
            "container_name": "db",
            "binary": "/cockroach/cockroach",
            "sql_host": "db-0.db.ns.svc.cluster.local",
            "sql_port": 26270,
            "tls_mode": "insecure",
            "certs_dir": None,
            "timeout": 1.0,
        }
        with patch.object(adapter, "_exec", return_value=success) as run:
            adapter.node_status(**common)
        status_argv = run.call_args.args[3]
        self.assertEqual(
            status_argv,
            [
                "/cockroach/cockroach",
                "node",
                "status",
                "--all",
                "--insecure",
                "--host=db-0.db.ns.svc.cluster.local",
                "--port=26270",
                "--format=csv",
            ],
        )
        self.assertNotIn("26300", status_argv)

        with patch.object(adapter, "_exec", return_value=success) as run:
            adapter.query_sql(**common, sql=_READ_ONLY_LIVENESS_SQL)
        sql_argv = run.call_args.args[3]
        self.assertIn("--port=26270", sql_argv)
        self.assertEqual(sql_argv[-1], _READ_ONLY_LIVENESS_SQL)
        with self.assertRaises(UnsupportedLayoutError):
            adapter.query_sql(**common, sql="SELECT now();")

    def test_native_identity_http_cookie_stays_on_stdin_and_secure_sql_auth_is_used_for_http(self):
        adapter = KubectlAdapter()
        session = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="session=source-shaped_cookie-123; Path=/; HttpOnly; SameSite=Strict\n",
            stderr="",
        )
        node = subprocess.CompletedProcess(args=[], returncode=0, stdout='{"nodeId":7}\n200', stderr="")
        cluster = subprocess.CompletedProcess(args=[], returncode=0, stdout=f'{{"clusterId":"{_CLUSTER_ID}"}}\n200', stderr="")
        with patch("cases.common.cockroachdb.adapter.subprocess.run", side_effect=[session, node, cluster]) as run:
            identity = adapter.native_identity(
                namespace="ns",
                pod_name="db-0",
                pod_uid="pod-uid-7",
                container_name="db",
                binary="/cockroach/cockroach",
                sql_host="db-0.db.ns.svc.cluster.local",
                sql_port=26257,
                tls_mode="tls",
                certs_dir="/cockroach/cockroach-certs",
                http_port=8080,
                http_transport="http",
                client_cert_available=True,
                auth_scope="secret-fingerprint-scope",
                timeout=2,
            )

        self.assertEqual(identity, (7, _CLUSTER_ID))
        login_command = run.call_args_list[0].args[0]
        login_argv = login_command[login_command.index("--") + 1:]
        self.assertEqual(login_argv[1:5], ["auth-session", "login", "root", "--only-cookie"])
        self.assertIn("--expire-after=45s", login_argv)
        self.assertIn("--url=postgresql://root@db-0.db.ns.svc.cluster.local:26257/", login_argv[-1])
        self.assertNotIn("-i", login_command)
        for call in run.call_args_list[1:]:
            command = call.args[0]
            self.assertIn("exec", command)
            self.assertIn("-i", command)
            inner = command[command.index("--") + 1:]
            self.assertEqual(inner[0], "curl")
            self.assertIn("--config", inner)
            self.assertNotIn("source-shaped_cookie-123", " ".join(command))
            self.assertEqual(call.kwargs["input"], 'header = "Cookie: session=source-shaped_cookie-123"\n')
            self.assertNotIn("--cert", inner)  # HTTP is local/plain while SQL stays secure.
            self.assertTrue(inner[-1].startswith("http://localhost:8080/"))

    def test_native_http_statuses_are_typed_safe_and_never_relogin(self):
        cases = (
            (401, AuthenticationError),
            (403, AuthenticationError),
            (404, UnsupportedLayoutError),
            (503, TransientError),
        )
        for status, error_type in cases:
            with self.subTest(status=status):
                adapter = KubectlAdapter()
                login = subprocess.CompletedProcess(
                    args=[], returncode=0, stdout="session=native-http-status-token; Path=/\n", stderr=""
                )
                response = subprocess.CompletedProcess(
                    args=[], returncode=0, stdout=f'{{"secret":"private-{status}"}}\n{status}', stderr=""
                )
                with patch("cases.common.cockroachdb.adapter.subprocess.run", side_effect=[login, response]) as run:
                    with self.assertRaises(error_type) as raised:
                        adapter.native_identity(
                            namespace="ns", pod_name="db-0", pod_uid="pod-a", container_name="db",
                            binary="/cockroach/cockroach", sql_host="db-0.db.ns.svc.cluster.local",
                            sql_port=26257, tls_mode="tls", certs_dir="/certs", http_port=8080,
                            http_transport="http", client_cert_available=True, auth_scope="scope", timeout=2,
                        )
                rendered = "".join(traceback.format_exception(raised.exception))
                self.assertNotIn("native-http-status-token", rendered)
                self.assertNotIn(f"private-{status}", rendered)
                self.assertEqual(run.call_count, 2)  # One login and one endpoint request; no re-login.

    def test_native_http_malformed_body_is_typed_and_redacted(self):
        adapter = KubectlAdapter()
        login = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="session=malformed-body-token; Path=/\n", stderr=""
        )
        response = subprocess.CompletedProcess(
            args=[], returncode=0, stdout='{"private":"malformed-body-sentinel"\n200', stderr=""
        )
        with patch("cases.common.cockroachdb.adapter.subprocess.run", side_effect=[login, response]) as run:
            with self.assertRaises(ConnectionError) as raised:
                adapter.native_identity(
                    namespace="ns", pod_name="db-0", pod_uid="pod-a", container_name="db",
                    binary="/cockroach/cockroach", sql_host="db-0.db.ns.svc.cluster.local",
                    sql_port=26257, tls_mode="tls", certs_dir="/certs", http_port=8080,
                    http_transport="http", client_cert_available=True, auth_scope="scope", timeout=2,
                )
        rendered = "".join(traceback.format_exception(raised.exception))
        self.assertNotIn("malformed-body-token", rendered)
        self.assertNotIn("malformed-body-sentinel", rendered)
        self.assertEqual(run.call_count, 2)

    def test_native_session_cookie_cache_expiry_is_measured_from_login_start(self):
        adapter = KubectlAdapter()
        login = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="session=slow-login-cookie; Path=/\n", stderr=""
        )
        common = {
            "namespace": "ns", "pod_name": "db-0", "container_name": "db",
            "binary": "/cockroach/cockroach", "sql_host": "db-0.db.ns.svc.cluster.local",
            "sql_port": 26257, "certs_dir": "/certs", "auth_scope": "scope", "timeout": 2,
        }
        with patch.object(adapter, "_exec", return_value=login) as login_call, patch(
            "cases.common.cockroachdb.adapter.time.monotonic", side_effect=[100.0, 131.0, 200.0, 201.0]
        ):
            first = adapter._session_cookie(**common, pod_uid="pod-a")
            self.assertEqual(first, "session=slow-login-cookie")
            self.assertEqual(adapter._auth_sessions, {})  # Login consumed the conservative cache window.
            second = adapter._session_cookie(**common, pod_uid="pod-a")
            self.assertEqual(second, first)
            self.assertEqual(login_call.call_count, 2)
            self.assertEqual(adapter._auth_sessions[("ns", "pod-a", "db", "db-0.db.ns.svc.cluster.local", 26257, "scope")][0], 230.0)

    def test_native_identity_cookie_cache_is_scoped_to_pod_endpoint_and_certificate_identity(self):
        adapter = KubectlAdapter()
        login = subprocess.CompletedProcess(args=[], returncode=0, stdout="session=cache-token; Path=/\n", stderr="")
        responses = []
        for node_id in (1, 1, 1, 1, 1, 1):
            responses.extend(
                [
                    subprocess.CompletedProcess(args=[], returncode=0, stdout=f'{{"nodeId":{node_id}}}\n200', stderr=""),
                    subprocess.CompletedProcess(args=[], returncode=0, stdout=f'{{"clusterId":"{_CLUSTER_ID}"}}\n200', stderr=""),
                ]
            )
        common = {
            "namespace": "ns", "pod_name": "db-0", "container_name": "db",
            "binary": "/cockroach/cockroach", "sql_host": "db-0.db.ns.svc.cluster.local",
            "sql_port": 26257, "tls_mode": "tls", "certs_dir": "/certs", "http_port": 8080,
            "http_transport": "http", "client_cert_available": True,
            "auth_scope": "cert-set-A", "timeout": 2,
        }
        with patch.object(adapter, "_exec", side_effect=[login, login, login, login, login]) as login_call, patch.object(
            adapter, "_exec_with_input", side_effect=responses
        ):
            adapter.native_identity(**common, pod_uid="pod-A")
            adapter.native_identity(**common, pod_uid="pod-A")
            adapter.native_identity(**{**common, "auth_scope": "cert-set-B"}, pod_uid="pod-A")
            adapter.native_identity(**{**common, "auth_scope": "cert-set-B"}, pod_uid="pod-B")
            adapter.native_identity(
                **{**common, "auth_scope": "cert-set-B", "sql_port": 26258}, pod_uid="pod-B"
            )
            adapter.native_identity(
                **{**common, "auth_scope": "cert-set-B", "container_name": "cockroach-sidecar"},
                pod_uid="pod-B",
            )
        self.assertEqual(login_call.call_count, 5)
        self.assertEqual(len(adapter._auth_sessions), 5)

    def test_private_cookie_is_absent_from_timeout_and_oserror_tracebacks(self):
        adapter = KubectlAdapter()
        sentinel = "private-session-token-4fd2"
        inner = ["curl", "--config", "-", "http://localhost:8080/_admin/v1/cluster"]
        with patch(
            "cases.common.cockroachdb.adapter.subprocess.run",
            side_effect=subprocess.TimeoutExpired(["kubectl", "exec", *inner], 1, output=sentinel, stderr=sentinel),
        ):
            with self.assertRaises(TransientError) as raised:
                adapter._exec_with_input("ns", "db-0", "db", inner, 1, "native identity", f'header = "Cookie: session={sentinel}"\n')
        rendered = "".join(traceback.format_exception(raised.exception))
        self.assertNotIn(sentinel, rendered)

        with patch("cases.common.cockroachdb.adapter.subprocess.run", side_effect=OSError(sentinel)):
            with self.assertRaises(KubernetesAccessError) as raised_os:
                adapter._exec_with_input("ns", "db-0", "db", inner, 1, "native identity", f'header = "Cookie: session={sentinel}"\n')
        rendered_os = "".join(traceback.format_exception(raised_os.exception))
        self.assertNotIn(sentinel, rendered_os)

    def test_native_session_cookie_parser_accepts_attributes_and_rejects_config_injection(self):
        from cases.common.cockroachdb.adapter import KubectlAdapter

        self.assertEqual(
            KubectlAdapter._parse_session_cookie("session=abc_DEF-123; Path=/; HttpOnly; SameSite=Strict"),
            "session=abc_DEF-123",
        )
        with self.assertRaises(AuthenticationError):
            KubectlAdapter._parse_session_cookie('session=bad\nurl = "https://attacker"')
        with self.assertRaises(AuthenticationError):
            KubectlAdapter._parse_session_cookie("other=value; Path=/")

    def test_health_http_uses_observed_transport_not_sql_tls(self):
        adapter = KubectlAdapter()
        success = subprocess.CompletedProcess(args=[], returncode=0, stdout="ok\n200", stderr="")
        with patch.object(adapter, "_exec", return_value=success) as run:
            response = adapter.health_http(
                namespace="ns", pod_name="db-0", container_name="db", http_port=8080,
                http_transport="http", certs_dir="/certs", client_cert_available=True,
                path="/health?ready=1", timeout=2,
            )
        self.assertEqual(response.status, 200)
        argv = run.call_args.args[3]
        self.assertTrue(argv[-1].startswith("http://localhost:8080/"))
        self.assertNotIn("--cert", argv)
        self.assertNotIn("--insecure", argv)

    def test_native_version_selection_boundary_is_semver_based(self):
        from cases.common.cockroachdb.library import _requires_native_identity, _server_version_tuple

        self.assertEqual(_server_version_tuple("CockroachDB CCL v26.1.8 (linux)") , (26, 1, 8))
        self.assertFalse(_requires_native_identity("CockroachDB CCL v26.0.9"))
        self.assertTrue(_requires_native_identity("CockroachDB CCL v26.1.0"))
        self.assertTrue(_requires_native_identity("CockroachDB CCL v27.0.0"))
        self.assertFalse(_requires_native_identity("unknown version"))

    def test_context_not_found_is_api_error_not_missing_resource(self):
        adapter = KubectlAdapter(kubectl="kubectl", context="gone")
        failed = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="error: context gone not found"
        )
        with patch("cases.common.cockroachdb.adapter.subprocess.run", return_value=failed) as run:
            with self.assertRaises(KubernetesAccessError):
                adapter.get_resource("statefulset", "ns", "db")
        self.assertIn("--ignore-not-found=true", run.call_args.args[0])

    def test_patch_requires_both_test_guards_and_requests_json_output(self):
        adapter = KubectlAdapter(kubectl="kubectl")
        with self.assertRaises(StaleIdentityError):
            adapter.patch_statefulset_json(
                namespace="ns", name="db", uid="uid", resource_version="1",
                operations=[
                    {"op": "replace", "path": "/metadata/uid", "value": "uid"},
                    {"op": "test", "path": "/metadata/resourceVersion", "value": "1"},
                ], timeout=2,
            )
        success = subprocess.CompletedProcess(args=[], returncode=0, stdout='{"metadata":{"uid":"uid"}}', stderr="")
        operations = [
            {"op": "test", "path": "/metadata/uid", "value": "uid"},
            {"op": "test", "path": "/metadata/resourceVersion", "value": "1"},
            {"op": "remove", "path": "/spec/template/spec/containers/0/livenessProbe/exec"},
        ]
        with patch("cases.common.cockroachdb.adapter.subprocess.run", return_value=success) as run:
            result = adapter.patch_statefulset_json(
                namespace="ns", name="db", uid="uid", resource_version="1", operations=operations, timeout=2
            )
        self.assertEqual(result["metadata"]["uid"], "uid")
        self.assertIn("--output=json", run.call_args.args[0])


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import copy
import contextlib
import hashlib
import io
import json
import subprocess
import tempfile
import unittest
from typing import Any
from unittest.mock import patch

from karma.crdb import CrdbLibrary, KubectlAdapter, Lifecycle, ProbeStatus, Requirement, TLSMode, WorkloadRef
from karma.crdb.adapter import HttpHealthResponse
from karma.crdb.types import (
    AuthenticationError,
    ConnectionError,
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
        self.fingerprint_calls: list[str] = []
        self.queried_sql_hosts: list[str] = []
        self.mutate_before_second_sts_read = False
        self.rollout_once = False
        self.transient_query_once = False
        self.pending_pod_set_once = False

    def get_resource(self, kind: str, namespace: str, name: str):
        if namespace != self.namespace:
            return None
        if kind == "statefulset" and name == self.name:
            self.get_count += 1
            if self.mutate_before_second_sts_read and self.get_count == 2:
                self.sts["metadata"]["resourceVersion"] = "stale"
            if self.rollout_once:
                self.rollout_once = False
                self.sts["status"]["observedGeneration"] = 0
            elif self.sts["status"]["observedGeneration"] < self.sts["metadata"]["generation"]:
                self.sts["status"]["observedGeneration"] = self.sts["metadata"]["generation"]
            return copy.deepcopy(self.sts)
        return None

    def list_resources(self, kind: str, namespace: str):
        if kind == "pod" and self.pending_pod_set_once:
            self.pending_pod_set_once = False
            return self.pods[1:]
        return {
            "pod": self.pods,
            "service": self.services,
            "pvc": self.pvcs,
        }.get(kind, ())

    def secret_fingerprint(self, namespace: str, name: str):
        from karma.crdb.types import SecretFingerprint, MissingResourceError

        self.fingerprint_calls.append(name)
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
        self.queried_sql_hosts.append(kwargs["sql_host"])
        if self.transient_query_once:
            self.transient_query_once = False
            raise TransientError("test node is rolling")
        if self.query_error:
            raise self.query_error
        if not self.initialized:
            raise UninitializedError("test node is not initialized")
        ordinal = int(kwargs["pod_name"].rsplit("-", 1)[1])
        return f"cluster_id,node_id,version\n{_CLUSTER_ID},{ordinal + 1},v24.1.4\n"

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
    def test_inspects_bash_downward_api_and_actual_named_ports(self):
        adapter = MemoryAdapter()
        observation = CrdbLibrary(adapter).inspect(WorkloadRef(adapter.namespace, adapter.name))
        self.assertEqual(observation.tls_mode, TLSMode.INSECURE)
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
        from karma.crdb.types import InvalidRequirementError

        with self.assertRaises(InvalidRequirementError):
            Requirement(Lifecycle.DEPLOYED, minimum_nodes=True)
        with self.assertRaises(InvalidRequirementError):
            WorkloadRef("-bad", "db")
        with self.assertRaises(InvalidRequirementError):
            Requirement("deployed")

    def test_observation_and_cli_never_expose_startup_or_multiline_env_secrets(self):
        from karma.crdb.cli import main

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
        with patch("karma.crdb.cli.KubectlAdapter", return_value=adapter), contextlib.redirect_stdout(cli_out):
            self.assertEqual(main(["inspect", "--namespace", adapter.namespace, "--statefulset", adapter.name]), 0)
        self.assertNotIn("private-value", cli_out.getvalue())
        self.assertNotIn("quoted private token", cli_out.getvalue())
        self.assertNotIn("private-key-body-91c0", cli_out.getvalue())

    def test_probe_sql_interface_rejects_arbitrary_statements(self):
        from karma.crdb.types import InvalidRequirementError

        adapter = KubectlAdapter()
        with self.assertRaises(UnsupportedLayoutError):
            adapter.query_sql(
                namespace="ns", pod_name="db-0", container_name="db", binary="cockroach",
                sql_host="db-0.db.ns.svc.cluster.local", sql_port=26257, tls_mode="insecure", certs_dir=None,
                sql="SELECT 1; RESET CLUSTER SETTING sql.defaults.distsql",
                timeout=1,
            )

    def test_read_only_witness_has_stable_csv_aliases(self):
        from karma.crdb.adapter import _READ_ONLY_SQL
        from karma.crdb.library import _WITNESS_SQL, _parse_witness

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
        from karma.crdb.cli import main

        adapter = MemoryAdapter()
        with patch("karma.crdb.cli.KubectlAdapter", return_value=adapter):
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
        from karma.crdb.adapter import _READ_ONLY_SQL

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

    def test_context_not_found_is_api_error_not_missing_resource(self):
        adapter = KubectlAdapter(kubectl="kubectl", context="gone")
        failed = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="error: context gone not found"
        )
        with patch("karma.crdb.adapter.subprocess.run", return_value=failed) as run:
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
        with patch("karma.crdb.adapter.subprocess.run", return_value=success) as run:
            result = adapter.patch_statefulset_json(
                namespace="ns", name="db", uid="uid", resource_version="1", operations=operations, timeout=2
            )
        self.assertEqual(result["metadata"]["uid"], "uid")
        self.assertIn("--output=json", run.call_args.args[0])


if __name__ == "__main__":
    unittest.main()

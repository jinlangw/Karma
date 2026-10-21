#!/usr/bin/env python3
"""Prepare the selected CockroachDB fixture using its observed connection settings."""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from collections.abc import Mapping
from typing import Any

import yaml

from karma.crdb import (
    CrdbError,
    CrdbLibrary,
    KubectlAdapter,
    SQLConnectionObservation,
    TLSMode,
    WorkloadRef,
)
from karma.crdb.types import (
    AuthenticationError,
    ConnectionError,
    KubernetesAccessError,
    MissingResourceError,
    RolloutInProgressError,
    TransientError,
    UninitializedError,
    UnsupportedLayoutError,
)


NAMESPACE = os.environ["BENCH_NAMESPACE"]
CLUSTER_NAME = os.environ["BENCH_PARAM_CLUSTER_NAME"]
POD_LABEL = f"app.kubernetes.io/name=cockroachdb,app.kubernetes.io/instance={CLUSTER_NAME}"
RESOURCES = Path(__file__).resolve().parent
MANIFEST_FILES = ("rbac.yaml", "services.yaml", "statefulset.yaml")
_READINESS_SQL = "SELECT 1;"
_READINESS_FAILURES = (
    AuthenticationError,
    ConnectionError,
    KubernetesAccessError,
    MissingResourceError,
    RolloutInProgressError,
    TransientError,
    UninitializedError,
)


def kubectl(
    namespace: str,
    *args: str,
    timeout: float = 30,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    command = ["kubectl", "-n", namespace, f"--request-timeout={max(1, int(timeout))}s", *args]
    try:
        return subprocess.run(command, input=input_text, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(command, 124, "", f"timed out after {timeout}s")


def require(
    result: subprocess.CompletedProcess[str],
    action: str,
    *,
    print_stdout: bool = True,
) -> subprocess.CompletedProcess[str]:
    if print_stdout and result.stdout:
        print(result.stdout, end="", flush=True)
    if result.returncode != 0:
        detail = result.stderr.strip() or f"exit {result.returncode}"
        raise RuntimeError(f"Kubernetes {action} failed: {detail}")
    return result


class TargetCluster:
    """Keep the case's bounded restart/recreate policy around shared observations."""

    def __init__(
        self,
        namespace: str,
        cluster_name: str,
        *,
        adapter: Any | None = None,
        library: Any | None = None,
        command: Any | None = None,
        manifest_dir: Path | None = None,
    ) -> None:
        self.namespace = namespace
        self.cluster_name = cluster_name
        self.ref = WorkloadRef(namespace, cluster_name)
        self.adapter = adapter if adapter is not None else KubectlAdapter()
        self.library = library if library is not None else CrdbLibrary(self.adapter)
        self.command = command if command is not None else lambda *args, **kwargs: kubectl(namespace, *args, **kwargs)
        self.manifest_dir = manifest_dir if manifest_dir is not None else RESOURCES

    def run(self, mode: str) -> int:
        if mode == "probe":
            return self.probe()
        if mode == "apply":
            self.apply()
            return 0
        if mode == "verify":
            return 0 if self.wait_for_sql(120) else 1
        raise ValueError("mode must be probe, apply, or verify")

    def _statefulset(self) -> Mapping[str, Any] | None:
        return self.adapter.get_resource("statefulset", self.namespace, self.cluster_name)

    @staticmethod
    def _uid(value: Mapping[str, Any], kind: str) -> str:
        metadata = value.get("metadata", {})
        uid = metadata.get("uid") if isinstance(metadata, Mapping) else None
        if not isinstance(uid, str) or not uid:
            raise RuntimeError(f"Selected {kind} has no Kubernetes UID")
        return uid

    def _query_ready(self, connection: SQLConnectionObservation, *, timeout: float = 10) -> bool:
        if connection.tls_mode not in (TLSMode.TLS, TLSMode.INSECURE):
            raise UnsupportedLayoutError("Observed target TLS mode is unknown")
        if connection.tls_mode is TLSMode.TLS and not connection.certs_dir:
            raise UnsupportedLayoutError("Observed TLS target has no supported certificate directory")
        try:
            self.adapter.query_sql(
                namespace=connection.namespace,
                pod_name=connection.pod_name,
                container_name=connection.container_name,
                binary=connection.sql_binary,
                sql_host=connection.sql_host,
                sql_port=connection.sql_port,
                tls_mode=connection.tls_mode.value,
                certs_dir=connection.certs_dir,
                sql=_READINESS_SQL,
                timeout=timeout,
            )
            return True
        except _READINESS_FAILURES:
            return False

    def _sql_ready_once(self, expected_uid: str | None = None, *, timeout: float = 10) -> bool:
        try:
            selected = self._statefulset()
            if selected is None:
                return False
            selected_uid = self._uid(selected, "StatefulSet")
            if expected_uid is not None and selected_uid != expected_uid:
                raise RuntimeError("Selected StatefulSet identity changed during readiness")
            replicas = selected.get("spec", {}).get("replicas", 1)
            if type(replicas) is int and replicas == 0:
                return False
            connection = self.library.inspect_sql_connection(self.ref, ordinal=0)
        except _READINESS_FAILURES:
            return False
        if connection.workload_uid != selected_uid:
            raise RuntimeError("Selected StatefulSet identity changed during SQL connection inspection")
        if expected_uid is not None and connection.workload_uid != expected_uid:
            raise RuntimeError("Selected StatefulSet identity changed during readiness")
        return self._query_ready(connection, timeout=timeout)

    def wait_for_sql(self, seconds: float, *, expected_uid: str | None = None) -> bool:
        deadline = time.monotonic() + max(0, seconds)
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            if self._sql_ready_once(expected_uid, timeout=min(10, max(1, remaining))):
                return True
            remaining = deadline - time.monotonic()
            if remaining > 0:
                time.sleep(min(4, remaining))
        return False

    def probe(self) -> int:
        return 0 if self.wait_for_sql(180) else 1

    @staticmethod
    def _labels(statefulset: Mapping[str, Any]) -> Mapping[str, str]:
        selector = statefulset.get("spec", {}).get("selector", {}).get("matchLabels", {})
        if not isinstance(selector, Mapping) or not selector:
            raise RuntimeError("Selected StatefulSet has no supported pod selector")
        return selector

    @staticmethod
    def _matches(labels: Any, selector: Mapping[str, str]) -> bool:
        return isinstance(labels, Mapping) and all(labels.get(key) == value for key, value in selector.items())

    @staticmethod
    def _owner_uid(pod: Mapping[str, Any]) -> str | None:
        owners = pod.get("metadata", {}).get("ownerReferences", [])
        for owner in owners if isinstance(owners, list) else ():
            if isinstance(owner, Mapping) and owner.get("kind") == "StatefulSet" and owner.get("controller") is True:
                return owner.get("uid")
        return None

    def _owned_pods(self, statefulset: Mapping[str, Any], uid: str) -> list[Mapping[str, Any]]:
        selector = self._labels(statefulset)
        matches = [
            pod for pod in self.adapter.list_resources("pod", self.namespace)
            if self._matches(pod.get("metadata", {}).get("labels", {}), selector)
        ]
        if any(self._owner_uid(pod) != uid for pod in matches):
            raise RuntimeError("Selected pod labels match a Pod not owned by the target StatefulSet")
        return matches

    def _delete_owned_pods(
        self,
        statefulset: Mapping[str, Any],
        uid: str,
        *,
        known_pods: list[Mapping[str, Any]] | None = None,
        allow_orphaned: bool = False,
    ) -> None:
        pods = known_pods if known_pods is not None else self._owned_pods(statefulset, uid)
        selector = self._labels(statefulset)
        known_uids = {
            pod.get("metadata", {}).get("name"): pod.get("metadata", {}).get("uid")
            for pod in pods
        }
        for pod in pods:
            metadata = pod.get("metadata", {})
            name = metadata.get("name")
            pod_uid = metadata.get("uid")
            if not isinstance(name, str) or not isinstance(pod_uid, str):
                raise RuntimeError("Selected target Pod identity is incomplete")
            current = self.adapter.get_resource("pod", self.namespace, name)
            if current is None or current.get("metadata", {}).get("uid") != pod_uid:
                raise RuntimeError("Selected target Pod identity changed before restart")
            owner_uid = self._owner_uid(current)
            if owner_uid != uid and not (allow_orphaned and owner_uid is None and known_uids.get(name) == pod_uid):
                raise RuntimeError("Selected target Pod owner changed before restart")
            if not self._matches(current.get("metadata", {}).get("labels", {}), selector):
                raise RuntimeError("Selected target Pod selector changed before restart")
            self._delete_uid_guarded(
                "pod", name, pod_uid, grace_period_seconds=0, wait=False,
            )

    def _target_pvcs(self) -> list[Mapping[str, Any]]:
        # Match the original case's full identity selector. It also finds
        # claims left by an older volumeClaimTemplate name after a prior reset.
        identity = {
            "app.kubernetes.io/name": "cockroachdb",
            "app.kubernetes.io/instance": self.cluster_name,
        }
        return [
            pvc for pvc in self.adapter.list_resources("pvc", self.namespace)
            if self._matches(pvc.get("metadata", {}).get("labels", {}), identity)
        ]

    @staticmethod
    def _same_spec(current: Mapping[str, Any] | None, expected: Mapping[str, Any]) -> bool:
        return current is not None and current.get("spec") == expected.get("spec")

    def _assert_same_target(self, initial: Mapping[str, Any]) -> None:
        current = self._statefulset()
        if current is None or self._uid(current, "StatefulSet") != self._uid(initial, "StatefulSet"):
            raise RuntimeError("Selected StatefulSet identity changed before recreation")
        if not self._same_spec(current, initial):
            raise RuntimeError("Selected StatefulSet spec changed before recreation")

    def _delete_uid_guarded(
        self,
        kind: str,
        name: str,
        uid: str,
        *,
        wait_timeout: float = 120,
        propagation_policy: str | None = None,
        grace_period_seconds: int | None = None,
        wait: bool = True,
    ) -> None:
        if kind == "statefulset":
            resource_path = f"/apis/apps/v1/namespaces/{self.namespace}/statefulsets/{name}"
        else:
            resources = {"pod": "pods", "pvc": "persistentvolumeclaims"}
            try:
                resource_path = f"/api/v1/namespaces/{self.namespace}/{resources[kind]}/{name}"
            except KeyError as error:
                raise ValueError("unsupported guarded delete resource") from error
        options: dict[str, Any] = {
            "apiVersion": "v1",
            "kind": "DeleteOptions",
            "preconditions": {"uid": uid},
        }
        if propagation_policy is not None:
            options["propagationPolicy"] = propagation_policy
        if grace_period_seconds is not None:
            options["gracePeriodSeconds"] = grace_period_seconds
        require(
            self.command(
                "delete", f"--raw={resource_path}", "-f", "-",
                input_text=json.dumps(options), timeout=wait_timeout + 15,
            ),
            f"deleting selected {kind} {name}",
            print_stdout=False,
        )
        if not wait:
            return
        deadline = time.monotonic() + wait_timeout
        while True:
            current = self.adapter.get_resource(kind, self.namespace, name)
            if current is None:
                return
            current_uid = current.get("metadata", {}).get("uid")
            if current_uid != uid:
                raise RuntimeError(f"Selected {kind} identity changed during deletion")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError(f"Selected {kind} did not finish deletion")
            time.sleep(min(1, remaining))

    def _delete_pvcs(self, pvcs: list[Mapping[str, Any]]) -> None:
        for pvc in pvcs:
            metadata = pvc.get("metadata", {})
            name, uid = metadata.get("name"), metadata.get("uid")
            if not isinstance(name, str) or not isinstance(uid, str):
                raise RuntimeError("Selected target PVC identity is incomplete")
            current = self.adapter.get_resource("pvc", self.namespace, name)
            if current is None or current.get("metadata", {}).get("uid") != uid:
                raise RuntimeError("Selected target PVC identity changed before recreation")
            self._delete_uid_guarded("pvc", name, uid)

    @staticmethod
    def _clean_statefulset(statefulset: Mapping[str, Any], namespace: str) -> dict[str, Any]:
        value = copy.deepcopy(dict(statefulset))
        value.pop("status", None)
        metadata = value.setdefault("metadata", {})
        for key in ("uid", "resourceVersion", "generation", "creationTimestamp", "deletionTimestamp", "deletionGracePeriodSeconds", "managedFields", "selfLink"):
            metadata.pop(key, None)
        metadata["namespace"] = namespace
        return value

    def _create_observed_statefulset(self, statefulset: Mapping[str, Any]) -> str:
        document = self._clean_statefulset(statefulset, self.namespace)
        result = require(
            self.command("create", "-f", "-", "--output=json", input_text=yaml.safe_dump(document, sort_keys=False), timeout=120),
            "recreating the observed StatefulSet",
            print_stdout=False,
        )
        try:
            created = json.loads(result.stdout)
        except (TypeError, json.JSONDecodeError) as error:
            raise RuntimeError("Kubernetes did not return the recreated StatefulSet identity") from error
        return self._uid(created, "recreated StatefulSet")

    def _recreation_spec(self, statefulset: Mapping[str, Any]) -> Mapping[str, Any]:
        replicas = statefulset.get("spec", {}).get("replicas", 1)
        if type(replicas) is not int or replicas < 0:
            raise RuntimeError("Selected target has an invalid replica count for recovery")
        if replicas > 0:
            return statefulset
        _documents, case_statefulset = self._rendered_documents()
        case_replicas = case_statefulset.get("spec", {}).get("replicas", 1)
        if type(case_replicas) is not int or case_replicas < 1:
            raise RuntimeError("Case manifests do not provide a positive replica count for recovery")
        recreated = copy.deepcopy(dict(statefulset))
        recreated.setdefault("spec", {})["replicas"] = case_replicas
        return recreated

    def _wait_for_running(self, statefulset: Mapping[str, Any], uid: str, timeout: float = 300) -> None:
        replicas = statefulset.get("spec", {}).get("replicas", 1)
        selector = self._labels(statefulset)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self._assert_statefulset_uid(uid)
            pods = [
                pod for pod in self.adapter.list_resources("pod", self.namespace)
                if self._matches(pod.get("metadata", {}).get("labels", {}), selector)
            ]
            if any(self._owner_uid(pod) != uid for pod in pods):
                raise RuntimeError("Selected target Pod is not owned by the recreated StatefulSet")
            running = sum(
                pod.get("status", {}).get("phase") == "Running"
                for pod in pods
            )
            if running >= replicas:
                return
            time.sleep(min(2, max(0, deadline - time.monotonic())))
        raise RuntimeError("target cluster pods did not reach Running")

    def _assert_statefulset_uid(self, expected_uid: str) -> Mapping[str, Any]:
        current = self._statefulset()
        if current is None or self._uid(current, "StatefulSet") != expected_uid:
            raise RuntimeError("Selected StatefulSet identity changed during recovery")
        return current

    def _init(self, expected_uid: str, *, timeout: float = 15) -> bool:
        pod_name = f"{self.cluster_name}-0"
        try:
            self._assert_statefulset_uid(expected_uid)
            connection = self.library.inspect_sql_connection(self.ref, ordinal=0)
        except _READINESS_FAILURES:
            return False
        if connection.workload_uid != expected_uid:
            raise RuntimeError("Selected StatefulSet identity changed before init")
        if connection.tls_mode is TLSMode.TLS:
            if not connection.certs_dir:
                raise RuntimeError("Observed TLS target has no supported certificate directory")
            tls_args = [f"--certs-dir={connection.certs_dir}"]
        elif connection.tls_mode is TLSMode.INSECURE:
            tls_args = ["--insecure"]
        else:
            raise RuntimeError("Observed target TLS mode is unknown")
        self._assert_statefulset_uid(expected_uid)
        host = connection.rpc_host
        if host is None:
            raise UnsupportedLayoutError("Selected Pod has no supported advertised RPC host for init")
        rpc_port = connection.rpc_port
        self._assert_statefulset_uid(expected_uid)
        try:
            result = self.command(
                "exec", pod_name, "--container", connection.container_name, "--", connection.sql_binary,
                "init", *tls_args, f"--host={host}:{rpc_port}", timeout=timeout,
            )
        except _READINESS_FAILURES:
            return False
        if result.returncode != 0:
            return False
        if result.stdout:
            print(result.stdout, end="", flush=True)
        self._assert_statefulset_uid(expected_uid)
        return True

    def _initialize_until_queryable(self, uid: str) -> None:
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            if self._sql_ready_once(uid, timeout=min(10, max(1, remaining))):
                return
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            if self._init(uid, timeout=min(15, max(1, remaining))):
                return
            remaining = deadline - time.monotonic()
            if remaining > 0:
                time.sleep(min(3, remaining))
        raise RuntimeError("target cluster could not be initialized")

    def _wait_for_ready(self) -> None:
        require(
            self.command(
                "wait", "--for=condition=ready", "pod", "-l", POD_LABEL,
                "--timeout=600s", timeout=640,
            ),
            "waiting for target Pods to become Ready",
        )

    def _complete_bootstrap(self, statefulset: Mapping[str, Any], uid: str) -> None:
        self._wait_for_pod_created(statefulset, uid)
        self._wait_for_running(statefulset, uid)
        self._initialize_until_queryable(uid)
        self._wait_for_ready()

    def _apply_bootstrap_support(self, documents: list[dict[str, Any]]) -> None:
        for document in documents:
            if document.get("kind") == "StatefulSet":
                continue
            require(
                self.command("apply", "-f", "-", input_text=yaml.safe_dump(document, sort_keys=False), timeout=120),
                f"applying {document.get('kind', 'resource')} before target recreation",
            )

    def _bootstrap_absent(self) -> None:
        # The committed flow also removes leftovers when the StatefulSet is
        # already absent. Keep that case-scoped cleanup before applying fresh
        # resources, using the original full identity labels and exact UIDs.
        if self._statefulset() is not None:
            raise RuntimeError("Target StatefulSet appeared before absent-target cleanup")
        identity = {
            "app.kubernetes.io/name": "cockroachdb",
            "app.kubernetes.io/instance": self.cluster_name,
        }
        for pod in self.adapter.list_resources("pod", self.namespace):
            metadata = pod.get("metadata", {})
            if not self._matches(metadata.get("labels", {}), identity):
                continue
            name, uid = metadata.get("name"), metadata.get("uid")
            if not isinstance(name, str) or not isinstance(uid, str):
                raise RuntimeError("Selected leftover Pod identity is incomplete")
            current = self.adapter.get_resource("pod", self.namespace, name)
            if current is None or current.get("metadata", {}).get("uid") != uid:
                raise RuntimeError("Selected leftover Pod identity changed before cleanup")
            if not self._matches(current.get("metadata", {}).get("labels", {}), identity):
                raise RuntimeError("Selected leftover Pod labels changed before cleanup")
            self._delete_uid_guarded("pod", name, uid, grace_period_seconds=0, wait=False)
        self._delete_pvcs(self._target_pvcs())

        documents, _statefulset = self._rendered_documents()
        for document in documents:
            require(
                self.command("apply", "-f", "-", input_text=yaml.safe_dump(document, sort_keys=False), timeout=120),
                f"applying {document['kind']}",
            )
        created = self._statefulset()
        if created is None:
            raise RuntimeError("target StatefulSet was not created")
        uid = self._uid(created, "StatefulSet")
        self._complete_bootstrap(created, uid)

    def _wait_for_pod_created(self, statefulset: Mapping[str, Any], uid: str, timeout: float = 60) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self._assert_statefulset_uid(uid)
            if self._owned_pods(statefulset, uid):
                return
            remaining = deadline - time.monotonic()
            if remaining > 0:
                time.sleep(min(2, remaining))
        raise RuntimeError("target cluster pods were not created")

    def _rendered_documents(self) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        substitutions = {"${BENCH_NAMESPACE}": self.namespace, "${BENCH_PARAM_CLUSTER_NAME}": self.cluster_name}
        documents: list[dict[str, Any]] = []
        for filename in MANIFEST_FILES:
            text = (self.manifest_dir / filename).read_text(encoding="utf-8")
            for variable, value in substitutions.items():
                text = text.replace(variable, value)
            if "${" in text:
                raise RuntimeError(f"Manifest {filename} contains an unsupported unresolved variable")
            try:
                parsed = yaml.safe_load_all(text)
                for document in parsed:
                    if document is not None:
                        if not isinstance(document, dict):
                            raise RuntimeError(f"Manifest {filename} contains a non-object resource")
                        documents.append(document)
            except yaml.YAMLError as error:
                raise RuntimeError(f"Manifest {filename} is invalid YAML") from error
        statefulsets = [item for item in documents if item.get("kind") == "StatefulSet"]
        if len(statefulsets) != 1 or statefulsets[0].get("metadata", {}).get("name") != self.cluster_name:
            raise RuntimeError("Fresh target manifests must declare exactly the selected StatefulSet")
        return documents, statefulsets[0]

    def _recreate_inherited(self, statefulset: Mapping[str, Any]) -> None:
        uid = self._uid(statefulset, "StatefulSet")
        recreation_spec = self._recreation_spec(statefulset)
        pvcs = self._target_pvcs()
        self._assert_same_target(statefulset)
        pods = self._owned_pods(statefulset, uid)
        for pod in pods:
            metadata = pod.get("metadata", {})
            name, pod_uid = metadata.get("name"), metadata.get("uid")
            if not isinstance(name, str) or not isinstance(pod_uid, str) or not pod_uid:
                raise RuntimeError("Selected target Pod identity is incomplete")
            current = self.adapter.get_resource("pod", self.namespace, name)
            if (
                current is None
                or current.get("metadata", {}).get("uid") != pod_uid
                or self._owner_uid(current) != uid
            ):
                raise RuntimeError("Selected target Pod ownership changed before recreation")
        # Preserve the case's reset order: remove the selected controller,
        # force-delete only its previously verified Pods, then its claim PVCs.
        self._delete_uid_guarded(
            "statefulset", self.cluster_name, uid, wait_timeout=60,
            propagation_policy="Orphan",
        )
        self._delete_owned_pods(statefulset, uid, known_pods=pods, allow_orphaned=True)
        self._delete_pvcs(pvcs)
        documents, _case_statefulset = self._rendered_documents()
        self._apply_bootstrap_support(documents)
        new_uid = self._create_observed_statefulset(recreation_spec)
        recreated = self._assert_statefulset_uid(new_uid)
        self._complete_bootstrap(recreated, new_uid)

    def apply(self) -> None:
        existing = self._statefulset()
        if existing is None:
            self._bootstrap_absent()
            return
        original_uid = self._uid(existing, "StatefulSet")
        statefulset = existing
        if self.wait_for_sql(10, expected_uid=original_uid):
            return
        self._delete_owned_pods(statefulset, original_uid)
        if self.wait_for_sql(60, expected_uid=original_uid):
            return
        self._assert_same_target(statefulset)
        self._recreate_inherited(statefulset)


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) == 2 else ""
    if mode not in {"probe", "apply", "verify"}:
        print(f"usage: {sys.argv[0]} {{probe|apply|verify}}", file=sys.stderr)
        return 2
    try:
        return TargetCluster(NAMESPACE, CLUSTER_NAME).run(mode)
    except (CrdbError, RuntimeError, ValueError, OSError) as error:
        print(f"Target cluster setup failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

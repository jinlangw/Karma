#!/usr/bin/env python3
"""Bounded live smoke for the CockroachDB cluster-settings case.

The harness reuses the common CRDB fixture's capacity checks, namespace audit,
redacted diagnostics, and UID-precondition cleanup. It runs insecure, TLS, and
small fresh-create phases sequentially by default, with one 1Gi PVC-backed node
at a time. Opt-in phases exercise bounded TLS recovery, a CockroachDB listener
layout that uses implicit root certificates and one SQL/RPC listener, or
certificate-rotation observer components. It invokes no solver or controller
and never changes the native case manifests.
"""

from __future__ import annotations

import argparse
import copy
from contextlib import contextmanager
import csv
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import runpy
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable, Iterator, Mapping

import yaml


ROOT = Path(__file__).resolve().parents[2]
BASE_PATH = ROOT / "experiments" / "crdb-common-library" / "live_smoke.py"
TARGET_PATH = ROOT / "cases" / "cockroachdb" / "cluster-settings" / "resource" / "ensure-target-cluster.py"
ORACLE_PATH = ROOT / "cases" / "cockroachdb" / "cluster-settings" / "oracle" / "oracle.py"
SECURE_TARGET_PATH = ROOT / "cases" / "cockroachdb" / "certificate-rotation" / "resource" / "secure_target.py"
SQL_READY_PATH = ROOT / "cases" / "cockroachdb" / "certificate-rotation" / "resource" / "sql_ready.py"
CERT_ROTATION_ORACLE_PATH = ROOT / "cases" / "cockroachdb" / "certificate-rotation" / "oracle" / "oracle.py"
CASE_STATEFULSET_MANIFEST = ROOT / "cases" / "cockroachdb" / "certificate-rotation" / "resource" / "statefulset.yaml"
CASE_SERVICES_MANIFEST = ROOT / "cases" / "cockroachdb" / "certificate-rotation" / "resource" / "services.yaml"
_BASE_SPEC = importlib.util.spec_from_file_location("crdb_library_live_smoke", BASE_PATH)
if _BASE_SPEC is None or _BASE_SPEC.loader is None:
    raise RuntimeError("Could not load the common CRDB live-fixture helper")
_BASE = importlib.util.module_from_spec(_BASE_SPEC)
_BASE_SPEC.loader.exec_module(_BASE)

from karma.crdb import (  # noqa: E402
    CrdbLibrary,
    KubectlAdapter,
    Lifecycle,
    ProbeStatus,
    Requirement,
    TLSMode,
    WorkloadRef,
)


_NATIVE_LABELS = {
    "app.kubernetes.io/name": "cockroachdb",
    "app.kubernetes.io/instance": "db",
}
_SETTING_NAME = "kv.snapshot_rebalance.max_rate"
_WITNESS_DB = "crdb_settings_case_smoke"
_WITNESS_TABLE = f"{_WITNESS_DB}.public.witness"
_WITNESS_ROWS = [
    ["id", "payload"],
    ["1", "preserve across case setup"],
    ["2", "preserve across pod restart"],
]


class SettingsFixture(_BASE.Fixture):
    """One-node native-shaped fixture with extra resources journaled by UID."""

    def __init__(self, args: argparse.Namespace, phase: str, run_id: str):
        super().__init__(args, phase, run_id)
        self.labels = {**_NATIVE_LABELS, "crdb-library-run": run_id}
        self.phase_data: dict[str, Any] | None = None

    def _recovery_event(self, event: dict[str, Any], checkpoint: str) -> dict[str, Any]:
        if self.phase_data is None:
            return event
        events = self.phase_data.setdefault("target_resource_history", [])
        events.append(event)
        self._checkpoint(checkpoint)
        return event

    def create(self, resource: dict[str, Any]) -> dict[str, Any]:
        if self.phase != "tls-recovery":
            return super().create(resource)
        metadata = resource.get("metadata", {})
        event = self._recovery_event(
            {
                "action": "create",
                "state": "intent",
                "kind": str(resource.get("kind", "")).lower(),
                "name": str(metadata.get("name", "")),
            },
            "fixture-resource-create-intent",
        )
        try:
            created = super().create(resource)
        except BaseException:
            event["state"] = "ambiguous"
            self._checkpoint("fixture-resource-create-ambiguous")
            raise
        event.update({"state": "created", "uid": self.created[(event["kind"], event["name"])]})
        self._checkpoint("fixture-resource-created")
        return created

    def make_secret(self, cert_dir: Path) -> None:
        if self.phase != "tls-recovery":
            return super().make_secret(cert_dir)
        secret_document = self.kubectl(
            "create", "secret", "generic", "db-certs",
            "--from-file=ca.crt=" + str(cert_dir / "ca.crt"),
            "--from-file=node.crt=" + str(cert_dir / "node.crt"),
            "--from-file=node.key=" + str(cert_dir / "node.key"),
            "--from-file=client.root.crt=" + str(cert_dir / "client.root.crt"),
            "--from-file=client.root.key=" + str(cert_dir / "client.root.key"),
            "--dry-run=client", "--output=json", namespace=self.namespace,
        )
        try:
            resource = json.loads(secret_document)
            resource.setdefault("metadata", {})["labels"] = self.labels
            resource["metadata"]["namespace"] = self.namespace
            serialized = json.dumps(resource, separators=(",", ":"))
            manifest_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        except (json.JSONDecodeError, KeyError, TypeError) as error:
            raise _BASE.SmokeFailure("Client could not prepare a TLS Secret manifest") from error
        event = self._recovery_event(
            {
                "action": "create",
                "state": "intent",
                "kind": "secret",
                "name": "db-certs",
                "manifest_sha256": manifest_hash,
            },
            "fixture-secret-create-intent",
        )
        try:
            uid = self.kubectl(
                "create", "--filename=-", "--output=jsonpath={.metadata.uid}",
                namespace=self.namespace, input_text=serialized,
            ).strip()
        except BaseException:
            event["state"] = "ambiguous"
            self._checkpoint("fixture-secret-create-ambiguous")
            raise
        if not uid:
            event["state"] = "ambiguous"
            self._checkpoint("fixture-secret-create-response-ambiguous")
            raise _BASE.SmokeFailure("Kubernetes did not return the TLS Secret identity")
        self.created[("secret", "db-certs")] = uid
        event.update({"state": "created", "uid": uid})
        self._checkpoint("fixture-secret-created")

    def _record_storage_snapshot(self, stage: str) -> list[dict[str, Any]]:
        if self.phase_data is None:
            return []
        items = self.get("persistentvolumeclaims").get("items", [])
        claims: list[dict[str, Any]] = []
        for pvc in items:
            metadata = pvc.get("metadata", {})
            name, uid = metadata.get("name"), metadata.get("uid")
            if (
                not isinstance(name, str)
                or not name.startswith("data-db-")
                or not name.removeprefix("data-db-").isdigit()
                or metadata.get("labels", {}).get("crdb-library-run") != self.run_id
                or not isinstance(uid, str)
                or not uid
            ):
                raise _BASE.SmokeFailure("Recovery storage observation found an unowned or unexpected PVC")
            volume_name = pvc.get("spec", {}).get("volumeName")
            pv_record = None
            if isinstance(volume_name, str) and volume_name:
                pv = self.get("persistentvolume", volume_name, all_namespaces=True)
                claim_ref = pv.get("spec", {}).get("claimRef", {}) if pv else {}
                if (
                    not pv
                    or claim_ref.get("uid") != uid
                    or claim_ref.get("namespace") != self.namespace
                    or claim_ref.get("name") != name
                ):
                    raise _BASE.SmokeFailure("Recovery PV does not reference the observed fixture PVC")
                pv_uid = pv.get("metadata", {}).get("uid")
                if not isinstance(pv_uid, str) or not pv_uid:
                    raise _BASE.SmokeFailure("Recovery PV identity is incomplete")
                pv_record = {
                    "name": volume_name,
                    "uid": pv_uid,
                    "reclaim_policy": pv.get("spec", {}).get("persistentVolumeReclaimPolicy"),
                    "claim_ref": {
                        "namespace": claim_ref.get("namespace"),
                        "name": claim_ref.get("name"),
                        "uid": claim_ref.get("uid"),
                    },
                }
            claims.append(
                {
                    "name": name,
                    "uid": uid,
                    "volume_name": volume_name if isinstance(volume_name, str) else None,
                    "pv": pv_record,
                }
            )
        if len(claims) > 1:
            raise _BASE.SmokeFailure("Recovery fixture unexpectedly has multiple PVCs")
        snapshots = self.phase_data.setdefault("storage_identity_history", [])
        snapshots.append({"stage": stage, "claims": claims})
        self._checkpoint(f"storage-identities-{stage}")
        return claims

    def _replacement_requested(self, kind: str, name: str, old_uid: str) -> bool:
        events = (self.phase_data or {}).get("target_resource_history", [])
        delete_index = next((
            index
            for index, event in enumerate(events)
            if event.get("action") == "delete"
            and event.get("kind") == kind
            and event.get("name") == name
            and event.get("uid") == old_uid
            and event.get("state") in {"requested", "ambiguous", "confirmed-by-recreate"}
        ), None)
        if delete_index is None:
            return False
        create_event = next(
            (
                event
                for event in events[delete_index + 1 :]
                if event.get("action") == "create"
                and event.get("kind") == "statefulset"
                and event.get("name") == "db"
                and event.get("state") in {"intent", "ambiguous", "created"}
            ),
            None,
        )
        if create_event:
            events[delete_index]["state"] = "confirmed-by-recreate"
            self._checkpoint("target-delete-confirmed-by-recreate")
        return create_event is not None

    def _initial_recovery_uid(self, kind: str, name: str) -> str | None:
        if self.phase_data is None:
            return None
        explicit = self.phase_data.get("initial_resource_uids", {}).get(f"{kind}/{name}")
        if isinstance(explicit, str) and explicit:
            return explicit
        for event in self.phase_data.get("target_resource_history", []):
            if (
                event.get("action") == "create"
                and event.get("kind") == kind
                and event.get("name") == name
                and event.get("state") == "created"
                and isinstance(event.get("uid"), str)
            ):
                return event["uid"]
        return None

    def _recover_ambiguous_create(self, kind: str, name: str) -> None:
        if self.phase_data is None or (kind, name) in self.created:
            return
        event = next(
            (
                item
                for item in reversed(self.phase_data.get("target_resource_history", []))
                if item.get("action") == "create"
                and item.get("kind") == kind
                and item.get("name") == name
                and item.get("state") in {"intent", "ambiguous"}
            ),
            None,
        )
        if event is None:
            return
        resource = self.get(kind, name)
        metadata = resource.get("metadata", {}) if resource else {}
        uid = metadata.get("uid")
        if (
            not resource
            or metadata.get("labels", {}).get("crdb-library-run") != self.run_id
            or not isinstance(uid, str)
            or not uid
        ):
            return
        self.created[(kind, name)] = uid
        event.update({"state": "created-after-ambiguous-response", "uid": uid})
        self._checkpoint(f"ambiguous-create-identity-recovered-{kind}-{name}")

    def _refresh_recovery_identities_for_cleanup(self) -> None:
        if self.phase != "tls-recovery" or self.phase_data is None or not self.namespace_uid:
            return
        for kind, name in (("service", "db"), ("service", "db-public"), ("secret", "db-certs")):
            self._recover_ambiguous_create(kind, name)
        sts = self.get("statefulset", "db")
        if sts:
            metadata = sts.get("metadata", {})
            uid = metadata.get("uid")
            previous = self._initial_recovery_uid("statefulset", "db")
            if metadata.get("labels", {}).get("crdb-library-run") != self.run_id or not isinstance(uid, str):
                raise _BASE.SmokeFailure("Recovery cleanup found an unowned StatefulSet")
            if previous and previous != uid and not self._replacement_requested("statefulset", "db", previous):
                raise _BASE.SmokeFailure("Recovery cleanup found an unjournaled StatefulSet replacement")
            self.created[("statefulset", "db")] = uid
            self._recovery_event(
                {"action": "observed", "kind": "statefulset", "name": "db", "uid": uid},
                "recovery-statefulset-identity-observed",
            )

        claims = self._record_storage_snapshot("cleanup-preflight")
        initial_claims = {
            (claim.get("name"), claim.get("uid"))
            for snapshot in self.phase_data.get("storage_identity_history", [])[:1]
            for claim in snapshot.get("claims", [])
        }
        for claim in claims:
            initial_uid = next(
                (uid for name, uid in initial_claims if name == claim["name"]),
                self._initial_recovery_uid("persistentvolumeclaim", claim["name"]),
            )
            if initial_uid and initial_uid != claim["uid"]:
                if not self._replacement_requested("persistentvolumeclaim", claim["name"], initial_uid):
                    raise _BASE.SmokeFailure("Recovery cleanup found an unjournaled PVC replacement")
            self.created[("persistentvolumeclaim", claim["name"])] = claim["uid"]
            pv = claim.get("pv")
            if pv:
                self.created[("persistentvolume", pv["name"])] = pv["uid"]

    def cleanup(self) -> None:
        self._refresh_recovery_identities_for_cleanup()
        super().cleanup()

    def statefulset_manifest(self, tls: bool) -> dict[str, Any]:
        manifest = super().statefulset_manifest(tls)
        if tls:
            spec = manifest["spec"]["template"]["spec"]
            container = spec["containers"][0]
            if self.phase in {"observer-compat", "oracle-rebind", "oracle-sql-connection"}:
                script = container["command"][2]
                script = script.replace("--sql-addr=0.0.0.0:26257 ", "")
                script = script.replace(" --certs-dir=/cockroach/certs", "")
                script = script.replace(
                    "--advertise-sql-addr=$(POD_NAME).db.$(POD_NAMESPACE).svc.cluster.local:26257",
                    "--advertise-sql-addr=$(POD_NAME).db.$(POD_NAMESPACE).svc.cluster.local:26258",
                )
                container["command"][2] = script
                for port in container["ports"]:
                    if port.get("name") == "sql":
                        port["containerPort"] = 26258
            else:
                container["command"][2] = container["command"][2].replace(
                    "--certs-dir=/cockroach/certs", "--certs-dir=/cockroach/cockroach-certs"
                )
            for mount in container["volumeMounts"]:
                if mount.get("name") == "certs":
                    mount["mountPath"] = (
                        "/root/.cockroach-certs"
                        if self.phase in {"observer-compat", "oracle-rebind", "oracle-sql-connection"}
                        else "/cockroach/cockroach-certs"
                    )
        return manifest

    def service_manifest(self) -> dict[str, Any]:
        manifest = super().service_manifest()
        if self.phase in {"observer-compat", "oracle-rebind", "oracle-sql-connection"}:
            manifest["spec"]["ports"] = [
                port for port in manifest["spec"]["ports"] if port.get("name") != "rpc"
            ]
            for port in manifest["spec"]["ports"]:
                if port.get("name") == "sql":
                    port["port"] = 26258
        return manifest

    def public_service_manifest(self) -> dict[str, Any]:
        service = self.service_manifest()
        service["metadata"]["name"] = "db-public"
        service["spec"].pop("clusterIP", None)
        service["spec"].pop("publishNotReadyAddresses", None)
        if self.phase == "tls-service-preservation":
            service["spec"]["type"] = "NodePort"
        return service

    def init(self, tls: bool) -> None:
        self.set_stage("explicit-cockroach-init")
        certs_dir = (
            "/root/.cockroach-certs"
            if self.phase in {"observer-compat", "oracle-rebind", "oracle-sql-connection"}
            else "/cockroach/cockroach-certs"
        )
        command = [
            *self.kubectl_base,
            "--namespace", self.namespace,
            "exec", "db-0", "--container=db", "--",
            "/cockroach/cockroach", "init",
            f"--certs-dir={certs_dir}" if tls else "--insecure",
            f"--host=db-0.db.{self.namespace}.svc.cluster.local:26258",
        ]
        _BASE.run(command, timeout=45, operation="cockroach init", observer=self._record_command)

    def wait_ready(self, timeout: float = 240) -> None:
        """Wait for the owned pod object to exist before issuing Kubernetes wait."""
        deadline = time.monotonic() + timeout
        self.set_stage("pod-running-before-ready")
        while time.monotonic() < deadline:
            pod = self.get("pods", "db-0", timeout=5)
            if pod.get("status", {}).get("phase") == "Running":
                remaining = max(1, deadline - time.monotonic())
                return super().wait_ready(timeout=remaining)
            time.sleep(min(1, max(0, deadline - time.monotonic())))
        raise _BASE.SmokeFailure("Settings fixture db-0 did not reach Running within the bounded wait")

    def _namespace_resource_identities(self) -> set[tuple[str, str, str]]:
        identities = super()._namespace_resource_identities()
        for kind in ("roles", "rolebindings"):
            for item in self.get(kind).get("items", []):
                metadata = item.get("metadata", {})
                identities.add((kind, str(metadata.get("name", "")), str(metadata.get("uid", ""))))
        return identities

    def _delete_rbac_uid(self, kind: str, name: str, uid: str) -> None:
        plural = {"role": "roles", "rolebinding": "rolebindings"}.get(kind)
        if plural is None:
            raise _BASE.SmokeFailure("Cleanup does not support this RBAC resource")
        endpoint = (
            f"/apis/rbac.authorization.k8s.io/v1/namespaces/{self.namespace}/{plural}/{name}"
        )
        options = {
            "apiVersion": "v1",
            "kind": "DeleteOptions",
            "preconditions": {"uid": uid},
        }
        _BASE.run(
            [*self.kubectl_base, "delete", "--raw=" + endpoint, "--filename=-"],
            timeout=30,
            input_text=json.dumps(options, separators=(",", ":")),
            operation=f"kubectl delete {kind}/{name} with UID precondition",
            observer=self._record_command,
        )

    def cleanup_additional_resources(self) -> None:
        # The headless DB service is retained by the base cleanup until the
        # StatefulSet, Pods, and PVCs are gone. Delete public routing next, then
        # RBAC in dependency order. This also cleans up a partial create.
        expected = (
            ("service", "db-public"),
            ("rolebinding", "db-rolebinding"),
            ("role", "db-role"),
            ("serviceaccount", "db-sa"),
        )
        for kind, name in expected:
            owned_uid = self.created.get((kind, name))
            if not owned_uid:
                continue
            resource = self.get(kind, name)
            if not resource:
                continue
            metadata = resource.get("metadata", {})
            if (
                metadata.get("uid") != owned_uid
                or metadata.get("labels", {}).get("crdb-library-run") != self.run_id
            ):
                raise _BASE.SmokeFailure(
                    f"Cleanup stopped because {kind}/{name} identity or ownership changed"
                )
            if kind in {"role", "rolebinding"}:
                self._delete_rbac_uid(kind, name, owned_uid)
            else:
                self.raw_delete_uid(kind, name, owned_uid)
            self.wait_absent(kind, name)
            self._checkpoint(f"{kind}-{name}-absent")
            if kind == "service":
                _wait_service_slices_absent(self, owned_uid)

        if self.phase == "tls-recovery" and self.phase_data is not None:
            known_claims = {
                (self.namespace, claim.get("name"), claim.get("uid"))
                for snapshot in self.phase_data.get("storage_identity_history", [])
                for claim in snapshot.get("claims", [])
            }
            recorded_pvs: dict[str, set[str]] = {}
            for snapshot in self.phase_data.get("storage_identity_history", []):
                for claim in snapshot.get("claims", []):
                    pv = claim.get("pv")
                    if pv:
                        recorded_pvs.setdefault(pv["name"], set()).add(pv["uid"])
            for name, known_uids in recorded_pvs.items():
                current = self.get("persistentvolume", name, all_namespaces=True)
                if not current:
                    continue
                metadata = current.get("metadata", {})
                uid = metadata.get("uid")
                claim_ref = current.get("spec", {}).get("claimRef", {})
                current_claim = (
                    claim_ref.get("namespace"), claim_ref.get("name"), claim_ref.get("uid")
                )
                if uid not in known_uids or current_claim not in known_claims:
                    raise _BASE.SmokeFailure("Recovery cleanup stopped because a recorded PV changed ownership")
                self.raw_delete_uid("persistentvolume", name, uid)
                self.wait_absent("persistentvolume", name, timeout=180)



@contextmanager
def case_environment(
    namespace: str,
    *,
    setting_name: str = _SETTING_NAME,
    setting_value: str = "128MiB",
    kubectl: str = "kubectl",
) -> Iterator[None]:
    """Provide the actual case's environment and restore the caller afterward."""
    updates = {
        "BENCH_NAMESPACE": namespace,
        "BENCH_PARAM_CLUSTER_NAME": "db",
        "BENCH_PARAM_SETTING_NAME": setting_name,
        "BENCH_PARAM_SETTING_VALUE": setting_value,
    }
    resolved = shutil.which(kubectl)
    if resolved and Path(kubectl).name == "kubectl":
        current_path = os.environ.get("PATH", "")
        updates["PATH"] = str(Path(resolved).parent) + os.pathsep + current_path
    previous = {key: os.environ.get(key) for key in updates}
    os.environ.update(updates)
    try:
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def run_case_command(
    fixture: SettingsFixture,
    mode: str,
    *,
    timeout: float,
    setting_value: str = "128MiB",
) -> dict[str, Any]:
    operation = f"cluster-settings precondition {mode}"
    fixture.set_stage(operation)
    started = time.monotonic()
    command = [sys.executable, str(TARGET_PATH), mode]
    with case_environment(
        fixture.namespace,
        setting_value=setting_value,
        kubectl=fixture.args.kubectl,
    ):
        try:
            result = subprocess.run(
                command, text=True, capture_output=True, timeout=timeout, check=False
            )
        except subprocess.TimeoutExpired as error:
            event = {
                "operation": operation,
                "outcome": "timeout",
                "returncode": None,
                "elapsed_ms": round((time.monotonic() - started) * 1000),
            }
            fixture._record_command(event)
            raise _BASE.SmokeFailure(f"{operation} timed out", command_event=event) from error
    elapsed = round((time.monotonic() - started) * 1000)
    event = {
        "operation": operation,
        "outcome": "ok" if result.returncode == 0 else "exit_error",
        "returncode": result.returncode,
        "elapsed_ms": elapsed,
    }
    fixture._record_command(event)
    if result.returncode != 0:
        detail = _BASE._safe_diagnostic_text(result.stderr)
        raise _BASE.SmokeFailure(f"{operation} failed: {detail}", command_event=event)
    return {"operation": operation, "outcome": "passed", "elapsed_ms": elapsed}


def _run_sql(fixture: SettingsFixture, tls: bool, sql: str) -> str:
    command = [
        *fixture.kubectl_base,
        "--namespace", fixture.namespace,
        "exec", "db-0", "--container=db", "--",
        "/cockroach/cockroach", "sql", "--host=localhost", "--port=26257", "--format=csv",
    ]
    command.append("--certs-dir=/cockroach/cockroach-certs" if tls else "--insecure")
    command.extend(["-e", sql])
    return _BASE.run(
        command, timeout=35, operation="settings fixture SQL", observer=fixture._record_command
    )


def _run_observer_compat_sql(fixture: SettingsFixture, sql: str) -> str:
    """Use fixture constants independently of the observer under test."""
    command = [
        *fixture.kubectl_base,
        "--namespace", fixture.namespace,
        "exec", "db-0", "--container=db", "--",
        "/cockroach/cockroach", "sql", "--host=localhost", "--port=26258", "--format=csv",
        "--certs-dir=/root/.cockroach-certs", "-e", sql,
    ]
    return _BASE.run(
        command,
        timeout=35,
        operation="observer compatibility fixture SQL",
        observer=fixture._record_command,
    )


def _witness_hash(fixture: SettingsFixture, tls: bool) -> tuple[int, str]:
    output = _run_sql(
        fixture, tls, f"SELECT id, payload FROM {_WITNESS_TABLE} ORDER BY id"
    )
    rows = [row for row in csv.reader(output.splitlines()) if row]
    if rows != _WITNESS_ROWS:
        raise _BASE.SmokeFailure("Persisted settings witness did not return the two expected rows")
    canonical = json.dumps(rows, ensure_ascii=False, separators=(",", ":"))
    return len(rows) - 1, hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _accepted_summary(state: Any) -> dict[str, Any]:
    return {
        "cluster_id": state.cluster_id,
        "node_ids": state.node_ids,
        "sql_versions": state.sql_versions,
        "tls_mode": state.tls_mode.value,
        "image": state.image,
        "desired_replicas": state.desired_replicas,
        "workload_spec_hash": state.workload_spec_hash,
        "pvc_identities": state.pvc_identities,
        "certificate_fingerprints": state.certificate_fingerprints,
        "service_routing": state.service_routing,
    }


def _sha256_json(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _observed_secret_summary(observation: Any) -> list[dict[str, Any]]:
    return [
        {
            "name": secret.name,
            "uid": secret.uid,
            "keys": secret.keys,
            "sha256_by_key": secret.sha256_by_key,
        }
        for secret in observation.secrets
    ]


def _service_summary(observation: Any) -> list[tuple[str, str, str]]:
    return sorted(
        (service.name, service.uid, service.routing_hash)
        for service in observation.services
    )


def _assert_service_preservation_projection(
    before_services: Mapping[str, Mapping[str, str]],
    after_services: Mapping[str, Mapping[str, str]],
    before_routing: Sequence[Sequence[str]],
    after_routing: Sequence[Sequence[str]],
    repair: Mapping[str, Any],
) -> dict[str, Any]:
    """Allow only the intended headless-Service spec/routing repair delta."""
    if set(before_services) != {"db", "db-public"} or set(after_services) != set(before_services):
        raise _BASE.SmokeFailure("Service repair changed the selected Service set")
    before_headless = before_services["db"]
    after_headless = after_services["db"]
    if before_headless.get("uid") != after_headless.get("uid"):
        raise _BASE.SmokeFailure("Headless Service repair replaced its Kubernetes identity")
    if before_headless.get("spec_sha256") == after_headless.get("spec_sha256"):
        raise _BASE.SmokeFailure("Headless Service repair did not record its intended spec change")
    if before_services["db-public"] != after_services["db-public"]:
        raise _BASE.SmokeFailure("Headless Service repair changed the public Service")
    repaired = repair.get("headless_repaired")
    if (
        not isinstance(repaired, Mapping)
        or repaired.get("uid") != after_headless.get("uid")
        or repaired.get("spec_sha256") != after_headless.get("spec_sha256")
    ):
        raise _BASE.SmokeFailure("Headless Service repair result does not match the observed Service")
    checks = repair.get("checks_after_repair")
    if not isinstance(checks, Mapping) or any(
        not isinstance(checks.get(name), Mapping) or checks[name].get("returncode") != 0
        for name in ("headless", "public")
    ):
        raise _BASE.SmokeFailure("Service checks did not confirm the repaired headless and public routes")

    def route_map(rows: Sequence[Sequence[str]]) -> dict[str, tuple[str, str]]:
        result: dict[str, tuple[str, str]] = {}
        for row in rows:
            if (
                not isinstance(row, (tuple, list))
                or len(row) != 3
                or not all(isinstance(item, str) and item for item in row)
                or row[0] in result
            ):
                raise _BASE.SmokeFailure("Service routing observation is incomplete or ambiguous")
            result[row[0]] = (row[1], row[2])
        return result

    before_routes = route_map(before_routing)
    after_routes = route_map(after_routing)
    if set(before_routes) != {"db", "db-public"} or set(after_routes) != set(before_routes):
        raise _BASE.SmokeFailure("Service repair changed the observed routing set")
    if before_routes["db-public"] != after_routes["db-public"]:
        raise _BASE.SmokeFailure("Headless Service repair changed observed public routing")
    if before_routes["db"][0] != after_routes["db"][0] or before_routes["db"][1] == after_routes["db"][1]:
        raise _BASE.SmokeFailure("Observed headless routing does not show the intended in-place repair")
    if before_routes["db"][0] != before_headless.get("uid") or after_routes["db"][0] != after_headless.get("uid"):
        raise _BASE.SmokeFailure("Observed headless routing does not match its Service identity")
    return {
        "headless_uid_preserved": True,
        "headless_spec_changed_by_original_repair": True,
        "public_service_identity_and_spec_preserved": True,
        "public_routing_preserved": True,
        "headless_routing_hash_before_after": [before_routes["db"][1], after_routes["db"][1]],
    }


def _require_single_health_response(results: Any, *, path: str) -> None:
    if results != (("db-0", 200, True),):
        raise _BASE.SmokeFailure(f"Health endpoint {path} did not return one successful db-0 response")


def _load_oracle(fixture: SettingsFixture, target_value: str) -> dict[str, Any]:
    with case_environment(
        fixture.namespace,
        setting_value=target_value,
        kubectl=fixture.args.kubectl,
    ):
        return runpy.run_path(str(ORACLE_PATH))


def _oracle_check(
    fixture: SettingsFixture,
    target_value: str,
    phase: str,
) -> list[str]:
    oracle = _load_oracle(fixture, target_value)
    errors: list[str] = []
    oracle["check"](errors, phase)
    return errors


def _choose_different_setting_value(oracle: Mapping[str, Any], current: str) -> str:
    for candidate in ("128MiB", "256MiB", "64MiB"):
        if not oracle["values_match"](candidate, current):
            return candidate
    raise _BASE.SmokeFailure("Could not choose a cluster setting value different from the fixture default")


def _wait_for_replacement_pod(
    fixture: SettingsFixture,
    *,
    old_uid: str,
    timeout: float = 180,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        pod = fixture.get("pods", "db-0", timeout=5)
        metadata = pod.get("metadata", {})
        if (
            metadata.get("uid")
            and metadata.get("uid") != old_uid
            and not metadata.get("deletionTimestamp")
            and _BASE._safe_pod_summary(pod).get("status", {}).get("phase") == "Running"
            and any(
                item.get("type") == "Ready" and item.get("status") == "True"
                for item in pod.get("status", {}).get("conditions", [])
            )
        ):
            return pod
        time.sleep(1)
    raise _BASE.SmokeFailure("UID-guarded replacement db-0 did not become Ready within the bound")


def _restart_pod_with_uid_guard(
    fixture: SettingsFixture,
    *,
    expected_uid: str | None = None,
    timeout: float = 180,
) -> tuple[str, str]:
    current = fixture.get("pods", "db-0")
    metadata = current.get("metadata", {})
    uid = str(metadata.get("uid", ""))
    if not uid or (expected_uid is not None and uid != expected_uid):
        raise _BASE.SmokeFailure("Pod identity changed before the controlled UID-guarded restart")
    if metadata.get("labels", {}).get("crdb-library-run") != fixture.run_id:
        raise _BASE.SmokeFailure("Refusing to restart a pod not owned by this settings fixture")
    fixture.set_stage("uid-guarded-normal-grace-pod-restart")
    fixture.raw_delete_uid("pod", "db-0", uid)
    replacement = _wait_for_replacement_pod(fixture, old_uid=uid, timeout=timeout)
    return uid, str(replacement["metadata"]["uid"])


def _exercise_existing_phase(
    args: argparse.Namespace,
    fixture: SettingsFixture,
    *,
    tls: bool,
) -> dict[str, Any]:
    fixture.wait_ready(timeout=args.ready_timeout)
    fixture.init(tls)
    library = CrdbLibrary(KubectlAdapter(kubectl=args.kubectl))
    ref = WorkloadRef(fixture.namespace, "db", "db")
    requirement = Requirement(
        Lifecycle.INITIALIZED,
        minimum_nodes=1,
        tls_mode=TLSMode.TLS if tls else TLSMode.INSECURE,
    )
    initialized = library.reconcile(
        ref,
        requirement,
        timeout=120,
        poll_interval=1,
        per_node_timeout=5,
    )
    if initialized.assessment.status is not ProbeStatus.SATISFIED:
        raise _BASE.SmokeFailure("Settings fixture did not become semantically initialized")

    fixture.set_stage("create-persisted-settings-witness")
    _run_sql(fixture, tls, f"CREATE DATABASE {_WITNESS_DB}")
    _run_sql(
        fixture,
        tls,
        f"CREATE TABLE {_WITNESS_TABLE} (id INT PRIMARY KEY, payload STRING NOT NULL)",
    )
    _run_sql(
        fixture,
        tls,
        f"INSERT INTO {_WITNESS_TABLE} VALUES "
        "(1, 'preserve across case setup'), (2, 'preserve across pod restart')",
    )
    witness_before = _witness_hash(fixture, tls)
    accepted_before = library.capture_accepted_state(ref, per_node_timeout=5)

    case_commands = [
        run_case_command(fixture, "probe", timeout=90),
        run_case_command(fixture, "apply", timeout=150),
        run_case_command(fixture, "verify", timeout=90),
    ]
    accepted_after_apply = library.capture_accepted_state(ref, per_node_timeout=5)
    if accepted_after_apply != accepted_before:
        raise _BASE.SmokeFailure("The case's healthy apply changed accepted workload state")
    noop_verified = library.verify_accepted_state(ref, accepted_before, per_node_timeout=5)
    if noop_verified.status is not ProbeStatus.SATISFIED:
        raise _BASE.SmokeFailure("Accepted state failed verification after the case's no-op apply")
    witness_after_apply = _witness_hash(fixture, tls)
    if witness_after_apply != witness_before:
        raise _BASE.SmokeFailure("Case precondition commands changed the persisted witness rows")

    oracle = _load_oracle(fixture, "128MiB")
    resolved_setting_name = oracle["resolve_setting_name"]()
    current_value, setting_error = oracle["get_setting"]()
    if setting_error or current_value is None:
        raise _BASE.SmokeFailure("Independent cluster-settings oracle could not read the initial setting")
    target_value = _choose_different_setting_value(oracle, current_value)
    before_errors = _oracle_check(fixture, target_value, "before controlled setting change")
    if not before_errors or not all("expected" in error and target_value in error for error in before_errors):
        raise _BASE.SmokeFailure("Independent oracle did not reject the setting's pre-change value")

    fixture.set_stage("apply-controlled-cluster-setting")
    _run_sql(
        fixture,
        tls,
        f"SET CLUSTER SETTING {resolved_setting_name} = '{target_value}';",
    )
    after_errors = _oracle_check(fixture, target_value, "after controlled setting change")
    if after_errors:
        raise _BASE.SmokeFailure("Independent oracle rejected the explicitly configured cluster setting")

    pod_before = fixture.get("pods", "db-0")
    old_pod_uid = str(pod_before.get("metadata", {}).get("uid", ""))
    old_uid, replacement_uid = _restart_pod_with_uid_guard(
        fixture, expected_uid=old_pod_uid, timeout=args.restart_timeout
    )
    recovered = library.reconcile(
        ref,
        requirement,
        timeout=120,
        poll_interval=1,
        per_node_timeout=5,
    )
    if recovered.assessment.status is not ProbeStatus.SATISFIED:
        raise _BASE.SmokeFailure("CockroachDB did not recover after the normal-grace UID-guarded pod restart")
    persistence_errors = _oracle_check(fixture, target_value, "after controlled pod restart")
    if persistence_errors:
        raise _BASE.SmokeFailure("Independent oracle rejected the cluster setting after restart")
    accepted_after_restart = library.capture_accepted_state(ref, per_node_timeout=5)
    if accepted_after_restart != accepted_before:
        raise _BASE.SmokeFailure("Accepted workload state changed across the no-op apply and pod restart")
    witness_after_restart = _witness_hash(fixture, tls)
    if witness_after_restart != witness_before:
        raise _BASE.SmokeFailure("Persisted witness rows changed across the pod restart")

    return {
        "tls_mode": "tls" if tls else "insecure",
        "precondition_commands": case_commands,
        "case_apply_noop": True,
        "accepted_state_before_after": [
            _accepted_summary(accepted_before),
            _accepted_summary(accepted_after_apply),
            _accepted_summary(accepted_after_restart),
        ],
        "initial_setting_value": current_value,
        "resolved_setting_name": resolved_setting_name,
        "test_setting_value": target_value,
        "oracle_rejected_before_change": True,
        "oracle_accepted_after_change": True,
        "oracle_accepted_after_restart": True,
        "pod_uid_before_after_restart": [old_uid, replacement_uid],
        "witness_row_count": witness_before[0],
        "witness_sha256_before_after_apply_and_restart": [
            witness_before[1], witness_after_apply[1], witness_after_restart[1],
        ],
    }


def _observer_compat_witness_hash(fixture: SettingsFixture) -> tuple[int, str]:
    output = _run_observer_compat_sql(
        fixture, f"SELECT id, payload FROM {_WITNESS_TABLE} ORDER BY id"
    )
    rows = [row for row in csv.reader(output.splitlines()) if row]
    if rows != _WITNESS_ROWS:
        raise _BASE.SmokeFailure("Observer-compatibility witness did not return the expected two rows")
    canonical = json.dumps(rows, ensure_ascii=False, separators=(",", ":"))
    return len(rows) - 1, hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _run_secure_target_component(
    fixture: SettingsFixture,
    mode: str,
    plan_path: Path,
    *,
    timeout: float = 60,
    service_name: str | None = None,
    services_manifest: Path | None = None,
    cluster_name: str | None = None,
    expected_status: int = 0,
    output_path: Path | None = None,
) -> dict[str, Any]:
    """Invoke only the certificate-rotation target component CLI, without its shell workflow."""
    operation = f"certificate-rotation target component {mode}"
    command = [
        sys.executable,
        str(SECURE_TARGET_PATH),
        mode,
        "--namespace", fixture.namespace,
        "--statefulset", "db",
        "--plan", str(plan_path),
        "--kubectl", fixture.args.kubectl,
    ]
    if mode == "prepare":
        command.extend(
            [
                "--secret", "db-certs",
                "--cert-dir", "/cockroach/cockroach-certs",
                "--case-manifest", str(CASE_STATEFULSET_MANIFEST),
            ]
        )
    elif mode == "service-check":
        if service_name is None:
            raise _BASE.SmokeFailure("service-check requires a selected Service name")
        command.extend(["--service", service_name])
    elif mode == "render-service":
        if service_name is None or services_manifest is None or cluster_name is None or output_path is None:
            raise _BASE.SmokeFailure("render-service requires a Service, manifest, cluster, and output path")
        command.extend(
            [
                "--service", service_name,
                "--services-manifest", str(services_manifest),
                "--cluster-name", cluster_name,
            ]
        )
    fixture.set_stage(operation)
    started = time.monotonic()
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        event = {
            "operation": operation,
            "outcome": "timeout",
            "returncode": None,
            "elapsed_ms": round((time.monotonic() - started) * 1000),
        }
        fixture._record_command(event)
        raise _BASE.SmokeFailure(f"{operation} timed out", command_event=event) from None
    except OSError:
        event = {
            "operation": operation,
            "outcome": "spawn_error",
            "returncode": None,
            "elapsed_ms": round((time.monotonic() - started) * 1000),
        }
        fixture._record_command(event)
        raise _BASE.SmokeFailure(f"Could not run {operation}", command_event=event) from None
    event = {
        "operation": operation,
        "outcome": (
            "ok" if result.returncode == 0
            else "expected_exit" if result.returncode == expected_status
            else "exit_error"
        ),
        "returncode": result.returncode,
        "expected_returncode": expected_status,
        "elapsed_ms": round((time.monotonic() - started) * 1000),
    }
    fixture._record_command(event)
    if result.returncode != expected_status:
        detail = _BASE._safe_diagnostic_text(result.stderr)
        raise _BASE.SmokeFailure(
            f"{operation} returned an unexpected status: {detail}", command_event=event
        )
    if output_path is not None:
        try:
            output_path.write_text(result.stdout, encoding="utf-8")
        except OSError as error:
            raise _BASE.SmokeFailure(f"{operation} output could not be saved") from error
    return {
        "operation": operation,
        "outcome": "passed",
        "returncode": result.returncode,
        "expected_returncode": expected_status,
        "elapsed_ms": event["elapsed_ms"],
    }


def _exercise_scaled_service_preservation(
    fixture: SettingsFixture,
    plan_path: Path,
    *,
    public_service_before: Mapping[str, Any],
    headless_service_before: Mapping[str, Any],
    phase_data: dict[str, Any],
) -> dict[str, Any]:
    """Exercise per-Service preservation and original repair while the target is scaled down."""
    headless_metadata = headless_service_before.get("metadata", {})
    headless_spec = headless_service_before.get("spec", {})
    headless_uid = headless_metadata.get("uid") if isinstance(headless_metadata, Mapping) else None
    resource_version = headless_metadata.get("resourceVersion") if isinstance(headless_metadata, Mapping) else None
    ports = headless_spec.get("ports") if isinstance(headless_spec, Mapping) else None
    if not isinstance(headless_uid, str) or not headless_uid or not isinstance(resource_version, str) or not resource_version:
        raise _BASE.SmokeFailure("Headless Service identity is incomplete before the repair check")
    if not isinstance(ports, list):
        raise _BASE.SmokeFailure("Headless Service ports are unavailable before the repair check")
    sql_indices = [
        index for index, item in enumerate(ports)
        if isinstance(item, Mapping) and item.get("port") == 26257 and item.get("protocol", "TCP") == "TCP"
    ]
    if len(sql_indices) != 1:
        raise _BASE.SmokeFailure("Headless Service SQL frontend is ambiguous in the fixture")
    sql_index = sql_indices[0]
    prior_target = ports[sql_index].get("targetPort", 26257)
    wrong_target = 26256 if prior_target != 26256 else 26255
    invalid_patch = [
        {"op": "test", "path": "/metadata/uid", "value": headless_uid},
        {"op": "test", "path": "/metadata/resourceVersion", "value": resource_version},
        {"op": "replace", "path": f"/spec/ports/{sql_index}/targetPort", "value": wrong_target},
    ]
    phase_data["service_preservation"] = {
        "public_service_before": {
            "uid": public_service_before.get("metadata", {}).get("uid"),
            "spec_sha256": _sha256_json(public_service_before.get("spec", {})),
            "type": public_service_before.get("spec", {}).get("type"),
            "node_ports": [
                item.get("nodePort") for item in public_service_before.get("spec", {}).get("ports", [])
                if isinstance(item, Mapping) and item.get("nodePort") is not None
            ],
        },
        "headless_service_uid": headless_uid,
        "headless_sql_target_before": prior_target,
        "headless_sql_target_injected": wrong_target,
        "invalid_patch_uid_and_resource_version_guarded": True,
    }
    fixture._checkpoint("service-repair-fault-intent-recorded")
    fixture.set_stage("inject-headless-service-routing-fault")
    fixture.kubectl(
        "patch", "service", "db", "--type=json", "--patch",
        json.dumps(invalid_patch, separators=(",", ":")),
        namespace=fixture.namespace,
        timeout=30,
    )
    invalid_headless = fixture.get("service", "db")
    invalid_spec = invalid_headless.get("spec", {})
    invalid_ports = invalid_spec.get("ports", []) if isinstance(invalid_spec, Mapping) else []
    if (
        invalid_headless.get("metadata", {}).get("uid") != headless_uid
        or len(invalid_ports) <= sql_index
        or invalid_ports[sql_index].get("targetPort") != wrong_target
    ):
        raise _BASE.SmokeFailure("Headless Service routing fault did not match its guarded intent")
    phase_data["service_preservation"]["invalid_headless_spec_sha256"] = _sha256_json(invalid_spec)
    fixture._checkpoint("headless-service-routing-fault-observed")

    headless_check = _run_secure_target_component(
        fixture, "service-check", plan_path, service_name="db", expected_status=4
    )
    public_check = _run_secure_target_component(
        fixture, "service-check", plan_path, service_name="db-public", expected_status=0
    )
    phase_data["service_preservation"]["checks_before_repair"] = {
        "headless": headless_check,
        "public": public_check,
    }
    public_after_check = fixture.get("service", "db-public")
    if (
        public_after_check.get("metadata", {}).get("uid") != public_service_before.get("metadata", {}).get("uid")
        or public_after_check.get("spec") != public_service_before.get("spec")
    ):
        raise _BASE.SmokeFailure("Valid public NodePort Service changed during the repair classification")
    fixture._checkpoint("headless-repair-needed-public-service-preserved")

    with tempfile.TemporaryDirectory(prefix="crdb-certificate-rotation-service-repair-") as temporary:
        rendered = Path(temporary) / "db-service.yaml"
        phase_data["service_preservation"]["render_original_headless"] = _run_secure_target_component(
            fixture,
            "render-service",
            plan_path,
            service_name="db",
            services_manifest=CASE_SERVICES_MANIFEST,
            cluster_name="db",
            output_path=rendered,
        )
        if not rendered.is_file() or not rendered.read_text(encoding="utf-8").strip():
            raise _BASE.SmokeFailure("Original headless Service document was not rendered")
        try:
            rendered_document = yaml.safe_load(rendered.read_text(encoding="utf-8"))
        except yaml.YAMLError as error:
            raise _BASE.SmokeFailure("Original headless Service document is invalid") from error
        metadata = rendered_document.get("metadata") if isinstance(rendered_document, Mapping) else None
        labels = metadata.get("labels", {}) if isinstance(metadata, Mapping) else None
        run_id = getattr(fixture, "run_id", None)
        if (
            not isinstance(rendered_document, Mapping)
            or rendered_document.get("kind") != "Service"
            or not isinstance(metadata, dict)
            or metadata.get("name") != "db"
            or not isinstance(labels, dict)
            or not isinstance(run_id, str)
            or not run_id
        ):
            raise _BASE.SmokeFailure("Rendered headless Service lacks its fixture ownership identity")
        original_case_document = copy.deepcopy(dict(rendered_document))
        case_service_spec = copy.deepcopy(rendered_document.get("spec", {}))
        case_spec_sha256 = _sha256_json(case_service_spec)
        case_document_sha256 = _sha256_json(original_case_document)
        applied_labels = {**labels, "crdb-library-run": run_id}
        expected_applied_document = copy.deepcopy(original_case_document)
        expected_applied_document["metadata"]["labels"] = applied_labels
        rendered_document["metadata"]["labels"] = applied_labels
        if (
            rendered_document.get("spec") != case_service_spec
            or rendered_document != expected_applied_document
        ):
            raise _BASE.SmokeFailure("Harness cleanup metadata changed the original Service document beyond its label")
        applied_document_sha256 = _sha256_json(rendered_document)
        rendered.write_text(yaml.safe_dump(dict(rendered_document), sort_keys=False), encoding="utf-8")
        phase_data["service_preservation"].update(
            {
                "rendered_case_service_spec_sha256": case_spec_sha256,
                "rendered_case_service_document_sha256": case_document_sha256,
                "applied_document_sha256": applied_document_sha256,
                "applied_document_delta": "harness ownership label in metadata only; Service spec unchanged",
            }
        )
        fixture.set_stage("apply-original-headless-service-repair")
        fixture.kubectl(
            "apply", "--filename", str(rendered), namespace=fixture.namespace, timeout=30
        )
        fixture._checkpoint("original-headless-service-repair-applied")

    headless_after = fixture.get("service", "db")
    public_after = fixture.get("service", "db-public")
    repaired_headless_spec = headless_after.get("spec", {})
    if (
        headless_after.get("metadata", {}).get("uid") != headless_uid
        or public_after.get("metadata", {}).get("uid") != public_service_before.get("metadata", {}).get("uid")
        or public_after.get("spec") != public_service_before.get("spec")
    ):
        raise _BASE.SmokeFailure("Service repair changed a Service identity or the valid public Service spec")
    headless_after_check = _run_secure_target_component(
        fixture, "service-check", plan_path, service_name="db", expected_status=0
    )
    public_after_check = _run_secure_target_component(
        fixture, "service-check", plan_path, service_name="db-public", expected_status=0
    )
    phase_data["service_preservation"].update(
        {
            "headless_repaired": {
                "uid": headless_uid,
                "spec_sha256": _sha256_json(repaired_headless_spec),
                "sql_target_after": next(
                    item.get("targetPort", item.get("port"))
                    for item in repaired_headless_spec.get("ports", [])
                    if isinstance(item, Mapping)
                    and item.get("port") == 26257
                    and item.get("protocol", "TCP") == "TCP"
                ),
            },
            "public_service_after": {
                "uid": public_after.get("metadata", {}).get("uid"),
                "spec_sha256": _sha256_json(public_after.get("spec", {})),
            },
            "checks_after_repair": {"headless": headless_after_check, "public": public_after_check},
            "original_case_service_spec_applied": True,
            "harness_ownership_metadata_added": True,
            "extra_rpc_port_removal_assumed": False,
        }
    )
    fixture._checkpoint("service-preservation-repair-verified")
    return phase_data["service_preservation"]


def _run_tls_only_readiness_bridge(fixture: SettingsFixture, *, expected_status: int) -> dict[str, Any]:
    operation = "certificate-rotation TLS-only SQL readiness bridge"
    command = [
        sys.executable,
        str(SQL_READY_PATH),
        "--namespace", fixture.namespace,
        "--statefulset", "db",
        "--policy", "tls-only",
    ]
    fixture.set_stage(operation)
    started = time.monotonic()
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired):
        event = {
            "operation": operation,
            "outcome": "execution_error",
            "returncode": None,
            "elapsed_ms": round((time.monotonic() - started) * 1000),
        }
        fixture._record_command(event)
        raise _BASE.SmokeFailure(f"{operation} could not complete within its bound", command_event=event) from None
    event = {
        "operation": operation,
        "outcome": "ok" if result.returncode == 0 else "exit_error",
        "returncode": result.returncode,
        "elapsed_ms": round((time.monotonic() - started) * 1000),
    }
    fixture._record_command(event)
    observation = {**event, "expected_returncode": expected_status}
    if result.returncode != expected_status:
        detail = _BASE._safe_diagnostic_text(result.stderr)
        raise _BASE.SmokeFailure(
            f"{operation} returned an unexpected status: {detail}", command_event=event
        )
    return observation


def _fixture_service_identities(fixture: SettingsFixture) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for name in ("db", "db-public"):
        service = fixture.get("service", name)
        metadata = service.get("metadata", {})
        uid = metadata.get("uid")
        if not isinstance(uid, str) or not uid:
            raise _BASE.SmokeFailure(f"Fixture Service {name} identity is incomplete")
        result[name] = {"uid": uid, "spec_sha256": _sha256_json(service.get("spec", {}))}
    return result


def _fixture_secret_fingerprints(fixture: SettingsFixture) -> dict[str, Any]:
    secret = fixture.get("secret", "db-certs")
    metadata = secret.get("metadata", {})
    data = secret.get("data", {})
    uid = metadata.get("uid")
    if not isinstance(uid, str) or not uid or not isinstance(data, Mapping) or not data:
        raise _BASE.SmokeFailure("Fixture TLS Secret identity or data is incomplete")
    return {
        "uid": uid,
        "sha256_by_key": {
            key: hashlib.sha256(value.encode("ascii")).hexdigest()
            for key, value in sorted(data.items())
            if isinstance(key, str) and isinstance(value, str)
        },
    }


def _install_insecure_http_liveness_probe(fixture: SettingsFixture) -> str:
    """Add one modeled HTTP probe to the insecure fixture without changing TCP readiness."""
    selected = fixture.get("statefulset", "db")
    metadata = selected.get("metadata", {})
    uid = metadata.get("uid")
    resource_version = metadata.get("resourceVersion")
    containers = selected.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
    index = next(
        (position for position, container in enumerate(containers) if container.get("name") == "db"),
        None,
    )
    if not isinstance(uid, str) or not uid or not isinstance(resource_version, str) or index is None:
        raise _BASE.SmokeFailure("Insecure fixture StatefulSet identity or database container is incomplete")
    current_probe = containers[index].get("livenessProbe")
    if not isinstance(current_probe, Mapping) or not isinstance(current_probe.get("tcpSocket"), Mapping):
        raise _BASE.SmokeFailure("Insecure fixture did not start with its expected TCP liveness probe")
    http_probe = {key: value for key, value in current_probe.items() if key != "tcpSocket"}
    http_probe["httpGet"] = {"path": "/health", "port": "http", "scheme": "HTTP"}
    adapter = KubectlAdapter(kubectl=fixture.args.kubectl)
    adapter.patch_statefulset_json(
        namespace=fixture.namespace,
        name="db",
        uid=uid,
        resource_version=resource_version,
        operations=[
            {"op": "test", "path": "/metadata/uid", "value": uid},
            {"op": "test", "path": "/metadata/resourceVersion", "value": resource_version},
            {
                "op": "replace",
                "path": f"/spec/template/spec/containers/{index}/livenessProbe",
                "value": http_probe,
            },
        ],
        timeout=30,
    )
    fixture._record_command(
        {"operation": "install controlled HTTP liveness probe", "outcome": "passed", "uid": uid}
    )
    return uid


def _exercise_tls_transform_component(
    args: argparse.Namespace,
    fixture: SettingsFixture,
    phase_data: dict[str, Any],
    *,
    service_preservation: bool = False,
) -> dict[str, Any]:
    """Exercise only the secure-template transformation on an initialized one-node fixture."""
    fixture.wait_ready(timeout=args.ready_timeout)
    library = CrdbLibrary(KubectlAdapter(kubectl=args.kubectl))
    ref = WorkloadRef(fixture.namespace, "db", "db")
    deployed = library.probe(
        ref,
        Requirement(Lifecycle.DEPLOYED, minimum_nodes=1, tls_mode=TLSMode.INSECURE),
        per_node_timeout=5,
    )
    if deployed.status is not ProbeStatus.SATISFIED or deployed.health.lifecycle is not Lifecycle.DEPLOYED:
        raise _BASE.SmokeFailure("Insecure component fixture was not positively deployed before explicit init")
    fixture._checkpoint("tls-transform-deployed-before-explicit-init")

    fixture.init(tls=False)
    requirement = Requirement(Lifecycle.INITIALIZED, minimum_nodes=1, tls_mode=TLSMode.INSECURE)
    initialized = library.reconcile(
        ref, requirement, timeout=120, poll_interval=1, per_node_timeout=5
    )
    if initialized.assessment.status is not ProbeStatus.SATISFIED:
        raise _BASE.SmokeFailure("Insecure component fixture did not initialize")

    original_pod = fixture.get("pods", "db-0")
    original_pod_uid = original_pod.get("metadata", {}).get("uid")
    if not isinstance(original_pod_uid, str) or not original_pod_uid:
        raise _BASE.SmokeFailure("Insecure component fixture Pod identity is incomplete")
    fixture.set_stage("prepare-controlled-http-liveness-probe")
    _install_insecure_http_liveness_probe(fixture)
    ready_pod = _wait_for_replacement_pod(
        fixture, old_uid=original_pod_uid, timeout=args.restart_timeout
    )
    liveness_sts = fixture.get("statefulset", "db")
    liveness_containers = liveness_sts.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
    liveness_container = next(
        (container for container in liveness_containers if container.get("name") == "db"),
        {},
    )
    liveness_probe = liveness_container.get("livenessProbe", {})
    readiness_probe = liveness_container.get("readinessProbe", {})
    if (
        liveness_probe.get("httpGet", {}).get("scheme") != "HTTP"
        or liveness_probe.get("httpGet", {}).get("path") != "/health"
        or readiness_probe.get("tcpSocket", {}).get("port") != "rpc"
    ):
        raise _BASE.SmokeFailure("Controlled baseline did not retain HTTP liveness and TCP readiness probes")
    fixture._checkpoint("controlled-http-liveness-ready")

    initialized = library.reconcile(
        ref, requirement, timeout=90, poll_interval=1, per_node_timeout=5
    )
    if initialized.assessment.status is not ProbeStatus.SATISFIED:
        raise _BASE.SmokeFailure("Insecure fixture did not converge after adding the HTTP liveness probe")

    insecure_health = library.probe_health_endpoint(ref, path="/health", per_node_timeout=5)
    _require_single_health_response(insecure_health, path="insecure /health")

    tls_only_before = _run_tls_only_readiness_bridge(fixture, expected_status=1)
    phase_data["readiness_bridge_before"] = tls_only_before
    fixture._checkpoint("tls-only-readiness-rejected-before-transform")

    fixture.set_stage("create-transform-witness")
    _run_sql(fixture, False, f"CREATE DATABASE {_WITNESS_DB}")
    _run_sql(
        fixture,
        False,
        f"CREATE TABLE {_WITNESS_TABLE} (id INT PRIMARY KEY, payload STRING NOT NULL)",
    )
    _run_sql(
        fixture,
        False,
        f"INSERT INTO {_WITNESS_TABLE} VALUES "
        "(1, 'preserve across case setup'), (2, 'preserve across pod restart')",
    )
    witness_before = _witness_hash(fixture, False)
    before_workload = initialized.assessment.workload
    accepted_before = library.accepted_state(initialized.assessment)
    before_sts = fixture.get("statefulset", "db")
    before_sts_metadata = before_sts.get("metadata", {})
    before_sts_uid = before_sts_metadata.get("uid")
    before_pod_uid = str(ready_pod.get("metadata", {}).get("uid", ""))
    before_storage = fixture._record_storage_snapshot("before-tls-transform")
    before_services = _fixture_service_identities(fixture)
    public_service_before = fixture.get("service", "db-public")
    headless_service_before = fixture.get("service", "db")
    before_secret = _fixture_secret_fingerprints(fixture)
    if before_sts_uid != fixture.created.get(("statefulset", "db")) or len(before_storage) != 1:
        raise _BASE.SmokeFailure("Component baseline does not match the owned StatefulSet and PVC identities")
    if service_preservation:
        public_spec = public_service_before.get("spec", {})
        public_ports = public_spec.get("ports", []) if isinstance(public_spec, Mapping) else []
        required_node_ports = [
            [port for port in public_ports if isinstance(port, Mapping)
             and port.get("port") == frontend and port.get("protocol", "TCP") == "TCP"]
            for frontend in (26257, 8080)
        ]
        if (
            not isinstance(public_spec, Mapping)
            or public_spec.get("type") != "NodePort"
            or any(len(matches) != 1 or not isinstance(matches[0].get("nodePort"), int)
                   for matches in required_node_ports)
        ):
            raise _BASE.SmokeFailure("Service-preservation fixture lacks allocated required NodePorts")
    phase_data["before_transform"] = {
        "accepted": _accepted_summary(accepted_before),
        "statefulset_uid": before_sts_uid,
        "pod_uid": before_pod_uid,
        "statefulset_spec_sha256": _sha256_json(before_sts.get("spec", {})),
        "storage": before_storage,
        "services": before_services,
        "secret_fingerprints": before_secret,
        "witness_rows": witness_before[0],
        "witness_sha256": witness_before[1],
    }
    fixture._checkpoint("tls-transform-baseline-recorded")

    with tempfile.TemporaryDirectory(prefix="crdb-certificate-rotation-component-") as temporary:
        plan_path = Path(temporary) / "secure-target-plan.json"
        prepare = _run_secure_target_component(fixture, "prepare", plan_path)
        try:
            plan = json.loads(plan_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise _BASE.SmokeFailure("Secure-template component did not produce a readable private plan") from error
        if plan.get("uid") != before_sts_uid or plan.get("original_spec") != before_sts.get("spec"):
            raise _BASE.SmokeFailure("Secure-template component plan does not match the recorded target baseline")
        if plan.get("target_replicas") != 1:
            raise _BASE.SmokeFailure("One-node component fixture changed its planned replica count")
        phase_data["component_prepare"] = prepare
        phase_data["planned_template_sha256"] = _sha256_json(plan.get("secure_template"))
        fixture._checkpoint("tls-transform-plan-validated")

        _run_secure_target_component(fixture, "scale", plan_path)
        fixture._checkpoint("tls-transform-scaled-to-zero")
        fixture.wait_absent("pod", "db-0", timeout=180)
        fixture._checkpoint("tls-transform-old-pod-terminated-normally")
        service_repair = None
        if service_preservation:
            service_repair = _exercise_scaled_service_preservation(
                fixture,
                plan_path,
                public_service_before=public_service_before,
                headless_service_before=headless_service_before,
                phase_data=phase_data,
            )
        _run_secure_target_component(fixture, "finish", plan_path)
        new_pod = _wait_for_replacement_pod(
            fixture, old_uid=before_pod_uid, timeout=args.ready_timeout
        )
        fixture._checkpoint("tls-transform-replacement-pod-ready")

    tls_only_after = _run_tls_only_readiness_bridge(fixture, expected_status=0)
    phase_data["readiness_bridge_after"] = tls_only_after
    fixture._checkpoint("tls-only-readiness-passed-after-transform")

    tls_requirement = Requirement(Lifecycle.INITIALIZED, minimum_nodes=1, tls_mode=TLSMode.TLS)
    tls_result = library.reconcile(
        ref, tls_requirement, timeout=120, poll_interval=1, per_node_timeout=5
    )
    if tls_result.assessment.status is not ProbeStatus.SATISFIED:
        raise _BASE.SmokeFailure("Transformed TLS target is not initialized and ready")
    endpoint_results = {
        path: library.probe_health_endpoint(ref, path=path, per_node_timeout=5)
        for path in ("/health", "/health?ready=1")
    }
    for path, results in endpoint_results.items():
        _require_single_health_response(results, path=f"HTTPS {path}")

    tls_sql_health = _witness_hash(fixture, True)
    after_workload = tls_result.assessment.workload
    accepted_after = library.accepted_state(tls_result.assessment)
    after_sts = fixture.get("statefulset", "db")
    after_storage = fixture._record_storage_snapshot("after-tls-transform")
    after_services = _fixture_service_identities(fixture)
    after_secret = _fixture_secret_fingerprints(fixture)
    after_sts_spec = after_sts.get("spec", {})
    final_containers = after_sts_spec.get("template", {}).get("spec", {}).get("containers", [])
    final_container = next(
        (container for container in final_containers if container.get("name") == "db"),
        {},
    )
    final_liveness = final_container.get("livenessProbe", {})
    if (
        final_liveness.get("httpGet", {}).get("scheme") != "HTTPS"
        or final_liveness.get("httpGet", {}).get("path") != "/health"
        or final_liveness.get("httpGet", {}).get("port") != "http"
        or final_container.get("readinessProbe", {}).get("tcpSocket", {}).get("port") != "rpc"
    ):
        raise _BASE.SmokeFailure("Secure-template transition did not convert only the modeled HTTP probe")
    expected_spec = copy.deepcopy(plan["original_spec"])
    expected_spec["template"] = plan["secure_template"]
    expected_spec["replicas"] = plan["target_replicas"]
    if (
        after_sts.get("metadata", {}).get("uid") != before_sts_uid
        or after_sts_spec != expected_spec
        or after_storage != before_storage
        or after_secret != before_secret
    ):
        raise _BASE.SmokeFailure("TLS transformation changed target identity or unplanned fixture resources")
    service_projection = None
    if service_preservation:
        if not isinstance(service_repair, Mapping):
            raise _BASE.SmokeFailure("Service-preservation repair evidence is missing")
        service_projection = _assert_service_preservation_projection(
            before_services,
            after_services,
            _service_summary(before_workload),
            _service_summary(after_workload),
            service_repair,
        )
    elif after_services != before_services:
        raise _BASE.SmokeFailure("TLS transformation changed target identity or unplanned fixture resources")
    initial_summary = _accepted_summary(accepted_before)
    after_summary = _accepted_summary(accepted_after)
    for field in (
        "cluster_id",
        "node_ids",
        "sql_versions",
        "image",
        "desired_replicas",
        "pvc_identities",
        "service_routing",
    ):
        if service_preservation and field == "service_routing":
            continue
        if after_summary[field] != initial_summary[field]:
            raise _BASE.SmokeFailure(f"TLS transformation changed accepted workload field {field}")
    if after_summary["tls_mode"] != "tls" or after_summary["workload_spec_hash"] == initial_summary["workload_spec_hash"]:
        raise _BASE.SmokeFailure("TLS transformation did not produce the intended secure workload change")
    if not service_preservation and _service_summary(after_workload) != _service_summary(before_workload):
        raise _BASE.SmokeFailure("TLS transformation changed observed Service routing")
    if _witness_hash(fixture, True) != witness_before:
        raise _BASE.SmokeFailure("TLS transformation changed the persisted two-row witness")
    if not before_pod_uid or new_pod.get("metadata", {}).get("uid") == before_pod_uid:
        raise _BASE.SmokeFailure("TLS transformation did not replace the selected Pod")
    init_commands = [event for event in fixture.command_trace if event.get("operation") == "cockroach init"]
    if len(init_commands) != 1:
        raise _BASE.SmokeFailure("TLS transformation implicitly initialized or reinitialized the target")

    result = {
        "scope": "component-only secure-template prepare/scale/finish; no full case workflow or task oracle",
        "initial_tls_mode": initial_summary["tls_mode"],
        "final_tls_mode": after_summary["tls_mode"],
        "lifecycle_before_after": ["INITIALIZED", "INITIALIZED"],
        "tls_only_readiness_bridge_before_after": [tls_only_before, tls_only_after],
        "https_health_endpoints": {
            path: [{"pod": pod, "status": status, "passed": passed} for pod, status, passed in rows]
            for path, rows in endpoint_results.items()
        },
        "accepted_state_before_after": [initial_summary, after_summary],
        "statefulset_uid_before_after": [before_sts_uid, after_sts.get("metadata", {}).get("uid")],
        "pod_uid_before_after": [before_pod_uid, new_pod.get("metadata", {}).get("uid")],
        "pvc_storage_before_after": [before_storage, after_storage],
        "service_identities_and_spec_hashes_before_after": [before_services, after_services],
        "secret_fingerprints_before_after": [before_secret, after_secret],
        "statefulset_spec_sha256_before_after": [
            _sha256_json(before_sts.get("spec", {})),
            _sha256_json(after_sts_spec),
        ],
        "witness_rows": witness_before[0],
        "witness_sha256_before_after": [witness_before[1], tls_sql_health[1]],
        "explicit_init_count": len(init_commands),
        "task_oracle": "not run",
    }
    if service_preservation:
        result["service_preservation_component"] = {
            "public_service_full_spec_and_uid_preserved": True,
            "headless_service_uid_retained": True,
            "headless_service_repair": service_repair,
            "accepted_routing_projection": service_projection,
            "scope": "component service-check and original headless Service spec apply with harness ownership metadata; no full shell workflow",
        }
    phase_data["tls_transform_component"] = result
    fixture._checkpoint("tls-transform-component-verified")
    return result


def _exercise_observer_compat_phase(
    args: argparse.Namespace,
    fixture: SettingsFixture,
    *,
    oracle_rebind: bool = False,
    oracle_sql_connection: bool = False,
) -> dict[str, Any]:
    """Exercise the observer-compatible fixture and its opt-in proof component."""
    fixture.wait_ready(timeout=args.ready_timeout)
    library = CrdbLibrary(KubectlAdapter(kubectl=args.kubectl))
    ref = WorkloadRef(fixture.namespace, "db", "db")
    deployed = library.probe(
        ref,
        Requirement(Lifecycle.DEPLOYED, minimum_nodes=1, tls_mode=TLSMode.TLS),
        per_node_timeout=5,
    )
    if (
        deployed.status is not ProbeStatus.SATISFIED
        or deployed.health.lifecycle is not Lifecycle.DEPLOYED
        or getattr(deployed.workload.http_transport, "value", None) != "https"
    ):
        raise _BASE.SmokeFailure(
            "Observer-compatibility target was not positively deployed, uninitialized, and HTTPS-served"
        )

    observed = library.inspect_sql_connection(ref, ordinal=0)
    if (
        observed.workload_uid != deployed.workload.workload_uid
        or observed.tls_mode is not TLSMode.TLS
        or observed.certs_dir != "/root/.cockroach-certs"
        or observed.sql_port != 26258
        or observed.rpc_port != 26258
    ):
        raise _BASE.SmokeFailure("Shared observer did not resolve the fixture's expected TLS/26258 endpoints")
    fixture._checkpoint("observer-compat-deployed-before-explicit-init")

    certificate_oracle = None
    preinit_oracle_check = None
    oracle_sql_result = None
    pod_uids_deployed = tuple(pod.uid for pod in deployed.workload.pods)
    if oracle_sql_connection:
        if len(pod_uids_deployed) != 1 or observed.pod_uid != pod_uids_deployed[0]:
            raise _BASE.SmokeFailure("Initial SQL observer did not identify the selected fixture Pod")
        certificate_oracle = _load_certificate_rotation_oracle(fixture)
        oracle_sql_result = {
            "preinit": None,
            "oracle_main_invoked": False,
            "explicit_init_count": 0,
            "checks": [],
        }
        fixture.phase_data["certificate_rotation_sql_connection"] = oracle_sql_result
        preinit_oracle_check = _certificate_oracle_sql_check(
            fixture,
            certificate_oracle,
            label="before-explicit-init",
            expect_success=False,
        )
        oracle_sql_result["preinit"] = preinit_oracle_check
        fixture._checkpoint("certificate-oracle-preinit-result-recorded")
        still_deployed = library.probe(
            ref,
            Requirement(Lifecycle.DEPLOYED, minimum_nodes=1, tls_mode=TLSMode.TLS),
            per_node_timeout=5,
        )
        if (
            still_deployed.status is not ProbeStatus.SATISFIED
            or still_deployed.health.lifecycle is not Lifecycle.DEPLOYED
            or still_deployed.workload.workload_uid != deployed.workload.workload_uid
            or tuple(pod.uid for pod in still_deployed.workload.pods) != pod_uids_deployed
            or any(event.get("operation") == "cockroach init" for event in fixture.command_trace)
        ):
            raise _BASE.SmokeFailure("Pre-initialization SQL helper changed the DEPLOYED fixture")
        fixture._checkpoint("certificate-oracle-preinit-rejected-without-init")

    fixture.init(tls=True)
    if oracle_sql_connection:
        oracle_sql_result["explicit_init_count"] = sum(
            event.get("operation") == "cockroach init" for event in fixture.command_trace
        )
        fixture._checkpoint("certificate-oracle-explicit-init-recorded")
        if oracle_sql_result["explicit_init_count"] != 1:
            raise _BASE.SmokeFailure("Certificate SQL proof did not perform exactly one explicit init")
    initialized = library.reconcile(
        ref,
        Requirement(Lifecycle.INITIALIZED, minimum_nodes=1, tls_mode=TLSMode.TLS),
        timeout=120,
        poll_interval=1,
        per_node_timeout=5,
    )
    if initialized.assessment.status is not ProbeStatus.SATISFIED:
        raise _BASE.SmokeFailure("Observer-compatibility target did not become semantically initialized")
    endpoints = {
        path: library.probe_health_endpoint(ref, path=path, per_node_timeout=5)
        for path in ("/health", "/health?ready=1")
    }
    for path, results in endpoints.items():
        if len(results) != 1 or results[0] != ("db-0", 200, True):
            raise _BASE.SmokeFailure(
                f"TLS health endpoint {path} did not return exactly one successful db-0 response"
            )

    settings_value_before = None
    settings_value_matcher = None
    if oracle_sql_connection:
        settings_oracle = _load_oracle(fixture, "128MiB")
        settings_value_matcher = settings_oracle["values_match"]
        settings_value_before = _observer_compat_setting_value(fixture, "128MiB")
        if settings_value_before is None or not settings_value_matcher("128MiB", settings_value_before):
            raise _BASE.SmokeFailure("Fixture setting was not independently set and read before baseline capture")
        fixture._checkpoint("certificate-oracle-controlled-setting-before-baseline")

    fixture.set_stage("create-observer-compat-persisted-witness")
    _run_observer_compat_sql(fixture, f"CREATE DATABASE {_WITNESS_DB}")
    _run_observer_compat_sql(
        fixture,
        f"CREATE TABLE {_WITNESS_TABLE} (id INT PRIMARY KEY, payload STRING NOT NULL)",
    )
    _run_observer_compat_sql(
        fixture,
        f"INSERT INTO {_WITNESS_TABLE} VALUES "
        "(1, 'preserve across case setup'), (2, 'preserve across pod restart')",
    )
    witness_before = _observer_compat_witness_hash(fixture)
    accepted_before = library.capture_accepted_state(ref, per_node_timeout=5)
    pod_uids_before = tuple(pod.uid for pod in initialized.assessment.workload.pods)
    if oracle_sql_connection and pod_uids_before != pod_uids_deployed:
        raise _BASE.SmokeFailure("Explicit init unexpectedly changed the selected fixture Pod identity")

    setting_value_after = None
    if oracle_sql_connection:
        if certificate_oracle is None or settings_value_matcher is None:
            raise _BASE.SmokeFailure("Certificate SQL proof setup is incomplete")
        observed_after_init = library.inspect_sql_connection(ref, ordinal=0)
        if (
            observed_after_init.workload_uid != observed.workload_uid
            or observed_after_init.pod_uid != pod_uids_before[0]
            or observed_after_init.tls_mode is not TLSMode.TLS
        ):
            raise _BASE.SmokeFailure("Post-init SQL observer did not retain the original TLS Pod binding")
        oracle_sql_result["checks"].append(
            _certificate_oracle_sql_check(
                fixture,
                certificate_oracle,
                label="after-explicit-init",
                expect_success=True,
            )
        )
        if not _certificate_oracle_binding_matches(
            observed_after_init, oracle_sql_result["checks"][-1]["returned_binding"]
        ):
            raise _BASE.SmokeFailure("Certificate SQL success did not match the independently observed endpoint")
        accepted_after_first_check = library.capture_accepted_state(ref, per_node_timeout=5)
        if accepted_after_first_check != accepted_before:
            raise _BASE.SmokeFailure("Certificate SQL helper changed accepted workload state")

        before_uid = pod_uids_before[0] if len(pod_uids_before) == 1 else None
        if before_uid is None:
            raise _BASE.SmokeFailure("Certificate SQL restart proof requires exactly one selected Pod")
        old_uid, new_uid = _restart_pod_with_uid_guard(
            fixture, expected_uid=before_uid, timeout=args.restart_timeout
        )
        after_restart = library.reconcile(
            ref,
            Requirement(Lifecycle.INITIALIZED, minimum_nodes=1, tls_mode=TLSMode.TLS),
            timeout=args.ready_timeout,
            poll_interval=1,
            per_node_timeout=5,
        )
        if after_restart.assessment.status is not ProbeStatus.SATISFIED:
            raise _BASE.SmokeFailure("Certificate SQL fixture did not recover after the normal Pod restart")
        observed_after_restart = library.inspect_sql_connection(ref, ordinal=0)
        if (
            observed_after_restart.workload_uid != observed.workload_uid
            or observed_after_restart.pod_uid != new_uid
            or observed_after_restart.tls_mode is not TLSMode.TLS
        ):
            raise _BASE.SmokeFailure("Observer did not bind the replacement TLS Pod")
        oracle_sql_result["pod_uid_before_after"] = [old_uid, new_uid]
        oracle_sql_result["replacement_binding"] = _oracle_connection_summary(observed_after_restart)
        oracle_sql_result["checks"].append(
            _certificate_oracle_sql_check(
                fixture,
                certificate_oracle,
                label="after-normal-pod-restart",
                expect_success=True,
            )
        )
        if not _certificate_oracle_binding_matches(
            observed_after_restart, oracle_sql_result["checks"][-1]["returned_binding"]
        ):
            raise _BASE.SmokeFailure("Restarted SQL success did not match the replacement Pod observation")
        accepted_after = library.capture_accepted_state(ref, per_node_timeout=5)
        if accepted_after != accepted_before:
            raise _BASE.SmokeFailure("Certificate SQL helper or Pod restart changed accepted workload state")
        verified = library.verify_accepted_state(ref, accepted_before, per_node_timeout=5)
        if verified.status is not ProbeStatus.SATISFIED:
            raise _BASE.SmokeFailure("Accepted state failed verification after certificate SQL helper checks")
        witness_after = _observer_compat_witness_hash(fixture)
        setting_value_after = _observer_compat_setting_readback(fixture)
        if setting_value_after is None or not settings_value_matcher("128MiB", setting_value_after):
            raise _BASE.SmokeFailure("Controlled setting did not persist across the normal Pod restart")
        pod_uids_after = tuple(pod.uid for pod in verified.workload.pods)
        if pod_uids_after != (new_uid,):
            raise _BASE.SmokeFailure("Certificate SQL proof did not retain the expected replacement Pod identity")
        commands = []
    else:
        commands = [
            run_case_command(fixture, "probe", timeout=90),
            run_case_command(fixture, "apply", timeout=150),
            run_case_command(fixture, "verify", timeout=90),
        ]
        accepted_after = library.capture_accepted_state(ref, per_node_timeout=5)
        if accepted_after != accepted_before:
            raise _BASE.SmokeFailure("Settings case commands changed accepted observer-compat workload state")
        verified = library.verify_accepted_state(ref, accepted_before, per_node_timeout=5)
        if verified.status is not ProbeStatus.SATISFIED:
            raise _BASE.SmokeFailure("Accepted state failed verification after observer-compat case commands")
        witness_after = _observer_compat_witness_hash(fixture)
        pod_uids_after = tuple(pod.uid for pod in verified.workload.pods)
        if pod_uids_after != pod_uids_before:
            raise _BASE.SmokeFailure("Settings case commands changed the observer-compat Pod identity")
    if witness_after != witness_before:
        raise _BASE.SmokeFailure("Observer-compat phase changed the persisted two-row witness")

    oracle_rebind_result = None
    if oracle_rebind:
        if len(pod_uids_after) != 1:
            raise _BASE.SmokeFailure("Oracle rebinding proof requires exactly one selected Pod")
        oracle_rebind_result = _exercise_oracle_rebind(
            args,
            fixture,
            library,
            ref,
            expected_connection=observed,
            accepted_before=accepted_after,
            pod_uid_before=pod_uids_after[0],
            witness_before=witness_after,
        )

    return {
        "tls_mode": "TLS",
        "lifecycle_before_explicit_init": deployed.health.lifecycle.value,
        "observer_expected_endpoint_match": {
            "tls_mode": observed.tls_mode.value,
            "certs_dir": observed.certs_dir,
            "sql_port": observed.sql_port,
            "rpc_port": observed.rpc_port,
        },
        "health_endpoints": {
            path: [{"pod": pod, "status": status, "passed": passed} for pod, status, passed in results]
            for path, results in endpoints.items()
        },
        "case_precondition_commands": commands,
        "case_apply_noop": None if oracle_sql_connection else True,
        "case_commands_run": not oracle_sql_connection,
        "accepted_state_before_after": [
            _accepted_summary(accepted_before), _accepted_summary(accepted_after),
        ],
        "pod_uids_before_after": [pod_uids_before, pod_uids_after],
        "witness_row_count": witness_before[0],
        "witness_sha256_before_after": [witness_before[1], witness_after[1]],
        "task_oracle": (
            "check() component invoked three times; oracle.main() not run"
            if oracle_rebind
            else "secure_sql_result() component only; certificate-rotation oracle.main() not run"
            if oracle_sql_connection
            else "not run: environment-preparation phase does not invoke the task oracle"
        ),
        "oracle_rebind": oracle_rebind_result,
        "certificate_rotation_sql_connection": oracle_sql_result,
        "controlled_setting_before_after": (
            [settings_value_before, setting_value_after] if oracle_sql_connection else None
        ),
    }


def _oracle_connection_summary(connection: Any) -> dict[str, Any]:
    """Keep only the non-secret endpoint identity used by the oracle."""
    tls_mode = getattr(connection, "tls_mode", None)
    return {
        "workload_uid": getattr(connection, "workload_uid", None),
        "pod_name": getattr(connection, "pod_name", None),
        "pod_uid": getattr(connection, "pod_uid", None),
        "container_name": getattr(connection, "container_name", None),
        "image": getattr(connection, "image", None),
        "sql_binary": getattr(connection, "sql_binary", None),
        "sql_host": getattr(connection, "sql_host", None),
        "sql_port": getattr(connection, "sql_port", None),
        "tls_mode": getattr(tls_mode, "value", tls_mode),
        "certs_dir": getattr(connection, "certs_dir", None),
    }


def _observer_compat_setting_value(fixture: SettingsFixture, value: str) -> str | None:
    """Set and independently read the one fixed proof setting over known fixture SQL."""
    if value not in {"64MiB", "128MiB", "256MiB"}:
        raise _BASE.SmokeFailure("Oracle rebinding proof received an unrecognized fixed setting value")
    _run_observer_compat_sql(
        fixture,
        f"SET CLUSTER SETTING {_SETTING_NAME} = '{value}';",
    )
    return _observer_compat_setting_readback(fixture)


def _observer_compat_setting_readback(fixture: SettingsFixture) -> str | None:
    """Read the fixed proof setting without changing it."""
    output = _run_observer_compat_sql(fixture, f"SHOW CLUSTER SETTING {_SETTING_NAME};")
    rows = [row for row in csv.reader(output.splitlines()) if any(cell.strip() for cell in row)]
    if len(rows) < 2 or not rows[-1] or not rows[-1][0].strip():
        return None
    return rows[-1][0].strip()


def _load_certificate_rotation_oracle(fixture: SettingsFixture) -> Any:
    """Load the actual Oracle once for the bounded SQL-helper component proof."""
    spec = importlib.util.spec_from_file_location(
        f"certificate_rotation_oracle_{fixture.run_id}", CERT_ROTATION_ORACLE_PATH
    )
    if spec is None or spec.loader is None:
        raise _BASE.SmokeFailure("Could not load the certificate-rotation Oracle module")
    oracle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(oracle)
    oracle.NAMESPACE = fixture.namespace
    oracle.CLUSTER_NAME = "db"
    oracle.NODE_NAME = "db-0"
    return oracle


def _certificate_oracle_command_summary(command: Any) -> dict[str, Any]:
    """Extract only safe routing fields; never journal SQL or raw process output."""
    argv = [str(item) for item in command] if isinstance(command, (list, tuple)) else []

    def option_value(prefix: str) -> str | None:
        return next((item[len(prefix):] for item in argv if item.startswith(prefix)), None)

    namespace = None
    if "-n" in argv:
        index = argv.index("-n")
        if index + 1 < len(argv):
            namespace = argv[index + 1]
    pod_name = None
    if "exec" in argv:
        index = argv.index("exec")
        if index + 1 < len(argv):
            pod_name = argv[index + 1]
    container = option_value("--container=")
    if container is None and "--container" in argv:
        index = argv.index("--container")
        if index + 1 < len(argv):
            container = argv[index + 1]
    payload = argv[argv.index("--") + 1:] if "--" in argv else []
    certs_dir = option_value("--certs-dir=")
    return {
        "route": "observed-tls" if container else "legacy",
        "namespace": namespace,
        "pod_name": pod_name,
        "container_name": container,
        "sql_binary": payload[0] if payload else None,
        "sql_host": option_value("--host="),
        "sql_port": option_value("--port="),
        "certs_dir": certs_dir,
        "insecure_flag": "--insecure" in argv,
    }


def _certificate_oracle_binding_matches(connection: Any, binding: Mapping[str, Any]) -> bool:
    """Compare the successful process endpoint with independent observation."""
    expected = {
        "namespace": connection.namespace,
        "pod_name": connection.pod_name,
        "container_name": connection.container_name,
        "sql_binary": connection.sql_binary,
        "sql_host": connection.sql_host,
        "sql_port": str(connection.sql_port),
        "certs_dir": connection.certs_dir,
    }
    return all(binding.get(field) == value for field, value in expected.items())


def _certificate_oracle_sql_check(
    fixture: SettingsFixture,
    oracle: Any,
    *,
    label: str,
    expect_success: bool,
) -> dict[str, Any]:
    """Call secure_sql_result unchanged and journal only bounded safe attempt metadata."""
    phase_data = fixture.phase_data
    if phase_data is None:
        raise _BASE.SmokeFailure("Certificate SQL proof has no durable phase journal")
    evidence = phase_data.setdefault(
        "certificate_rotation_sql_helper",
        {"oracle_main_invoked": False, "checks": []},
    )
    check: dict[str, Any] = {"label": label, "status": "running", "attempts": []}
    evidence["checks"].append(check)
    fixture._checkpoint(f"certificate-oracle-{label}-intent")

    original_run = oracle.run

    def recorded_run(command, timeout=30):
        try:
            result = original_run(command, timeout=timeout)
        except BaseException as error:
            attempt = {
                **_certificate_oracle_command_summary(command),
                "timeout_seconds": timeout,
                "error_type": type(error).__name__,
            }
            check["attempts"].append(attempt)
            fixture._checkpoint(f"certificate-oracle-{label}-attempt")
            raise
        attempt = {
            **_certificate_oracle_command_summary(command),
            "timeout_seconds": timeout,
            "returncode": getattr(result, "returncode", None),
            "stdout_present": bool(getattr(result, "stdout", "")),
            "stderr_present": bool(getattr(result, "stderr", "")),
        }
        check["attempts"].append(attempt)
        fixture._checkpoint(f"certificate-oracle-{label}-attempt")
        return result

    oracle.run = recorded_run
    try:
        result = oracle.secure_sql_result()
    except BaseException as error:
        check.update({"status": "raised", "error_type": type(error).__name__})
        fixture._checkpoint(f"certificate-oracle-{label}-raised")
        raise
    finally:
        oracle.run = original_run

    returned_summary = _certificate_oracle_command_summary(getattr(result, "args", None))
    returncode = getattr(result, "returncode", None)
    check.update({
        "status": "returned",
        "returncode": returncode,
        "returned_route": returned_summary["route"],
        "returned_binding": returned_summary,
        "attempt_count": len(check["attempts"]),
    })
    fixture._checkpoint(f"certificate-oracle-{label}-result")

    attempts = check["attempts"]
    if len(attempts) != 3:
        raise _BASE.SmokeFailure(
            f"Certificate SQL {label} check did not exercise legacy and both observed TLS candidates"
        )
    if (
        attempts[0]["route"] != "legacy"
        or attempts[1]["route"] != "observed-tls"
        or attempts[1]["certs_dir"] != "/cockroach/cockroach-certs"
        or attempts[2]["route"] != "observed-tls"
        or attempts[2]["certs_dir"] != "/root/.cockroach-certs"
        or any(attempt.get("insecure_flag") for attempt in attempts)
    ):
        raise _BASE.SmokeFailure("Certificate SQL helper did not use the expected TLS-only candidate order")

    if expect_success:
        if (
            any(attempt.get("returncode") in (None, 0) for attempt in attempts[:2])
            or attempts[2].get("returncode") != 0
            or returncode != 0
            or returned_summary != {key: value for key, value in attempts[-1].items()
                                    if key not in {"timeout_seconds", "returncode", "stdout_present", "stderr_present"}}
        ):
            raise _BASE.SmokeFailure("Observed TLS SQL helper did not return its successful observed process")
    elif (
        any(attempt.get("returncode") in (None, 0) for attempt in attempts)
        or returncode in (None, 0)
        or returned_summary != {key: value for key, value in attempts[0].items()
                                if key not in {"timeout_seconds", "returncode", "stdout_present", "stderr_present"}}
    ):
        raise _BASE.SmokeFailure("Pre-initialization SQL check did not preserve its failed legacy result")
    check["accepted"] = expect_success
    fixture._checkpoint(f"certificate-oracle-{label}-verified")
    return check


def _exercise_oracle_rebind(
    args: argparse.Namespace,
    fixture: SettingsFixture,
    library: CrdbLibrary,
    ref: WorkloadRef,
    *,
    expected_connection: Any,
    accepted_before: Any,
    pod_uid_before: str,
    witness_before: tuple[int, str],
) -> dict[str, Any]:
    """Run the same actual oracle check function across a Pod replacement."""
    target_value = "128MiB"
    oracle = _load_oracle(fixture, target_value)
    check = oracle["check"]
    setting_name = oracle["SETTING_NAME"]
    wrong_value = _choose_different_setting_value(oracle, target_value)
    phase_data = fixture.phase_data
    if phase_data is None:
        raise _BASE.SmokeFailure("Oracle rebinding proof has no durable phase journal")
    evidence: dict[str, Any] = {
        "setting_name": setting_name,
        "target_value": target_value,
        "wrong_value": wrong_value,
        "checks": [],
        "oracle_main_invoked": False,
    }
    phase_data["oracle_rebind"] = evidence

    def record_check(
        label: str,
        errors: list[str],
        *,
        expected_value: str,
        actual_value: str | None,
    ) -> dict[str, Any]:
        connection = check.__globals__.get("_SQL_CONNECTION")
        summary = _oracle_connection_summary(connection) if connection is not None else None
        safe_errors = [_BASE._safe_diagnostic_text(message, limit=400) for message in errors]
        mismatch_reported = (
            len(errors) == 1
            and actual_value is not None
            and setting_name in errors[0]
            and "expected" in errors[0].lower()
            and f"'{actual_value}'" in errors[0]
            and f"'{expected_value}'" in errors[0]
        )
        row = {
            "label": label,
            "expected_value": expected_value,
            "actual_value": actual_value,
            "error_count": len(errors),
            "errors": safe_errors,
            "value_mismatch_reported": mismatch_reported,
            "accepted": not errors,
            "binding": summary,
        }
        evidence["checks"].append(row)
        fixture._checkpoint(f"oracle-rebind-{label}")
        if summary is None:
            raise _BASE.SmokeFailure(f"Oracle {label} check did not retain its observed SQL binding")
        return row

    fixture.set_stage("oracle-rebind-wrong-setting-rejection")
    wrong_readback = _observer_compat_setting_value(fixture, wrong_value)
    evidence["wrong_value_readback"] = wrong_readback
    fixture._checkpoint("oracle-rebind-wrong-value-readback")
    if wrong_readback is None or not oracle["values_match"](wrong_value, wrong_readback):
        raise _BASE.SmokeFailure("Independent SQL client did not read back the deliberately wrong setting")
    wrong_errors: list[str] = []
    check(wrong_errors, "before configured setting change")
    wrong_binding = record_check(
        "wrong-value", wrong_errors, expected_value=target_value, actual_value=wrong_readback
    )
    if not wrong_binding["value_mismatch_reported"]:
        raise _BASE.SmokeFailure("The actual settings oracle did not reject the wrong value as a value mismatch")

    fixture.set_stage("oracle-rebind-configured-setting-acceptance")
    target_readback = _observer_compat_setting_value(fixture, target_value)
    evidence["target_value_readback"] = target_readback
    fixture._checkpoint("oracle-rebind-target-value-readback")
    if target_readback is None or not oracle["values_match"](target_value, target_readback):
        raise _BASE.SmokeFailure("Independent SQL client did not read back the configured target setting")
    target_errors: list[str] = []
    check(target_errors, "after configured setting change")
    target_binding = record_check(
        "target-value", target_errors, expected_value=target_value, actual_value=target_readback
    )
    if target_errors:
        raise _BASE.SmokeFailure("The actual settings oracle rejected the configured target setting value")

    expected = _oracle_connection_summary(expected_connection)
    for binding_result in (wrong_binding, target_binding):
        binding = binding_result["binding"]
        if any(binding.get(field) != expected.get(field) for field in (
            "workload_uid", "pod_name", "container_name", "sql_host", "sql_port", "tls_mode", "certs_dir",
        )):
            raise _BASE.SmokeFailure("Oracle SQL binding did not match the independently observed fixture endpoint")
    if (
        wrong_binding["binding"]["pod_uid"] != pod_uid_before
        or target_binding["binding"]["pod_uid"] != pod_uid_before
    ):
        raise _BASE.SmokeFailure("Oracle checks did not bind to the selected pre-restart Pod UID")

    fixture.set_stage("oracle-rebind-uid-guarded-pod-restart")
    old_uid, new_uid = _restart_pod_with_uid_guard(
        fixture,
        expected_uid=pod_uid_before,
        timeout=getattr(args, "restart_timeout", 180),
    )
    evidence["pod_uid_before_after_restart"] = [old_uid, new_uid]
    fixture._checkpoint("oracle-rebind-pod-restarted")
    if old_uid != pod_uid_before or new_uid == old_uid:
        raise _BASE.SmokeFailure("Oracle rebinding restart did not replace the selected Pod identity")

    fixture.set_stage("oracle-rebind-post-restart-acceptance")
    restarted_errors: list[str] = []
    check(restarted_errors, "after pod restart")
    restarted_binding = record_check(
        "post-restart", restarted_errors, expected_value=target_value, actual_value=target_readback
    )
    if restarted_errors:
        raise _BASE.SmokeFailure("The actual settings oracle rejected the setting after Pod restart")
    if restarted_binding["binding"]["pod_uid"] != new_uid:
        raise _BASE.SmokeFailure("The settings oracle reused a stale Pod binding after restart")
    if any(restarted_binding["binding"].get(field) != expected.get(field) for field in (
        "workload_uid", "pod_name", "container_name", "sql_host", "sql_port", "tls_mode", "certs_dir",
    )):
        raise _BASE.SmokeFailure("Post-restart oracle binding changed the observed fixture endpoint")

    current = library.capture_accepted_state(ref, per_node_timeout=5)
    verified = library.verify_accepted_state(ref, accepted_before, per_node_timeout=5)
    if current != accepted_before or verified.status is not ProbeStatus.SATISFIED:
        raise _BASE.SmokeFailure("Oracle checks or Pod restart changed accepted fixture state")
    witness_after = _observer_compat_witness_hash(fixture)
    evidence["accepted_state_preserved"] = True
    evidence["witness_rows_before_after"] = [witness_before[0], witness_after[0]]
    evidence["witness_sha256_before_after"] = [witness_before[1], witness_after[1]]
    evidence["single_oracle_check_function_reused"] = True
    fixture._checkpoint("oracle-rebind-complete")
    if witness_after != witness_before:
        raise _BASE.SmokeFailure("Oracle check or Pod restart changed the persisted two-row witness")
    return evidence


def _exercise_tls_recovery_phase(
    args: argparse.Namespace,
    fixture: SettingsFixture,
    phase_data: dict[str, Any],
) -> dict[str, Any]:
    """Exercise the actual TLS restart/recreate/init path with operation-time UID history."""
    fixture.wait_ready(timeout=args.ready_timeout)
    library = CrdbLibrary(KubectlAdapter(kubectl=args.kubectl))
    ref = WorkloadRef(fixture.namespace, "db", "db")
    deployed = library.probe(
        ref,
        Requirement(Lifecycle.DEPLOYED, minimum_nodes=1, tls_mode=TLSMode.TLS),
        per_node_timeout=5,
    )
    if deployed.status is not ProbeStatus.SATISFIED or deployed.health.lifecycle is not Lifecycle.DEPLOYED:
        raise _BASE.SmokeFailure("TLS recovery fixture did not remain positively deployed and uninitialized")
    before = deployed.workload
    if before.tls_mode is not TLSMode.TLS or len(before.pods) != 1 or not before.pods[0].pod_ready:
        raise _BASE.SmokeFailure("TLS recovery fixture did not expose one Ready TLS Pod")

    old_sts_uid = before.workload_uid
    old_sts = fixture.get("statefulset", "db")
    if old_sts.get("metadata", {}).get("uid") != old_sts_uid:
        raise _BASE.SmokeFailure("TLS recovery StatefulSet identity changed during preflight")
    old_storage = fixture._record_storage_snapshot("before-target-recovery")
    if len(old_storage) != 1:
        raise _BASE.SmokeFailure("TLS recovery fixture did not bind exactly one PVC")
    old_pvc = old_storage[0]
    initial_ids = {
        "statefulset/db": old_sts_uid,
        "persistentvolumeclaim/" + old_pvc["name"]: old_pvc["uid"],
    }
    for kind, name in (("service", "db"), ("service", "db-public"), ("secret", "db-certs")):
        uid = fixture.created.get((kind, name))
        if not isinstance(uid, str) or not uid:
            raise _BASE.SmokeFailure(f"TLS recovery fixture is missing the owned {kind}/{name} identity")
        initial_ids[f"{kind}/{name}"] = uid
    phase_data["initial_resource_uids"] = initial_ids
    phase_data["before_recovery"] = {
        "lifecycle": deployed.health.lifecycle.value,
        "tls_mode": before.tls_mode.value,
        "statefulset_uid": old_sts_uid,
        "pod_uids": [pod.uid for pod in before.pods],
        "image": before.image,
        "desired_replicas": before.desired_replicas,
        "workload_spec_sha256": before.workload_spec_hash,
        "statefulset_spec_sha256": _sha256_json(old_sts.get("spec")),
        "services": _service_summary(before),
        "secret_fingerprints": _observed_secret_summary(before),
        "storage": old_storage,
    }
    fixture._checkpoint("tls-recovery-baseline-recorded")

    with case_environment(fixture.namespace, kubectl=args.kubectl):
        module_globals = runpy.run_path(str(TARGET_PATH))
    target = module_globals["TargetCluster"](
        fixture.namespace,
        "db",
        adapter=KubectlAdapter(kubectl=args.kubectl),
        library=library,
        command=_tracked_target_command(fixture, phase_data),
    )
    fixture.set_stage("case-bounded-tls-restart-recreate-init")
    target.apply()

    new_storage = fixture._record_storage_snapshot("after-target-recovery")
    if len(new_storage) != 1 or new_storage[0]["name"] != old_pvc["name"]:
        raise _BASE.SmokeFailure("TLS recovery did not bind the expected replacement PVC")
    fixture._refresh_recovery_identities_for_cleanup()
    fixture.wait_ready(timeout=args.ready_timeout)

    after_assessment = library.probe(
        ref,
        Requirement(Lifecycle.INITIALIZED, minimum_nodes=1, tls_mode=TLSMode.TLS),
        per_node_timeout=5,
    )
    if after_assessment.status is not ProbeStatus.SATISFIED:
        raise _BASE.SmokeFailure("TLS recovery did not produce a semantically initialized target")
    accepted = library.accepted_state(after_assessment)
    after = after_assessment.workload
    new_sts = fixture.get("statefulset", "db")
    new_sts_uid = new_sts.get("metadata", {}).get("uid")
    if not isinstance(new_sts_uid, str) or new_sts_uid == old_sts_uid:
        raise _BASE.SmokeFailure("TLS recovery did not recreate the selected StatefulSet")
    new_sts_spec_hash = _sha256_json(new_sts.get("spec"))
    if (
        accepted.tls_mode is not TLSMode.TLS
        or accepted.image != before.image
        or accepted.desired_replicas != before.desired_replicas
        or accepted.workload_spec_hash != before.workload_spec_hash
        or new_sts_spec_hash != phase_data["before_recovery"]["statefulset_spec_sha256"]
        or _service_summary(after) != phase_data["before_recovery"]["services"]
        or _observed_secret_summary(after) != phase_data["before_recovery"]["secret_fingerprints"]
    ):
        raise _BASE.SmokeFailure("TLS recovery did not preserve the observed config, services, and certificates")
    if [pod.uid for pod in after.pods] == phase_data["before_recovery"]["pod_uids"]:
        raise _BASE.SmokeFailure("TLS recovery unexpectedly retained the pre-recovery Pod identity")
    new_pvc = new_storage[0]
    if new_pvc["uid"] == old_pvc["uid"]:
        raise _BASE.SmokeFailure("TLS recovery did not replace the selected PVC identity")

    history = phase_data.get("target_resource_history", [])
    init_events = [event for event in history if event.get("action") == "init"]
    if not init_events or init_events[-1].get("state") != "requested":
        raise _BASE.SmokeFailure("TLS recovery did not record the case's explicit post-recreate init")
    if not any(
        event.get("action") == "delete"
        and event.get("kind") == "statefulset"
        and event.get("uid") == old_sts_uid
        and event.get("propagation_policy") == "Foreground"
        for event in history
    ):
        raise _BASE.SmokeFailure("TLS recovery did not use the UID-guarded foreground StatefulSet recreate")

    commands = [
        run_case_command(fixture, "probe", timeout=90),
        run_case_command(fixture, "apply", timeout=150),
        run_case_command(fixture, "verify", timeout=90),
    ]
    verified = library.verify_accepted_state(ref, accepted, per_node_timeout=5)
    if verified.status is not ProbeStatus.SATISFIED:
        raise _BASE.SmokeFailure("TLS recovery accepted state changed during the case CLI checks")
    phase_data["recovery_uid_history"] = {
        "statefulset": [old_sts_uid, new_sts_uid],
        "pods": [phase_data["before_recovery"]["pod_uids"], [pod.uid for pod in after.pods]],
        "pvc": [old_pvc, new_pvc],
    }
    return {
        "pre_recovery_lifecycle": "DEPLOYED",
        "post_recovery_lifecycle": "INITIALIZED",
        "target_apply_recovered_and_recreated_tls_cluster": True,
        "preserved_tls_image_replicas_workload_spec_services_and_certificates": True,
        "case_cli_commands": commands,
        "accepted_state_after_recovery": _accepted_summary(accepted),
        "before_after_identities": phase_data["recovery_uid_history"],
        "sql_data_across_storage_recreate": "intentionally reset by original case policy; no cross-recreate data claim",
    }


def _fresh_documents(fixture: SettingsFixture) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Build small create-only manifests for the case helper's manifest_dir seam."""
    labels = {
        **_NATIVE_LABELS,
        "app.kubernetes.io/instance": "${BENCH_PARAM_CLUSTER_NAME}",
        "crdb-library-run": fixture.run_id,
    }
    service_ports = [
        {"name": "sql", "port": 26257, "targetPort": "sql", "protocol": "TCP"},
        {"name": "rpc", "port": 26258, "targetPort": "rpc", "protocol": "TCP"},
        {"name": "http", "port": 8080, "targetPort": "http", "protocol": "TCP"},
    ]
    headless = {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": "${BENCH_PARAM_CLUSTER_NAME}",
            "labels": {**labels, "app.kubernetes.io/instance": "${BENCH_PARAM_CLUSTER_NAME}"},
        },
        "spec": {
            "clusterIP": "None",
            "publishNotReadyAddresses": True,
            "selector": labels,
            "ports": service_ports,
        },
    }
    public = {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": "${BENCH_PARAM_CLUSTER_NAME}-public",
            "labels": {**labels, "app.kubernetes.io/instance": "${BENCH_PARAM_CLUSTER_NAME}"},
        },
        "spec": {"selector": labels, "ports": service_ports},
    }
    service_account = {
        "apiVersion": "v1",
        "kind": "ServiceAccount",
        "metadata": {
            "name": "${BENCH_PARAM_CLUSTER_NAME}-sa",
            "labels": {**labels, "app.kubernetes.io/instance": "${BENCH_PARAM_CLUSTER_NAME}"},
        },
    }
    role = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "Role",
        "metadata": {
            "name": "${BENCH_PARAM_CLUSTER_NAME}-role",
            "labels": {**labels, "app.kubernetes.io/instance": "${BENCH_PARAM_CLUSTER_NAME}"},
        },
        "rules": [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get", "list", "watch"]}],
    }
    role_binding = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "RoleBinding",
        "metadata": {
            "name": "${BENCH_PARAM_CLUSTER_NAME}-rolebinding",
            "labels": {**labels, "app.kubernetes.io/instance": "${BENCH_PARAM_CLUSTER_NAME}"},
        },
        "roleRef": {
            "apiGroup": "rbac.authorization.k8s.io",
            "kind": "Role",
            "name": "${BENCH_PARAM_CLUSTER_NAME}-role",
        },
        "subjects": [{
            "kind": "ServiceAccount",
            "name": "${BENCH_PARAM_CLUSTER_NAME}-sa",
            "namespace": "${BENCH_NAMESPACE}",
        }],
    }
    statefulset = fixture.statefulset_manifest(tls=False)
    sts_spec = statefulset["spec"]
    sts_spec["serviceName"] = "${BENCH_PARAM_CLUSTER_NAME}"
    sts_spec["replicas"] = 1
    sts_spec["selector"]["matchLabels"] = labels
    sts_spec["template"]["metadata"]["labels"] = labels
    pod_spec = sts_spec["template"]["spec"]
    pod_spec["serviceAccountName"] = "${BENCH_PARAM_CLUSTER_NAME}-sa"
    container = pod_spec["containers"][0]
    script = container["command"][2]
    script = script.replace(
        f".db.{fixture.namespace}.svc.cluster.local",
        ".${BENCH_PARAM_CLUSTER_NAME}.$(POD_NAMESPACE).svc.cluster.local",
    )
    script = script.replace("db-0.db.", "${BENCH_PARAM_CLUSTER_NAME}-0.${BENCH_PARAM_CLUSTER_NAME}.")
    container["command"][2] = script
    claim = sts_spec["volumeClaimTemplates"][0]
    claim["metadata"]["labels"] = labels
    claim["spec"]["resources"]["requests"]["storage"] = "1Gi"
    container["imagePullPolicy"] = "Never"
    container["resources"] = {
        "requests": {"cpu": "100m", "memory": "256Mi"},
        "limits": {"cpu": "1", "memory": "1Gi"},
    }
    statefulset["metadata"]["name"] = "${BENCH_PARAM_CLUSTER_NAME}"
    statefulset["metadata"]["labels"] = labels

    documents = [service_account, role, role_binding, headless, public, statefulset]
    return documents, statefulset


def _write_small_manifest_dir(directory: Path, fixture: SettingsFixture) -> None:
    import yaml

    documents, _statefulset = _fresh_documents(fixture)
    (directory / "rbac.yaml").write_text(
        yaml.safe_dump_all(documents[:3], sort_keys=False), encoding="utf-8"
    )
    (directory / "services.yaml").write_text(
        yaml.safe_dump_all(documents[3:5], sort_keys=False), encoding="utf-8"
    )
    (directory / "statefulset.yaml").write_text(
        yaml.safe_dump(documents[5], sort_keys=False), encoding="utf-8"
    )


def _target_create_identity(fixture: SettingsFixture, input_text: str | None) -> tuple[str, str, str]:
    try:
        documents = [item for item in yaml.safe_load_all(input_text or "") if item is not None]
        if len(documents) != 1 or not isinstance(documents[0], dict):
            raise ValueError("expected one resource document")
        document = documents[0]
        metadata = document.get("metadata", {})
        kind = str(document.get("kind", "")).lower()
        name = metadata.get("name") if isinstance(metadata, dict) else None
        manifest_namespace = metadata.get("namespace") if isinstance(metadata, dict) else None
        if kind not in {"service", "statefulset"} or not isinstance(name, str) or not name:
            raise ValueError("unsupported target create")
        if manifest_namespace not in (None, "", fixture.namespace):
            raise ValueError("foreign namespace")
        digest = hashlib.sha256(input_text.encode("utf-8")).hexdigest()
        return kind, name, digest
    except (TypeError, ValueError, yaml.YAMLError) as error:
        raise _BASE.SmokeFailure("Recovery command has an unsupported create manifest") from error


def _target_delete_identity(
    fixture: SettingsFixture,
    args: tuple[str, ...],
    input_text: str | None,
) -> tuple[str, str, str, str | None] | None:
    raw = next((argument.removeprefix("--raw=") for argument in args if argument.startswith("--raw=")), None)
    if raw is None:
        return None
    patterns = (
        (r"/apis/apps/v1/namespaces/([^/]+)/statefulsets/([^/]+)", "statefulset"),
        (r"/api/v1/namespaces/([^/]+)/pods/([^/]+)", "pod"),
        (r"/api/v1/namespaces/([^/]+)/persistentvolumeclaims/([^/]+)", "persistentvolumeclaim"),
    )
    match = None
    kind = ""
    for pattern, candidate_kind in patterns:
        match = re.fullmatch(pattern, raw)
        if match:
            kind = candidate_kind
            break
    if match is None or match.group(1) != fixture.namespace:
        raise _BASE.SmokeFailure("Recovery command has an unsupported or foreign raw delete target")
    try:
        options = json.loads(input_text or "")
        uid = options["preconditions"]["uid"]
        if options.get("kind") != "DeleteOptions" or not isinstance(uid, str) or not uid:
            raise ValueError("missing UID precondition")
    except (TypeError, KeyError, json.JSONDecodeError, ValueError) as error:
        raise _BASE.SmokeFailure("Recovery delete is missing its exact UID precondition") from error
    return kind, match.group(2), uid, options.get("propagationPolicy")


def _tracked_target_command(
    fixture: SettingsFixture,
    phase_data: dict[str, Any],
) -> Callable[..., subprocess.CompletedProcess[str]]:
    def command(*args: str, timeout: float = 30, input_text: str | None = None):
        recovery = fixture.phase == "tls-recovery"
        event: dict[str, Any] | None = None
        if recovery and args and args[0] == "create":
            kind, name, manifest_hash = _target_create_identity(fixture, input_text)
            event = fixture._recovery_event(
                {
                    "action": "create",
                    "state": "intent",
                    "kind": kind,
                    "name": name,
                    "manifest_sha256": manifest_hash,
                },
                f"target-create-intent-{kind}-{name}",
            )
        elif recovery and args and args[0] == "delete":
            identity = _target_delete_identity(fixture, args, input_text)
            if identity is None:
                raise _BASE.SmokeFailure("Recovery deletes must use a raw endpoint and exact UID precondition")
            kind, name, uid, propagation = identity
            if kind in {"statefulset", "pod", "persistentvolumeclaim"}:
                fixture._record_storage_snapshot(f"before-{kind}-delete")
            event = fixture._recovery_event(
                {
                    "action": "delete",
                    "state": "intent",
                    "kind": kind,
                    "name": name,
                    "uid": uid,
                    "propagation_policy": propagation,
                },
                f"target-delete-intent-{kind}-{name}",
            )
        elif recovery and args and args[0] == "exec":
            separator = args.index("--") + 1 if "--" in args else len(args)
            if "init" in args[separator:]:
                event = fixture._recovery_event(
                    {
                        "action": "init",
                        "state": "intent",
                        "pod_name": args[1] if len(args) > 1 else "unknown",
                        "statefulset_uid": fixture.created.get(("statefulset", "db")),
                    },
                    "target-cockroach-init-intent",
                )
        try:
            stdout = fixture.kubectl(
                *args,
                namespace=fixture.namespace,
                timeout=timeout,
                input_text=input_text,
                diagnose_api_error=True,
            )
        except BaseException:
            if event is not None:
                event["state"] = "ambiguous"
                fixture._checkpoint("target-resource-operation-ambiguous")
            raise
        if args and args[0] == "create" and input_text:
            try:
                created = json.loads(stdout)
                metadata = created["metadata"]
                kind = str(created["kind"]).lower()
                name = str(metadata["name"])
                uid = str(metadata["uid"])
            except (json.JSONDecodeError, KeyError, TypeError) as error:
                if event is not None:
                    event["state"] = "ambiguous"
                    fixture._checkpoint("target-create-response-ambiguous")
                raise _BASE.SmokeFailure("Target create did not return a complete safe resource identity") from error
            if event is not None and ((kind, name) != (event["kind"], event["name"]) or not uid):
                event["state"] = "ambiguous"
                fixture._checkpoint("target-create-response-mismatch")
                raise _BASE.SmokeFailure("Target create returned an unexpected resource identity")
            fixture.created[(kind, name)] = uid
            identities = phase_data.setdefault("target_create_identities", [])
            identities.append({"kind": kind, "name": name, "uid": uid})
            if event is not None:
                event.update({"state": "created", "uid": uid})
            fixture._checkpoint(f"target-resource-created-{kind}-{name}")
        elif event is not None and event["action"] in {"delete", "init"}:
            event["state"] = "requested"
            suffix = f"{event['kind']}-{event['name']}" if event["action"] == "delete" else "cockroach-init"
            fixture._checkpoint(f"target-operation-requested-{suffix}")
        return subprocess.CompletedProcess(list(args), 0, stdout, "")

    return command


def _run_fresh_creation_phase(
    args: argparse.Namespace,
    fixture: SettingsFixture,
    phase_data: dict[str, Any],
) -> dict[str, Any]:
    fixture.set_stage("fresh-create-through-case-target")
    with tempfile.TemporaryDirectory(prefix="crdb-settings-small-manifests-") as temporary:
        manifest_dir = Path(temporary)
        _write_small_manifest_dir(manifest_dir, fixture)
        with case_environment(fixture.namespace, kubectl=args.kubectl):
            module_globals = runpy.run_path(str(TARGET_PATH))
        target = module_globals["TargetCluster"](
            fixture.namespace,
            "db",
            adapter=KubectlAdapter(kubectl=args.kubectl),
            library=CrdbLibrary(KubectlAdapter(kubectl=args.kubectl)),
            command=_tracked_target_command(fixture, phase_data),
            manifest_dir=manifest_dir,
        )
        target.apply()

    fixture.wait_ready(timeout=args.ready_timeout)
    created = phase_data.get("target_create_identities", [])
    expected_kinds = [
        ("serviceaccount", "db-sa"),
        ("role", "db-role"),
        ("rolebinding", "db-rolebinding"),
        ("service", "db"),
        ("service", "db-public"),
        ("statefulset", "db"),
    ]
    actual_kinds = [(item["kind"], item["name"]) for item in created]
    if actual_kinds != expected_kinds:
        raise _BASE.SmokeFailure("Fresh target did not create and journal exactly its six declared resources")
    if any(fixture.created.get(identity) != row["uid"] for identity, row in zip(actual_kinds, created, strict=True)):
        raise _BASE.SmokeFailure("A fresh-create resource identity was not retained by the cleanup journal")

    library = CrdbLibrary(KubectlAdapter(kubectl=args.kubectl))
    ref = WorkloadRef(fixture.namespace, "db", "db")
    accepted_before = library.capture_accepted_state(ref, per_node_timeout=5)
    commands = [
        run_case_command(fixture, "probe", timeout=90),
        run_case_command(fixture, "apply", timeout=150),
        run_case_command(fixture, "verify", timeout=90),
    ]
    accepted_after = library.capture_accepted_state(ref, per_node_timeout=5)
    if accepted_after != accepted_before:
        raise _BASE.SmokeFailure("Case commands changed accepted state after fresh bootstrap completed")
    return {
        "fresh_target_created_and_initialized": True,
        "resource_count": len(created),
        "created_resource_identities": created,
        "kubernetes_downward_api_expansions_preserved": True,
        "fixture_storage": "one PVC requesting 1Gi",
        "fixture_resources": {"requests": {"cpu": "100m", "memory": "256Mi"}, "limits": {"cpu": "1", "memory": "1Gi"}},
        "case_precondition_commands": commands,
        "post_bootstrap_apply_noop": accepted_after == accepted_before,
        "accepted_state": _accepted_summary(accepted_after),
    }


def _wait_service_slices_absent(fixture: SettingsFixture, uid: str, timeout: float = 60) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        slices = fixture.get("endpointslices").get("items", [])
        if not any(
            reference.get("uid") == uid
            for item in slices
            for reference in item.get("metadata", {}).get("ownerReferences", [])
        ):
            return
        time.sleep(1)
    raise _BASE.SmokeFailure("Owned service EndpointSlices did not disappear within cleanup bound")


def _safe_failure_detail(error: BaseException) -> str:
    if isinstance(error, (_BASE.SmokeFailure, _BASE.CrdbError)):
        return _BASE._safe_diagnostic_text(error)
    return "details withheld"


def phase(
    args: argparse.Namespace,
    name: str,
    run_id: str,
    evidence_dir: Path,
) -> dict[str, Any]:
    fixture = SettingsFixture(args, name, run_id)
    phase_data: dict[str, Any] = {"phase": name, "namespace": fixture.namespace}
    failure: BaseException | None = None
    cleanup_failure: BaseException | None = None

    def checkpoint(status: str) -> None:
        _BASE.write_json_atomic(
            evidence_dir / f"{name}-journal.json",
            {
                "phase": name,
                "run_id": run_id,
                "namespace": fixture.namespace,
                "status": status,
                "namespace_uid": fixture.namespace_uid,
                "namespace_baseline": sorted(fixture.namespace_baseline),
                "owned_resource_uids": [
                    {"kind": kind, "name": resource_name, "uid": uid}
                    for (kind, resource_name), uid in sorted(fixture.created.items())
                ],
                "safe_observations": phase_data,
            },
        )

    fixture.checkpoint_callback = checkpoint
    fixture.phase_data = phase_data
    checkpoint("preflight-started")
    try:
        fixture.set_stage("capacity-preflight")
        phase_data["capacity_preflight"] = _BASE.preflight(args, fixture)
        fixture.storage_class = phase_data["capacity_preflight"]["storage_class"]
        checkpoint("preflight-passed")
        fixture.set_stage("namespace-prepare")
        fixture.prepare_namespace()
        if name == "fresh-create":
            phase_data.update(_run_fresh_creation_phase(args, fixture, phase_data))
        elif name == "tls-recovery":
            fixture.set_stage("service-create")
            fixture.create(fixture.service_manifest())
            fixture.create(fixture.public_service_manifest())
            with tempfile.TemporaryDirectory(prefix="crdb-settings-certs-") as temporary:
                _BASE.make_certificates(Path(temporary), fixture.namespace)
                fixture.make_secret(Path(temporary))
                fixture.set_stage("statefulset-create-uninitialized-tls")
                fixture.create(fixture.statefulset_manifest(tls=True))
                phase_data.update(_exercise_tls_recovery_phase(args, fixture, phase_data))
        elif name in {"observer-compat", "oracle-rebind", "oracle-sql-connection"}:
            fixture.set_stage("service-create")
            fixture.create(fixture.service_manifest())
            fixture.create(fixture.public_service_manifest())
            with tempfile.TemporaryDirectory(prefix="crdb-settings-certs-") as temporary:
                _BASE.make_certificates(Path(temporary), fixture.namespace)
                fixture.make_secret(Path(temporary))
                fixture.set_stage("statefulset-create-observer-compat-tls")
                fixture.create(fixture.statefulset_manifest(tls=True))
                phase_data.update(
                    _exercise_observer_compat_phase(
                        args,
                        fixture,
                        oracle_rebind=name == "oracle-rebind",
                        oracle_sql_connection=name == "oracle-sql-connection",
                    )
                )
        elif name in {"tls-transform", "tls-service-preservation"}:
            fixture.set_stage("service-create")
            fixture.create(fixture.service_manifest())
            fixture.create(fixture.public_service_manifest())
            with tempfile.TemporaryDirectory(prefix="crdb-settings-certs-") as temporary:
                _BASE.make_certificates(Path(temporary), fixture.namespace)
                fixture.make_secret(Path(temporary))
                fixture.set_stage("statefulset-create-insecure-transform-target")
                fixture.create(fixture.statefulset_manifest(tls=False))
                if name == "tls-service-preservation":
                    phase_data.update(
                        _exercise_tls_transform_component(
                            args, fixture, phase_data, service_preservation=True
                        )
                    )
                else:
                    phase_data.update(_exercise_tls_transform_component(args, fixture, phase_data))
        else:
            fixture.set_stage("service-create")
            fixture.create(fixture.service_manifest())
            tls = name == "tls"
            if tls:
                with tempfile.TemporaryDirectory(prefix="crdb-settings-certs-") as temporary:
                    _BASE.make_certificates(Path(temporary), fixture.namespace)
                    fixture.make_secret(Path(temporary))
                    fixture.set_stage("statefulset-create")
                    fixture.create(fixture.statefulset_manifest(tls=True))
                    phase_data.update(_exercise_existing_phase(args, fixture, tls=True))
            else:
                fixture.set_stage("statefulset-create")
                fixture.create(fixture.statefulset_manifest(tls=False))
                phase_data.update(_exercise_existing_phase(args, fixture, tls=False))
        checkpoint("work-complete")
    except BaseException as error:
        failure = error
        phase_data["failure_stage"] = fixture.stage_snapshot()
        if isinstance(error, _BASE.SmokeFailure) and error.command_event:
            phase_data["failure_command"] = dict(error.command_event)
        detail = _safe_failure_detail(error)
        phase_data["execution_failure"] = {"type": type(error).__name__, "detail": detail}
        try:
            fixture.capture_diagnostics(phase_data, label="before-cleanup")
        except BaseException as diagnostic_error:
            phase_data["diagnostic_capture_failure"] = {
                "type": type(diagnostic_error).__name__,
                "detail": _BASE._safe_diagnostic_text(diagnostic_error),
            }
    try:
        fixture.cleanup()
        phase_data["cleanup_verdict"] = "completed with UID preconditions and normal deletion"
    except BaseException as error:
        cleanup_failure = error
        detail = _safe_failure_detail(error)
        phase_data["cleanup_failure"] = {"type": type(error).__name__, "detail": detail}
        phase_data["cleanup_verdict"] = "incomplete; ownership journal retained"

    phase_data["stage_timing"] = fixture.stage_snapshot()
    phase_data["command_trace"] = list(fixture.command_trace[-80:])
    phase_data["result"] = "passed" if failure is None and cleanup_failure is None else "failed"
    _BASE.write_json_atomic(evidence_dir / f"{name}-phase.json", phase_data)
    checkpoint("phase-finished")
    if failure or cleanup_failure:
        raise _BASE.SmokeFailure(
            f"{name} settings phase failed; inspect {evidence_dir / f'{name}-phase.json'} and its ownership journal"
        ) from (failure or cleanup_failure)
    return phase_data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kubectl", default="kubectl")
    parser.add_argument("--docker", default="docker")
    parser.add_argument("--node", default="kind-worker")
    parser.add_argument("--image", default="cockroachdb/cockroach:v24.1.0")
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument(
        "--proof-mode",
        choices=(
            "default", "tls-recovery", "observer-compat", "oracle-rebind",
            "oracle-sql-connection", "tls-transform", "tls-service-preservation",
        ),
        default="default",
    )
    parser.add_argument("--ready-timeout", type=float, default=240.0)
    parser.add_argument("--restart-timeout", type=float, default=180.0)
    args = parser.parse_args(argv)
    # The native case CLI and oracle also use the current kubectl context.
    args.context = None
    if (
        not math.isfinite(args.ready_timeout)
        or not 0 < args.ready_timeout <= 300
        or not math.isfinite(args.restart_timeout)
        or not 0 < args.restart_timeout <= 240
    ):
        raise _BASE.SmokeFailure("Ready and restart timeouts must be finite and within their bounded ranges")
    evidence_dir = args.evidence_dir.expanduser().resolve()
    if evidence_dir.exists():
        raise _BASE.SmokeFailure("Evidence directory must be new; refusing to overwrite prior records")
    if not re.fullmatch(r"cockroachdb/cockroach:v24\.1\.0", args.image):
        raise _BASE.SmokeFailure("This smoke supports only the cached v24.1.0 CockroachDB image")
    if args.kubectl != "kubectl" and Path(args.kubectl).name != "kubectl":
        raise _BASE.SmokeFailure("The case scripts require a kubectl executable named 'kubectl'")
    evidence_dir.mkdir(parents=True, exist_ok=False)
    run_id = f"{time.strftime('%y%m%d')}-{os.getpid():x}"
    if not _BASE.re.fullmatch(r"[a-z0-9-]{1,16}", run_id):
        raise _BASE.SmokeFailure("Generated run identity is not a valid DNS label")
    print(f"Starting cluster-settings {args.proof_mode} smoke; run id {run_id}", flush=True)
    results = []
    names = {
        "default": ("insecure", "tls", "fresh-create"),
        "tls-recovery": ("tls-recovery",),
        "observer-compat": ("observer-compat",),
        "oracle-rebind": ("oracle-rebind",),
        "oracle-sql-connection": ("oracle-sql-connection",),
        "tls-transform": ("tls-transform",),
        "tls-service-preservation": ("tls-service-preservation",),
    }[args.proof_mode]
    for name in names:
        result = phase(args, name, run_id, evidence_dir)
        results.append(result)
        print(f"{name} phase completed and cleaned: {result['namespace']}", flush=True)
    _BASE.write_json_atomic(evidence_dir / "live-summary.json", {"run_id": run_id, "phases": results})
    print(f"Settings case smoke passed; safe evidence at {evidence_dir}", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except _BASE.SmokeFailure as error:
        print(f"SETTINGS CASE SMOKE STOPPED: {error}", file=sys.stderr, flush=True)
        raise SystemExit(2)

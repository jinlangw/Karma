from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import subprocess
import tempfile
import unittest
from unittest.mock import patch


_HARNESS_PATH = Path(__file__).parents[2] / "experiments" / "crdb-common-library" / "live_smoke.py"
_SPEC = importlib.util.spec_from_file_location("crdb_live_smoke_harness", _HARNESS_PATH)
assert _SPEC and _SPEC.loader
_HARNESS = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_HARNESS)


class LiveSmokeHarnessTests(unittest.TestCase):
    def setUp(self):
        self.args = SimpleNamespace(kubectl="kubectl", context="kind-test", image="cockroachdb/cockroach:v24.1.0", node="kind-worker")
        self.fixture = _HARNESS.Fixture(self.args, "insecure", "261018-abcd")

    def test_raw_cleanup_uses_kubernetes_uid_deleteoptions_and_foreground_for_statefulset(self):
        with patch.object(_HARNESS, "run") as runner:
            self.fixture.raw_delete_uid("statefulset", "db", "sts-original-uid", propagation="Foreground")
        command = runner.call_args.args[0]
        options = json.loads(runner.call_args.kwargs["input_text"])
        self.assertEqual(
            command,
            [
                "kubectl", "--context", "kind-test", "delete",
                "--raw=/apis/apps/v1/namespaces/karma-crdb-library-261018-abcd-insecure/statefulsets/db",
                "--filename=-",
            ],
        )
        self.assertEqual(options["preconditions"], {"uid": "sts-original-uid"})
        self.assertEqual(options["propagationPolicy"], "Foreground")
        self.assertNotIn("--preconditions", command)

    def test_fixture_starts_with_rpc_tcp_probes_and_bounded_resources(self):
        fixture = self.fixture
        fixture.storage_class = "local-path"
        manifest = fixture.statefulset_manifest(tls=False)
        spec = manifest["spec"]
        container = spec["template"]["spec"]["containers"][0]
        self.assertEqual(spec["replicas"], 1)
        self.assertEqual(container["imagePullPolicy"], "Never")
        self.assertEqual(container["livenessProbe"]["tcpSocket"]["port"], "rpc")
        self.assertEqual(container["readinessProbe"]["tcpSocket"]["port"], "rpc")
        self.assertEqual(container["resources"]["requests"], {"cpu": "100m", "memory": "256Mi"})
        self.assertEqual(container["resources"]["limits"], {"cpu": "1", "memory": "1Gi"})
        self.assertIn("--cache=128MiB", container["command"][2])
        self.assertIn("--max-sql-memory=128MiB", container["command"][2])
        self.assertEqual(spec["volumeClaimTemplates"][0]["spec"]["resources"]["requests"]["storage"], "1Gi")

    def test_namespace_labels_are_created_atomically_and_system_baseline_is_snapshotted(self):
        def get(resource, name=None, **kwargs):
            if resource == "namespace":
                return {}
            if resource == "serviceaccounts":
                return {"items": [{"metadata": {"name": "default", "uid": "sa-uid"}}]}
            if resource == "configmaps":
                return {"items": [{"metadata": {"name": "kube-root-ca.crt", "uid": "ca-uid"}}]}
            return {"items": []}

        created_namespace = {"metadata": {"uid": "ns-uid"}}
        with patch.object(self.fixture, "get", side_effect=get), patch.object(
            self.fixture, "kubectl", return_value=json.dumps(created_namespace)
        ) as command:
            self.fixture.prepare_namespace()
        argv = command.call_args.args
        self.assertEqual(argv[:3], ("create", "--filename=-", "--output=json"))
        manifest = json.loads(command.call_args.kwargs["input_text"])
        self.assertEqual(manifest["kind"], "Namespace")
        self.assertEqual(manifest["metadata"]["labels"], self.fixture.labels)
        self.assertIn(("configmaps", "kube-root-ca.crt", "ca-uid"), self.fixture.namespace_baseline)
        self.assertIn(("serviceaccounts", "default", "sa-uid"), self.fixture.namespace_baseline)

    def test_tls_phase_rejects_libressl_before_fixture_creation(self):
        with patch.object(_HARNESS, "run", return_value="LibreSSL 3.3.6"):
            with self.assertRaises(_HARNESS.SmokeFailure):
                _HARNESS._openssl_version()

    def test_diagnostic_text_redacts_credentials_pem_and_startup_arguments(self):
        value = (
            "password=top-secret token:abc123 Bearer xyz987\n"
            "-----BEGIN PRIVATE KEY-----\nprivate-material\n-----END PRIVATE KEY-----\n"
            "cockroach start --certs-dir=/private/certs"
        )
        safe = _HARNESS._safe_diagnostic_text(value)
        self.assertNotIn("top-secret", safe)
        self.assertNotIn("abc123", safe)
        self.assertNotIn("xyz987", safe)
        self.assertNotIn("private-material", safe)
        self.assertNotIn("/private/certs", safe)
        self.assertIn("REDACTED", safe)
        json_value = _HARNESS._safe_diagnostic_text('{"password": "json-secret", "token":"json-token"}')
        self.assertNotIn("json-secret", json_value)
        self.assertNotIn("json-token", json_value)

    def test_pod_diagnostic_projection_omits_commands_env_and_volume_data(self):
        pod = {
            "metadata": {"name": "db-0", "namespace": "ns", "uid": "uid"},
            "spec": {
                "nodeName": "kind-worker",
                "containers": [{
                    "name": "db", "image": "cockroachdb/cockroach:v24.1.0",
                    "command": ["start", "password=do-not-record"],
                    "args": ["--secret=do-not-record"],
                    "env": [{"name": "TOKEN", "value": "do-not-record"}],
                    "volumeMounts": [{"name": "certs", "mountPath": "/secret"}],
                    "ports": [{"name": "rpc", "containerPort": 26258, "protocol": "TCP"}],
                    "readinessProbe": {"tcpSocket": {"port": "rpc"}, "periodSeconds": 3},
                }],
            },
            "status": {
                "phase": "Running",
                "conditions": [{"type": "Ready", "status": "False", "reason": "ContainersNotReady"}],
                "containerStatuses": [{
                    "name": "db", "ready": False, "restartCount": 0,
                    "state": {"running": {"startedAt": "2026-10-19T00:00:00Z"}},
                }],
            },
        }
        projected = _HARNESS._safe_pod_summary(pod)
        encoded = json.dumps(projected)
        self.assertNotIn("do-not-record", encoded)
        self.assertNotIn("volumeMounts", encoded)
        self.assertNotIn("command", encoded)
        self.assertEqual(projected["status"]["phase"], "Running")
        self.assertEqual(projected["spec"]["containers"][0]["readinessProbe"]["tcpSocket"]["port"], "rpc")

    def test_command_diagnostics_record_safe_operation_exit_code_and_elapsed_time(self):
        events = []
        completed = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="private output")
        with patch.object(_HARNESS.subprocess, "run", return_value=completed):
            with self.assertRaises(_HARNESS.SmokeFailure) as raised:
                _HARNESS.run(
                    ["kubectl", "wait", "--for=condition=Ready", "pod/db-0"],
                    timeout=2,
                    operation="kubectl wait pod/db-0 Ready",
                    observer=events.append,
                )
        self.assertEqual(events[0]["operation"], "kubectl wait pod/db-0 Ready")
        self.assertEqual(events[0]["returncode"], 1)
        self.assertGreaterEqual(events[0]["elapsed_ms"], 0)
        self.assertNotIn("private output", str(raised.exception))

    def test_failure_diagnostics_precede_cleanup_and_preserve_primary_error(self):
        order = []
        execution_error = _HARNESS.SmokeFailure(
            "primary execution failure",
            command_event={
                "operation": "cockroach init",
                "outcome": "timeout",
                "returncode": None,
                "elapsed_ms": 45_000,
            },
        )
        cleanup_error = _HARNESS.SmokeFailure("secondary cleanup failure")

        def fail_phase(*_args, **_kwargs):
            raise execution_error

        def capture(phase_data, *, label):
            order.append("capture")
            phase_data.setdefault("runtime_diagnostics", {})[label] = {"safe": True}

        def cleanup():
            order.append("cleanup")
            raise cleanup_error

        with tempfile.TemporaryDirectory() as evidence_directory:
            args = SimpleNamespace(
                context="kind-test", kubectl="kubectl",
                image="cockroachdb/cockroach:v24.1.0", node="kind-worker",
                diagnostic_only=False,
            )
            fixture = _HARNESS.Fixture(args, "insecure", "261018-fail")
            fixture.namespace_uid = "namespace-uid"
            with (
                patch.object(_HARNESS, "Fixture", return_value=fixture),
                patch.object(_HARNESS, "preflight", return_value={"storage_class": "standard"}),
                patch.object(fixture, "prepare_namespace"),
                patch.object(fixture, "create", return_value={"metadata": {"uid": "owned-uid"}}),
                patch.object(fixture, "statefulset_manifest", return_value={}),
                patch.object(fixture, "capture_diagnostics", side_effect=capture),
                patch.object(fixture, "cleanup", side_effect=cleanup),
                patch.object(_HARNESS, "_exercise_phase", side_effect=fail_phase),
            ):
                with self.assertRaises(_HARNESS.SmokeFailure) as raised:
                    _HARNESS.phase(args, "insecure", "261018-fail", Path(evidence_directory))

            phase_data = json.loads((Path(evidence_directory) / "insecure-phase.json").read_text())

        self.assertEqual(order, ["capture", "cleanup"])
        self.assertTrue(str(raised.exception).startswith("insecure phase failed; inspect "))
        self.assertEqual(
            phase_data["execution_failure"]["type"],
            "SmokeFailure",
            {"failure": phase_data["execution_failure"], "stage": phase_data.get("failure_stage")},
        )
        self.assertEqual(phase_data["execution_failure"]["detail"], "primary execution failure")
        self.assertEqual(phase_data["failure_command"]["operation"], "cockroach init")
        self.assertIn("secondary cleanup failure", phase_data["cleanup_failure"]["detail"])
        self.assertEqual(phase_data["runtime_diagnostics"]["before-cleanup"], {"safe": True})

    def test_pre_ready_probe_failure_is_recorded_without_skipping_ready_verdict(self):
        order = []
        args = SimpleNamespace(
            kubectl="kubectl", context="kind-test", ready_timeout=20,
            running_observation_timeout=1,
        )
        fixture = self.fixture
        fixture.wait_pod_running = lambda timeout: order.append("running") or True
        fixture.wait_ready = lambda timeout: order.append("ready")
        fixture.capture_diagnostics = lambda phase_data, label: order.append("capture")

        class FakeLibrary:
            def __init__(self, _adapter):
                self.probes = 0

            def inspect(self, _ref):
                order.append("inspect")
                raise RuntimeError("inspection unavailable")

            def probe(self, _ref, _requirement, *, per_node_timeout):
                order.append("probe")
                self.probes += 1
                if self.probes == 1:
                    raise RuntimeError("pre-ready probe unavailable")
                return SimpleNamespace(
                    status=_HARNESS.ProbeStatus.SATISFIED,
                    health=SimpleNamespace(
                        lifecycle=_HARNESS.Lifecycle.DEPLOYED,
                        deployed_pods=("db-0",),
                        uninitialized_pods=("db-0",),
                    ),
                    reasons=(),
                )

        phase_data = {}
        with patch.object(_HARNESS, "CrdbLibrary", FakeLibrary):
            result = _HARNESS._diagnostic_readiness_phase(args, fixture, phase_data)
        self.assertEqual(order, ["running", "inspect", "probe", "ready", "probe", "capture"])
        self.assertIn("pre_ready_library_probe_error", phase_data)
        self.assertEqual(result["post_ready_library_probe"]["status"], "satisfied")

    def test_explicit_init_targets_rpc_listen_address(self):
        with patch.object(_HARNESS, "run") as runner:
            self.fixture.init(tls=False)
        argv = runner.call_args.args[0]
        self.assertIn(
            "--host=db-0.db.karma-crdb-library-261018-abcd-insecure.svc.cluster.local:26258",
            argv,
        )
        self.assertIn("--insecure", argv)

    def test_secure_fixture_uses_direct_readonly_secret_and_http_rollout_keeps_tls(self):
        manifest = self.fixture.statefulset_manifest(tls=True)
        spec = manifest["spec"]["template"]["spec"]
        container = spec["containers"][0]
        self.assertIn("--certs-dir=/cockroach/certs", container["command"][2])
        mount = next(mount for mount in container["volumeMounts"] if mount["name"] == "certs")
        self.assertTrue(mount["readOnly"])
        volume = next(volume for volume in spec["volumes"] if volume["name"] == "certs")
        self.assertEqual(volume["secret"]["secretName"], "db-certs")
        self.assertEqual(volume["secret"]["defaultMode"], 256)
        self.assertNotIn("securityContext", spec)


if __name__ == "__main__":
    unittest.main()

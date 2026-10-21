from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import runpy
import sys
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock, patch


_HARNESS_PATH = Path(__file__).parents[2] / "experiments" / "crdb-case-migration" / "health_recovery_case_smoke.py"
_SPEC = importlib.util.spec_from_file_location("health_recovery_case_smoke_harness", _HARNESS_PATH)
assert _SPEC and _SPEC.loader
_HARNESS = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_HARNESS)


class HealthRecoveryCaseHarnessTests(unittest.TestCase):
    def setUp(self):
        args = SimpleNamespace(
            kubectl="kubectl",
            context=None,
            image="cockroachdb/cockroach:v24.1.0",
            node="kind-worker",
            docker="docker",
        )
        self.fixture = _HARNESS.HealthCaseFixture(args, "insecure", "261019-abcd")
        self.fixture.storage_class = "local-path"

    def test_three_node_manifest_is_native_shaped_and_resource_bounded(self):
        manifest = self.fixture.statefulset_manifest(tls=False)
        spec = manifest["spec"]
        pod_spec = spec["template"]["spec"]
        container = pod_spec["containers"][0]
        self.assertEqual(spec["replicas"], 3)
        self.assertEqual(spec["selector"]["matchLabels"], self.fixture.labels)
        self.assertEqual(pod_spec["serviceAccountName"], "db-sa")
        self.assertEqual(container["imagePullPolicy"], "Never")
        self.assertEqual(container["livenessProbe"]["tcpSocket"]["port"], "rpc")
        self.assertEqual(container["readinessProbe"]["tcpSocket"]["port"], "rpc")
        self.assertEqual(container["resources"]["requests"], {"cpu": "100m", "memory": "256Mi"})
        self.assertEqual(container["resources"]["limits"], {"cpu": "1", "memory": "1Gi"})
        self.assertEqual(spec["volumeClaimTemplates"][0]["spec"]["resources"]["requests"]["storage"], "1Gi")
        self.assertIn("--listen-addr=0.0.0.0:26258", container["command"][2])
        self.assertIn("--sql-addr=0.0.0.0:26257", container["command"][2])
        self.assertEqual(
            self.fixture.labels,
            {
                "app.kubernetes.io/name": "cockroachdb",
                "app.kubernetes.io/instance": "db",
                "crdb-library-run": "261019-abcd",
            },
        )

    def test_recovery_mode_only_changes_fixture_probe_timing_and_keeps_default_unchanged(self):
        standard = self.fixture.statefulset_manifest(tls=True)["spec"]["template"]["spec"]["containers"][0]
        self.assertEqual(standard["livenessProbe"]["failureThreshold"], 6)
        self.assertEqual(standard["readinessProbe"]["failureThreshold"], 5)

        recovery_args = SimpleNamespace(
            kubectl="kubectl", context=None, image="cockroachdb/cockroach:v24.1.0",
            node="kind-worker", docker="docker", proof_mode="recovery",
        )
        recovery = _HARNESS.HealthCaseFixture(recovery_args, "tls", "261019-ef01")
        container = recovery.statefulset_manifest(tls=True)["spec"]["template"]["spec"]["containers"][0]
        self.assertEqual(container["livenessProbe"]["failureThreshold"], 120)
        self.assertEqual(container["readinessProbe"]["failureThreshold"], 1)
        self.assertEqual(container["readinessProbe"]["periodSeconds"], 3)

    def test_recovery_mode_selects_only_tls_and_default_keeps_both_original_phases(self):
        self.assertEqual(_HARNESS._phase_names(SimpleNamespace()), ("insecure", "tls"))
        self.assertEqual(_HARNESS._phase_names(SimpleNamespace(proof_mode="fault")), ("insecure", "tls"))
        self.assertEqual(_HARNESS._phase_names(SimpleNamespace(proof_mode="recovery")), ("tls",))

    def test_controlled_sql_setting_readback_accepts_only_128mib(self):
        with patch.object(_HARNESS, "_run_sql", return_value="kv.snapshot_rebalance.max_rate\n128 MiB\n"):
            self.assertEqual(_HARNESS._read_controlled_fixture_setting(self.fixture, tls=True), "128 MiB")
        with patch.object(_HARNESS, "_run_sql", return_value="kv.snapshot_rebalance.max_rate\n64 MiB\n"):
            with self.assertRaises(_HARNESS._BASE.SmokeFailure):
                _HARNESS._read_controlled_fixture_setting(self.fixture, tls=True)

    def test_expected_unhealthy_command_requires_nonzero_and_keeps_safe_reason(self):
        result = SimpleNamespace(returncode=1, stderr="CockroachDB readiness endpoint is not ready", stdout="")
        with patch.object(_HARNESS.subprocess, "run", return_value=result):
            observed = _HARNESS.run_case_command(
                self.fixture, "cluster", "probe", timeout=5, expect_failure=True,
            )
        self.assertEqual(observed["outcome"], "expected_failure")
        self.assertIn("readiness endpoint is not ready", observed["reason"])

        success = SimpleNamespace(returncode=0, stderr="", stdout="ready")
        with patch.object(_HARNESS.subprocess, "run", return_value=success):
            with self.assertRaises(_HARNESS._BASE.SmokeFailure):
                _HARNESS.run_case_command(
                    self.fixture, "cluster", "probe", timeout=5, expect_failure=True,
                )

    def test_recovery_signal_checks_pod_uid_and_cockroach_pid1_before_fixed_signal(self):
        fixture = self.fixture
        fixture.get = Mock(return_value={"metadata": {"uid": "owned-pod"}})
        fixture.kubectl = Mock(side_effect=["cockroach-pid1", ""])
        _HARNESS._signal_owned_cockroach(fixture, "owned-pod", "STOP")
        self.assertEqual(fixture.kubectl.call_count, 2)
        self.assertTrue(any("readlink /proc/1/exe" in item for item in fixture.kubectl.call_args_list[0].args))
        self.assertEqual(fixture.kubectl.call_args_list[1].args[-1], "kill -STOP 1")

        fixture.get = Mock(return_value={"metadata": {"uid": "replacement-pod"}})
        fixture.kubectl = Mock()
        with self.assertRaises(_HARNESS._BASE.SmokeFailure):
            _HARNESS._signal_owned_cockroach(fixture, "owned-pod", "STOP")
        fixture.kubectl.assert_not_called()

    def test_unready_wait_requires_only_target_to_change_readiness(self):
        fixture = self.fixture
        pods = {
            "db-0": {"metadata": {"uid": "pod-0"}, "status": {"phase": "Running", "conditions": [{"type": "Ready", "status": "True"}]}},
            "db-1": {"metadata": {"uid": "pod-1"}, "status": {"phase": "Running", "conditions": [{"type": "Ready", "status": "False"}]}},
            "db-2": {"metadata": {"uid": "pod-2"}, "status": {"phase": "Running", "conditions": [{"type": "Ready", "status": "True"}]}},
        }
        fixture.get = lambda kind, name=None, **_kwargs: pods.get(name)
        result = _HARNESS._wait_for_one_owned_pod_unready(
            fixture, {f"db-{index}": f"pod-{index}" for index in range(3)}, timeout=0.01,
        )
        self.assertEqual(result["metadata"]["uid"], "pod-1")
        pods["db-2"]["status"]["conditions"][0]["status"] = "False"
        with self.assertRaises(_HARNESS._BASE.SmokeFailure):
            _HARNESS._wait_for_one_owned_pod_unready(
                fixture, {f"db-{index}": f"pod-{index}" for index in range(3)}, timeout=0.01,
            )

    def test_recovery_phase_resumes_stopped_owned_process_before_cleanup_on_failure(self):
        calls = []

        class FakeFixture:
            def __init__(self, args, phase, run_id):
                self.namespace = "health-fixture"
                self.namespace_uid = "namespace-uid"
                self.namespace_baseline = set()
                self.created = {}
                self.command_trace = []
                self.storage_class = None
                self.proof_mode = "recovery"
                self.checkpoint_callback = None

            def _checkpoint(self, status):
                if self.checkpoint_callback:
                    self.checkpoint_callback(status)

            def set_stage(self, _name):
                pass

            def stage_snapshot(self):
                return {"current_stage": "test", "completed_stages": []}

            def prepare_namespace(self):
                pass

            def service_account_manifest(self):
                return {"kind": "ServiceAccount"}

            def service_manifests(self):
                return ({"kind": "Service"}, {"kind": "Service"})

            def statefulset_manifest(self, tls):
                return {"kind": "StatefulSet", "tls": tls}

            def create(self, _resource):
                pass

            def make_secret(self, _directory):
                pass

            def capture_diagnostics(self, _data, *, label):
                calls.append(("diagnostics", label))
                return {}

            def get(self, kind, name=None, **_kwargs):
                if kind == "pods" and name == "db-1":
                    return {"metadata": {"uid": "stopped-pod"}}
                return {}

            def kubectl(self, *args, **_kwargs):
                calls.append(("kubectl", args))
                return "cockroach-pid1" if any("readlink /proc/1/exe" in item for item in args) else ""

            def cleanup(self):
                calls.append(("cleanup",))

        args = SimpleNamespace(
            kubectl="kubectl", context=None, image="cockroachdb/cockroach:v24.1.0",
            node="kind-worker", docker="docker", proof_mode="recovery",
        )

        def fail_after_stop(_args, _fixture, *, tls, phase_data):
            self.assertTrue(tls)
            phase_data["recovery_fault"] = {
                # The bounded exec may time out after delivering SIGSTOP, so
                # cleanup must resume by recorded intent even without success.
                "pod_uid": "stopped-pod", "stop_intent_recorded": True, "sigstop_sent": False,
            }
            raise _HARNESS._BASE.SmokeFailure("expected test failure")

        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(_HARNESS, "HealthCaseFixture", FakeFixture), \
             patch.object(_HARNESS, "preflight", return_value={"storage_class": "local-path"}), \
             patch.object(_HARNESS, "make_case_certificates"), \
             patch.object(_HARNESS, "exercise_case_phase", side_effect=fail_after_stop):
            with self.assertRaises(_HARNESS._BASE.SmokeFailure):
                _HARNESS.phase(args, "tls", "261019-abcd", Path(temporary))
            phase_data = json.loads((Path(temporary) / "tls-phase.json").read_text())

        self.assertEqual(phase_data["result"], "failed")
        self.assertEqual(phase_data["fault_process_cleanup"], {"action": "resumed-owned-cockroach-process"})
        cont = next(index for index, item in enumerate(calls) if item[0] == "kubectl" and item[1][-1] == "kill -CONT 1")
        cleanup = next(index for index, item in enumerate(calls) if item[0] == "cleanup")
        self.assertLess(cont, cleanup)

    def test_case_services_and_service_account_are_run_owned(self):
        headless, public = self.fixture.service_manifests()
        self.assertEqual((headless["metadata"]["name"], public["metadata"]["name"]), ("db", "db-public"))
        self.assertEqual(headless["spec"]["clusterIP"], "None")
        for service in (headless, public):
            self.assertEqual(service["spec"]["selector"], self.fixture.labels)
            self.assertEqual(service["metadata"]["labels"], self.fixture.labels)
        self.assertEqual(self.fixture.service_account_manifest()["metadata"]["labels"], self.fixture.labels)

    def test_tls_manifest_uses_native_cert_mount_and_readonly_secret_mode(self):
        manifest = self.fixture.statefulset_manifest(tls=True)
        pod_spec = manifest["spec"]["template"]["spec"]
        container = pod_spec["containers"][0]
        self.assertIn("--certs-dir=/cockroach/cockroach-certs", container["command"][2])
        cert_mount = next(mount for mount in container["volumeMounts"] if mount["name"] == "certs")
        cert_volume = next(volume for volume in pod_spec["volumes"] if volume["name"] == "certs")
        self.assertEqual(cert_mount["mountPath"], "/cockroach/cockroach-certs")
        self.assertTrue(cert_mount["readOnly"])
        self.assertEqual(cert_volume["secret"]["defaultMode"], 256)
        self.assertNotIn("fsGroup", pod_spec.get("securityContext", {}))

    def test_three_node_capacity_guard_includes_aggregate_requests_and_headroom(self):
        enough = {
            "kind_node_free_cpu_cores": "0.5",
            "kind_node_free_memory_bytes": 3584 * 1024**2,
            "host_free_bytes": 8 * 1024**3,
            "kind_node_free_bytes": 4 * 1024**3,
            "storage_class": "local-path",
        }
        result = _HARNESS.enforce_three_node_capacity(enough)
        self.assertEqual(result["fixture_pods"], 3)
        self.assertEqual(result["fixture_total_pvc"], "3Gi")
        self.assertEqual(result["aggregate_requested"], {"cpu": "300m", "memory": "768Mi"})
        with self.assertRaises(_HARNESS._BASE.SmokeFailure):
            _HARNESS.enforce_three_node_capacity({**enough, "kind_node_free_cpu_cores": "0.49"})
        with self.assertRaises(_HARNESS._BASE.SmokeFailure):
            _HARNESS.enforce_three_node_capacity({**enough, "kind_node_free_memory_bytes": 3584 * 1024**2 - 1})
        with self.assertRaises(_HARNESS._BASE.SmokeFailure):
            _HARNESS.enforce_three_node_capacity({**enough, "host_free_bytes": 8 * 1024**3 - 1})
        with self.assertRaises(_HARNESS._BASE.SmokeFailure):
            _HARNESS.enforce_three_node_capacity({**enough, "kind_node_free_bytes": 4 * 1024**3 - 1})

    def test_tls_certificate_profile_has_all_three_node_dns_names(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(_HARNESS._BASE, "run"):
            _HARNESS.make_case_certificates(Path(temporary), self.fixture.namespace)
            extension = (Path(temporary) / "extensions.cnf").read_text()
        for ordinal in range(3):
            self.assertIn(f"DNS:db-{ordinal}.db.{self.fixture.namespace}.svc.cluster.local", extension)
        self.assertIn("DNS:localhost", extension)

    def test_unowned_health_baseline_is_never_adopted_by_cleanup(self):
        fixture = self.fixture
        fixture.baseline_create_intent = False
        fixture.get = lambda kind, name=None, **_kwargs: (
            {"metadata": {"name": name, "uid": "foreign-uid", "labels": {
                "app.kubernetes.io/name": "cockroachdb",
                "app.kubernetes.io/instance": "db",
                "karma.dev/fixture": "health-recovery-baseline",
            }}}
            if kind == "configmap" and name == "db-health-recovery-baseline" else {}
        )
        with self.assertRaises(_HARNESS._BASE.SmokeFailure):
            fixture.cleanup_additional_resources()
        self.assertNotIn(("configmap", "db-health-recovery-baseline"), fixture.created)

    def test_health_baseline_adoption_requires_matching_fixture_statefulset_uid(self):
        fixture = self.fixture
        fixture.baseline_create_intent = True
        fixture.created[("statefulset", "db")] = "owned-sts-uid"
        baseline = {
            "metadata": {
                "name": "db-health-recovery-baseline",
                "uid": "baseline-uid",
                "labels": {
                    "app.kubernetes.io/name": "cockroachdb",
                    "app.kubernetes.io/instance": "db",
                    "karma.dev/fixture": "health-recovery-baseline",
                },
            },
            "data": {"statefulset_uid": "foreign-sts-uid"},
        }
        fixture.get = lambda kind, name=None, **_kwargs: (
            baseline if kind == "configmap" and name == "db-health-recovery-baseline" else {}
        )
        deleted = []
        fixture.raw_delete_uid = lambda *args, **_kwargs: deleted.append(args)
        with self.assertRaises(_HARNESS._BASE.SmokeFailure):
            fixture.cleanup_additional_resources()
        self.assertEqual(deleted, [])
        self.assertNotIn(("configmap", "db-health-recovery-baseline"), fixture.created)

    def test_owned_health_baseline_is_adopted_only_for_fixture_statefulset_uid(self):
        fixture = self.fixture
        fixture.baseline_create_intent = True
        fixture.created[("statefulset", "db")] = "owned-sts-uid"
        baseline = {
            "metadata": {
                "name": "db-health-recovery-baseline",
                "uid": "baseline-uid",
                "labels": {
                    "app.kubernetes.io/name": "cockroachdb",
                    "app.kubernetes.io/instance": "db",
                    "karma.dev/fixture": "health-recovery-baseline",
                },
            },
            "data": {"statefulset_uid": "owned-sts-uid"},
        }
        responses = [baseline, {}]

        def get(kind, name=None, **_kwargs):
            if kind == "configmap" and name == "db-health-recovery-baseline":
                return responses.pop(0)
            return {}

        fixture.get = get
        deleted = []
        fixture.raw_delete_uid = lambda *args, **_kwargs: deleted.append(args)
        fixture.wait_absent = lambda *_args, **_kwargs: None
        fixture._checkpoint = lambda _status: None
        fixture.cleanup_additional_resources()
        self.assertEqual(deleted, [("configmap", "db-health-recovery-baseline", "baseline-uid")])

    def test_expected_fault_probe_message_matches_actual_case_fault_precondition(self):
        scripts = Path(__file__).parents[2] / "cases" / "cockroachdb" / "health-check-recovery" / "scripts"
        cluster_module = sys.modules.pop("cluster", None)
        sys.path.insert(0, str(scripts))
        try:
            fault = runpy.run_path(str(scripts / "fault.py"))["Fault"]
        finally:
            sys.path.remove(str(scripts))
            sys.modules.pop("cluster", None)
            if cluster_module is not None:
                sys.modules["cluster"] = cluster_module

        class MissingFaultCluster:
            name = "db"

            def statefulset(self):
                return {"metadata": {"uid": "fixture-sts"}, "spec": {"template": {"spec": {"containers": []}}}}

            def get(self, kind, name=None):
                self.asserted_resource = (kind, name)
                return None

        with self.assertRaises(RuntimeError) as raised:
            fault(MissingFaultCluster()).active()
        self.assertEqual(str(raised.exception), _HARNESS._NO_FAULT_REASON)

    def test_oracle_load_and_evaluation_run_inside_case_environment(self):
        before = {key: os.environ.get(key) for key in ("BENCH_NAMESPACE", "BENCH_PARAM_CLUSTER_NAME")}
        observations = []

        def load_oracle():
            observations.append(("load", os.environ.get("BENCH_NAMESPACE"), os.environ.get("BENCH_PARAM_CLUSTER_NAME")))

            def evaluate():
                observations.append(("evaluate", os.environ.get("BENCH_NAMESPACE"), os.environ.get("BENCH_PARAM_CLUSTER_NAME")))
                return []

            return evaluate

        with patch.object(_HARNESS, "_load_oracle_evaluate", side_effect=load_oracle):
            self.assertEqual(_HARNESS._evaluate_case_oracle(self.fixture), [])
        self.assertEqual(observations, [("load", self.fixture.namespace, "db"), ("evaluate", self.fixture.namespace, "db")])
        self.assertEqual({key: os.environ.get(key) for key in before}, before)

    def test_witness_hash_parses_and_checks_both_persisted_rows(self):
        output = "id,payload\n1,before probe rollout\n2,after fault recovery\n"
        with patch.object(_HARNESS, "_timed", return_value=output):
            count, digest = _HARNESS._witness_hash(object(), tls=False)
        self.assertEqual(count, 2)
        self.assertEqual(len(digest), 64)

        with patch.object(_HARNESS, "_timed", return_value="id,payload\n1,before probe rollout\n"):
            with self.assertRaises(_HARNESS._BASE.SmokeFailure):
                _HARNESS._witness_hash(object(), tls=False)

    def test_statefulset_restore_patch_is_scoped_and_uid_resource_version_guarded(self):
        statefulset = {
            "metadata": {"uid": "fixture-sts-uid", "resourceVersion": "17"},
        }
        fixture = SimpleNamespace(
            namespace="health-fixture",
            get=Mock(return_value=statefulset),
            kubectl=Mock(return_value="{}"),
        )
        _HARNESS._patch_statefulset(
            fixture,
            uid="fixture-sts-uid",
            fields={"template": {"metadata": {"labels": {"restore": "baseline"}}}},
        )
        fixture.kubectl.assert_called_once()
        args, kwargs = fixture.kubectl.call_args
        self.assertEqual(kwargs.get("namespace"), fixture.namespace)
        self.assertEqual(args[:4], ("patch", "statefulset", "db", "--type=json"))
        operations = json.loads(args[5])
        self.assertEqual(operations[:2], [
            {"op": "test", "path": "/metadata/uid", "value": "fixture-sts-uid"},
            {"op": "test", "path": "/metadata/resourceVersion", "value": "17"},
        ])
        self.assertTrue(kwargs.get("diagnose_api_error"))

    def test_progress_milestones_checkpoint_safe_partial_results(self):
        checkpoints = []
        self.fixture.checkpoint_callback = checkpoints.append
        phase_data = {}
        _HARNESS._record_milestone(
            self.fixture,
            phase_data,
            "oracle_rejected_planted_fault",
            "health endpoint unavailable",
        )
        self.assertEqual(phase_data["milestones"]["oracle_rejected_planted_fault"], "health endpoint unavailable")
        self.assertEqual(phase_data["last_progress"]["milestone"], "oracle_rejected_planted_fault")
        self.assertEqual(checkpoints, ["milestone-oracle_rejected_planted_fault"])


if __name__ == "__main__":
    unittest.main()

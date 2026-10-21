from __future__ import annotations

import importlib.util
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from karma.crdb.types import NodeLivenessObservation, NodeStatusObservation


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

    def test_raw_cleanup_supports_pods_and_case_owned_resources_with_uid_guards(self):
        endpoints = {
            "pod": "/api/v1/namespaces/karma-crdb-library-261018-abcd-insecure/pods/db-1",
            "configmap": "/api/v1/namespaces/karma-crdb-library-261018-abcd-insecure/configmaps/db-health-recovery-baseline",
            "serviceaccount": "/api/v1/namespaces/karma-crdb-library-261018-abcd-insecure/serviceaccounts/db-sa",
        }
        with patch.object(_HARNESS, "run") as runner:
            for kind, endpoint in endpoints.items():
                self.fixture.raw_delete_uid(kind, endpoint.rsplit("/", 1)[1], f"uid-{kind}")
                command = runner.call_args.args[0]
                options = json.loads(runner.call_args.kwargs["input_text"])
                self.assertIn("--raw=" + endpoint, command)
                self.assertEqual(options["preconditions"], {"uid": f"uid-{kind}"})

    def test_additional_resource_cleanup_hook_runs_after_owned_pvcs(self):
        fixture = self.fixture
        order = []
        fixture.namespace_uid = "namespace-uid"
        fixture.namespace_baseline = set()
        fixture.created[("persistentvolumeclaim", "data-db-0")] = "pvc-uid"
        pvc = {
            "metadata": {"name": "data-db-0", "uid": "pvc-uid", "labels": {"crdb-library-run": self.fixture.run_id}},
            "spec": {},
            "status": {"phase": "Bound"},
        }

        def get(kind, name=None, **kwargs):
            order.append(f"get:{kind}:{name}")
            return {"items": [pvc]} if kind == "persistentvolumeclaims" else {}

        fixture.get = get
        fixture.raw_delete_uid = lambda kind, name, uid, **kwargs: order.append(f"delete:{kind}:{name}:{uid}")
        fixture.wait_absent = lambda kind, name, **kwargs: order.append(f"absent:{kind}:{name}")
        fixture.cleanup_additional_resources = lambda: order.append("extra-cleanup")
        fixture._namespace_resource_identities = lambda: set()
        fixture._checkpoint = lambda _status: None
        fixture.cleanup()
        self.assertLess(order.index("delete:persistentvolumeclaim:data-db-0:pvc-uid"), order.index("extra-cleanup"))

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

    def test_proof_mode_selects_default_or_http_transport_compatibility_phases(self):
        self.assertEqual(_HARNESS._proof_phase_names("standard"), ("insecure", "tls"))
        self.assertEqual(
            _HARNESS._proof_phase_names("http-transport-compatibility"),
            ("tls-local-http", "tls-https"),
        )
        with self.assertRaises(_HARNESS.SmokeFailure):
            _HARNESS._proof_phase_names("unknown")

    def test_main_uses_compatibility_pair_only_when_explicitly_selected(self):
        observed = []

        def phase(_args, name, run_id, evidence_dir):
            observed.append(name)
            return {"phase": name, "namespace": f"ns-{name}"}

        with tempfile.TemporaryDirectory() as root, patch.object(_HARNESS, "phase", side_effect=phase):
            standard_dir = Path(root) / "standard"
            compatibility_dir = Path(root) / "compatibility"
            self.assertEqual(_HARNESS.main(["--evidence-dir", str(standard_dir)]), 0)
            standard_phases = tuple(observed)
            observed.clear()
            self.assertEqual(
                _HARNESS.main(
                    [
                        "--evidence-dir", str(compatibility_dir),
                        "--proof-mode", "http-transport-compatibility",
                    ]
                ),
                0,
            )
            compatibility_phases = tuple(observed)
            standard_summary = json.loads((standard_dir.resolve() / "live-summary.json").read_text())
            compat_summary = json.loads((compatibility_dir.resolve() / "live-summary.json").read_text())

        self.assertEqual(standard_phases, ("insecure", "tls"))
        self.assertEqual(compatibility_phases, ("tls-local-http", "tls-https"))
        self.assertEqual(standard_summary["proof_mode"], "standard")
        self.assertEqual(compat_summary["proof_mode"], "http-transport-compatibility")

    def test_phase_routes_opt_in_local_http_tls_fixture_to_compatibility_exercise(self):
        args = SimpleNamespace(
            context="kind-test", kubectl="kubectl", image="cockroachdb/cockroach:v24.1.0",
            node="kind-worker", diagnostic_only=False, proof_mode="http-transport-compatibility",
        )
        fixture = _HARNESS.Fixture(args, "tls-local-http", "261019-compat")
        with tempfile.TemporaryDirectory() as evidence_directory:
            with (
                patch.object(_HARNESS, "Fixture", return_value=fixture),
                patch.object(_HARNESS, "preflight", return_value={"storage_class": "local-path"}),
                patch.object(fixture, "prepare_namespace"),
                patch.object(fixture, "create", return_value={"metadata": {"uid": "owned-uid"}}),
                patch.object(fixture, "make_secret"),
                patch.object(fixture, "cleanup"),
                patch.object(_HARNESS, "make_certificates"),
                patch.object(fixture, "statefulset_manifest", wraps=fixture.statefulset_manifest) as manifest,
                patch.object(
                    _HARNESS,
                    "_exercise_compatibility_phase",
                    return_value={"native_http_identity_matches_sql": True},
                ) as exercise,
            ):
                result = _HARNESS.phase(
                    args,
                    "tls-local-http",
                    "261019-compat",
                    Path(evidence_directory),
                )

        self.assertEqual(result["result"], "passed")
        self.assertEqual(result["tls_mode"], "tls")
        self.assertEqual(result["proof_mode"], "http-transport-compatibility")
        self.assertTrue(result["native_http_identity_matches_sql"])
        manifest.assert_called_once_with(tls=True, unencrypted_localhost_http=True)
        self.assertEqual(exercise.call_args.kwargs["http_transport"], _HARNESS.HTTPTransport.HTTP)

    def test_localhost_http_fixture_keeps_secure_sql_and_tcp_kubelet_probes(self):
        local_http = self.fixture.statefulset_manifest(tls=True, unencrypted_localhost_http=True)
        normal_https = self.fixture.statefulset_manifest(tls=True)
        local_container = local_http["spec"]["template"]["spec"]["containers"][0]
        https_container = normal_https["spec"]["template"]["spec"]["containers"][0]
        self.assertIn("--certs-dir=/cockroach/certs", local_container["command"][2])
        self.assertIn("--unencrypted-localhost-http", local_container["command"][2])
        self.assertIn("--http-addr=localhost:8080", local_container["command"][2])
        self.assertNotIn("--http-addr=:8080", local_container["command"][2])
        self.assertNotIn("--http-addr=0.0.0.0:8080", local_container["command"][2])
        self.assertNotIn("--insecure", local_container["command"][2])
        self.assertNotIn("--unencrypted-localhost-http", https_container["command"][2])
        self.assertEqual(local_container["livenessProbe"]["tcpSocket"]["port"], "rpc")
        self.assertEqual(local_container["readinessProbe"]["tcpSocket"]["port"], "rpc")

    def test_localhost_http_startup_conflict_diagnostic_omits_explicit_host(self):
        sentinel = "credential-sentinel.example"
        diagnostic = _HARNESS._safe_diagnostic_text(
            f"ERROR: --unencrypted-localhost-http is incompatible with --http-addr={sentinel}:8080"
        )
        self.assertIn("incompatible localhost-only HTTP startup flags", diagnostic)
        self.assertNotIn(sentinel, diagnostic)
        self.assertNotIn("8080", diagnostic)

    def test_native_identity_comparison_checks_node_and_cluster_identity(self):
        _HARNESS._assert_native_matches_sql_identity((7, "ABCDEF00-0000-0000-0000-000000000001"), (7, "abcdef00-0000-0000-0000-000000000001"))
        with self.assertRaises(_HARNESS.SmokeFailure):
            _HARNESS._assert_native_matches_sql_identity((8, "cluster-a"), (7, "cluster-a"))
        with self.assertRaises(_HARNESS.SmokeFailure):
            _HARNESS._assert_native_matches_sql_identity((7, "cluster-b"), (7, "cluster-a"))

    def test_native_identity_session_scope_includes_certificate_fingerprints(self):
        secret = SimpleNamespace(name="db-certs", uid="secret-uid", sha256_by_key=(("ca.crt", "digest-a"),))
        workload = SimpleNamespace(certs_dir="/cockroach/certs", secrets=(secret,))
        first = _HARNESS._native_auth_scope(workload)
        changed = SimpleNamespace(
            certs_dir="/cockroach/certs",
            secrets=(SimpleNamespace(name="db-certs", uid="secret-uid", sha256_by_key=(("ca.crt", "digest-b"),)),),
        )
        self.assertEqual(len(first), 64)
        self.assertNotEqual(first, _HARNESS._native_auth_scope(changed))
        self.assertNotIn("digest-a", first)

    def test_compatibility_preservation_checks_state_pods_and_witness(self):
        accepted = SimpleNamespace(
            cluster_id="cluster-id", node_ids=(1,), sql_versions=(("db-0", "v24.1.0"),),
            image="cockroachdb/cockroach:v24.1.0", desired_replicas=1, pvc_identities=(("data-db-0", "pvc", "pv", "Bound", "hash"),),
            certificate_fingerprints=(("db-certs", "secret", "ca.crt", "fingerprint"),),
            service_routing=(("db", "service-uid", "route-hash"),), workload_spec_hash="spec-hash",
        )
        workload = SimpleNamespace(
            pods=(SimpleNamespace(name="db-0", uid="pod-uid"),),
            liveness_probe=SimpleNamespace(handler="tcpSocket"),
            readiness_probe=SimpleNamespace(handler="tcpSocket"),
        )
        verified = SimpleNamespace(status=_HARNESS.ProbeStatus.SATISFIED)

        class FakeLibrary:
            def verify_accepted_state(self, *_args, **_kwargs):
                return verified

            def capture_accepted_state(self, *_args, **_kwargs):
                return accepted

            def inspect(self, *_args, **_kwargs):
                return workload

        fixture = SimpleNamespace()
        witness = "id,payload\n1,one\n2,two\n"
        digest = hashlib.sha256(witness.encode()).hexdigest()
        probes = {"liveness": {"handler": "tcpSocket"}, "readiness": {"handler": "tcpSocket"}}
        with patch.object(_HARNESS, "_fixture_sql", return_value=witness):
            result = _HARNESS._assert_compatibility_preserved(
                FakeLibrary(),
                "workload-ref",
                fixture,
                tls=True,
                accepted_before=accepted,
                pod_uids_before=(("db-0", "pod-uid"),),
                probes_before=probes,
                witness_hash_before=digest,
            )
        self.assertTrue(result["accepted_state_verified"])
        self.assertEqual(result["pod_uids_before_after"], [(("db-0", "pod-uid"),), (("db-0", "pod-uid"),)])
        self.assertEqual(result["probes_before_after"], [probes, probes])
        self.assertEqual(result["witness_sha256_before_after"], [digest, digest])

    def test_compatibility_preservation_rejects_changed_state_pod_or_witness(self):
        accepted = SimpleNamespace(
            cluster_id="cluster-id", node_ids=(1,), sql_versions=(("db-0", "v24.1.0"),),
            image="cockroachdb/cockroach:v24.1.0", desired_replicas=1, pvc_identities=(),
            certificate_fingerprints=(), service_routing=(), workload_spec_hash="spec-hash",
        )
        probe = SimpleNamespace(handler="tcpSocket")
        workload = SimpleNamespace(pods=(SimpleNamespace(name="db-0", uid="pod-uid"),), liveness_probe=probe, readiness_probe=probe)
        probes = {"liveness": {"handler": "tcpSocket"}, "readiness": {"handler": "tcpSocket"}}
        verified = SimpleNamespace(status=_HARNESS.ProbeStatus.SATISFIED)
        witness = "id,payload\n1,one\n2,two\n"
        digest = hashlib.sha256(witness.encode()).hexdigest()

        class FakeLibrary:
            captured = accepted
            inspected = workload

            def verify_accepted_state(self, *_args, **_kwargs):
                return verified

            def capture_accepted_state(self, *_args, **_kwargs):
                return self.captured

            def inspect(self, *_args, **_kwargs):
                return self.inspected

        scenarios = (
            ("accepted state", lambda library: setattr(library, "captured", SimpleNamespace(**{**vars(accepted), "workload_spec_hash": "changed"})), witness),
            ("Pod UID", lambda library: setattr(library, "inspected", SimpleNamespace(
                pods=(SimpleNamespace(name="db-0", uid="replacement-pod"),), liveness_probe=probe, readiness_probe=probe,
            )), witness),
            ("witness", lambda _library: None, "id,payload\n1,changed\n2,two\n"),
        )
        for label, change, observed_witness in scenarios:
            with self.subTest(label=label):
                fake_library = FakeLibrary()
                fake_library.captured = accepted
                fake_library.inspected = workload
                change(fake_library)
                with patch.object(_HARNESS, "_fixture_sql", return_value=observed_witness):
                    with self.assertRaises(_HARNESS.SmokeFailure):
                        _HARNESS._assert_compatibility_preserved(
                            fake_library,
                            "ref",
                            SimpleNamespace(),
                            tls=True,
                            accepted_before=accepted,
                            pod_uids_before=(("db-0", "pod-uid"),),
                            probes_before=probes,
                            witness_hash_before=digest,
                        )

    def test_loopback_probe_rejection_fails_if_adapter_attempts_a_patch(self):
        class FakeLibrary:
            def prepare_health_recovery_probes(self, *_args, **_kwargs):
                raise _HARNESS.UnsupportedLayoutError("loopback only")

        adapter = _HARNESS._PatchCountingAdapter(SimpleNamespace())
        _HARNESS._require_probe_preparation_rejected_without_patch(FakeLibrary(), "ref", adapter)
        self.assertEqual(adapter.patch_calls, 0)

        class MutatingFakeLibrary:
            def prepare_health_recovery_probes(self, *_args, **_kwargs):
                adapter.patch_calls += 1
                raise _HARNESS.UnsupportedLayoutError("too late")

        with self.assertRaises(_HARNESS.SmokeFailure):
            _HARNESS._require_probe_preparation_rejected_without_patch(MutatingFakeLibrary(), "ref", adapter)

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

    def test_compatibility_tls_phases_run_openssl_preflight_before_creation(self):
        for phase_name in ("tls-local-http", "tls-https"):
            with self.subTest(phase=phase_name), tempfile.TemporaryDirectory() as evidence_dir:
                args = SimpleNamespace(
                    context="kind-test",
                    kubectl="kubectl",
                    docker="docker",
                    image="cockroachdb/cockroach:v24.1.0",
                    node="kind-worker",
                    diagnostic_only=False,
                    proof_mode="http-transport-compatibility",
                    ready_timeout=120,
                    running_observation_timeout=8,
                )
                fixture = _HARNESS.Fixture(args, phase_name, "261019-compat")
                order = []

                def get(resource, name=None, **_kwargs):
                    if resource == "nodes":
                        return {"items": [{
                            "metadata": {"name": "kind-worker"},
                            "status": {"allocatable": {"cpu": "8", "memory": "8Gi"}},
                        }]}
                    if resource == "storageclasses":
                        return {"items": [{
                            "metadata": {
                                "name": "local-path",
                                "annotations": {"storageclass.kubernetes.io/is-default-class": "true"},
                            },
                        }]}
                    return {"items": []}

                fixture.get = get

                def command(argv, **_kwargs):
                    if argv[1:3] == ["ps", "--format={{.Image}}"]:
                        return ""
                    if "df" in argv:
                        return "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev 12000000 1000 11999000 1% /var/lib/containerd\n"
                    if "crictl" in argv:
                        return json.dumps({"images": [{"repoTags": [args.image]}]})
                    raise AssertionError(f"unexpected preflight command: {argv}")

                def openssl_version():
                    order.append("openssl")
                    return "OpenSSL 3.0.0"

                def create(_manifest):
                    order.append("create")
                    return {"metadata": {"uid": f"uid-{len(order)}"}}

                with (
                    patch.object(_HARNESS, "Fixture", return_value=fixture),
                    patch.object(_HARNESS, "run", side_effect=command),
                    patch.object(_HARNESS.shutil, "disk_usage", return_value=SimpleNamespace(free=10 * 1024**3)),
                    patch.object(_HARNESS, "_openssl_version", side_effect=openssl_version),
                    patch.object(fixture, "prepare_namespace", side_effect=lambda: order.append("namespace")),
                    patch.object(fixture, "create", side_effect=create),
                    patch.object(fixture, "make_secret", side_effect=lambda _path: None),
                    patch.object(fixture, "cleanup"),
                    patch.object(_HARNESS, "make_certificates"),
                    patch.object(_HARNESS, "_exercise_compatibility_phase", return_value={"verified": True}),
                ):
                    result = _HARNESS.phase(args, phase_name, "261019-compat", Path(evidence_dir))

                self.assertEqual(result["result"], "passed")
                self.assertLess(order.index("openssl"), order.index("namespace"))
                self.assertLess(order.index("openssl"), order.index("create"))

    def test_compatibility_full_health_wait_is_bounded_and_records_observations(self):
        observed = SimpleNamespace(
            status=_HARNESS.ProbeStatus.SATISFIED,
            reasons=(),
            attempts=2,
            pod_node_ids=(("db-0", 1),),
            node_status=(NodeStatusObservation(1, "active", False, True, 0, 0, True),),
            node_liveness=(NodeLivenessObservation(1, "active", False, True),),
        )

        class FakeLibrary:
            calls = []

            def wait_for_full_health(self, ref, **kwargs):
                self.calls.append((ref, kwargs))
                return observed

        library = FakeLibrary()
        verdict = _HARNESS._full_health_verdict(library, "workload-ref")
        self.assertEqual(library.calls, [(
            "workload-ref",
            {"timeout": 90, "poll_interval": 1, "per_node_timeout": 5},
        )])
        self.assertEqual(verdict["status"], "satisfied")
        self.assertEqual(verdict["attempts"], 2)
        self.assertEqual(verdict["pod_node_ids"], [["db-0", 1]])
        self.assertEqual(verdict["node_status"][0]["ranges_underreplicated"], 0)
        self.assertEqual(verdict["node_liveness"][0]["is_live"], True)

        class UnsatisfiedLibrary:
            def wait_for_full_health(self, *_args, **_kwargs):
                return SimpleNamespace(status=_HARNESS.ProbeStatus.UNSATISFIED)

        with self.assertRaises(_HARNESS.SmokeFailure):
            _HARNESS._full_health_verdict(UnsatisfiedLibrary(), "workload-ref")

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

    def test_opt_in_kubectl_error_reports_only_bounded_namespace_and_api_reason(self):
        events = []
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=1,
            stdout="",
            stderr=("Error from server (NotFound): secret-response=must-not-appear " + "x" * 5000),
        )
        with patch.object(_HARNESS.subprocess, "run", return_value=completed):
            with self.assertRaises(_HARNESS.SmokeFailure) as raised:
                _HARNESS.run(
                    ["kubectl", "patch", "statefulset", "db"],
                    timeout=2,
                    operation="kubectl patch",
                    failure_context="namespace/health-fixture",
                    observer=events.append,
                )
        message = str(raised.exception)
        self.assertIn("namespace/health-fixture", message)
        self.assertIn("Kubernetes API reason: NotFound", message)
        self.assertNotIn("must-not-appear", message)
        self.assertLess(len(message), 200)
        self.assertEqual(events[0]["failure_context"], "namespace/health-fixture")
        self.assertEqual(events[0]["api_reason"], "NotFound")

    def test_failed_kubectl_patch_without_diagnostic_opt_in_remains_generic(self):
        completed = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="Error from server (Invalid): private")
        with patch.object(_HARNESS.subprocess, "run", return_value=completed):
            with self.assertRaises(_HARNESS.SmokeFailure) as raised:
                _HARNESS.run(["kubectl", "patch", "statefulset", "db"], timeout=2)
        self.assertEqual(str(raised.exception), "kubectl returned an error")

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

    def test_compatibility_mode_failure_journals_redacted_reason_before_cleanup(self):
        order = []
        sentinel = "cookie=private-session-proof-sentinel"
        execution_error = _HARNESS.SmokeFailure(f"native HTTP failure {sentinel}")
        args = SimpleNamespace(
            context="kind-test", kubectl="kubectl", image="cockroachdb/cockroach:v24.1.0",
            node="kind-worker", diagnostic_only=False, proof_mode="http-transport-compatibility",
        )
        fixture = _HARNESS.Fixture(args, "tls-local-http", "261019-redact")

        def capture(phase_data, *, label):
            order.append("capture")
            phase_data.setdefault("runtime_diagnostics", {})[label] = {"captured": True}

        def cleanup():
            order.append("cleanup")

        with tempfile.TemporaryDirectory() as evidence_directory:
            with (
                patch.object(_HARNESS, "Fixture", return_value=fixture),
                patch.object(_HARNESS, "preflight", return_value={"storage_class": "local-path"}),
                patch.object(fixture, "prepare_namespace"),
                patch.object(fixture, "create", return_value={"metadata": {"uid": "owned-uid"}}),
                patch.object(fixture, "make_secret"),
                patch.object(fixture, "cleanup", side_effect=cleanup),
                patch.object(_HARNESS, "make_certificates"),
                patch.object(fixture, "statefulset_manifest", return_value={}),
                patch.object(fixture, "capture_diagnostics", side_effect=capture),
                patch.object(_HARNESS, "_exercise_compatibility_phase", side_effect=execution_error),
            ):
                with self.assertRaises(_HARNESS.SmokeFailure):
                    _HARNESS.phase(args, "tls-local-http", "261019-redact", Path(evidence_directory))
            phase_data = json.loads((Path(evidence_directory) / "tls-local-http-phase.json").read_text())

        self.assertEqual(order, ["capture", "cleanup"])
        self.assertEqual(phase_data["result"], "failed")
        self.assertEqual(phase_data["cleanup_verdict"], "completed with UID preconditions and normal deletion")
        self.assertNotIn("private-session-proof-sentinel", json.dumps(phase_data))
        self.assertIn("REDACTED", phase_data["execution_failure"]["detail"])

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

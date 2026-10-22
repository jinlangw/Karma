from __future__ import annotations

import copy
import importlib.util
import os
from pathlib import Path
import subprocess

import pytest

from cases.common.cockroachdb.types import KubernetesAccessError, StaleIdentityError, UnsupportedLayoutError


ROOT = Path(__file__).resolve().parents[2]
HELPER_PATH = ROOT / "cases/tests/cockroachdb/certificate-rotation/resource/secure_target.py"
SPEC = importlib.util.spec_from_file_location("certificate_rotation_secure_target", HELPER_PATH)
assert SPEC is not None and SPEC.loader is not None
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)


CERT_DIR = "/cockroach/cockroach-certs"


def statefulset(*, replicas=3):
    return {
        "apiVersion": "apps/v1",
        "kind": "StatefulSet",
        "metadata": {"name": "db", "namespace": "bench", "uid": "sts-1", "resourceVersion": "10"},
        "spec": {
            "replicas": replicas,
            "serviceName": "db",
            "selector": {"matchLabels": {"app": "db"}},
            "template": {
                "metadata": {"labels": {"app": "db"}},
                "spec": {
                    "containers": [
                        {
                            "name": "database",
                            "image": "cockroachdb/cockroach:v24.1.0",
                            "command": ["/cockroach/cockroach", "start"],
                            "args": ["--insecure", "--port=26257", "--cache=25%"],
                            "ports": [{"name": "http", "containerPort": 8080}],
                            "livenessProbe": {"httpGet": {"path": "/health", "port": "http"}},
                        }
                    ]
                },
            },
            "updateStrategy": {"type": "RollingUpdate"},
            "volumeClaimTemplates": [
                {"metadata": {"name": "datadir"}, "spec": {"resources": {"requests": {"storage": "10Gi"}}}}
            ],
        },
    }


class MemoryAdapter:
    def __init__(self, sts=None, *, services=None, pods=None):
        self.sts = copy.deepcopy(sts) if sts is not None else None
        self.services = copy.deepcopy(services or {})
        self.pods = copy.deepcopy(pods or [])
        self.patches = []

    def get_resource(self, kind, namespace, name):
        if kind == "statefulset":
            return copy.deepcopy(self.sts)
        if kind == "service":
            return copy.deepcopy(self.services.get(name))
        raise AssertionError(f"unexpected resource kind {kind}")

    def list_resources(self, kind, namespace):
        assert kind == "pod"
        return copy.deepcopy(self.pods)

    def patch_statefulset_json(self, *, namespace, name, uid, resource_version, operations, timeout):
        assert self.sts is not None
        assert self.sts["metadata"]["uid"] == uid
        assert self.sts["metadata"]["resourceVersion"] == resource_version
        self.patches.append(copy.deepcopy(list(operations)))
        for operation in operations[2:]:
            path = operation["path"].split("/")[1:]
            target = self.sts
            for component in path[:-1]:
                target = target[component]
            if operation["op"] == "add":
                target[path[-1]] = copy.deepcopy(operation["value"])
            elif operation["op"] == "replace":
                target[path[-1]] = copy.deepcopy(operation["value"])
            else:
                raise AssertionError(f"unexpected patch operation {operation['op']}")
        self.sts["metadata"]["resourceVersion"] = str(int(resource_version) + 1)
        return copy.deepcopy(self.sts)


def make_plan(sts):
    return HELPER.build_plan(
        sts,
        secret_name="db-certs",
        cert_dir=CERT_DIR,
        case_replicas=3,
    )


def service(name, *, ports=None, selector=None, service_type="ClusterIP", headless=False, **extra_spec):
    spec = {
        "type": service_type,
        "clusterIP": "None" if headless else "10.0.0.10",
        "selector": selector or {"app": "db"},
        "ports": copy.deepcopy(ports or [
            {"name": "sql", "port": 26257, "targetPort": 26257},
            {"name": "http", "port": 8080, "targetPort": "http"},
        ]),
    }
    if headless:
        spec["publishNotReadyAddresses"] = True
    spec.update(copy.deepcopy(extra_spec))
    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": name, "namespace": "bench", "uid": f"{name}-uid", "resourceVersion": "4"},
        "spec": spec,
    }


def scaled_adapter(*, services=None, pods=None, replicas=3):
    adapter = MemoryAdapter(statefulset(replicas=replicas), services=services, pods=pods)
    plan = make_plan(adapter.sts)
    HELPER.scale_existing(adapter, "bench", "db", plan)
    return adapter, plan


@pytest.mark.parametrize(("original_replicas", "target_replicas"), [(3, 3), (2, 2), (1, 1), (0, 3)])
def test_existing_target_plan_preserves_nonzero_size_and_restores_empty_target_to_case_size(
    original_replicas, target_replicas
):
    selected = statefulset(replicas=original_replicas)
    original_spec = copy.deepcopy(selected["spec"])

    plan = make_plan(selected)

    assert plan["original_replicas"] == original_replicas
    assert plan["target_replicas"] == target_replicas
    assert plan["original_spec"] == original_spec
    assert selected["spec"] == original_spec
    assert plan["secure_template"] != original_spec["template"]


def test_omitted_existing_replica_count_uses_kubernetes_default_of_one():
    selected = statefulset()
    selected["spec"].pop("replicas")

    plan = make_plan(selected)

    assert plan["original_replicas"] == 1
    assert plan["target_replicas"] == 1


def test_zero_replica_target_uses_the_case_manifest_replica_count():
    manifest = ROOT / "cases/tests/cockroachdb/certificate-rotation/resource/statefulset.yaml"

    assert HELPER._case_replicas_from_manifest(manifest) == 3


def test_case_manifest_replica_reader_rejects_ambiguous_or_missing_count(tmp_path):
    manifest = tmp_path / "statefulset.yaml"
    manifest.write_text(
        "apiVersion: apps/v1\nkind: StatefulSet\nspec:\n  replicas: 0\n",
        encoding="utf-8",
    )
    with pytest.raises(UnsupportedLayoutError, match="valid replica count"):
        HELPER._case_replicas_from_manifest(manifest)

    manifest.write_text(
        "apiVersion: apps/v1\nkind: StatefulSet\nspec:\n  replicas: 2\n---\n"
        "apiVersion: apps/v1\nkind: StatefulSet\nspec:\n  replicas: 4\n",
        encoding="utf-8",
    )
    with pytest.raises(UnsupportedLayoutError, match="one StatefulSet"):
        HELPER._case_replicas_from_manifest(manifest)


@pytest.mark.parametrize(("original_replicas", "target_replicas"), [(3, 3), (1, 1), (0, 3)])
def test_guarded_scale_and_finish_change_only_template_and_case_replica_target(original_replicas, target_replicas):
    adapter = MemoryAdapter(statefulset(replicas=original_replicas))
    original_spec = copy.deepcopy(adapter.sts["spec"])
    plan = make_plan(adapter.sts)

    HELPER.scale_existing(adapter, "bench", "db", plan)

    assert adapter.sts["spec"]["replicas"] == 0
    assert {key: value for key, value in adapter.sts["spec"].items() if key != "replicas"} == {
        key: value for key, value in original_spec.items() if key != "replicas"
    }
    assert adapter.patches[-1][0] == {"op": "test", "path": "/metadata/uid", "value": "sts-1"}
    assert adapter.patches[-1][1] == {"op": "test", "path": "/metadata/resourceVersion", "value": "10"}

    HELPER.finish_existing(adapter, "bench", "db", plan)

    expected_spec = copy.deepcopy(original_spec)
    expected_spec["template"] = plan["secure_template"]
    expected_spec["replicas"] = target_replicas
    assert adapter.sts["spec"] == expected_spec
    assert adapter.sts["metadata"]["uid"] == "sts-1"
    assert len(adapter.patches) == 2


def test_scale_rejects_changed_or_replaced_statefulset_before_patch():
    adapter = MemoryAdapter(statefulset())
    plan = make_plan(adapter.sts)
    adapter.sts["spec"]["template"]["metadata"]["labels"]["concurrent"] = "change"

    with pytest.raises(StaleIdentityError, match="changed before the guarded scale"):
        HELPER.scale_existing(adapter, "bench", "db", plan)
    assert adapter.patches == []

    adapter.sts = statefulset()
    plan = make_plan(adapter.sts)
    adapter.sts["metadata"]["uid"] = "sts-replacement"
    with pytest.raises(StaleIdentityError, match="changed before the guarded scale"):
        HELPER.scale_existing(adapter, "bench", "db", plan)
    assert adapter.patches == []


def test_scale_uses_latest_resource_version_after_status_only_update():
    adapter = MemoryAdapter(statefulset())
    plan = make_plan(adapter.sts)
    adapter.sts["metadata"]["resourceVersion"] = "11"
    adapter.sts["status"] = {"readyReplicas": 3}

    HELPER.scale_existing(adapter, "bench", "db", plan)

    assert adapter.patches[0][1] == {
        "op": "test",
        "path": "/metadata/resourceVersion",
        "value": "11",
    }


def test_finish_rejects_spec_or_uid_change_after_scale():
    adapter = MemoryAdapter(statefulset())
    plan = make_plan(adapter.sts)
    HELPER.scale_existing(adapter, "bench", "db", plan)
    patch_count = len(adapter.patches)
    adapter.sts["spec"]["updateStrategy"] = {"type": "OnDelete"}

    with pytest.raises(StaleIdentityError, match="changed before the guarded TLS update"):
        HELPER.finish_existing(adapter, "bench", "db", plan)
    assert len(adapter.patches) == patch_count

    adapter.sts["spec"]["updateStrategy"] = {"type": "RollingUpdate"}
    adapter.sts["metadata"]["uid"] = "sts-replacement"
    with pytest.raises(StaleIdentityError, match="changed before the guarded TLS update"):
        HELPER.finish_existing(adapter, "bench", "db", plan)
    assert len(adapter.patches) == patch_count


def test_prepare_treats_only_confirmed_missing_statefulset_as_fresh():
    adapter = MemoryAdapter()
    assert HELPER.prepare_existing(
        adapter, "bench", "db", secret_name="db-certs", cert_dir=CERT_DIR, case_replicas=3
    ) is None

    class FailedAdapter(MemoryAdapter):
        def get_resource(self, *_args):
            raise KubernetesAccessError("permission denied")

    with pytest.raises(KubernetesAccessError):
        HELPER.prepare_existing(
            FailedAdapter(), "bench", "db", secret_name="db-certs", cert_dir=CERT_DIR, case_replicas=3
        )


def test_valid_services_keep_nodeport_allocations_and_unchecked_extra_rpc_port():
    public = service(
        "db-public",
        service_type="NodePort",
        ports=[
            {"name": "sql", "port": 26257, "targetPort": 26257, "nodePort": 31257},
            {"name": "http", "port": 8080, "targetPort": "http", "nodePort": 30080},
            {"name": "rpc", "port": 26258, "targetPort": 26258, "nodePort": 31258},
        ],
    )
    headless = service("db", headless=True)
    adapter, plan = scaled_adapter(services={"db": headless, "db-public": public})
    before_headless = copy.deepcopy(headless)
    before_public = copy.deepcopy(public)

    assert HELPER.service_needs_repair(adapter, "bench", "db", "db", plan) is False
    assert HELPER.service_needs_repair(adapter, "bench", "db", "db-public", plan) is False
    assert adapter.services == {"db": before_headless, "db-public": before_public}
    assert adapter.sts["spec"]["replicas"] == 0


def test_valid_loadbalancer_keeps_local_health_port_and_allocated_fields():
    public = service(
        "db-public",
        service_type="LoadBalancer",
        ports=[
            {"name": "sql", "port": 26257, "targetPort": 26257, "nodePort": 31257},
            {"name": "http", "port": 8080, "targetPort": "http", "nodePort": 30080},
        ],
        externalTrafficPolicy="Local",
        healthCheckNodePort=32000,
        loadBalancerIP="192.0.2.20",
    )
    adapter, plan = scaled_adapter(services={"db": service("db", headless=True), "db-public": public})
    before = copy.deepcopy(public)

    assert HELPER.service_needs_repair(adapter, "bench", "db", "db-public", plan) is False
    assert adapter.services["db-public"] == before


def test_service_routing_resolves_named_backend_ports_and_split_sql_rpc_listeners():
    selected = statefulset()
    database = selected["spec"]["template"]["spec"]["containers"][0]
    database["command"] = ["/cockroach/cockroach", "start"]
    database["args"] = [
        "--insecure",
        "--sql-addr=0.0.0.0:26300",
        "--listen-addr=0.0.0.0:26258",
        "--port=26257",
        "--http-addr=0.0.0.0:8081",
    ]
    database["ports"] = [
        {"name": "sql", "containerPort": 26300},
        {"name": "rpc", "containerPort": 26258},
        {"name": "http", "containerPort": 8081},
    ]
    custom_ports = [
        {"name": "sql", "port": 26257, "targetPort": "sql"},
        {"name": "http", "port": 8080, "targetPort": "http"},
    ]
    adapter = MemoryAdapter(
        selected,
        services={
            "db": service("db", headless=True, ports=custom_ports),
            "db-public": service("db-public", ports=custom_ports),
        },
        pods=[],
    )
    plan = make_plan(adapter.sts)
    HELPER.scale_existing(adapter, "bench", "db", plan)

    assert plan["service_requirements"]["sql_port"] == 26300
    assert plan["service_requirements"]["http_port"] == 8081
    # The original SQL/RPC split does not require a separate Service RPC port.
    assert HELPER.service_needs_repair(adapter, "bench", "db", "db", plan) is False
    assert HELPER.service_needs_repair(adapter, "bench", "db", "db-public", plan) is False


def test_service_planning_accepts_start_single_node_and_tcp_with_an_extra_udp_frontend():
    selected = statefulset()
    container = selected["spec"]["template"]["spec"]["containers"][0]
    container["command"] = ["/cockroach/cockroach", "start-single-node"]
    container["args"] = ["--insecure", "--port=26257"]
    container["ports"] = [{"name": "http", "containerPort": 8080}]
    headless = service(
        "db",
        headless=True,
        ports=[
            {"port": 26257, "targetPort": 26257, "protocol": "TCP"},
            {"port": 26257, "targetPort": 26257, "protocol": "UDP"},
            {"port": 8080, "targetPort": "http", "protocol": "TCP"},
        ],
    )
    adapter = MemoryAdapter(selected, services={"db": headless, "db-public": service("db-public")})
    plan = make_plan(adapter.sts)
    HELPER.scale_existing(adapter, "bench", "db", plan)

    assert HELPER.service_needs_repair(adapter, "bench", "db", "db", plan) is False


def test_service_selector_may_use_template_labels_but_not_foreign_pods():
    selected = statefulset()
    selected["spec"]["template"]["metadata"]["labels"]["zone"] = "blue"
    headless = service("db", headless=True, selector={"app": "db", "zone": "blue"})
    public = service("db-public", selector={"app": "db", "zone": "blue"})
    adapter = MemoryAdapter(selected, services={"db": headless, "db-public": public}, pods=[])
    plan = make_plan(adapter.sts)
    HELPER.scale_existing(adapter, "bench", "db", plan)
    assert HELPER.service_needs_repair(adapter, "bench", "db", "db", plan) is False

    adapter.pods = [{
        "metadata": {
            "name": "other-0",
            "namespace": "bench",
            "labels": {"app": "db", "zone": "blue"},
            "ownerReferences": [{"kind": "StatefulSet", "uid": "other-sts", "controller": True}],
        }
    }]
    assert HELPER.service_needs_repair(adapter, "bench", "db", "db", plan) is True


def test_service_repair_is_independent_and_only_confirmed_absence_or_invalidity_repairs():
    valid_headless = service("db", headless=True)
    invalid_public = service("db-public", ports=[{"port": 26257, "targetPort": 26257}])
    adapter, plan = scaled_adapter(services={"db": valid_headless, "db-public": invalid_public})

    assert HELPER.service_needs_repair(adapter, "bench", "db", "db", plan) is False
    assert HELPER.service_needs_repair(adapter, "bench", "db", "db-public", plan) is True
    assert HELPER.service_needs_repair(adapter, "bench", "db", "missing", plan) is True

    class ApiFailureAdapter(MemoryAdapter):
        def get_resource(self, kind, namespace, name):
            if kind == "service":
                raise KubernetesAccessError("permission denied")
            return super().get_resource(kind, namespace, name)

    failed = ApiFailureAdapter(adapter.sts)
    with pytest.raises(KubernetesAccessError, match="permission denied"):
        HELPER.service_needs_repair(failed, "bench", "db", "db-public", plan)


def test_service_check_accepts_empty_zero_replica_target_without_live_pods():
    adapter, plan = scaled_adapter(
        services={"db": service("db", headless=True), "db-public": service("db-public")},
        replicas=0,
        pods=[],
    )

    assert adapter.sts["spec"]["replicas"] == 0
    assert HELPER.service_needs_repair(adapter, "bench", "db", "db", plan) is False
    assert HELPER.service_needs_repair(adapter, "bench", "db", "db-public", plan) is False


def test_render_service_selects_only_requested_original_manifest_document(tmp_path):
    manifest = ROOT / "cases/tests/cockroachdb/certificate-rotation/resource/services.yaml"

    rendered = HELPER.render_service(manifest, "db-public", "db")
    document = HELPER.yaml.safe_load(rendered)

    assert document["kind"] == "Service"
    assert document["metadata"]["name"] == "db-public"
    assert document["spec"]["type"] == "ClusterIP"
    assert "---" not in rendered
    assert "${BENCH_PARAM_CLUSTER_NAME}" not in rendered


def _fake_executable(path: Path, source: str) -> None:
    path.write_text(source, encoding="utf-8")
    path.chmod(0o755)


def run_tls_apply(tmp_path, *, prepare_status: int, valid_services=""):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "operations.log"
    _fake_executable(
        bindir / "python3",
        "#!/bin/sh\n"
        "printf 'python:%s\\n' \"$2\" >> \"$OP_LOG\"\n"
        "if [ \"$2\" = prepare ]; then printf 'prepare-args:%s\\n' \"$*\" >> \"$OP_LOG\"; exit \"$PREPARE_STATUS\"; fi\n"
        "if [ \"$2\" = service-check ]; then service_name=; while [ $# -gt 0 ]; do if [ \"$1\" = --service ]; then service_name=$2; shift 2; else shift; fi; done; printf 'service-check:%s\\n' \"$service_name\" >> \"$OP_LOG\"; case \",${SERVICE_CHECK_VALID},\" in *\",$service_name,\"*) exit 0 ;; esac; exit 4; fi\n"
        "if [ \"$2\" = render-service ]; then service_name=; while [ $# -gt 0 ]; do if [ \"$1\" = --service ]; then service_name=$2; shift 2; else shift; fi; done; printf 'apiVersion: v1\\nkind: Service\\nmetadata:\\n  name: %s\\n' \"$service_name\"; exit 0; fi\n"
        "exit 0\n",
    )
    _fake_executable(
        bindir / "sh",
        "#!/bin/sh\nprintf 'toolbox\\n' >> \"$OP_LOG\"\nexit 0\n",
    )
    _fake_executable(bindir / "envsubst", "#!/bin/sh\ncat\n")
    _fake_executable(
        bindir / "kubectl",
        "#!/bin/sh\n"
        "printf 'kubectl:%s\\n' \"$*\" >> \"$OP_LOG\"\n"
        "if [ \"$1\" = -n ]; then shift 2; fi\n"
        "case \"$1\" in\n"
        "  cp) mkdir -p \"$3\"; for f in ca.crt node.crt node.key client.root.crt client.root.key; do printf x > \"$3/$f\"; done ;;\n"
        "  get) case \"$*\" in *'pods -l '*) printf 'db-0\\n' ;; esac ;;\n"
        "  create) case \"$2\" in secret) printf 'apiVersion: v1\\nkind: Secret\\n' ;; esac ;;\n"
        "  apply) if [ \"$2\" = -f ] && [ \"$3\" != - ]; then payload=$(cat \"$3\"); else payload=$(cat); fi; case \"$payload\" in *'kind: StatefulSet'*) printf 'apply:statefulset\\n' >> \"$OP_LOG\" ;; *'kind: ServiceAccount'*) printf 'apply:rbac\\n' >> \"$OP_LOG\" ;; *'kind: Service'*) service_name=$(printf '%s\\n' \"$payload\" | sed -n 's/^  name: //p' | head -1); printf 'apply:service:%s\\n' \"$service_name\" >> \"$OP_LOG\" ;; *'kind: Secret'*) printf 'apply:secret\\n' >> \"$OP_LOG\" ;; *) printf 'apply:other\\n' >> \"$OP_LOG\" ;; esac ;;\n"
        "esac\n"
        "exit 0\n",
    )
    environment = {
        **os.environ,
        "PATH": f"{bindir}:{os.environ['PATH']}",
        "BENCH_NAMESPACE": "bench",
        "BENCH_PARAM_CLUSTER_NAME": "db",
        "OP_LOG": str(log),
        "PREPARE_STATUS": str(prepare_status),
        "SERVICE_CHECK_VALID": valid_services,
    }
    result = subprocess.run(
        ["/bin/sh", str(ROOT / "cases/tests/cockroachdb/certificate-rotation/resource/ensure-target-tls.sh"), "apply"],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    operations = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
    return result, operations


def test_apply_preflights_and_preserves_existing_statefulset_instead_of_applying_static_manifest(tmp_path):
    result, operations = run_tls_apply(tmp_path, prepare_status=0)

    assert result.returncode == 0, result.stderr
    assert operations.index("python:prepare") < operations.index("toolbox") < operations.index("python:scale")
    prepare_args = next(line for line in operations if line.startswith("prepare-args:"))
    assert "--case-manifest cases/tests/cockroachdb/certificate-rotation/resource/statefulset.yaml" in prepare_args
    assert operations.index("apply:rbac") < operations.index("apply:service:db") < operations.index("python:finish")
    assert "apply:service:db-public" in operations
    assert "python:finish" in operations
    assert "apply:statefulset" not in operations


def test_apply_uses_unchanged_static_manifest_path_only_for_confirmed_absence(tmp_path):
    result, operations = run_tls_apply(tmp_path, prepare_status=3)

    assert result.returncode == 0, result.stderr
    assert operations.index("python:prepare") < operations.index("toolbox")
    assert "python:scale" not in operations
    assert "python:finish" not in operations
    assert "apply:rbac" in operations
    assert any(line.startswith("apply:service:") for line in operations)
    assert "apply:statefulset" in operations


def test_apply_stops_on_preflight_api_error_before_toolbox_or_mutation(tmp_path):
    result, operations = run_tls_apply(tmp_path, prepare_status=1)

    assert result.returncode == 1
    assert operations[0] == "python:prepare"
    assert len(operations) == 2 and operations[1].startswith("prepare-args:")


def test_existing_service_apply_repairs_only_the_service_that_needs_it(tmp_path):
    result, operations = run_tls_apply(tmp_path, prepare_status=0, valid_services="db-public")

    assert result.returncode == 0, result.stderr
    assert "service-check:db" in operations
    assert "service-check:db-public" in operations
    assert "apply:service:db" in operations
    assert "apply:service:db-public" not in operations
    assert operations.index("apply:service:db") < operations.index("python:finish")

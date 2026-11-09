from __future__ import annotations

import copy

import pytest

from cases.common.cockroachdb import secure_template
from cases.common.cockroachdb.security import insecure_template, mounted_secret_signatures
from cases.common.cockroachdb.types import UnsupportedLayoutError


CERT_DIR = "/cockroach/cockroach-certs"

class SecretLookupError(RuntimeError):
    pass


def workload_template(*, startup: list[str] | None = None) -> dict:
    command = [
        "/bin/bash",
        "-c",
        "exec /cockroach/cockroach start "
        "--advertise-host=$(POD_NAME).db.$(POD_NAMESPACE).svc.cluster.local "
        "--http-addr=0.0.0.0:8080 --port=26257 --insecure "
        "--accept-sql-without-tls --unencrypted-localhost-http "
        "--certs-dir=/old/certs --cache=25%",
    ]
    args = []
    if startup is not None:
        if startup[0] in {"/bin/bash", "/bin/sh", "bash", "sh"}:
            command = startup
        else:
            command, args = [startup[0]], startup[1:]
    return {
        "metadata": {"labels": {"keep": "this"}},
        "spec": {
            "serviceAccountName": "db-sa",
            "containers": [
                {
                    "name": "db",
                    "image": "cockroachdb/cockroach:v24.1.0",
                    "command": command,
                    "args": args,
                    "ports": [
                        {"name": "grpc", "containerPort": 26257, "protocol": "TCP"},
                        {"name": "http", "containerPort": 8080, "protocol": "TCP"},
                    ],
                    "volumeMounts": [{"name": "data", "mountPath": "/cockroach/cockroach-data"}],
                    "livenessProbe": {
                        "httpGet": {"path": "/health", "port": "http", "scheme": "HTTP"},
                        "periodSeconds": 10,
                    },
                    "readinessProbe": {
                        "httpGet": {"path": "/health?ready=1", "port": 8080, "scheme": "HTTP"},
                        "initialDelaySeconds": 7,
                    },
                    "startupProbe": {"tcpSocket": {"port": "grpc"}, "failureThreshold": 20},
                }
            ],
            "initContainers": [],
            "volumes": [{"name": "data", "persistentVolumeClaim": {"claimName": "db-data-db-0"}}],
        },
    }


def test_secure_template_removes_insecure_flags_and_secures_only_crdb_http_probes():
    original = workload_template()
    preserved = copy.deepcopy(original)

    updated = secure_template(original, secret_name="db-certs", cert_dir=CERT_DIR)

    assert original == preserved
    container = updated["spec"]["containers"][0]
    tokens = container["command"][2].split()
    assert "--insecure" not in tokens
    assert "--accept-sql-without-tls" not in tokens
    assert "--unencrypted-localhost-http" not in tokens
    assert "--certs-dir=/old/certs" not in tokens
    assert tokens[-1] == f"--certs-dir={CERT_DIR}"
    assert "--cache=25%" in tokens
    assert container["livenessProbe"]["httpGet"]["scheme"] == "HTTPS"
    assert container["readinessProbe"]["httpGet"]["scheme"] == "HTTPS"
    assert container["startupProbe"] == {"tcpSocket": {"port": "grpc"}, "failureThreshold": 20}
    assert container["volumeMounts"][-1] == {
        "name": "cockroach-certs",
        "mountPath": "/cockroach/cockroach-certs",
        "readOnly": True,
    }
    assert updated["spec"]["volumes"][-1] == {
        "name": "cockroach-certs",
        "secret": {
            "secretName": "db-certs",
            "defaultMode": 256,
            "items": [
                {"key": name, "path": name}
                for name in ("ca.crt", "node.crt", "node.key", "client.root.crt", "client.root.key")
            ],
            "optional": False,
        },
    }
    assert updated["spec"]["serviceAccountName"] == "db-sa"
    assert updated["metadata"] == original["metadata"]


@pytest.mark.parametrize("flag", ["--insecure", "--accept-sql-without-tls", "--unencrypted-localhost-http"])
def test_secure_template_removes_inline_boolean_forms(flag):
    original = workload_template(startup=[
        "/cockroach/cockroach", "start", f"{flag}=true", "--http-addr=0.0.0.0:8080",
    ])

    updated = secure_template(original, secret_name="db-certs", cert_dir=CERT_DIR)

    assert flag not in " ".join(updated["spec"]["containers"][0]["command"] + updated["spec"]["containers"][0]["args"])


def test_secure_template_rewrites_existing_dedicated_secret_mount_in_place():
    template = workload_template()
    container = template["spec"]["containers"][0]
    container["volumeMounts"].append({
        "name": "old-certs",
        "mountPath": "/cockroach/cockroach-certs",
        "readOnly": True,
        "subPath": "",
        "subPathExpr": "",
    })
    template["spec"]["volumes"].append({
        "name": "old-certs",
        "secret": {
            "secretName": "previous-certs",
            "defaultMode": 288,
            "items": [{"key": "old-root.crt", "path": "ca.crt"}],
        },
    })

    updated = secure_template(template, secret_name="db-certs", cert_dir=CERT_DIR)

    assert updated["spec"]["volumes"][-1] == {
        "name": "old-certs",
        "secret": {
            "secretName": "db-certs",
            "defaultMode": 288,
            "items": [
                {"key": name, "path": name}
                for name in ("ca.crt", "node.crt", "node.key", "client.root.crt", "client.root.key")
            ],
            "optional": False,
        },
    }
    assert len(updated["spec"]["volumes"]) == 2
    assert updated["spec"]["containers"][0]["volumeMounts"][1]["readOnly"] is True


def test_secure_template_rejects_dynamic_subpath_on_certificate_mount():
    template = workload_template()
    container = template["spec"]["containers"][0]
    container["volumeMounts"].append({
        "name": "old-certs",
        "mountPath": CERT_DIR,
        "subPathExpr": "$(POD_NAME)",
    })
    template["spec"]["volumes"].append({"name": "old-certs", "secret": {"secretName": "old"}})

    with pytest.raises(UnsupportedLayoutError, match="unsupported subPath"):
        secure_template(template, secret_name="db-certs", cert_dir=CERT_DIR)


def test_secure_template_preserves_unrelated_http_probe_and_exec_probe():
    template = workload_template()
    container = template["spec"]["containers"][0]
    container["startupProbe"] = {"httpGet": {"path": "/metrics", "port": 9090, "scheme": "HTTP"}}
    container["readinessProbe"] = {"exec": {"command": ["/bin/sh", "-c", "test -f /tmp/ready"]}}

    updated = secure_template(template, secret_name="db-certs", cert_dir=CERT_DIR)

    assert updated["spec"]["containers"][0]["startupProbe"] == container["startupProbe"]
    assert updated["spec"]["containers"][0]["readinessProbe"] == container["readinessProbe"]


@pytest.mark.parametrize(
    "command",
    [
        ["/bin/sh", "-c", "exec /cockroach/cockroach sql --insecure -e 'SELECT 1'"] ,
        ["/bin/sh", "-ec", "exec /cockroach/cockroach sql --certs-dir=/old/certs -e 'SELECT 1'"] ,
    ],
)
def test_secure_template_rejects_cockroach_sql_exec_probe(command):
    template = workload_template()
    template["spec"]["containers"][0]["readinessProbe"] = {"exec": {"command": command}}

    with pytest.raises(UnsupportedLayoutError, match="exec probe requires explicit TLS conversion"):
        secure_template(template, secret_name="db-certs", cert_dir=CERT_DIR)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda c, p: c["command"].__setitem__(2, "exec /cockroach/cockroach start --insecure /unexpected"),
        lambda c, p: c["command"].__setitem__(2, "exec /cockroach/cockroach start; echo unsafe"),
        lambda c, p: c["volumeMounts"].append({"name": "other", "mountPath": "/cockroach/cockroach-certs"}),
        lambda c, p: c["ports"].append({"name": "http", "containerPort": 8081, "protocol": "TCP"}),
    ],
)
def test_secure_template_fails_closed_on_ambiguous_or_unsafe_layout(mutate):
    template = workload_template()
    container = template["spec"]["containers"][0]
    mutate(container, template)

    with pytest.raises(UnsupportedLayoutError):
        secure_template(template, secret_name="db-certs", cert_dir=CERT_DIR)


def test_secure_template_preserves_command_args_partition_and_unrelated_arguments():
    template = workload_template(startup=[
        "/cockroach/cockroach",
        "start",
        "--cache=25%",
        "--insecure",
        "--port=26257",
    ])
    template["spec"]["containers"][0]["command"] = ["/cockroach/cockroach", "start"]
    template["spec"]["containers"][0]["args"] = ["--cache=25%", "--insecure", "--port=26257"]

    updated = secure_template(template, secret_name="db-certs", cert_dir=CERT_DIR)

    assert updated["spec"]["containers"][0]["command"] == ["/cockroach/cockroach", "start"]
    assert updated["spec"]["containers"][0]["args"] == [
        "--cache=25%", "--port=26257", f"--certs-dir={CERT_DIR}"
    ]


def test_secure_template_adds_mounts_when_list_fields_are_absent():
    template = workload_template()
    container = template["spec"]["containers"][0]
    del container["volumeMounts"]
    del template["spec"]["volumes"]

    updated = secure_template(template, secret_name="db-certs", cert_dir=CERT_DIR)

    assert updated["spec"]["containers"][0]["volumeMounts"] == [
        {"name": "cockroach-certs", "mountPath": CERT_DIR, "readOnly": True}
    ]
    assert updated["spec"]["volumes"][0]["name"] == "cockroach-certs"


def test_secure_template_allows_certificate_mount_nested_below_parent_data_mount():
    template = workload_template()
    template["spec"]["containers"][0]["volumeMounts"] = [
        {"name": "data", "mountPath": "/cockroach"}
    ]

    updated = secure_template(template, secret_name="db-certs", cert_dir=CERT_DIR)

    assert updated["spec"]["containers"][0]["volumeMounts"] == [
        {"name": "data", "mountPath": "/cockroach"},
        {"name": "cockroach-certs", "mountPath": CERT_DIR, "readOnly": True},
    ]


def test_secure_template_uses_an_available_volume_name_for_new_secret_mount():
    template = workload_template()
    template["spec"]["volumes"].append({"name": "cockroach-certs", "emptyDir": {}})

    updated = secure_template(template, secret_name="db-certs", cert_dir=CERT_DIR)

    assert updated["spec"]["containers"][0]["volumeMounts"][-1]["name"] == "cockroach-certs-1"
    assert updated["spec"]["volumes"][-1]["name"] == "cockroach-certs-1"


def insecure_workload_template(*, startup=None, cert_dir="/old/certs"):
    template = workload_template(startup=startup)
    container = template["spec"]["containers"][0]
    if startup is None:
        container["command"][2] = container["command"][2].replace(
            "--certs-dir=/old/certs", f"--certs-dir={cert_dir}"
        )
    mount_name = "old-certs"
    container["volumeMounts"].append({"name": mount_name, "mountPath": cert_dir, "readOnly": True})
    template["spec"]["volumes"].append({
        "name": mount_name,
        "secret": {"secretName": "old-certs", "defaultMode": 256},
    })
    container["livenessProbe"] = {
        "httpGet": {"path": "/health", "port": "http", "scheme": "HTTPS"},
        "periodSeconds": 10,
    }
    return template


def test_insecure_template_preserves_non_certificate_mounts_and_input():
    original = insecure_workload_template(
        startup=["/cockroach/cockroach", "start-single-node", "--port=26257", "--insecure=false"]
    )
    before = copy.deepcopy(original)

    updated = insecure_template(original, {"old-certs"})

    assert original == before
    container = updated["spec"]["containers"][0]
    assert container["command"] == ["/cockroach/cockroach"]
    assert container["args"] == ["start-single-node", "--port=26257", "--insecure"]
    assert container["livenessProbe"]["httpGet"]["scheme"] == "HTTP"
    assert container["readinessProbe"]["httpGet"]["scheme"] == "HTTP"
    assert container["startupProbe"] == {
        "tcpSocket": {"port": "grpc"}, "failureThreshold": 20
    }
    assert container["volumeMounts"] == [{"name": "data", "mountPath": "/cockroach/cockroach-data"}]
    assert updated["spec"]["volumes"] == [
        {"name": "data", "persistentVolumeClaim": {"claimName": "db-data-db-0"}}
    ]


@pytest.mark.parametrize(
    ("startup", "cert_dir"),
    [
        (["/cockroach/cockroach", "start", "--port=26257", "--insecure=true", "--certs-dir=/old/certs"], "/old/certs"),
        (["/cockroach/cockroach", "start", "--port=26257", "--insecure", "--certs-dir", CERT_DIR], CERT_DIR),
    ],
)
def test_insecure_template_removes_direct_secret_and_uses_original_cert_dir(startup, cert_dir):
    template = insecure_workload_template(startup=startup, cert_dir=cert_dir)
    template["spec"]["volumes"].append({"name": "unrelated", "emptyDir": {}})
    template["spec"]["containers"][0]["volumeMounts"].append(
        {"name": "unrelated", "mountPath": "/tmp/keep"}
    )

    updated = insecure_template(template, {"old-certs"})
    container = updated["spec"]["containers"][0]
    tokens = container["command"] + container["args"]

    assert "--certs-dir" not in tokens
    assert not any(token.startswith("--certs-dir=") for token in tokens)
    assert tokens[-1] == "--insecure"
    assert {volume["name"] for volume in updated["spec"]["volumes"]} == {"data", "unrelated"}
    assert {mount["name"] for mount in container["volumeMounts"]} == {"data", "unrelated"}


def test_insecure_template_preserves_simple_shell_quoting_and_command_args_partition():
    template = insecure_workload_template()
    container = template["spec"]["containers"][0]
    container["command"] = [
        "/bin/sh",
        "-ec",
        "exec /cockroach/cockroach start --certs-dir=/old/certs --cache='25%' --accept-sql-without-tls",
    ]
    container["args"] = ["--join=db-0.$(POD_NAMESPACE).svc:26258"]

    updated = insecure_template(template, {"old-certs"})
    result = updated["spec"]["containers"][0]

    assert result["command"] == [
        "/bin/sh", "-ec", "exec /cockroach/cockroach start  --cache='25%' --insecure"
    ]
    assert result["args"] == ["--join=db-0.$(POD_NAMESPACE).svc:26258"]


def test_insecure_template_preserves_projected_unselected_secrets():
    template = insecure_workload_template()
    template["spec"]["volumes"][-1] = {
        "name": "old-certs",
        "projected": {"sources": [{"secret": {"name": "old-certs"}}, {"secret": {"name": "other"}}]},
    }

    with pytest.raises(UnsupportedLayoutError, match="^certificate volume includes unrelated sources or non-Secret storage$"):
        insecure_template(template, {"old-certs"})


def test_insecure_template_removes_selected_projected_secret_volume():
    template = insecure_workload_template()
    template["spec"]["volumes"][-1] = {
        "name": "old-certs",
        "projected": {"sources": [{"secret": {"name": "old-certs"}}]},
    }

    updated = insecure_template(template, {"old-certs"})

    assert all(volume["name"] != "old-certs" for volume in updated["spec"]["volumes"])


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda template: template["spec"]["containers"].append(
                {"name": "other", "image": "cockroachdb/cockroach:v24.1.0", "command": ["start"]}
            ),
            "cannot identify exactly one CockroachDB server container",
        ),
        (
            lambda template: template["spec"]["containers"][0].update(
                {"readinessProbe": {"exec": {"command": ["./cockroach", "sql", "--certs-dir=/x"]}}}
            ),
            "certificate-based exec health probe requires explicit mode conversion",
        ),
        (
            lambda template: template["spec"]["containers"].append(
                {"name": "sidecar", "image": "busybox", "volumeMounts": [{"name": "old-certs", "mountPath": "/tmp/certs"}]}
            ),
            "another container uses the database certificate volume",
        ),
    ],
)
def test_insecure_template_rejects_unsafe_layout(mutate, message):
    template = insecure_workload_template()
    mutate(template)

    with pytest.raises(UnsupportedLayoutError, match=f"^{message}$"):
        insecure_template(template, {"old-certs"})


def test_secure_template_rejects_unmodeled_http_port_alias_before_rewrite():
    template = workload_template(startup=[
        "/cockroach/cockroach", "start", "--http-port=8081", "--insecure"
    ])

    with pytest.raises(UnsupportedLayoutError, match="unsupported --http-port"):
        secure_template(template, secret_name="db-certs", cert_dir=CERT_DIR)


def test_mounted_secret_signatures_detect_changes_to_mounted_data():
    template = {
        "spec": {
            "volumes": [
                {"name": "z-direct", "secret": {"secretName": "zeta"}},
                {
                    "name": "projected",
                    "projected": {
                        "sources": [
                            {"secret": {"name": "beta"}},
                            {"configMap": {"name": "unrelated"}},
                            {"secret": {"name": "zeta"}},
                        ]
                    },
                },
                {"name": "a-direct", "secret": {"secretName": "alpha"}},
            ]
        }
    }
    original = copy.deepcopy(template)
    data = {
        "alpha": {"b": "two", "a": "one"},
        "beta": {"value": "three"},
        "zeta": {},
    }
    calls = []

    def get_secret(name):
        calls.append(name)
        return {"metadata": {"uid": f"uid-{name}"}, "data": data[name]}

    result = mounted_secret_signatures(template, get_secret, error_type=SecretLookupError)

    assert calls == ["alpha", "beta", "zeta"]
    assert {name: signature["uid"] for name, signature in result.items()} == {
        "alpha": "uid-alpha", "beta": "uid-beta", "zeta": "uid-zeta",
    }
    data["alpha"] = {"a": "one", "b": "two"}
    assert mounted_secret_signatures(template, get_secret, error_type=SecretLookupError) == result

    data["alpha"]["a"] = "rotated"
    rotated = mounted_secret_signatures(template, get_secret, error_type=SecretLookupError)
    assert rotated["alpha"]["sha256"] != result["alpha"]["sha256"]
    assert rotated["beta"] == result["beta"] and rotated["zeta"] == result["zeta"]
    assert template == original


def test_mounted_secret_signatures_preserve_missing_and_getter_errors():
    template = {
        "spec": {
            "volumes": [
                {"secret": {"secretName": "alpha"}},
                {"projected": {"sources": [{"secret": {"name": "beta"}}]}},
            ]
        }
    }
    calls = []

    def missing_beta(name):
        calls.append(name)
        if name == "beta":
            return None
        return {"metadata": {"uid": "uid-alpha"}}

    with pytest.raises(SecretLookupError, match="^mounted Secret is missing$"):
        mounted_secret_signatures(template, missing_beta, error_type=SecretLookupError)
    assert calls == ["alpha", "beta"]

    failure = LookupError("getter failure")

    def failing_getter(_name):
        raise failure

    with pytest.raises(LookupError) as caught:
        mounted_secret_signatures(template, failing_getter, error_type=SecretLookupError)
    assert caught.value is failure

    with pytest.raises(KeyError):
        mounted_secret_signatures(
            template,
            lambda _name: {"data": {"value": "missing metadata"}},
            error_type=SecretLookupError,
        )


def test_mounted_secret_signatures_empty_template_does_not_call_getter():
    calls = []
    template = {"spec": {"volumes": []}}

    assert mounted_secret_signatures(
        template,
        lambda name: calls.append(name),
        error_type=SecretLookupError,
    ) == {}
    assert calls == []

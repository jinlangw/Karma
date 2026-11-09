from __future__ import annotations

import json

import pytest

from cases.common.cockroachdb.health import observe_initialization_state


class UnsupportedHealthLayout(ValueError):
    pass


def ready_pod(*, scheme="HTTP", port="http", running=True, sql_tls=False):
    state = {"running": {}} if running else {"waiting": {"reason": "CrashLoopBackOff"}}
    startup = ["/cockroach/cockroach", "start"]
    startup.append("--certs-dir=/cockroach/certs" if sql_tls else "--insecure")
    return {
        "metadata": {"name": "db-0"},
        "spec": {
            "containers": [
                {
                    "name": "db",
                    "image": "cockroachdb/cockroach:v24.1.0",
                    "command": startup,
                    "ports": [{"name": "http", "containerPort": 8080}],
                    "readinessProbe": {
                        "httpGet": {
                            "path": "/health?ready=1",
                            "port": port,
                            "scheme": scheme,
                        }
                    },
                }
            ]
        },
        "status": {
            "phase": "Running",
            "containerStatuses": [{"name": "db", "state": state}],
        },
    }


@pytest.mark.parametrize(
    "scheme,port,sql_tls,expected",
    [
        ("HTTP", "http", True, "http://localhost:8080/health?ready=1"),
        ("HTTPS", 8080, False, "https://localhost:8080/health?ready=1"),
    ],
)
def test_observation_uses_http_transport_independently_of_sql_tls(scheme, port, sql_tls, expected):
    def curl(pod_name, container_name, argv, _timeout):
        assert (pod_name, container_name) == ("db-0", "db")
        assert argv[-1] == expected
        return '{"ok":true}\n200'

    state = observe_initialization_state(
        ready_pod(scheme=scheme, port=port, sql_tls=sql_tls),
        execute_curl=curl,
        error_type=UnsupportedHealthLayout,
    )

    assert state == "initialized"


@pytest.mark.parametrize(
    "output,expected",
    [
        ('{"error":"node is waiting for cluster initialization"}\n503', "uninitialized"),
        ('{"error":"other"}\n503', None),
        ('{"error":"node is waiting for cluster initialization"}\n500', None),
    ],
)
def test_only_the_initialization_sentinel_reports_uninitialized(output, expected):
    def observe():
        return observe_initialization_state(
            ready_pod(), execute_curl=lambda *_: output, error_type=UnsupportedHealthLayout,
        )

    if expected is None:
        with pytest.raises(RuntimeError, match="health failed"):
            observe()
    else:
        assert observe() == expected


def test_observation_refuses_nonrunning_container_and_invalid_endpoint():
    def curl(*_):
        pytest.fail("unsupported state must not exec curl")

    with pytest.raises(RuntimeError, match="database process is not Running"):
        observe_initialization_state(
            ready_pod(running=False), execute_curl=curl, error_type=UnsupportedHealthLayout,
        )

    invalid = ready_pod()
    invalid["spec"]["containers"][0]["readinessProbe"]["httpGet"]["host"] = "db.internal"
    with pytest.raises(UnsupportedHealthLayout):
        observe_initialization_state(
            invalid, execute_curl=curl, error_type=UnsupportedHealthLayout,
        )


def test_observation_propagates_malformed_json_and_exec_failures():
    with pytest.raises(json.JSONDecodeError):
        observe_initialization_state(
            ready_pod(), execute_curl=lambda *_: "not-json\n200", error_type=UnsupportedHealthLayout,
        )

    def exec_failure(*_):
        raise RuntimeError("kubectl exec failed")

    with pytest.raises(RuntimeError, match="kubectl exec failed"):
        observe_initialization_state(
            ready_pod(), execute_curl=exec_failure, error_type=UnsupportedHealthLayout,
        )

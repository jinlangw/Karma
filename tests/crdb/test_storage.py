from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
import sys

import pytest

from cases.common.cockroachdb.storage import pvc_store_mappings


class CaseError(RuntimeError):
    pass


ROOT = Path(__file__).resolve().parents[2]


def _load_case_cluster(case, monkeypatch):
    path = ROOT / "cases/tests/cockroachdb" / case / "scripts/cluster.py"
    module_name = f"pvc_store_wrapper_{case.replace('-', '_')}"
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, module_name, module)
    spec.loader.exec_module(module)
    return module


def _statefulset(*, command=None, mounts=None, claims=None, containers=None, working_dir="/cockroach"):
    database = {
        "name": "db",
        "image": "cockroachdb/cockroach:v24.1.0",
        "command": command or ["/cockroach/cockroach", "start"],
        "volumeMounts": copy.deepcopy(mounts or [{"name": "data", "mountPath": "/cockroach"}]),
    }
    if working_dir is not None:
        database["workingDir"] = working_dir
    return {
        "spec": {
            "replicas": 2,
            "template": {
                "spec": {
                    "containers": copy.deepcopy(containers or [database]),
                    "initContainers": [],
                }
            },
            "volumeClaimTemplates": copy.deepcopy(
                claims or [{"metadata": {"name": "data"}}]
            ),
        }
    }


def test_store_mappings_parse_flags_use_longest_mount_and_keep_store_order():
    sts = _statefulset(
        command=[
            "/cockroach/cockroach",
            "start",
            "--store=path=/cockroach/data/first,type=ssd",
            "--store",
            "path=/cockroach/data/second,type=ssd",
        ],
        mounts=[
            {"name": "root", "mountPath": "/cockroach"},
            {"name": "data", "mountPath": "/cockroach/data"},
        ],
        claims=[{"metadata": {"name": "root"}}, {"metadata": {"name": "data"}}],
    )

    assert pvc_store_mappings(sts, error_type=CaseError) == [
        {"volume": "data", "relative": "first"},
        {"volume": "data", "relative": "second"},
    ]


def test_store_mappings_accept_short_flag_forms_without_mutating_statefulset():
    sts = _statefulset(
        command=[
            "/cockroach/cockroach",
            "start",
            "--store=path=/cockroach/long,type=ssd",
            "-s=path=/cockroach/equals,type=ssd",
            "-spath=/cockroach/compact,type=ssd",
            "-s",
            "path=/cockroach/split,type=ssd",
        ]
    )
    original = copy.deepcopy(sts)

    assert pvc_store_mappings(sts, error_type=CaseError) == [
        {"volume": "data", "relative": "long"},
        {"volume": "data", "relative": "equals"},
        {"volume": "data", "relative": "compact"},
        {"volume": "data", "relative": "split"},
    ]
    assert sts == original


def test_store_mappings_keep_default_path_from_working_directory():
    sts = _statefulset(working_dir="/cockroach/db")

    assert pvc_store_mappings(sts, error_type=CaseError) == [
        {"volume": "data", "relative": "db/cockroach-data"},
    ]


def test_store_mappings_keep_default_path_when_working_directory_is_absent():
    sts = _statefulset(working_dir=None)

    assert pvc_store_mappings(sts, error_type=CaseError) == [
        {"volume": "data", "relative": "cockroach-data"},
    ]


@pytest.mark.parametrize(
    "case",
    [
        "rollback-rehearsal",
        "zone-config",
        "monitoring-integration",
        "version-check",
        "initialize",
        "major-upgrade-finalize",
    ],
)
def test_case_store_wrappers_keep_pvc_lookup_and_identity_local(case, monkeypatch):
    module = _load_case_cluster(case, monkeypatch)
    cluster = module.Cluster.__new__(module.Cluster)
    cluster.name = "db"
    pvc = {
        "metadata": {"name": "data-db-0", "uid": "pvc-uid"},
        "status": {"phase": "Bound"},
    }
    lookups = []
    identities = []
    cluster.get = lambda kind, name: lookups.append((kind, name)) or pvc
    cluster.identity = lambda observed: identities.append(observed)

    result = cluster.stores(_statefulset(), count=1)

    assert lookups == [("pvc", "data-db-0")]
    assert identities == [pvc]
    assert result == [
        {
            "volume": "data",
            "relative": "cockroach-data",
            "claim": "data-db-0",
            "uid": "pvc-uid",
        }
    ]


@pytest.mark.parametrize(
    ("store_args", "mounts", "claims", "containers", "expected"),
    [
        (
            ["--store=type=mem"],
            [{"name": "data", "mountPath": "/cockroach"}],
            [{"metadata": {"name": "data"}}],
            None,
            "reset requires absolute normalized PVC-backed store paths",
        ),
        (
            ["--store=path=/cockroach/../other"],
            [{"name": "data", "mountPath": "/cockroach"}],
            [{"metadata": {"name": "data"}}],
            None,
            "reset requires absolute normalized PVC-backed store paths",
        ),
        (
            ["--store=path=/cockroach/data"],
            [{"name": "scratch", "mountPath": "/cockroach"}],
            [{"metadata": {"name": "data"}}],
            None,
            "reset only supports exclusive volumeClaimTemplate stores without subPath",
        ),
        (
            ["--store=path=/cockroach/data"],
            [{"name": "data", "mountPath": "/cockroach", "subPath": "db"}],
            [{"metadata": {"name": "data"}}],
            None,
            "reset only supports exclusive volumeClaimTemplate stores without subPath",
        ),
        (
            ["--store=path=/cockroach/data"],
            [{"name": "data", "mountPath": "/cockroach"}],
            [{"metadata": {"name": "data"}}],
            [
                {
                    "name": "db",
                    "image": "cockroachdb/cockroach:v24.1.0",
                    "command": ["/cockroach/cockroach", "start", "--store=path=/cockroach/data"],
                    "volumeMounts": [{"name": "data", "mountPath": "/cockroach"}],
                },
                {"name": "metrics", "image": "prometheus/exporter:v1", "volumeMounts": [{"name": "data", "mountPath": "/data"}]},
            ],
            "database store is shared with another container",
        ),
        (
            ["--store=path=/cockroach", "--store=path=/cockroach/child"],
            [{"name": "data", "mountPath": "/cockroach"}],
            [{"metadata": {"name": "data"}}],
            None,
            "overlapping database stores are unsupported",
        ),
    ],
)
def test_store_mapping_rejections_keep_case_error_type_and_message(
    store_args, mounts, claims, containers, expected
):
    database = {
        "name": "db",
        "image": "cockroachdb/cockroach:v24.1.0",
        "command": ["/cockroach/cockroach", "start", *store_args],
        "volumeMounts": copy.deepcopy(mounts),
    }
    if containers is None:
        containers = [database]
    else:
        containers = copy.deepcopy(containers)
    sts = _statefulset(mounts=mounts, claims=claims, containers=containers)

    with pytest.raises(CaseError, match=f"^{expected}$"):
        pvc_store_mappings(sts, error_type=CaseError)

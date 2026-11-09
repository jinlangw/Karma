from __future__ import annotations

import copy

import pytest

from cases.common.cockroachdb.storage import pvc_store_mappings


class CaseError(RuntimeError):
    pass


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

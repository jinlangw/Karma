"""Explicit historical release paths; binary and logical state are separate."""
import os
import re

from cases.common.cockroachdb.startup import official_image_version
from cluster import UnsafeState, database_container

# These production-release edges are documented in the versioned upgrade guides.
# Every chosen binary is pinned; no floating tags or skipped major releases.
RELEASES = ('22.2', '23.1', '23.2', '24.1', '24.2')
PINNED = {release: release + '.0' for release in RELEASES}


def series(version):
    match = re.fullmatch(r'v?(\d+)\.(\d+)(?:\.(\d+))?', version)
    if not match:
        raise RuntimeError('logical version is transitional or binary version is unrecognized: ' + version)
    return tuple(map(int, match.group(1, 2)))


def release(version):
    return '.'.join(map(str, series(version)))


def source_version(source):
    return source if source.count('.') == 2 else PINNED[release(source)]


def patch_upgrade(source, target):
    return series(source) == series(target)


def parameters():
    source = os.environ.get('BENCH_PARAM_FROM_VERSION', '23.2')
    target = os.environ.get('BENCH_PARAM_TO_VERSION', '24.1.0')
    if not re.fullmatch(r'\d+\.\d+(?:\.\d+)?', source) or not re.fullmatch(r'\d+\.\d+\.\d+', target) or release(source) not in RELEASES:
        raise UnsafeState('case requires a documented production source and target release')
    if patch_upgrade(source, target):
        if tuple(map(int, target.split('.'))) < tuple(map(int, source_version(source).split('.'))):
            raise UnsafeState('upgrade target must not precede the configured source patch')
    elif release(source) == RELEASES[-1] or series(target) != series(RELEASES[RELEASES.index(release(source)) + 1]):
        raise UnsafeState('source and target must share a release or be consecutive supported major releases')
    return source, target


def image(version):
    return 'cockroachdb/cockroach:v' + version


def image_version(value):
    version = official_image_version(value)
    if version is None:
        raise UnsafeState('version preparation requires a tagged official CockroachDB production image')
    return version


def state(cluster):
    cluster.ready()
    sts = cluster.statefulset()
    binaries, logical = [], []
    for ordinal, pod in enumerate(cluster.pods(sts)):
        db = database_container({'spec': pod['spec']})
        tag = cluster.require(cluster.kubectl('exec', pod['metadata']['name'], '-c', db['name'], '--', './cockroach', 'version', '--build-tag')).strip()
        version = tag.removeprefix('v')
        if not re.fullmatch(r'\d+\.\d+\.\d+', version) or image_version(db['image']) != version:
            raise UnsafeState('actual executable and selected pod image do not agree')
        server = cluster.value('SELECT version();', ordinal)
        if not re.search(r'\bv' + re.escape(version) + r'(?:\s|$)', server):
            raise UnsafeState('actual running server differs from its selected binary')
        binaries.append(version)
        value = cluster.setting('version', ordinal)
        series(value)  # Never compare transitional versions as stable releases.
        logical.append(value)
    if len(set(logical)) != 1:
        raise RuntimeError('selected nodes disagree on their logical version')
    return {'binaries': binaries, 'logical': logical[0], 'cluster_id': cluster.cluster_id()}


def source_ready(cluster):
    source, target = parameters()
    current = state(cluster)
    desired = image_version(database_container(cluster.statefulset()['spec']['template'])['image'])
    exact = source.count('.') == 2 or patch_upgrade(source, target)
    return (current['logical'] == release(source) and len(set(current['binaries'])) == 1
            and all(series(v) == series(source) for v in current['binaries'])
            and current['binaries'][0] == desired
            and (not exact or desired == source_version(source)))

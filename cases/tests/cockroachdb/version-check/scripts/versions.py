"""Pinned production releases, checked against official docs/registry on 2026-10-15.

CURRENT_SUPPORTED is vendor support; RELEASES also contains historical workflow
compatibility releases. See docs/research/cockroachdb-version-check-supported-releases-20261015.md.
Only a single documented binary edge is used; this task never finalizes an upgrade.
"""
import os
import re

from cases.common.cockroachdb.startup import official_image_version
from cluster import UnsafeState, database_container

PINNED = dict(zip(
    ('22.2','23.1','23.2','24.1','24.2','24.3','25.1','25.2','25.3','25.4','26.1','26.2','26.3'),
    ('22.2.19','23.1.30','23.2.31','24.1.33','24.2.10','24.3.36','25.1.10','25.2.24','25.3.7','25.4.17','26.1.8','26.2.7','26.3.2')))
RELEASES = tuple(PINNED)
CURRENT_SUPPORTED = ('24.1','24.3','25.2','25.4','26.2','26.3')
EDGES = {family:(RELEASES[index+1],) for index,family in enumerate(RELEASES[:-1])}
for source,target in [('24.1','24.3'),('24.3','25.2'),('25.2','25.4'),('25.4','26.2')]:
    EDGES[source] += (target,)


def series(version):
    match = re.fullmatch(r'[vV]?(\d+)\.(\d+)(?:\.(\d+))?', version)
    if not match:
        raise RuntimeError('version is transitional or not a production release: ' + version)
    return tuple(map(int, match.group(1, 2)))


def release(version):
    return '.'.join(map(str, series(version)))


def exact(version):
    value = version.lstrip('vV')
    if release(value) not in RELEASES:
        raise UnsafeState('version is outside the documented compatibility releases: ' + value)
    return value if value.count('.') == 2 else PINNED[release(value)]


def image(version):
    return 'cockroachdb/cockroach:v' + exact(version)


def image_version(value):
    version = official_image_version(value)
    if version is None:
        raise UnsafeState('version preparation requires a tagged official production image')
    return version


def next_binary(logical):
    family = release(logical)
    options = EDGES.get(family,())
    if not options:return None
    # Use the smallest documented step. Older workflow preparers understand
    # adjacent rolling windows; a valid Regular-release skip can exceed them.
    return PINNED[options[0]]


def fallback_pair():
    source = exact(os.environ.get('BENCH_PARAM_FROM_VERSION', '23.2'))
    target = exact(os.environ.get('BENCH_PARAM_TO_VERSION', '24.1.0'))
    # Historical version-check stages used patch pairs as image assertions.
    # Keep their source/target as bootstrap hints; never weaken the gap to a patch.
    if series(source) == series(target):
        target = next_binary(source)
        if target is None:
            raise UnsafeState('fallback needs an older source with an available newer release')
    if series(target) <= series(source):
        raise UnsafeState('fallback target must be a newer release family')
    if release(target) not in EDGES.get(release(source),()):
        raise UnsafeState('fallback pair must follow a documented compatible release edge')
    return source, target


def choose_plan(current):
    logical = current['logical']
    families = {series(v) for v in current['binaries']}
    successor = next_binary(logical)
    allowed = {series(logical)} | {series(v) for v in EDGES.get(release(logical),())}
    if successor and families <= allowed:
        newer = [v for v in current['binaries'] if series(v) > series(logical)]
        # Preserve the inherited newer patch during partial rollouts. A template
        # pointing to the old family will be advanced to the same actual binary.
        binary = max(newer, key=lambda v: tuple(map(int,v.split('.')))) if newer else successor
        return {'reset':False, 'logical':logical, 'binary':binary, 'reason':'documented binary upgrade, preserving inherited gaps or choosing the next family'}
    source, target = fallback_pair()
    return {'reset':True, 'logical':release(source), 'source':source, 'binary':target,
            'reason':'no documented in-place binary edge; selected fresh stores required'}


def state(cluster):
    cluster.ready()
    sts = cluster.statefulset()
    binaries, logical = [], []
    for ordinal, pod in enumerate(cluster.pods(sts)):
        db = database_container({'spec':pod['spec']})
        tag = cluster.require(cluster.kubectl('exec', pod['metadata']['name'], '-c', db['name'], '--', cluster.executable(db), 'version', '--build-tag')).strip().removeprefix('v')
        if not re.fullmatch(r'\d+\.\d+\.\d+',tag) or image_version(db['image']) != tag:
            raise UnsafeState('actual executable and selected image do not agree')
        server = cluster.value('SELECT version();', ordinal)
        if not re.search(r'\bv' + re.escape(tag) + r'(?:\s|$)', server):
            raise UnsafeState('actual running server differs from selected executable')
        binaries.append(tag)
        value = cluster.setting('version',ordinal)
        series(value)
        logical.append(value)
    if len(set(logical)) != 1:
        raise RuntimeError('selected nodes disagree on their feature version')
    return {'binaries':binaries, 'logical':logical[0], 'cluster_id':cluster.cluster_id()}

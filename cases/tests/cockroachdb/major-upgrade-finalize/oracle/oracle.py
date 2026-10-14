#!/usr/bin/env python3
"""Every selected node must run the target release with finalization complete."""
import json
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from cluster import Cluster, UnsafeState, database_container
from prepare import Preparation
from versions import image_version, series, state


def evaluate():
    c = Cluster()
    p = Preparation(c)
    baseline = p.load()
    if baseline is None or baseline['data']['phase'] != 'held' or not p.same_task(baseline):
        raise RuntimeError('verified source-version and upgrade-hold baseline is missing')
    sts = c.statefulset()
    p.preserved(baseline, sts)
    if c.get('namespace', c.namespace, namespace='')['metadata']['uid'] != baseline['data']['namespace_uid']:
        raise UnsafeState('selected namespace identity changed')
    if sts['spec'].get('updateStrategy', {'type': 'RollingUpdate'}) != json.loads(baseline['data']['original_strategy']):
        raise RuntimeError('original update strategy has not been restored')
    desired = database_container(sts['spec']['template'])
    if series(image_version(desired['image'])) != series(p.target):
        raise RuntimeError('StatefulSet desired image is not on the target release')
    for pod in c.pods(sts):
        actual = database_container({'spec': pod['spec']})
        if any(actual.get(k, []) != desired.get(k, []) for k in ('command', 'args')) or c.connection_flags(actual) != json.loads(baseline['data']['connection_flags']):
            raise UnsafeState('an actual selected node changed its startup or security mode')
        ordinal = pod['metadata']['name'].rsplit('-', 1)[1]
        volumes = {v['name']: v.get('persistentVolumeClaim', {}).get('claimName') for v in pod['spec'].get('volumes', [])}
        if any(volumes.get(v['metadata']['name']) != f'{v["metadata"]["name"]}-{c.name}-{ordinal}' for v in sts['spec'].get('volumeClaimTemplates', [])):
            raise UnsafeState('an actual selected node changed its selected claim mounts')
    current = state(c)
    if any(series(version) != series(p.target) for version in current['binaries']):
        raise RuntimeError('not every actual selected node runs the target release')
    target_series = '.'.join(map(str, series(p.target)))
    if current['logical'] != target_series:
        raise RuntimeError('major version upgrade has not finalized to ' + target_series)
    if current['cluster_id'] != baseline['data']['normalized_uuid']:
        raise UnsafeState('prepared database identity changed during the solver task')
    if c.setting('cluster.preserve_downgrade_option'):
        raise RuntimeError('preserve_downgrade_option has not been cleared')
    return True


if __name__ == '__main__':
    try:
        Cluster().wait(evaluate, 150)
        print('Major upgrade finalized on every selected node; identity, storage and security preserved.', flush=True)
    except (RuntimeError, ValueError, KeyError, OSError, subprocess.TimeoutExpired) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)

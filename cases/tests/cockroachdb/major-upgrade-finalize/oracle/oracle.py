#!/usr/bin/env python3
"""Every selected node must run the target release with finalization complete."""
import json
import os
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from cluster import Cluster, UnsafeState, database_container
from prepare import Preparation
from versions import image_version, parameters, patch_upgrade, series, state


def evaluate():
    c = Cluster()
    p = Preparation(c)
    baseline = p.load_for_task()
    if baseline is None or baseline['data']['phase'] != ('prepared' if p.patch else 'held') or not p.same_task(baseline):
        raise RuntimeError('verified source-version and upgrade-hold baseline is missing')
    sts = c.statefulset()
    p.preserved(baseline, sts)
    if c.get('namespace', c.namespace, namespace='')['metadata']['uid'] != baseline['data']['namespace_uid']:
        raise UnsafeState('selected namespace identity changed')
    if sts['spec'].get('updateStrategy', {'type': 'RollingUpdate'}) != json.loads(baseline['data']['original_strategy']):
        raise RuntimeError('original update strategy has not been restored')
    def matches_target(version):
        return version == p.target if p.patch else series(version) == series(p.target)

    desired = database_container(sts['spec']['template'])
    desired_version = image_version(desired['image'])
    final_version_progression = (os.environ.get('BENCH_ORACLE_PHASE') == 'final_sweep'
                                 and series(desired_version) > series(p.target))
    if not final_version_progression and not matches_target(desired_version):
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
    target_series = '.'.join(map(str, series(p.target)))
    if final_version_progression:
        logical_series = series(current['logical'])
        if not series(p.target) <= logical_series <= series(desired_version):
            raise RuntimeError('finalized logical version is outside the target-to-binary release range')
        if any(version != desired_version for version in current['binaries']):
            raise RuntimeError('actual selected nodes have not converged to the desired binary')
    else:
        if any(not matches_target(version) for version in current['binaries']):
            raise RuntimeError('not every actual selected node runs the target release')
        if current['logical'] != target_series:
            raise RuntimeError('major version upgrade has not finalized to ' + target_series)
    if current['cluster_id'] != baseline['data']['normalized_uuid']:
        raise UnsafeState('prepared database identity changed during the solver task')
    if p.patch:
        hold = c.setting('cluster.preserve_downgrade_option')
        if final_version_progression:
            if hold and hold != current['logical']:
                raise RuntimeError('preserve_downgrade_option does not match the logical version')
        elif hold != baseline['data']['source_preserve']:
            raise RuntimeError('patch rollout changed the inherited upgrade hold')
        policy = baseline['data']['source_auto_upgrade']
        if policy != '(unavailable)' and c.setting('cluster.auto_upgrade.enabled') != policy:
            raise RuntimeError('patch rollout changed the inherited automatic-upgrade policy')
    else:
        hold = c.setting('cluster.preserve_downgrade_option')
        if hold and (not final_version_progression or hold != current['logical']):
            raise RuntimeError('preserve_downgrade_option has not been cleared')
    return True


if __name__ == '__main__':
    try:
        source, target = parameters()
        Cluster().wait(evaluate, 70 if patch_upgrade(source, target) else 150)
        result = 'Patch rollout completed' if patch_upgrade(source, target) else 'Major upgrade finalized'
        print(result + ' on every selected node; identity, storage and security preserved.', flush=True)
    except (RuntimeError, ValueError, KeyError, OSError, subprocess.TimeoutExpired) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)

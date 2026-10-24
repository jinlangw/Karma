#!/usr/bin/env python3
"""All selected nodes must have joined one initialized database."""
import argparse
import csv
import io
import json
import os
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from cluster import Cluster, UnsafeState, database_container, flag_value
from prepare import Preparation


def evaluate():
    cluster = Cluster()
    preparation = Preparation(cluster)
    baseline = preparation.load()
    if baseline is None or baseline['data']['phase'] != 'faulted':
        raise RuntimeError('verified initialization fixture baseline is missing')
    sts = cluster.statefulset()
    final_sweep = os.environ.get('BENCH_ORACLE_PHASE') == 'final_sweep'
    if final_sweep:
        count = int(baseline['data']['replicas'])
        if int(sts['spec'].get('replicas', 1)) != count:
            raise UnsafeState('selected replica count changed during preparation')
        if cluster.stores(sts, count) != json.loads(baseline['data']['stores']):
            raise UnsafeState('selected store configuration or PVC identity changed')
    else:
        preparation.preserved(baseline, sts)
    if sts['spec'].get('updateStrategy', {'type': 'RollingUpdate'}) != json.loads(baseline['data']['original_strategy']):
        raise RuntimeError('original StatefulSet update strategy has not been restored')
    if cluster.deployment_ready() != 'initialized':
        raise RuntimeError('selected nodes are still waiting for initialization')
    identity = cluster.cluster_id()
    if identity == baseline['data']['old_cluster_id']:
        raise RuntimeError('selected stores were not reset to a fresh database')
    containers = [database_container(sts['spec']['template'])]
    containers += [database_container({'spec': pod['spec']}) for pod in cluster.pods(sts)]
    for container in containers:
        if '.invalid' in flag_value(container, '--join', ''):
            raise RuntimeError('injected join fault remains in the template or an actual node')
        if not final_sweep and cluster.connection_flags(container) != json.loads(baseline['data']['connection_flags']):
            raise UnsafeState('a selected node changed its security mode')
    # A successful init on node 0 alone, or independent databases, must fail.
    count = int(baseline['data']['replicas'])
    for ordinal in range(count):
        if cluster.cluster_id(ordinal) != identity:
            raise RuntimeError('selected nodes belong to different database clusters')
        result = cluster.client('node', 'status', ordinal=ordinal)
        rows = list(csv.DictReader(io.StringIO(cluster.require(result))))
        if len(rows) != count or any(row.get('is_live', '').lower() != 'true' for row in rows):
            raise RuntimeError('not all expected nodes are live from every SQL gateway')
    operator = cluster.kubectl('get', 'crdbcluster', '-o', 'json')
    if operator.returncode == 0 and any(obj['metadata']['name'] == cluster.name for obj in json.loads(operator.stdout).get('items', [])):
        raise RuntimeError('operator-managed clusters are not allowed for this case')
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--timeout', type=int, default=5, help='Retained CLI compatibility; calls have bounded deadlines.')
    parser.parse_args()
    Cluster().wait(evaluate, 150)
    print('All selected nodes initialized, joined one database and accept SQL.', flush=True)


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, ValueError, KeyError, OSError, subprocess.TimeoutExpired) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)

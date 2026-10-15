"""Deterministic public audit schema, selected-cluster snapshot and encrypted baseline."""
import csv
import hashlib
import io
import json
import os
import sys

from cryptography.fernet import Fernet, InvalidToken

from cluster import UnsafeState
from storage import signatures


class Audit:
    def __init__(self, cluster):
        self.cluster = cluster
        self.context = {'namespace': cluster.namespace, 'cluster_name': cluster.name,
                        'run_id': os.environ['BENCH_RUN_ID'], 'stage_id': os.environ['BENCH_STAGE_ID']}
        digest = hashlib.sha256('/'.join(self.context[k] for k in ('namespace', 'cluster_name', 'run_id', 'stage_id')).encode()).hexdigest()[:20]
        self.report_name = 'crdb-audit-' + digest
        self.baseline_name = self.report_name + '-baseline'
        self.labels = {**cluster.labels, 'karma.dev/fixture': 'readonly-audit', 'karma.dev/audit-id': digest}

    def owned(self, obj):
        if obj and any(obj['metadata'].get('labels', {}).get(k) != v for k, v in self.labels.items()):
            raise UnsafeState('audit artifact name is occupied by a resource with different ownership')

    def report_absent(self):
        obj = self.cluster.get('configmap', self.report_name)
        return obj is None

    def clear_report(self):
        obj = self.cluster.get('configmap', self.report_name)
        # This unique run/stage output name defines the cleanup scope. Labels
        # are agent-controlled: a malformed report must not block a fresh retry.
        if obj:
            options = {'apiVersion': 'v1', 'kind': 'DeleteOptions',
                       'preconditions': {'uid': obj['metadata']['uid'], 'resourceVersion': obj['metadata']['resourceVersion']}}
            self.cluster.require(self.cluster.kubectl('delete', '--raw=' + f'/api/v1/namespaces/{self.cluster.namespace}/configmaps/{self.report_name}',
                                                     '-f', '-', input_text=json.dumps(options)))

    def rows(self, query):
        return list(csv.DictReader(io.StringIO(self.cluster.require(self.cluster.sql(query, timeout=30)))))

    def snapshot(self):
        c = self.cluster
        c.ready()
        sts = c.statefulset()
        settings = self.rows('SELECT variable, value FROM crdb_internal.cluster_settings ORDER BY variable;')
        if not settings or not any(row['variable'] == 'kv.snapshot_rebalance.max_rate' for row in settings):
            raise RuntimeError('audited cluster settings are unavailable')
        zones = self.rows('SHOW ZONE CONFIGURATIONS;')
        if not zones or any(not row.get('target') or not row.get('raw_config_sql') for row in zones):
            raise RuntimeError('zone configuration snapshot is incomplete')
        pods = c.pods(sts)
        report = {'schema_version': 1, 'identity': {**self.context, 'cluster_id': c.cluster_id()},
                  'settings': {r['variable']: r['value'] for r in settings},
                  'zones': sorted([{'target': r['target'], 'raw_config_sql': r['raw_config_sql']} for r in zones], key=lambda r: r['target']),
                  'replicas': int(sts['spec']['replicas']),
                  'nodes': sorted([{'pod': p['metadata']['name'], 'node_id': c.value('SELECT crdb_internal.node_id();', i),
                                    'version': c.value('SELECT version();', i)} for i, p in enumerate(pods)], key=lambda r: r['pod']),
                  'healthy': True, 'tls': c.connection_flags()[0] != '--insecure'}
        # Configuration identity excludes runtime counters, heartbeat times and pod UIDs.
        claims = sorted({v['persistentVolumeClaim']['claimName'] for p in pods for v in p['spec'].get('volumes', []) if 'persistentVolumeClaim' in v})
        state = {'statefulset_uid': sts['metadata']['uid'], 'spec': sts['spec'],
                 'pvc_uids': {name: c.get('pvc', name)['metadata']['uid'] for name in claims},
                 'secrets': signatures(c, sts['spec']['template'])}
        return {'report': report, 'state': state}

    def load(self, private):
        obj = self.cluster.get('configmap', self.baseline_name)
        self.owned(obj)
        if not obj or set(obj.get('data', {})) != {'snapshot.enc'}:
            raise RuntimeError('encrypted audit baseline is missing or malformed')
        try:
            baseline = json.loads(Fernet(private['key'].encode()).decrypt(obj['data']['snapshot.enc'].encode()))
        except (InvalidToken, ValueError, KeyError, TypeError) as error:
            raise RuntimeError('encrypted audit baseline authentication failed') from error
        if baseline.get('report', {}).get('identity', {}) != {**self.context, 'cluster_id': self.cluster.cluster_id()}:
            raise RuntimeError('audit baseline belongs to another stage or cluster incarnation')
        return baseline

    def record(self, private):
        if private['frozen']:
            self.load(private)
            print('Preserved the frozen pre-agent audit baseline')
            return
        snapshot = self.snapshot()
        encrypted = Fernet(private['key'].encode()).encrypt(json.dumps(snapshot, sort_keys=True).encode()).decode()
        obj = self.cluster.get('configmap', self.baseline_name)
        self.owned(obj)
        data = {'snapshot.enc': encrypted}
        if obj:
            patch = [{'op': 'test', 'path': '/metadata/uid', 'value': obj['metadata']['uid']},
                     {'op': 'test', 'path': '/metadata/resourceVersion', 'value': obj['metadata']['resourceVersion']},
                     {'op': 'add', 'path': '/data', 'value': data}]
            self.cluster.require(self.cluster.kubectl('patch', 'configmap', self.baseline_name, '--type=json', '-p', json.dumps(patch)))
        else:
            self.cluster.create({'apiVersion': 'v1', 'kind': 'ConfigMap',
                                 'metadata': {'name': self.baseline_name, 'namespace': self.cluster.namespace, 'labels': self.labels}, 'data': data})
        self.load(private)
        print('Captured encrypted pre-agent audit baseline')


def private_input():
    payload = json.load(sys.stdin)
    if set(payload) != {'key', 'frozen'} or not isinstance(payload['frozen'], bool):
        raise ValueError('invalid trusted framework input')
    return payload

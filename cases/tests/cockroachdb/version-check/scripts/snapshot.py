"""Deterministic selected-cluster version state and encrypted baseline."""
import hashlib
import json
import os
import re
import sys

from cryptography.fernet import Fernet, InvalidToken

from cluster import UnsafeState
from storage import signatures


class Snapshot:
    def __init__(self, cluster):
        self.cluster = cluster
        self.context = {'namespace': cluster.namespace, 'cluster_name': cluster.name,
                        'run_id': os.environ['BENCH_RUN_ID'], 'stage_id': os.environ['BENCH_STAGE_ID']}
        digest = hashlib.sha256('/'.join(self.context[k] for k in ('namespace', 'cluster_name', 'run_id', 'stage_id')).encode()).hexdigest()[:20]
        prefix = os.environ.get('BENCH_PARAM_REPORT_CONFIGMAP_NAME','crdb-version-report')
        if not re.fullmatch(r'[a-z0-9]([-a-z0-9]*[a-z0-9])?',prefix) or len(prefix)>63:
            raise ValueError('report_configmap_name must be a DNS label prefix')
        self.report_name = prefix + '-' + digest
        self.report_key = os.environ.get('BENCH_PARAM_REPORT_KEY','db_version')
        if not re.fullmatch(r'[a-zA-Z0-9._-]+',self.report_key) or len(self.report_key)>253:
            raise ValueError('invalid report key')
        self.baseline_name = self.report_name + '-baseline'
        self.labels = {**cluster.labels, 'karma.dev/fixture': 'version-check', 'karma.dev/version-id': digest}

    def owned(self, obj):
        if obj and any(obj['metadata'].get('labels', {}).get(k) != v for k, v in self.labels.items()):
            raise UnsafeState('version-check artifact name is occupied by a resource with different ownership')

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

    def snapshot(self):
        c = self.cluster
        from versions import state, series
        from gap import Gap
        Gap(c).ready()
        versions = state(c)
        sts = c.statefulset()
        report = {'identity':{**self.context,'cluster_id':versions['cluster_id']},
                  'feature_version':versions['logical'], 'binaries':versions['binaries'],
                  'hold':c.setting('cluster.preserve_downgrade_option'),
                  'auto_upgrade':c.setting('cluster.auto_upgrade.enabled') if series(versions['logical']) >= (23,2) else None}
        state = {'statefulset_uid':sts['metadata']['uid'], 'spec':sts['spec'],
                 'stores':c.stores(sts), 'secrets':signatures(c,sts['spec']['template'])}
        return {'report':report,'state':state}

    def unchanged(self, private):
        baseline = self.load(private)
        if self.snapshot() != baseline:
            raise RuntimeError('selected version state or workload changed after baseline capture')
        return baseline

    def load(self, private):
        obj = self.cluster.get('configmap', self.baseline_name)
        self.owned(obj)
        if not obj or set(obj.get('data', {})) != {'snapshot.enc'}:
            raise RuntimeError('encrypted version-check baseline is missing or malformed')
        try:
            baseline = json.loads(Fernet(private['key'].encode()).decrypt(obj['data']['snapshot.enc'].encode()))
        except (InvalidToken, ValueError, KeyError, TypeError) as error:
            raise RuntimeError('encrypted version-check baseline authentication failed') from error
        if baseline.get('report', {}).get('identity', {}) != {**self.context, 'cluster_id': self.cluster.cluster_id()}:
            raise RuntimeError('version-check baseline belongs to another stage or cluster incarnation')
        return baseline

    def record(self, private):
        if private['frozen']:
            self.load(private)
            print('Preserved the frozen pre-agent version-check baseline')
            return
        from gap import Gap
        gap = Gap(self.cluster)
        obj = gap.load()
        if obj and obj['data']['phase'] == 'ready':
            options = {'apiVersion':'v1','kind':'DeleteOptions','preconditions':{'uid':obj['metadata']['uid'],'resourceVersion':obj['metadata']['resourceVersion']}}
            self.cluster.require(self.cluster.kubectl('delete','--raw='+f'/api/v1/namespaces/{self.cluster.namespace}/configmaps/{gap.name}', '-f','-',input_text=json.dumps(options)))
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
        print('Captured encrypted pre-agent version-check baseline')


def private_input():
    payload = json.load(sys.stdin)
    if set(payload) != {'key', 'frozen'} or not isinstance(payload['frozen'], bool):
        raise ValueError('invalid trusted framework input')
    return payload

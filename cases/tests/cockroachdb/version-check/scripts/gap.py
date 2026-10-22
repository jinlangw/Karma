"""Prepare an actual held feature/binary gap with scoped, resumable recovery."""
import copy
import hashlib
import json
import os
import subprocess
import time
import uuid

from cluster import UnsafeState, arguments, database_container
from storage import Stores, signatures
from versions import image, image_version, series, state, choose_plan


def without_image(template):
    result = copy.deepcopy(template)
    database_container(result).pop('image')
    return result


def workload_spec(sts):
    return {key: value for key, value in sts['spec'].items()
            if key not in ('template', 'replicas', 'updateStrategy')}


class Gap(Stores):
    def __init__(self, cluster):
        self.cluster = cluster
        self.name = cluster.name + '-version-gap-preparation'

    def load(self):
        obj = self.cluster.get('configmap', self.name)
        if obj is None:
            return None
        if obj['metadata'].get('labels', {}).get('karma.dev/fixture') != 'version-gap-preparation' or obj['metadata'].get('labels', {}).get('app.kubernetes.io/instance') != self.cluster.name:
            raise UnsafeState('version preparation name belongs to another resource')
        if obj['data']['statefulset_uid'] != self.cluster.statefulset()['metadata']['uid']:
            return None
        return obj

    def pending(self):
        obj = self.load()
        return obj and obj['data']['phase'] != 'ready'

    def ready(self):
        if self.pending():
            raise RuntimeError('version-gap preparation requires resumption')
        current = state(self.cluster)
        if len(set(current['binaries'])) != 1 or series(current['binaries'][0]) <= series(current['logical']):
            raise RuntimeError('selected nodes do not have a coherent binary/feature version gap')
        sts = self.cluster.statefulset()
        if image_version(database_container(sts['spec']['template'])['image']) != current['binaries'][0]:
            raise RuntimeError('selected binary template has not converged')
        if self.cluster.setting('cluster.preserve_downgrade_option') != current['logical']:
            raise RuntimeError('feature version is not held against automatic finalization')
        return True

    def update(self, baseline, values):
        patch = [{'op': 'test', 'path': '/metadata/uid', 'value': baseline['metadata']['uid']},
                 {'op': 'test', 'path': '/metadata/resourceVersion', 'value': baseline['metadata']['resourceVersion']},
                 {'op': 'replace', 'path': '/data', 'value': {**baseline['data'], **values}}]
        self.cluster.require(self.cluster.kubectl('patch', 'configmap', self.name, '--type=json', '-p', json.dumps(patch)))
        return self.load()

    def preserved(self, baseline, sts, paused=False):
        data = baseline['data']
        count = int(data['replicas'])
        if int(sts['spec'].get('replicas', 1)) not in ((0, count) if paused else (count,)):
            raise UnsafeState('selected replica count changed during preparation')
        if without_image(sts['spec']['template']) != without_image(json.loads(data['original_template'])):
            raise UnsafeState('selected non-version startup configuration changed during preparation')
        if workload_spec(sts) != json.loads(data['workload_spec']):
            raise UnsafeState('selected non-version workload configuration changed during preparation')
        if self.cluster.connection_flags() != json.loads(data['connection_flags']):
            raise UnsafeState('selected security mode or certificate path changed')
        if self.cluster.stores(sts, count) != json.loads(data['stores']):
            raise UnsafeState('selected store configuration or PVC identity changed')
        if signatures(self.cluster, sts['spec']['template']) != json.loads(data['secret_signatures']):
            raise UnsafeState('mounted Secret identity or contents changed')

    def validate_binary(self, version, sts):
        """Parse inherited startup using the chosen binary, without any stores."""
        c = self.cluster
        db = copy.deepcopy(database_container(sts['spec']['template']))
        tokens = arguments(db)
        executable = tokens[1:] if tokens and tokens[0] == 'exec' else tokens
        if not executable or executable[0] not in ('/cockroach/cockroach', './cockroach', 'cockroach', 'start'):
            raise UnsafeState('unsupported server executable')
        command = db.get('command', [])
        if len(command) == 3 and command[0] in ('/bin/bash', '/bin/sh', 'bash', 'sh'):
            if db.get('args'):
                raise UnsafeState('shell positional startup arguments are unsupported')
            command[2] = command[2].rstrip() + ' --help'
        else:
            db.setdefault('args', []).append('--help')
        db['image'] = image(version)
        db.pop('volumeMounts', None)
        for key in ('livenessProbe', 'readinessProbe', 'startupProbe', 'ports', 'lifecycle'):
            db.pop(key, None)
        db['resources'] = {'requests': {'cpu': '10m', 'memory': '32Mi'}, 'limits': {'memory': '256Mi'}}
        name = c.name + '-version-check'
        fingerprint = hashlib.sha256(json.dumps(db, sort_keys=True).encode()).hexdigest()
        pod = c.get('pod', name)
        if pod:
            # A retry can encounter the other candidate's completed helper
            # after interruption between source/target compatibility checks.
            previous = copy.deepcopy(db)
            previous['image'] = database_container({'spec':pod['spec']})['image']
            previous_fingerprint = hashlib.sha256(json.dumps(previous,sort_keys=True).encode()).hexdigest()
            if (pod['metadata'].get('labels',{}).get('karma.dev/fixture') != 'version-check'
                    or pod['metadata'].get('annotations',{}).get('karma.dev/version-check') != previous_fingerprint
                    or not any(ref.get('uid') == sts['metadata']['uid'] for ref in pod['metadata'].get('ownerReferences', []))):
                raise UnsafeState('binary compatibility helper name is occupied by another resource')
            c.delete_pod(pod)
        c.create({'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': name, 'namespace': c.namespace,
            'labels': {'karma.dev/fixture': 'version-check'}, 'annotations': {'karma.dev/version-check': fingerprint},
            'ownerReferences': [{'apiVersion': 'apps/v1', 'kind': 'StatefulSet', 'name': c.name, 'uid': sts['metadata']['uid']}]},
            'spec': {'restartPolicy': 'Never', 'automountServiceAccountToken': False,
                'terminationGracePeriodSeconds': 1, 'securityContext': sts['spec']['template']['spec'].get('securityContext', {}),
                'containers': [db]}})
        def finished():
            return c.get('pod', name).get('status', {}).get('phase') in ('Succeeded', 'Failed')
        c.wait(finished, 240)
        obj = c.get('pod', name)
        logs = c.require(c.kubectl('logs', name, '-c', db['name'], '--tail=15'))
        c.delete_pod(obj)
        if obj['status']['phase'] != 'Succeeded':
            raise UnsafeState('inherited startup is incompatible with selected binary: ' + logs)

    def hold(self, logical):
        if self.cluster.setting('version') != logical:
            raise UnsafeState('logical version changed before establishing upgrade hold')
        if self.cluster.setting('cluster.preserve_downgrade_option') != logical:
            self.cluster.require(self.cluster.sql("SET CLUSTER SETTING cluster.preserve_downgrade_option='" + logical + "';"))
        if self.cluster.setting('version') != logical or self.cluster.setting('cluster.preserve_downgrade_option') != logical:
            raise UnsafeState('upgrade hold did not protect the recorded logical version')

    def roll_to(self, baseline, version):
        c = self.cluster
        self.preserved(baseline, c.statefulset())
        template = json.loads(baseline['data']['original_template'])
        database_container(template)['image'] = image(version)
        sts = c.statefulset()
        if sts['spec']['template'] != template or sts['spec'].get('updateStrategy') != {'type': 'OnDelete'}:
            c.patch_spec(sts, {'template': template, 'updateStrategy': {'type': 'OnDelete'}})
        def stabilize(peer):
            def healthy():
                c.ready()
                c.require(c.sql('SELECT 1;', peer))
                return True
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                c.wait(healthy, 60)
                time.sleep(3)
        for ordinal in reversed(range(int(baseline['data']['replicas']))):
            c.wait(c.ready, 240)
            pod = c.pods(c.statefulset())[ordinal]
            peer = 1 if ordinal == 0 and int(baseline['data']['replicas']) > 1 else 0
            if image_version(database_container({'spec': pod['spec']})['image']) == version:
                # An interruption may have happened after replacement but
                # before stabilization. Protect the next node even on retry.
                if any(image_version(database_container({'spec': other['spec']})['image']) != version
                       for other in c.pods(c.statefulset())[:ordinal]):
                    print(f'Stabilizing inherited or resumed node {ordinal} before the next replacement', flush=True)
                    stabilize(peer)
                continue
            c.require(c.sql('SELECT 1;', peer))
            print(f'Rolling selected node {ordinal} to {version}', flush=True)
            c.delete_pod(pod)
            c.wait(c.ready, 300)
            # Follow the documented one-minute stabilization between nodes,
            # checking real health throughout instead of an unchecked sleep.
            if ordinal > 0: stabilize(peer)
        current = state(c)
        if any(v != version for v in current['binaries']):
            raise RuntimeError('selected binary rollout has not converged')
        self.preserved(self.load(), c.statefulset())

    def stable_state(self):
        observed = []
        def read():
            observed[:] = [state(self.cluster)]
            return True
        self.cluster.wait(read, 180)
        return observed[0]

    def begin(self, current):
        c = self.cluster
        sts = c.statefulset()
        plan = choose_plan(current)
        stores = self.preflight(sts) if plan['reset'] else c.stores(sts)
        for version in dict.fromkeys(([plan['source']] if plan['reset'] else []) + [plan['binary']]):
            self.validate_binary(version, sts)
        data = {'statefulset_uid': sts['metadata']['uid'],
                'namespace_uid': c.get('namespace', c.namespace, namespace='')['metadata']['uid'],
                'replicas': str(sts['spec']['replicas']),
                'original_template': json.dumps(sts['spec']['template'], sort_keys=True),
                'workload_spec': json.dumps(workload_spec(sts), sort_keys=True),
                'original_strategy': json.dumps(sts['spec'].get('updateStrategy', {'type': 'RollingUpdate'})),
                'connection_flags': json.dumps(c.connection_flags()),
                'stores': json.dumps(stores),
                'secret_signatures': json.dumps(signatures(c, sts['spec']['template'])),
                'initial_state': json.dumps(current), 'plan': json.dumps(plan), 'prepared_cluster_id': '',
                'nonce': uuid.uuid4().hex[:12], 'phase': 'resetting' if plan['reset'] else 'rolling'}
        obj = c.get('configmap', self.name)
        if obj:
            # load() already checked ownership, including stale incarnations.
            obj = self.update(obj, data)
        else:
            c.create({'apiVersion':'v1', 'kind':'ConfigMap', 'metadata':{'name':self.name,
                      'namespace':c.namespace, 'labels':{**c.labels,'karma.dev/fixture':'version-gap-preparation'}}, 'data':data})
            obj = self.load()
        print('Version-gap plan: ' + json.dumps(plan, sort_keys=True), flush=True)
        return obj

    def reset(self, record):
        c = self.cluster
        plan = json.loads(record['data']['plan'])
        if record['data']['phase'] == 'resetting':
            self.exclusive(c.statefulset(), json.loads(record['data']['stores']), record)
            c.patch_spec(c.statefulset(), {'replicas':0,'updateStrategy':{'type':'OnDelete'}})
            uid = record['data']['statefulset_uid']
            c.wait(lambda: not any(any(r.get('uid') == uid for r in p['metadata'].get('ownerReferences', [])) for p in c.get('pods')['items']), 180)
            for index, store in enumerate(json.loads(record['data']['stores'])):
                self.reset_store(record, store, index)
            record = self.update(self.load(), {'phase':'starting'})
        template = json.loads(record['data']['original_template'])
        database_container(template)['image'] = image(plan['source'])
        c.patch_spec(c.statefulset(), {'template':template,'replicas':int(record['data']['replicas'])})
        c.wait(c.deployment_ready, 300)
        if c.deployment_ready() == 'uninitialized': c.require(c.client('init'))
        c.configure_fresh_replication()
        c.wait(c.ready, 240)
        if c.setting('version') != plan['logical']:
            raise UnsafeState('fresh stores did not initialize at the configured source release')
        if c.cluster_id() == json.loads(record['data']['initial_state'])['cluster_id']:
            raise UnsafeState('fresh stores unexpectedly retained the old database identity')
        return self.update(self.load(), {'phase':'rolling', 'prepared_cluster_id':c.cluster_id()})

    def apply(self):
        c = self.cluster
        record = self.load()
        if record is None or record['data']['phase'] == 'ready':
            c.wait(c.ready, 180)
            current = self.stable_state()
            # A missing hold alone never justifies a reset or a binary change.
            if len(set(current['binaries'])) == 1 and series(current['binaries'][0]) > series(current['logical']):
                try:
                    self.hold(current['logical'])
                except UnsafeState:
                    if c.setting('version') != current['logical']:
                        return self.apply()
                    raise
                try:
                    if self.ready(): return
                except RuntimeError:
                    pass
            record = self.begin(current)
        self.preserved(record, c.statefulset(), paused=True)
        if c.get('namespace', c.namespace, namespace='')['metadata']['uid'] != record['data']['namespace_uid']:
            raise UnsafeState('namespace incarnation changed during version preparation')
        if record['data']['phase'] in ('resetting','starting'):
            record = self.reset(record)
        plan = json.loads(record['data']['plan'])
        c.wait(c.ready, 180)
        identity = record['data'].get('prepared_cluster_id') or json.loads(record['data']['initial_state'])['cluster_id']
        if c.cluster_id() != identity:
            raise UnsafeState('database identity changed during binary rollout')
        if c.setting('version') != plan['logical']:
            # Before any image/store change, auto-finalization may win a race.
            # Replan only with exact unchanged original binaries and workload.
            original = json.loads(record['data']['initial_state'])
            if not plan['reset'] and c.statefulset()['spec']['template'] == json.loads(record['data']['original_template']) and state(c)['binaries'] == original['binaries']:
                self.update(record, {'phase':'ready'})
                return self.apply()
            raise UnsafeState('feature version advanced during held preparation')
        self.hold(plan['logical'])
        self.roll_to(record, plan['binary'])
        c.patch_spec(c.statefulset(), {'updateStrategy':json.loads(record['data']['original_strategy'])})
        self.update(self.load(), {'phase':'ready'})
        self.ready()

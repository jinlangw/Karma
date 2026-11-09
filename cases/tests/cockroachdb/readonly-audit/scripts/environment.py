"""Case-local, selected-cluster recovery; inherited healthy databases are untouched."""
import copy
import json
import uuid

from cluster import UnsafeState, database_container, flag_value
from storage import Stores, signatures


class Environment(Stores):
    def __init__(self, cluster):
        self.cluster = cluster
        self.name = cluster.name + '-audit-recovery'

    def load(self):
        obj = self.cluster.get('configmap', self.name)
        if obj and (obj['metadata'].get('labels', {}).get('karma.dev/fixture') != 'audit-recovery' or obj['metadata'].get('labels', {}).get('app.kubernetes.io/instance') != self.cluster.name):
            raise UnsafeState('recovery record does not belong to the selected cluster')
        if obj and obj['data']['statefulset_uid'] != self.cluster.statefulset()['metadata']['uid']:
            return None  # An earlier incarnation must not block a healthy replacement.
        return obj

    def update(self, record, phase):
        self.patch(record, {'data': {**record['data'], 'phase': phase}})
        return self.load()

    def patch(self, obj, fields):
        c = self.cluster
        changes = [{'op': 'test', 'path': '/metadata/uid', 'value': obj['metadata']['uid']},
                   {'op': 'test', 'path': '/metadata/resourceVersion', 'value': obj['metadata']['resourceVersion']}]
        changes += [{'op': 'add', 'path': '/' + key, 'value': value} for key, value in fields.items()]
        c.require(c.kubectl('patch', obj['kind'], obj['metadata']['name'], '--type=json', '-p', json.dumps(changes)))

    def probe(self):
        record = self.load()
        if record and record['data']['phase'] != 'ready':
            raise RuntimeError('owned database recovery requires resumption')
        return self.cluster.ready()

    def services(self):
        c = self.cluster
        sts = c.statefulset()
        selector = sts['spec']['selector']['matchLabels']
        for name, headless in [(sts['spec']['serviceName'], True), (c.name + '-public', False)]:
            obj = c.get('service', name)
            port = int(flag_value(database_container(sts['spec']['template']), '--port', '26257'))
            if obj is None:
                spec = {'selector': selector, 'ports': [{'name': 'grpc', 'port': port}, {'name': 'http', 'port': 8080}]}
                if headless: spec.update(clusterIP='None', publishNotReadyAddresses=True)
                c.create({'apiVersion': 'v1', 'kind': 'Service', 'metadata': {'name': name, 'namespace': c.namespace,
                          'labels': c.labels}, 'spec': spec})
                continue
            c.identity(obj)
            spec = copy.deepcopy(obj['spec'])
            if headless and spec.get('clusterIP') != 'None':
                raise UnsafeState('headless service name is occupied by a regular Service')
            # Prove that tightening a selector cannot remove foreign backends.
            old = spec.get('selector', {})
            for pod in c.get('pods')['items']:
                if old and all(pod['metadata'].get('labels', {}).get(k) == v for k, v in old.items()) and not any(ref.get('uid') == sts['metadata']['uid'] for ref in pod['metadata'].get('ownerReferences', [])):
                    raise UnsafeState('selected service has unrelated backends')
            spec['selector'] = selector
            if headless: spec['publishNotReadyAddresses'] = True
            if spec != obj['spec']: self.patch(obj, {'spec': spec})

    def preserved(self, record, sts, paused=False):
        data = record['data']
        if sts['metadata']['uid'] != data['statefulset_uid'] or sts['spec']['template'] != json.loads(data['original_template']):
            raise UnsafeState('selected workload changed during recovery')
        if {k:v for k,v in sts['spec'].items() if k not in ('template', 'replicas', 'updateStrategy')} != json.loads(data['workload_spec']):
            raise UnsafeState('selected workload configuration changed during recovery')
        if signatures(self.cluster, sts['spec']['template']) != json.loads(data['secret_signatures']):
            raise UnsafeState('TLS material changed during recovery')
        if self.cluster.stores(sts, int(data['replicas'])) != json.loads(data['stores']):
            raise UnsafeState('selected store identities changed during recovery')

    def reset(self, record=None):
        c = self.cluster
        sts = c.statefulset()
        if record is None or record['data']['phase'] == 'ready':
            stores = c.stores(sts)
            self.exclusive(sts, stores)
            db = database_container(sts['spec']['template'])
            join = flag_value(db, '--join', '')
            for env in db.get('env', []):
                if env.get('valueFrom', {}).get('fieldRef', {}).get('fieldPath') == 'metadata.namespace' or env.get('value') == c.namespace:
                    join = join.replace('$(' + env['name'] + ')', c.namespace)
            port = flag_value(db, '--listen-addr', flag_value(db, '--port', '26257')).rsplit(':', 1)[-1]
            hosts = {c.host(i, sts) + ':' + port for i in range(int(sts['spec']['replicas']))}
            if not join or any(seed not in hosts for seed in join.split(',')):
                raise UnsafeState('recovery join seeds are not exclusively selected nodes')
            if sts['spec'].get('persistentVolumeClaimRetentionPolicy', {}).get('whenScaled', 'Retain') != 'Retain':
                raise UnsafeState('selected scale-down would delete PVCs')
            data = {'statefulset_uid': sts['metadata']['uid'], 'original_template': json.dumps(sts['spec']['template']),
                    'original_strategy': json.dumps(sts['spec'].get('updateStrategy', {'type': 'RollingUpdate'})),
                    'workload_spec': json.dumps({k:v for k,v in sts['spec'].items() if k not in ('template', 'replicas', 'updateStrategy')}),
                    'stores': json.dumps(stores), 'secret_signatures': json.dumps(signatures(c, sts['spec']['template'])),
                    'replicas': str(sts['spec']['replicas']), 'nonce': uuid.uuid4().hex[:12], 'phase': 'resetting'}
            record = record or c.get('configmap', self.name)
            if record:
                self.patch(record, {'data': data}); record = self.load()
            else:
                c.create({'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': self.name, 'namespace': c.namespace,
                         'labels': {**c.labels, 'karma.dev/fixture': 'audit-recovery'}}, 'data': data})
                record = self.load()
            print('Confirmed persistent database failure; resetting only selected exclusive stores', flush=True)
        self.preserved(record, sts, paused=True)
        if record['data']['phase'] == 'resetting':
            self.exclusive(sts, json.loads(record['data']['stores']), record)
            c.patch_spec(sts, {'replicas': 0, 'updateStrategy': {'type': 'OnDelete'}})
            c.wait(lambda: not any(any(ref.get('uid') == sts['metadata']['uid'] for ref in p['metadata'].get('ownerReferences', [])) for p in c.get('pods')['items']), 180)
            for i, store in enumerate(json.loads(record['data']['stores'])): self.reset_store(record, store, i)
            record = self.update(record, 'starting')
        c.patch_spec(c.statefulset(), {'replicas': int(record['data']['replicas'])})
        c.wait(c.deployment_ready, 240)
        if c.deployment_ready() == 'uninitialized': c.require(c.client('init'))
        c.wait(c.ready, 240)
        c.patch_spec(c.statefulset(), {'updateStrategy': json.loads(record['data']['original_strategy'])})
        self.update(record, 'ready')

    def apply(self):
        c = self.cluster
        fresh = c.get('statefulset', c.name) is None
        if fresh: c.bootstrap()
        record = self.load()
        if record and record['data']['phase'] != 'ready':
            self.reset(record)
        else:
            self.services()
            def usable():
                if c.deployment_ready() == 'uninitialized': c.require(c.client('init'))
                return c.ready()
            try: c.wait(usable, 90)
            except UnsafeState: raise
            except RuntimeError:
                # API errors are not evidence of broken stores. Require repeated
                # successful API reads and node-local connection failures first.
                failed = []
                for i in range(int(c.statefulset()['spec']['replicas'])):
                    result = c.sql('SELECT count(*) FROM system.namespace;', i)
                    if result.returncode == 124 or any(s in result.stderr.lower() for s in ('forbidden', 'unable to connect to the server', 'tls handshake timeout')):
                        raise RuntimeError('control-plane failure is not permission to reset the database')
                    failed.append(result.returncode != 0)
                if not all(failed):
                    # With usable quorum, retry selected unhealthy pods before any reset.
                    for pod in c.pods(c.statefulset()):
                        if not any(q.get('type') == 'Ready' and q.get('status') == 'True' for q in pod['status'].get('conditions', [])): c.delete_pod(pod)
                    try: c.wait(usable, 180)
                    except UnsafeState: raise
                    except RuntimeError:
                        c.get('pods')  # A fresh successful API read is required before reset.
                        self.reset(record)
                else: self.reset(record)
        self.services()
        c.wait(self.probe, 180)
        if fresh: c.require(c.sql("SET CLUSTER SETTING kv.snapshot_rebalance.max_rate = '1MiB';"))

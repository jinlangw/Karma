"""Reuse a usable database; repair exposure before scoped, resumable store reset."""
import copy
import json
import os
import re
import uuid

from cluster import UnsafeState, arguments, database_container, flag_value
from storage import Stores, signatures


class Environment(Stores):
    def __init__(self, cluster):
        self.cluster = cluster
        self.name = cluster.name + '-monitoring-recovery'
        self.port = int(os.environ.get('BENCH_PARAM_METRICS_PORT', '8080'))
        self.path = os.environ.get('BENCH_PARAM_METRICS_PATH', '/_status/vars')
        if not 1 <= self.port <= 65535 or not self.path.startswith('/') or any(c in self.path for c in '\r\n?#'):
            raise ValueError('invalid metrics endpoint parameters')

    def load(self):
        obj = self.cluster.get('configmap', self.name)
        if obj and (obj['metadata'].get('labels', {}).get('karma.dev/fixture') != 'monitoring-recovery' or obj['metadata'].get('labels', {}).get('app.kubernetes.io/instance') != self.cluster.name):
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

    def metrics(self):
        c = self.cluster
        sts = c.statefulset()
        db = database_container(sts['spec']['template'])
        scheme = 'http' if c.connection_flags(db)[0] == '--insecure' else 'https'
        for pod in c.pods(sts):
            output = c.require(c.kubectl('exec', pod['metadata']['name'], '-c', db['name'], '--', 'curl', '-kfsS',
                '--connect-timeout', '3', '--max-time', '8', f'{scheme}://localhost:{self.port}{self.path}', timeout=12))
            if not re.search(r'^sys_uptime(?:\{|\s)', output, re.M):
                raise RuntimeError('selected node does not return CockroachDB metrics')
        service = c.get('service', c.name + '-public')
        selector = service.get('spec', {}).get('selector', {}) if service else {}
        labels = sts['spec']['template']['metadata'].get('labels', {})
        if not selector or any(labels.get(k) != v for k, v in selector.items()):
            raise RuntimeError('metrics Service does not select the selected cluster')
        for pod in c.get('pods')['items']:
            if all(pod['metadata'].get('labels', {}).get(k) == v for k, v in selector.items()) and not any(ref.get('uid') == sts['metadata']['uid'] for ref in pod['metadata'].get('ownerReferences', [])):
                raise UnsafeState('metrics Service also selects another workload')
        ports = service['spec'].get('ports', [])
        if not any(p['port'] == self.port and p.get('targetPort', p['port']) in (self.port, 'http') for p in ports):
            raise RuntimeError('metrics Service port is missing')
        return True

    def probe(self):
        record = self.load()
        listener = self.cluster.get('configmap', self.cluster.name + '-monitoring-listener')
        if listener and listener.get('data', {}).get('phase') == 'repairing' and listener['data'].get('statefulset_uid') == self.cluster.statefulset()['metadata']['uid']:
            raise RuntimeError('owned listener repair requires resumption')
        if record and record['data']['phase'] != 'ready':
            raise RuntimeError('owned database recovery requires resumption')
        self.cluster.ready()
        return self.metrics()

    def services(self):
        c = self.cluster
        sts = c.statefulset()
        selector = sts['spec']['selector']['matchLabels']
        for name, headless in [(sts['spec']['serviceName'], True), (c.name + '-public', False)]:
            obj = c.get('service', name)
            port = int(flag_value(database_container(sts['spec']['template']), '--port', '26257'))
            if obj is None:
                spec = {'selector': selector, 'ports': [{'name': 'grpc', 'port': port}, {'name': 'http', 'port': self.port}]}
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
            ports = spec.setdefault('ports', [])
            http = next((p for p in ports if p.get('name') == 'http'), None)
            if http is None: ports.append({'name': 'http', 'port': self.port, 'targetPort': self.port})
            else: http.update(port=self.port, targetPort=self.port)
            if spec != obj['spec']: self.patch(obj, {'spec': spec})

    def repair_listener(self):
        c = self.cluster
        sts = c.statefulset()
        template = copy.deepcopy(sts['spec']['template'])
        db = database_container(template)
        record_name = c.name + '-monitoring-listener'
        record = c.get('configmap', record_name)
        if record and (record['metadata'].get('labels', {}).get('karma.dev/fixture') != 'monitoring-listener' or record['metadata'].get('labels', {}).get('app.kubernetes.io/instance') != c.name):
            raise UnsafeState('listener repair record belongs to another cluster')
        pending = record and record['data'].get('statefulset_uid') == sts['metadata']['uid'] and record['data']['phase'] == 'repairing'
        value = flag_value(db, '--http-addr', '0.0.0.0:8080')
        if value in (f'0.0.0.0:{self.port}', f':{self.port}') and not pending:
            return
        tokens = arguments(db)
        # Keep shell/direct startup and every unrelated flag; modify only the HTTP listener.
        desired = f'0.0.0.0:{self.port}'
        for key in ('command', 'args'):
            seq = db.get(key, [])
            for i, token in enumerate(seq):
                if token.startswith('--http-addr='): seq[i] = '--http-addr=' + desired
                elif token == '--http-addr': seq[i + 1] = desired
            if len(seq) == 3 and seq[0] in ('/bin/bash', '/bin/sh', 'bash', 'sh'):
                seq[2] = re.sub(r'--http-addr(?:=|\s+)\S+', '--http-addr=' + desired, seq[2])
        if not any(t.startswith('--http-addr') for t in tokens): db.setdefault('args', []).append('--http-addr=' + desired)
        db.setdefault('ports', [])
        http = next((p for p in db['ports'] if p.get('name') == 'http'), None)
        if http: http['containerPort'] = self.port
        for key in ('readinessProbe', 'livenessProbe', 'startupProbe'):
            if 'httpGet' in db.get(key, {}):
                probe = db[key]['httpGet']
                if probe.get('port') not in (self.port, 'http'): probe['port'] = self.port
                scheme = 'HTTP' if c.connection_flags(db)[0] == '--insecure' else 'HTTPS'
                if probe.get('scheme', 'HTTP') != scheme: probe['scheme'] = scheme
        strategy = json.loads(record['data']['original_strategy']) if pending else sts['spec'].get('updateStrategy', {'type': 'RollingUpdate'})
        data = {'statefulset_uid': sts['metadata']['uid'], 'original_strategy': json.dumps(strategy), 'phase': 'repairing'}
        if record: self.patch(record, {'data': data})
        else: c.create({'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': record_name, 'namespace': c.namespace, 'labels': {**c.labels, 'karma.dev/fixture': 'monitoring-listener'}}, 'data': data})
        c.patch_spec(sts, {'template': template, 'updateStrategy': {'type': 'OnDelete'}})
        for i in reversed(range(int(sts['spec']['replicas']))):
            pod = c.get('pod', f'{c.name}-{i}')
            if pod:
                actual = database_container({'spec': pod['spec']})
                if all(actual.get(k) == db.get(k) for k in ('command', 'args', 'ports', 'readinessProbe', 'livenessProbe')): continue
                c.delete_pod(pod)
            c.wait(lambda: self.node_sql(i), 180)
        c.patch_spec(c.statefulset(), {'updateStrategy': strategy})
        record = c.get('configmap', record_name)
        self.patch(record, {'data': {**record['data'], 'phase': 'ready'}})

    def node_sql(self, i):
        self.cluster.require(self.cluster.sql('SELECT count(*) FROM system.namespace;', i))
        return True

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
                         'labels': {**c.labels, 'karma.dev/fixture': 'monitoring-recovery'}}, 'data': data})
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
        if c.get('statefulset', c.name) is None: c.bootstrap()
        record = self.load()
        if record and record['data']['phase'] != 'ready':
            self.reset(record)
        else:
            self.services()
            self.repair_listener()
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

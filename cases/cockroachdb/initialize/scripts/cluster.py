"""Selected deployment inspection, with positive pre-initialization detection."""
import csv
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import subprocess
import time

import yaml


class UnsafeState(RuntimeError):
    """The selected state cannot be modified without guessing ownership."""


def database_container(template):
    candidates = [c for c in template['spec']['containers']
                  if 'cockroach' in (c.get('image', '') + ' '.join(c.get('command', []) + c.get('args', [])))
                  and re.search(r'\bstart\b', ' '.join(c.get('command', []) + c.get('args', [])))]
    if len(candidates) != 1:
        raise UnsafeState('expected exactly one multi-node CockroachDB server container')
    return candidates[0]


def arguments(container):
    command = container.get('command', [])
    if len(command) == 3 and command[0] in ('/bin/bash', '/bin/sh', 'bash', 'sh') and command[1] in ('-c', '-ec'):
        lexer = shlex.shlex(command[2], posix=True, punctuation_chars=';&|<>')
        lexer.whitespace_split = True
        if any(re.fullmatch(r'[;&|<>]+', token) for token in lexer):
            raise UnsafeState('compound server startup is unsupported')
        command = shlex.split(command[2])
    if not any(token == 'start' for token in command + container.get('args', [])):
        raise UnsafeState('multi-node cockroach start command is required')
    return command + container.get('args', [])


def flag_value(container, name, default=None):
    tokens = arguments(container)
    values = [t.split('=', 1)[1] for t in tokens if t.startswith(name + '=')]
    values += [tokens[i + 1] for i, t in enumerate(tokens[:-1]) if t == name]
    if len(values) > 1:
        raise UnsafeState('ambiguous startup flag: ' + name)
    return values[0] if values else default


class Cluster:
    def __init__(self):
        self.namespace = os.environ['BENCH_NAMESPACE']
        self.name = os.environ.get('BENCH_PARAM_CLUSTER_NAME', 'crdb-cluster')
        for value in (self.namespace, self.name):
            if len(value) > 63 or not re.fullmatch(r'[a-z0-9]([-a-z0-9]*[a-z0-9])?', value):
                raise ValueError('namespace and cluster_name must be DNS labels')
        if len(self.name) > 40:
            raise ValueError('cluster_name must leave room for fixture resource suffixes')
        self.labels = {'app.kubernetes.io/name': 'cockroachdb', 'app.kubernetes.io/instance': self.name}

    def kubectl(self, *args, timeout=20, input_text=None, namespace=None):
        ns = self.namespace if namespace is None else namespace
        command = ['kubectl', f'--request-timeout={timeout}s'] + (['-n', ns] if ns else []) + list(args)
        try:
            return subprocess.run(command, input=input_text, text=True, capture_output=True, timeout=timeout + 5)
        except subprocess.TimeoutExpired:
            return subprocess.CompletedProcess(command, 124, '', 'kubectl timed out')

    @staticmethod
    def require(result):
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or 'kubectl failed')
        return result.stdout

    def get(self, kind, name=None, namespace=None):
        args = ['get', kind] + ([name, '--ignore-not-found=true'] if name is not None else [])
        output = self.require(self.kubectl(*args, '-o', 'json', namespace=namespace))
        return json.loads(output) if output.strip() else None

    def create(self, obj):
        self.require(self.kubectl('create', '-f', '-', input_text=json.dumps(obj)))
        print('Created ' + obj['kind'] + '/' + obj['metadata']['name'], flush=True)

    def identity(self, obj):
        labels = obj['metadata'].get('labels', {})
        if any(k in labels and labels[k] != v for k, v in self.labels.items()):
            raise UnsafeState('selected resource has conflicting cluster labels')
        if any(ref.get('controller') for ref in obj['metadata'].get('ownerReferences', [])):
            raise UnsafeState('selected resource is managed by another controller')

    def statefulset(self):
        sts = self.get('statefulset', self.name)
        if sts is None:
            raise RuntimeError('selected StatefulSet is absent')
        self.identity(sts)
        if sts['metadata'].get('deletionTimestamp') or int(sts['spec'].get('ordinals', {}).get('start', 0)) != 0:
            raise UnsafeState('terminating or non-zero-ordinal StatefulSet is unsupported')
        return sts

    def pods(self, sts):
        items = {p['metadata']['name']: p for p in self.get('pods')['items']}
        result = []
        for i in range(int(sts['spec'].get('replicas', 1))):
            pod = items.get(f'{self.name}-{i}')
            if not pod or pod['metadata'].get('deletionTimestamp'):
                raise RuntimeError('selected database pod is missing or terminating')
            if not any(ref.get('controller') and ref.get('uid') == sts['metadata']['uid'] for ref in pod['metadata'].get('ownerReferences', [])):
                raise UnsafeState('selected pod belongs to another workload')
            result.append(pod)
        return result

    def connection_flags(self, container=None):
        container = container or database_container(self.statefulset()['spec']['template'])
        tokens = arguments(container)
        insecure = '--insecure' in tokens or '--insecure=true' in tokens
        flags = ['--insecure'] if insecure else ['--certs-dir=' + flag_value(container, '--certs-dir', '/cockroach/cockroach-certs')]
        name = flag_value(container, '--cluster-name')
        return flags + (['--cluster-name=' + name] if name else [])

    def host(self, ordinal, sts=None):
        sts = sts or self.statefulset()
        return f'{self.name}-{ordinal}.{sts["spec"]["serviceName"]}.{self.namespace}.svc.cluster.local'

    def client(self, *command, ordinal=0):
        sts = self.statefulset()
        db = database_container(sts['spec']['template'])
        port = flag_value(db, '--sql-addr', flag_value(db, '--listen-addr', flag_value(db, '--port', '26257'))).rsplit(':', 1)[-1]
        if command == ('init',):
            port = flag_value(db, '--listen-addr', flag_value(db, '--port', '26257')).rsplit(':', 1)[-1]
            return self.kubectl('exec', f'{self.name}-{ordinal}', '-c', db['name'], '--', './cockroach', 'init',
                                *self.connection_flags(db), '--host=' + self.host(ordinal, sts) + ':' + port, timeout=15)
        return self.kubectl('exec', f'{self.name}-{ordinal}', '-c', db['name'], '--', './cockroach', *command,
                            *self.connection_flags(db), '--host=' + self.host(ordinal, sts), '--port=' + port,
                            '--format=csv', timeout=10)

    def sql(self, query, ordinal=0):
        return self.client('sql', '-e', query, ordinal=ordinal)

    def cluster_id(self, ordinal=0):
        rows = list(csv.reader(io.StringIO(self.require(self.sql('SELECT crdb_internal.cluster_id();', ordinal)))))
        if len(rows) != 2 or len(rows[1]) != 1 or not re.fullmatch(r'[0-9a-fA-F-]{36}', rows[1][0]):
            raise RuntimeError('invalid database cluster identity')
        return rows[1][0]

    def node_state(self, pod):
        db = database_container({'spec': pod['spec']})
        if pod.get('status', {}).get('phase') != 'Running' or not any(s['name'] == db['name'] and 'running' in s.get('state', {}) for s in pod['status'].get('containerStatuses', [])):
            raise RuntimeError('database process is not Running')
        probe = db.get('readinessProbe', {}).get('httpGet', {})
        ports = {p.get('name'): p['containerPort'] for p in db.get('ports', [])}
        port = ports.get(probe.get('port'), probe.get('port'))
        scheme = probe.get('scheme', 'HTTP').lower()
        if probe.get('path') != '/health?ready=1' or probe.get('host') or not isinstance(port, int) or scheme not in ('http', 'https'):
            raise UnsafeState('case requires an HTTP /health?ready=1 readiness probe on the database listener')
        output = self.require(self.kubectl('exec', pod['metadata']['name'], '-c', db['name'], '--', 'curl',
            '--silent', '--show-error', '--insecure', '--connect-timeout', '2', '--max-time', '3',
            '--write-out', '\n%{http_code}', f'{scheme}://localhost:{port}/health?ready=1', timeout=8))
        body, status = output.rsplit('\n', 1)
        payload = json.loads(body)
        if status == '503' and payload.get('error') == 'node is waiting for cluster initialization':
            return 'uninitialized'
        if status == '200':
            return 'initialized'
        raise RuntimeError('database health failed for a reason other than waiting for initialization')

    def deployment_ready(self):
        sts = self.statefulset()
        if int(sts['spec'].get('replicas', 1)) < 2 or sts['spec'].get('podManagementPolicy') != 'Parallel':
            raise UnsafeState('initialization reset requires at least two nodes and Parallel pod management')
        database_container(sts['spec']['template'])
        self.services_ready(sts)
        states = [self.node_state(p) for p in self.pods(sts)]
        if len(set(states)) != 1:
            # A restarting node can expose its waiting endpoint before reading
            # its existing stores. Wait for convergence; persistent mixed state
            # still blocks setup and is never permission to reset data.
            raise RuntimeError('selected nodes mix initialized and uninitialized stores')
        if states[0] == 'initialized':
            identities = [self.cluster_id(i) for i in range(len(states))]
            if len(set(identities)) != 1:
                raise UnsafeState('selected nodes belong to different databases')
        return states[0]

    def services_ready(self, sts):
        service = self.get('service', sts['spec']['serviceName'])
        labels = sts['spec']['template']['metadata'].get('labels', {})
        if service is None or service['spec'].get('clusterIP') != 'None' or not service['spec'].get('publishNotReadyAddresses'):
            raise UnsafeState('headless Service must publish unready node addresses')
        selector = service['spec'].get('selector', {})
        if not selector or any(labels.get(k) != v for k, v in selector.items()):
            raise UnsafeState('headless Service does not select the selected workload')
        for pod in self.get('pods')['items']:
            if all(pod['metadata'].get('labels', {}).get(k) == v for k, v in selector.items()) and not any(ref.get('uid') == sts['metadata']['uid'] for ref in pod['metadata'].get('ownerReferences', [])):
                raise UnsafeState('headless Service also selects another workload')

    def wait(self, check, seconds):
        deadline = time.monotonic() + seconds
        last = 'not ready'
        while time.monotonic() < deadline:
            try:
                if check():
                    return
            except (RuntimeError, ValueError) as error:
                if isinstance(error, UnsafeState):
                    raise
                last = str(error)
            time.sleep(3)
        raise RuntimeError(last)

    def patch_spec(self, sts, fields):
        patch = [{'op': 'test', 'path': '/metadata/uid', 'value': sts['metadata']['uid']},
                 {'op': 'test', 'path': '/metadata/resourceVersion', 'value': sts['metadata']['resourceVersion']}]
        patch += [{'op': 'add', 'path': '/spec/' + k, 'value': v} for k, v in fields.items()]
        self.require(self.kubectl('patch', 'statefulset', self.name, '--type=json', '-p', json.dumps(patch)))

    def delete_pod(self, pod):
        meta = pod['metadata']
        options = {'apiVersion': 'v1', 'kind': 'DeleteOptions', 'preconditions': {'uid': meta['uid']}}
        self.require(self.kubectl('delete', '--raw=' + f'/api/v1/namespaces/{self.namespace}/pods/{meta["name"]}', '-f', '-', input_text=json.dumps(options)))
        self.wait(lambda: (self.get('pod', meta['name']) or {}).get('metadata', {}).get('uid') != meta['uid'], 120)

    def stores(self, sts, count=None):
        db = database_container(sts['spec']['template'])
        tokens = arguments(db)
        stores = [t.split('=', 1)[1] for t in tokens if t.startswith(('--store=', '-s='))]
        stores += [t[2:] for t in tokens if t.startswith('-s') and not t.startswith('-s=') and t != '-s']
        stores += [tokens[i + 1] for i, t in enumerate(tokens[:-1]) if t in ('--store', '-s')]
        claims = {v['metadata']['name'] for v in sts['spec'].get('volumeClaimTemplates', [])}
        mappings = []
        default_store = str(PurePosixPath(db.get('workingDir', '/cockroach')) / 'cockroach-data')
        for store in stores or [default_store]:
            options = dict(p.split('=', 1) for p in store.split(',') if '=' in p)
            path = options.get('path', store.split(',', 1)[0])
            mounts = sorted((m for m in db.get('volumeMounts', []) if path == m['mountPath'].rstrip('/') or path.startswith(m['mountPath'].rstrip('/') + '/')), key=lambda m: len(m['mountPath']), reverse=True)
            if options.get('type') == 'mem' or not path.startswith('/') or str(PurePosixPath(path)) != path or '..' in PurePosixPath(path).parts or not mounts:
                raise UnsafeState('reset requires absolute normalized PVC-backed store paths')
            mount = mounts[0]
            if mount['name'] not in claims or any(mount.get(k) for k in ('subPath', 'subPathExpr', 'readOnly')):
                raise UnsafeState('reset only supports exclusive volumeClaimTemplate stores without subPath')
            for container in sts['spec']['template']['spec'].get('containers', []) + sts['spec']['template']['spec'].get('initContainers', []):
                if container['name'] != db['name'] and any(m['name'] == mount['name'] for m in container.get('volumeMounts', [])):
                    raise UnsafeState('database store is shared with another container')
            relative = path[len(mount['mountPath'].rstrip('/')):].lstrip('/')
            if any(old['volume'] == mount['name'] and (not relative or not old['relative'] or relative == old['relative'] or relative.startswith(old['relative'] + '/') or old['relative'].startswith(relative + '/')) for old in mappings):
                raise UnsafeState('overlapping database stores are unsupported')
            mappings.append({'volume': mount['name'], 'relative': relative})
        result = []
        for i in range(count if count is not None else int(sts['spec'].get('replicas', 1))):
            for mapping in mappings:
                name = f'{mapping["volume"]}-{self.name}-{i}'
                pvc = self.get('pvc', name)
                if not pvc or pvc['metadata'].get('deletionTimestamp') or pvc.get('status', {}).get('phase') != 'Bound':
                    raise UnsafeState('database store PVC is missing or not Bound')
                self.identity(pvc)
                result.append({**mapping, 'claim': name, 'uid': pvc['metadata']['uid']})
        return result

    def bootstrap(self):
        if self.get('namespace', self.namespace, namespace='') is None:
            raise RuntimeError('Karma-managed namespace is missing')
        for kind in ('pods', 'pvc'):
            for obj in self.get(kind)['items']:
                name = obj['metadata']['name']
                if all(obj['metadata'].get('labels', {}).get(k) == v for k, v in self.labels.items()) or name.startswith(self.name + '-') or re.search('-' + re.escape(self.name) + r'-\d+$', name):
                    raise UnsafeState('target StatefulSet is absent but inherited pods or stores remain')
        directory = Path(__file__).resolve().parents[1] / 'resource'
        pending = []
        for filename in ('rbac.yaml', 'services.yaml', 'statefulset.yaml'):
            text = (directory / filename).read_text()
            for key, value in {'BENCH_NAMESPACE': self.namespace, 'BENCH_PARAM_CLUSTER_NAME': self.name,
                               'BENCH_PARAM_CRDB_VERSION': os.environ.get('BENCH_PARAM_CRDB_VERSION', '24.1.0')}.items():
                text = text.replace('${' + key + '}', value)
            for obj in yaml.safe_load_all(text):
                if obj['kind'] == 'StatefulSet':
                    obj['spec']['replicas'] = int(os.environ.get('BENCH_PARAM_REPLICA_COUNT', '3'))
                    if obj['spec']['replicas'] < 2:
                        raise UnsafeState('initialization task requires at least two nodes')
                    db = database_container(obj['spec']['template'])
                    join = ','.join(self.host(i, obj) + ':26257' for i in range(min(3, obj['spec']['replicas'])))
                    db['command'][2] = re.sub(r'--join=\S+', '--join=' + join, db['command'][2])
                existing = self.get(obj['kind'], obj['metadata']['name'])
                if existing:
                    self.identity(existing)
                    if any(existing.get(k) != obj[k] for k in ('rules', 'roleRef', 'subjects') if k in obj) or obj['kind'] == 'Service' and existing['spec'].get('selector') != obj['spec']['selector']:
                        raise UnsafeState('existing bootstrap resource is incompatible')
                else:
                    pending.append(obj)
        for obj in pending:
            self.create(obj)
        self.wait(self.deployment_ready, 300)

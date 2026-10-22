"""Selected deployment inspection, with positive pre-initialization detection."""
import csv
import io
import json
import os
from pathlib import Path
import re
import subprocess
import time

import yaml
from cases.common.cockroachdb.startup import (
    arguments as _startup_arguments,
    certificate_directory as _startup_certificate_directory,
    database_container as _startup_database_container,
    flag_value as _startup_flag_value,
)
from cases.common.cockroachdb.health import observe_initialization_state
from cases.common.cockroachdb.storage import pvc_store_mappings


class UnsafeState(RuntimeError):
    """The selected state cannot be modified without guessing ownership."""


def database_container(template):
    return _startup_database_container(template, error_type=UnsafeState)


def arguments(container):
    return _startup_arguments(container, error_type=UnsafeState)


def flag_value(container, name, default=None):
    return _startup_flag_value(container, name, default, error_type=UnsafeState)


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

    def connection_flags(self, container=None, sts=None):
        if container is None:
            sts = sts or self.statefulset()
            container = database_container(sts['spec']['template'])
        tokens = arguments(container)
        insecure = '--insecure' in tokens or '--insecure=true' in tokens
        if insecure:
            flags = ['--insecure']
        else:
            configured_directory = flag_value(container, '--certs-dir')
            directory = (
                configured_directory
                if configured_directory is not None
                else self.certificate_directory(container, sts=sts)
            )
            flags = ['--certs-dir=' + directory]
        name = flag_value(container, '--cluster-name')
        return flags + (['--cluster-name=' + name] if name else [])

    def certificate_directory(self, container, sts=None):
        configured_directory = flag_value(container, '--certs-dir')
        return _startup_certificate_directory(
            container,
            configured_directory,
            pod_security_context=lambda: (sts or self.statefulset())['spec']['template']['spec'].get('securityContext', {}),
            error_type=UnsafeState,
        )

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
                                *self.connection_flags(db, sts=sts),
                                '--host=' + self.host(ordinal, sts) + ':' + port, timeout=15)
        return self.kubectl('exec', f'{self.name}-{ordinal}', '-c', db['name'], '--', './cockroach', *command,
                            *self.connection_flags(db, sts=sts),
                            '--host=' + self.host(ordinal, sts), '--port=' + port,
                            '--format=csv', timeout=10)

    def sql(self, query, ordinal=0):
        return self.client('sql', '-e', query, ordinal=ordinal)

    def cluster_id(self, ordinal=0):
        rows = list(csv.reader(io.StringIO(self.require(self.sql('SELECT crdb_internal.cluster_id();', ordinal)))))
        if len(rows) != 2 or len(rows[1]) != 1 or not re.fullmatch(r'[0-9a-fA-F-]{36}', rows[1][0]):
            raise RuntimeError('invalid database cluster identity')
        return rows[1][0]

    def node_state(self, pod):
        def execute_curl(pod_name, container_name, argv, timeout):
            return self.require(self.kubectl(
                'exec', pod_name, '-c', container_name, '--', *argv, timeout=timeout
            ))

        return observe_initialization_state(
            pod,
            execute_curl=execute_curl,
            error_type=UnsafeState,
        )

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
        mappings = pvc_store_mappings(sts, error_type=UnsafeState)
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

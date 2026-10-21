"""Case-local inspection and connection handling for version-check preparation."""
import csv
import io
import json
import os
from pathlib import Path
import re
import subprocess
import time
from urllib.parse import urlencode

import yaml

from karma.crdb import CrdbLibrary, KubectlAdapter, ProbeStatus, WorkloadRef
from karma.crdb.health import observe_initialization_state
from karma.crdb.storage import pvc_store_mappings
from karma.crdb.types import (
    AuthenticationError,
    KubernetesAccessError,
    StaleIdentityError,
    UnsupportedLayoutError,
)
from karma.crdb.startup import (
    arguments as _startup_arguments,
    certificate_directory as _startup_certificate_directory,
    client_connection_flags as _startup_client_connection_flags,
    database_container as _startup_database_container,
    flag_value as _startup_flag_value,
)


class UnsafeState(RuntimeError):
    """The selected state cannot be modified without guessing ownership."""


def database_container(template):
    return _startup_database_container(template, error_type=UnsafeState)


def arguments(container):
    return _startup_arguments(container, error_type=UnsafeState)


def flag_value(container, name, default=None):
    return _startup_flag_value(container, name, default, error_type=UnsafeState)


class Cluster:
    def __init__(self, library=None):
        self.namespace = os.environ['BENCH_NAMESPACE']
        self.name = os.environ.get('BENCH_PARAM_CLUSTER_NAME', 'crdb-cluster')
        for value in (self.namespace, self.name):
            if len(value) > 63 or not re.fullmatch(r'[a-z0-9]([-a-z0-9]*[a-z0-9])?', value):
                raise ValueError('namespace and cluster_name must be DNS labels')
        if len(self.name) > 40:
            raise ValueError('cluster_name must leave room for fixture resource suffixes')
        self.labels = {'app.kubernetes.io/name': 'cockroachdb', 'app.kubernetes.io/instance': self.name}
        self.crdb_library = library if library is not None else CrdbLibrary(KubectlAdapter())

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
        return _startup_client_connection_flags(
            container,
            certificate_directory=lambda: self.certificate_directory(container),
            error_type=UnsafeState,
        )

    def certificate_directory(self, container):
        directory = flag_value(container, '--certs-dir')
        return _startup_certificate_directory(
            container,
            directory,
            pod_security_context=lambda: self.statefulset()['spec']['template']['spec'].get('securityContext', {}),
            error_type=UnsafeState,
        )

    def host(self, ordinal, sts=None):
        sts = sts or self.statefulset()
        return f'{self.name}-{ordinal}.{sts["spec"]["serviceName"]}.{self.namespace}.svc.cluster.local'

    def executable(self, container):
        tokens = arguments(container)
        if tokens and tokens[0] == 'exec': tokens = tokens[1:]
        first = tokens[0] if tokens else 'start'
        if first == 'start': return '/cockroach/cockroach'
        if first == 'cockroach' or first.endswith('/cockroach'): return first
        raise UnsafeState('selected server executable is unsupported')

    def client(self, *command, ordinal=0, timeout=10):
        sts = self.statefulset()
        db = database_container(sts['spec']['template'])
        port = flag_value(db, '--sql-addr', flag_value(db, '--listen-addr', flag_value(db, '--port', '26257'))).rsplit(':', 1)[-1]
        if command == ('init',):
            port = flag_value(db, '--listen-addr', flag_value(db, '--port', '26257')).rsplit(':', 1)[-1]
            return self.kubectl('exec', f'{self.name}-{ordinal}', '-c', db['name'], '--', self.executable(db), 'init',
                                *self.connection_flags(db), '--host=' + self.host(ordinal, sts) + ':' + port, timeout=15)
        return self.kubectl('exec', f'{self.name}-{ordinal}', '-c', db['name'], '--', self.executable(db), *command,
                            *self.connection_flags(db), '--host=' + self.host(ordinal, sts), '--port=' + port,
                            '--format=csv', timeout=timeout)

    def sql(self, query, ordinal=0, timeout=10):
        result = self.client('sql', '-e', query, ordinal=ordinal, timeout=timeout)
        # A diagnostic/query permission error says nothing about store health.
        if result.returncode and any(code in result.stderr for code in ('42501','42601','42703','42P01','42883','23514','22023')):
            raise UnsafeState('SQL capability or permission failure is not proof of database failure: ' + result.stderr.strip())
        return result

    def restricted_internals(self, ordinal=0):
        pod = self.get('pod', f'{self.name}-{ordinal}')
        if not pod: raise RuntimeError('selected pod is absent')
        match = re.search(r':v(\d+)\.(\d+)\.', database_container({'spec':pod['spec']})['image'])
        return bool(match and tuple(map(int,match.group(1,2))) >= (26,1))

    def api_cookie(self, ordinal, db, sts):
        pod = self.get('pod', f'{self.name}-{ordinal}')
        cache = getattr(self, '_api_sessions', {})
        saved = cache.get(ordinal)
        if saved and saved['pod_uid'] == pod['metadata']['uid'] and saved['expires'] > time.monotonic():
            return saved['cookie']
        directory = self.certificate_directory(db)
        port = flag_value(db, '--sql-addr', flag_value(db, '--listen-addr', flag_value(db, '--port','26257'))).rsplit(':',1)[-1]
        query = urlencode({'sslmode':'verify-full','sslrootcert':directory+'/ca.crt',
                           'sslcert':directory+'/client.root.crt','sslkey':directory+'/client.root.key'})
        url = f'postgresql://root@{self.host(ordinal,sts)}:{port}/?' + query
        result = self.kubectl('exec', f'{self.name}-{ordinal}', '-c', db['name'], '--', self.executable(db),
            'auth-session','login','root','--only-cookie','--expire-after=2m','--url='+url,timeout=15)
        cookie = self.require(result).strip()
        if not cookie.startswith('session=') or '\n' in cookie or '\r' in cookie or len(cookie)>8192:
            raise UnsafeState('native HTTP authentication returned an unsupported cookie')
        # Session cookies stay in process memory and expire naturally. Never log
        # them, write them to artifacts, or revoke other users' sessions.
        cache[ordinal] = {'pod_uid':pod['metadata']['uid'],'expires':time.monotonic()+90,'cookie':cookie}
        self._api_sessions = cache
        return cookie

    def admin_api(self, path, ordinal=0):
        """Pinned-version status identity API; no unsafe SQL session override."""
        sts = self.statefulset()
        db = database_container(sts['spec']['template'])
        probe = db['readinessProbe']['httpGet']
        port = {p['name']:p['containerPort'] for p in db.get('ports',[])}.get(probe['port'],probe['port'])
        scheme = probe.get('scheme','HTTP').lower()
        flags = []
        if scheme == 'https':
            directory = self.certificate_directory(db)
            flags = ['--cacert',directory+'/ca.crt','--cert',directory+'/client.root.crt','--key',directory+'/client.root.key',
                     '--cookie',self.api_cookie(ordinal,db,sts)]
        result = self.kubectl('exec', f'{self.name}-{ordinal}', '-c', db['name'], '--', 'curl',
            '--fail','--silent','--show-error','--connect-timeout','2','--max-time','5',*flags,
            f'{scheme}://{self.host(ordinal,sts)}:{port}{path}',timeout=10)
        if result.returncode and any(code in result.stderr for code in ('401','403','404')):
            raise UnsafeState('identity API permission/capability error is not proof of broken stores: '+result.stderr.strip())
        payload = json.loads(self.require(result))
        if not isinstance(payload,dict): raise UnsafeState('identity API returned an unsupported payload')
        return payload

    def node_id(self, ordinal=0):
        if not self.restricted_internals(ordinal):
            return self.value('SELECT crdb_internal.node_id();', ordinal)
        self.require(self.sql('SHOW DATABASES;',ordinal))
        payload = self.admin_api('/_status/details/local',ordinal)
        identity = str(payload.get('nodeId',payload.get('node_id','')))
        if not identity.isdigit() or int(identity)<1: raise UnsafeState('identity API omitted the selected node ID')
        return identity

    def initialize(self):
        """Initialize only confirmed fresh stores, including small test topologies."""
        self.require(self.client('init'))
        self.configure_fresh_replication()

    def configure_fresh_replication(self):
        count = int(self.statefulset()['spec']['replicas'])
        if count < 3:
            # Fresh built-in zones otherwise retain 3/5 replicas and never pass
            # real range health on an inherited one/two-node topology. Never
            # normalize these settings on an already initialized healthy store.
            for target in ('RANGE default', 'DATABASE system', 'RANGE meta', 'RANGE system', 'RANGE liveness'):
                self.require(self.sql('ALTER ' + target + ' CONFIGURE ZONE USING num_replicas=' + str(count) + (', num_voters=1' if count==2 else '') + ';'))

    def cluster_id(self, ordinal=0):
        if self.restricted_internals(ordinal):
            payload = self.admin_api('/_admin/v1/cluster',ordinal)
            identity = payload.get('clusterId',payload.get('cluster_id',''))
            if not isinstance(identity,str) or not re.fullmatch(r'[0-9a-fA-F-]{36}',identity):
                raise UnsafeState('identity API omitted the selected cluster UUID')
            return identity
        rows = list(csv.reader(io.StringIO(self.require(self.sql('SELECT crdb_internal.cluster_id();', ordinal)))))
        if len(rows) != 2 or len(rows[1]) != 1 or not re.fullmatch(r'[0-9a-fA-F-]{36}', rows[1][0]):
            raise RuntimeError('invalid database cluster identity')
        return rows[1][0]

    def value(self, query, ordinal=0):
        rows = list(csv.reader(io.StringIO(self.require(self.sql(query, ordinal)))))
        if not rows or len(rows) > 2 or len(rows[0]) != 1:
            raise RuntimeError('expected a single SQL value')
        return rows[1][0] if len(rows) == 2 and rows[1] else ''

    def setting(self, name, ordinal=0):
        if not re.fullmatch(r'[a-z_][a-z0-9_.]*', name):
            raise ValueError('invalid cluster setting name')
        return self.value('SHOW CLUSTER SETTING ' + name + ';', ordinal)

    def node_rows(self, ordinal=0):
        result = self.client('node', 'status', '--all', ordinal=ordinal)
        return list(csv.DictReader(io.StringIO(self.require(result))))

    def liveness_rows(self):
        if any(self.restricted_internals(i) for i in range(int(self.statefulset()['spec']['replicas']))):
            # Native status plus every selected node's live identity, SQL, HTTP
            # and range checks replace restricted SQL internals on 26.1+.
            return [{'node_id':r['id'], 'membership':r.get('membership','active'),
                     'draining':r.get('is_draining','false'),
                     'is_live':str(r.get('is_live')=='true' and r.get('is_available')=='true').lower()}
                    for r in self.node_rows()]
        # The 22.2 gossip_nodes.is_live gossip-client key is unreliable for
        # newer nodes. Read heartbeat state directly from KV;
        # unlike the gossip virtual table this also requires usable quorum.
        result = self.sql("SELECT node_id, membership, draining, "
                          "split_part(expiration, ',', 1)::DECIMAL > now()::DECIMAL AS is_live "
                          "FROM crdb_internal.kv_node_liveness ORDER BY node_id;")
        return list(csv.DictReader(io.StringIO(self.require(result))))

    def ready(self):
        if self.deployment_ready() != 'initialized':
            raise RuntimeError('selected database is not initialized')
        sts = self.statefulset()
        if int(sts['spec'].get('replicas', 1)) < 1:
            raise RuntimeError('selected workload has no running nodes')
        for pod in self.pods(sts):
            if not any(c.get('type') == 'Ready' and c.get('status') == 'True' for c in pod['status'].get('conditions', [])):
                raise RuntimeError('selected database pod is not Ready')
        selected_uid = sts['metadata']['uid']
        try:
            result = self.crdb_library.probe_full_health(
                WorkloadRef(self.namespace, self.name),
                per_node_timeout=5,
            )
        except (AuthenticationError, KubernetesAccessError, StaleIdentityError, UnsupportedLayoutError) as error:
            # These failures describe access or an unsupported observation
            # contract, not evidence that an owned data reset is warranted.
            raise UnsafeState(str(error)) from error
        observation = result.assessment.workload
        if observation.workload_uid != selected_uid:
            raise UnsafeState('selected StatefulSet identity changed during full health inspection')
        latest = self.statefulset()
        if latest['metadata'].get('uid') != selected_uid:
            raise UnsafeState('selected StatefulSet identity changed during full health inspection')
        if result.status is not ProbeStatus.SATISFIED:
            reason = '; '.join(result.reasons) or 'full health requirements are unsatisfied'
            raise RuntimeError(reason)
        return True

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
        if int(sts['spec'].get('replicas', 1)) < 1:
            raise RuntimeError('selected workload has no configured nodes')
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
                raise RuntimeError('selected nodes belong to different databases')
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
        from versions import fallback_pair
        directory = Path(__file__).resolve().parents[1] / 'resource'
        pending = []
        for filename in ('rbac.yaml', 'services.yaml', 'statefulset.yaml'):
            text = (directory / filename).read_text()
            for key, value in {'BENCH_NAMESPACE': self.namespace, 'BENCH_PARAM_CLUSTER_NAME': self.name, 'BENCH_PARAM_BOOTSTRAP_VERSION': fallback_pair()[0]}.items():
                text = text.replace('${' + key + '}', value)
            for obj in yaml.safe_load_all(text):
                if obj['kind'] == 'StatefulSet':
                    obj['spec']['replicas'] = int(os.environ.get('BENCH_PARAM_REPLICA_COUNT', '3'))
                    if obj['spec']['replicas'] < 1:
                        raise UnsafeState('version-check requires at least one node')
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

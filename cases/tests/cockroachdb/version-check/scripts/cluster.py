"""Case-local inspection and connection handling for version-check preparation."""
import json
import os
from pathlib import Path
import re

import yaml

from cases.common.cockroachdb import ProbeStatus, WorkloadRef
from cases.common.cockroachdb.cluster_backend import ClusterBackend
from cases.common.cockroachdb.types import (
    AuthenticationError,
    KubernetesAccessError,
    StaleIdentityError,
    UnsupportedLayoutError,
)
from cases.common.cockroachdb.startup import (
    arguments as _startup_arguments,
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


class Cluster(ClusterBackend):
    error_type = UnsafeState

    def __init__(self, library=None):
        self.namespace = os.environ['BENCH_NAMESPACE']
        self.name = os.environ.get('BENCH_PARAM_CLUSTER_NAME', 'crdb-cluster')
        for value in (self.namespace, self.name):
            if len(value) > 63 or not re.fullmatch(r'[a-z0-9]([-a-z0-9]*[a-z0-9])?', value):
                raise ValueError('namespace and cluster_name must be DNS labels')
        if len(self.name) > 40:
            raise ValueError('cluster_name must leave room for fixture resource suffixes')
        super().__init__(self.namespace, self.name, error_type=self.error_type, library=library)
        self.crdb_library = library if library is not None else self.library
        self.library = self.crdb_library

    def sql(self, query, ordinal=0, timeout=10):
        result = self.client('sql', '-e', query, ordinal=ordinal, timeout=timeout)
        # A diagnostic/query permission error says nothing about store health.
        if result.returncode and any(code in result.stderr for code in ('42501','42601','42703','42P01','42883','23514','22023')):
            raise UnsafeState('SQL capability or permission failure is not proof of database failure: ' + result.stderr.strip())
        return result

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

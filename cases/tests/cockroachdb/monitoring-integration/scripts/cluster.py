"""Case-local inspection and connection handling for monitoring preparation."""
import csv
import io
import os
from pathlib import Path
import re

import yaml
from cases.common.cockroachdb import CrdbLibrary, KubectlAdapter, ProbeStatus, WorkloadRef
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
        self._crdb_library = library or CrdbLibrary(KubectlAdapter())
        for value in (self.namespace, self.name):
            if len(value) > 63 or not re.fullmatch(r'[a-z0-9]([-a-z0-9]*[a-z0-9])?', value):
                raise ValueError('namespace and cluster_name must be DNS labels')
        if len(self.name) > 40:
            raise ValueError('cluster_name must leave room for fixture resource suffixes')
        super().__init__(self.namespace, self.name, error_type=UnsafeState, library=self._crdb_library)

    def sql(self, query, ordinal=0, timeout=10):
        return self.client('sql', '-e', query, ordinal=ordinal, timeout=timeout)

    def cluster_id(self, ordinal=0):
        rows = list(csv.reader(io.StringIO(self.require(self.sql('SELECT crdb_internal.cluster_id();', ordinal)))))
        if len(rows) != 2 or len(rows[1]) != 1 or not re.fullmatch(r'[0-9a-fA-F-]{36}', rows[1][0]):
            raise RuntimeError('invalid database cluster identity')
        return rows[1][0]

    def ready(self):
        if self.deployment_ready() != 'initialized':
            raise RuntimeError('selected database is not initialized')
        sts = self.statefulset()
        if int(sts['spec'].get('replicas', 1)) < 1:
            raise RuntimeError('selected workload has no running nodes')
        for pod in self.pods(sts):
            if not any(c.get('type') == 'Ready' and c.get('status') == 'True' for c in pod['status'].get('conditions', [])):
                raise RuntimeError('selected database pod is not Ready')
        try:
            health = self._crdb_library.probe_full_health(
                WorkloadRef(self.namespace, self.name), per_node_timeout=5
            )
        except (AuthenticationError, KubernetesAccessError, StaleIdentityError, UnsupportedLayoutError) as error:
            # Access, identity, and observation-contract failures are not evidence
            # that resetting the selected stores is appropriate.
            raise UnsafeState(str(error)) from error
        if health.status is not ProbeStatus.SATISFIED:
            raise RuntimeError('selected database has unavailable or under-replicated ranges: ' + '; '.join(health.reasons))
        return True

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
                               'BENCH_PARAM_UNUSED_FROM_VERSION': '24.1'}.items():
                text = text.replace('${' + key + '}', value)
            for obj in yaml.safe_load_all(text):
                if obj['kind'] == 'StatefulSet':
                    obj['spec']['replicas'] = int(os.environ.get('BENCH_PARAM_REPLICA_COUNT', '3'))
                    if obj['spec']['replicas'] < 1:
                        raise UnsafeState('monitoring requires at least one node')
                    db = database_container(obj['spec']['template'])
                    metrics_port = int(os.environ.get('BENCH_PARAM_METRICS_PORT', '8080'))
                    db['command'][2] = db['command'][2].replace('0.0.0.0:8080', '0.0.0.0:' + str(metrics_port))
                    for port in db.get('ports', []):
                        if port.get('name') == 'http': port['containerPort'] = metrics_port
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

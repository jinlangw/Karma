"""Case-local inspection and connection handling for upgrade preparation."""
import csv
import io
import os
from pathlib import Path
import re

import yaml
from cases.common.cockroachdb.cluster_backend import ClusterBackend
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

    def __init__(self):
        self.namespace = os.environ['BENCH_NAMESPACE']
        self.name = os.environ.get('BENCH_PARAM_CLUSTER_NAME', 'crdb-cluster')
        for value in (self.namespace, self.name):
            if len(value) > 63 or not re.fullmatch(r'[a-z0-9]([-a-z0-9]*[a-z0-9])?', value):
                raise ValueError('namespace and cluster_name must be DNS labels')
        if len(self.name) > 40:
            raise ValueError('cluster_name must leave room for fixture resource suffixes')
        self.labels = {'app.kubernetes.io/name': 'cockroachdb', 'app.kubernetes.io/instance': self.name}

    def client(self, *command, ordinal=0, timeout=10):
        sts = self.statefulset()
        db = database_container(sts['spec']['template'])
        port = flag_value(db, '--sql-addr', flag_value(db, '--listen-addr', flag_value(db, '--port', '26257'))).rsplit(':', 1)[-1]
        if command == ('init',):
            port = flag_value(db, '--listen-addr', flag_value(db, '--port', '26257')).rsplit(':', 1)[-1]
            return self.kubectl('exec', f'{self.name}-{ordinal}', '-c', db['name'], '--', './cockroach', 'init',
                                *self.connection_flags(db), '--host=' + self.host(ordinal, sts) + ':' + port, timeout=15)
        return self.kubectl('exec', f'{self.name}-{ordinal}', '-c', db['name'], '--', './cockroach', *command,
                            *self.connection_flags(db), '--host=' + self.host(ordinal, sts), '--port=' + port,
                            '--format=csv', timeout=timeout)

    def sql(self, query, ordinal=0, timeout=10):
        return self.client('sql', '-e', query, ordinal=ordinal, timeout=timeout)

    def cluster_id(self, ordinal=0):
        rows = list(csv.reader(io.StringIO(self.require(self.sql('SELECT crdb_internal.cluster_id();', ordinal)))))
        if len(rows) != 2 or len(rows[1]) != 1 or not re.fullmatch(r'[0-9a-fA-F-]{36}', rows[1][0]):
            raise RuntimeError('invalid database cluster identity')
        return rows[1][0]

    def liveness_rows(self):
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
        if int(sts['spec'].get('replicas', 1)) < 3:
            raise UnsafeState('rolling major upgrades require at least three selected nodes')
        for pod in self.pods(sts):
            if not any(c.get('type') == 'Ready' and c.get('status') == 'True' for c in pod['status'].get('conditions', [])):
                raise RuntimeError('selected database pod is not Ready')
        active = [row for row in self.node_rows() if row.get('membership') != 'decommissioned']
        if len(active) != int(sts['spec']['replicas']):
            raise UnsafeState('selected database has unexpected active or dead node records')
        ids = [self.value('SELECT crdb_internal.node_id();', i) for i in range(int(sts['spec']['replicas']))]
        if len(set(ids)) != len(ids) or set(ids) != {row['id'] for row in active}:
            raise UnsafeState('selected SQL gateways do not identify exactly the active selected nodes')
        live = [row for row in self.liveness_rows() if row.get('membership') != 'decommissioned']
        if len(live) != len(ids) or {row.get('node_id') for row in live} != set(ids):
            raise UnsafeState('fresh database liveness has unexpected active or dead node records')
        for row in live:
            if row.get('membership') != 'active' or row.get('draining', '').lower() not in ('false', 'f'):
                raise UnsafeState('fresh database liveness has incomplete decommissioning or draining nodes')
            if row.get('is_live', '').lower() not in ('true', 't'):
                raise RuntimeError('selected database has an expired live-node heartbeat')
        for row in active:
            if row.get('membership') not in ('active', None) or row.get('is_draining', 'false').lower() != 'false':
                raise UnsafeState('selected database has incomplete decommissioning or draining nodes')
            if row.get('is_available', '').lower() != 'true':
                raise RuntimeError('selected database has an unavailable node')
            for key in ('ranges_unavailable', 'ranges_underreplicated'):
                if key not in row or int(row[key]) != 0:
                    raise RuntimeError('selected database ranges are not ready for a rolling upgrade')
        return True

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

    def bootstrap(self):
        if self.get('namespace', self.namespace, namespace='') is None:
            raise RuntimeError('Karma-managed namespace is missing')
        for kind in ('pods', 'pvc'):
            for obj in self.get(kind)['items']:
                name = obj['metadata']['name']
                if all(obj['metadata'].get('labels', {}).get(k) == v for k, v in self.labels.items()) or name.startswith(self.name + '-') or re.search('-' + re.escape(self.name) + r'-\d+$', name):
                    raise UnsafeState('target StatefulSet is absent but inherited pods or stores remain')
        source = os.environ.get('BENCH_PARAM_FROM_VERSION', '23.2')
        if source.count('.') == 1:
            source += '.0'
        directory = Path(__file__).resolve().parents[1] / 'resource'
        pending = []
        for filename in ('rbac.yaml', 'services.yaml', 'statefulset.yaml'):
            text = (directory / filename).read_text()
            for key, value in {'BENCH_NAMESPACE': self.namespace, 'BENCH_PARAM_CLUSTER_NAME': self.name,
                               'BENCH_PARAM_FROM_VERSION': source}.items():
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

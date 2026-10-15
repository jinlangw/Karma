"""Disposable same-image database and namespace-scoped, in-cluster script execution."""
import copy
import csv
import io
import json
import re
import time
import uuid

import yaml

from targets import RATE, object_sql, quote

RUNNER_IMAGE = 'alpine/k8s:1.32.1@sha256:1892fdf41c09ec2b08a334daf352b3a24e79c1138690d035c804f21c8ec7aac6'


class Fixture:
    def __init__(self, source, baseline, script):
        self.source, self.baseline, self.script = source, baseline, script
        self.token = uuid.uuid4().hex[:12]
        self.namespace = 'oracle-rollback-' + self.token
        self.name = 'rehearsal-' + self.token
        self.uid = None
        self.created = False
        self.labels = {'karma.dev/fixture': 'rollback-oracle', 'karma.dev/nonce': self.token}
        self.secure = baseline['report']['tls']
        self.flags = ['--certs-dir=/certs'] if self.secure else ['--insecure']
        self.witnesses = []

    def k(self, *args, timeout=30, input_text=None):
        return self.source.kubectl(*args, timeout=timeout, input_text=input_text, namespace=self.namespace)

    def require(self, result): return self.source.require(result)

    def get(self, kind, name=None):
        result = self.require(self.k('get', kind, *([name, '--ignore-not-found'] if name else []), '-o', 'json'))
        return json.loads(result) if result.strip() else None

    def create(self, kind, name, **fields):
        api = {'StatefulSet': 'apps/v1', 'Role': 'rbac.authorization.k8s.io/v1',
               'RoleBinding': 'rbac.authorization.k8s.io/v1'}.get(kind, 'v1')
        obj = {'apiVersion': api, 'kind': kind,
               'metadata': {'name': name, 'namespace': self.namespace, 'labels': self.labels}, **fields}
        self.require(self.k('create', '-f', '-', input_text=json.dumps(obj)))

    def wait(self, check, seconds):
        deadline = time.monotonic() + seconds
        last = 'fixture not ready'
        while time.monotonic() < deadline:
            try:
                if check(): return
            except (RuntimeError, ValueError) as error: last = str(error)
            time.sleep(2)
        raise RuntimeError(last)

    def sql(self, query):
        return self.k('exec', self.name + '-0', '-c', 'db', '--', '/cockroach/cockroach', 'sql',
                      *self.flags, '--host=localhost', '--format=csv', '-e', query)

    def rows(self, query):
        return list(csv.DictReader(io.StringIO(self.require(self.sql(query)))))

    def value(self, query):
        rows = list(csv.reader(io.StringIO(self.require(self.sql(query)))))
        if len(rows) != 2 or len(rows[1]) != 1: raise RuntimeError('fixture SQL did not return one value')
        return rows[1][0]

    def setup(self):
        self.require(self.k('create', '-f', '-', input_text=json.dumps({'apiVersion': 'v1', 'kind': 'Namespace',
                     'metadata': {'name': self.namespace, 'labels': self.labels}})))
        self.created = True
        self.uid = self.get('namespace', self.namespace)['metadata']['uid']
        print('Created owned rollback fixture namespace ' + self.namespace, flush=True)
        image = self.baseline['fixture_image']
        if not re.fullmatch(r'(?:docker.io/)?cockroachdb/cockroach:v\d+\.\d+\.\d+', image):
            raise RuntimeError('rollback fixture requires a pinned official CockroachDB image')
        volumes = [{'name': 'data', 'emptyDir': {}}]
        db = {'name': 'db', 'image': image, 'imagePullPolicy': 'IfNotPresent',
              'command': ['/cockroach/cockroach', 'start-single-node', *self.flags,
                          '--listen-addr=0.0.0.0:26257', '--http-addr=0.0.0.0:8080',
                          '--store=/cockroach/cockroach-data', '--cache=32MiB', '--max-sql-memory=32MiB'],
              'volumeMounts': [{'name': 'data', 'mountPath': '/cockroach/cockroach-data'}],
              'resources': {'requests': {'cpu': '100m', 'memory': '256Mi'}, 'limits': {'memory': '768Mi'}},
              'readinessProbe': {'httpGet': {'path': '/health?ready=1', 'port': 8080,
                                          'scheme': 'HTTPS' if self.secure else 'HTTP'}, 'periodSeconds': 2},
              'securityContext': {'allowPrivilegeEscalation': False, 'capabilities': {'drop': ['ALL']}}}
        spec = {'automountServiceAccountToken': False, 'terminationGracePeriodSeconds': 2,
                'containers': [db], 'volumes': volumes}
        if self.secure:
            db['command'].append('--advertise-addr=localhost:26257')
            volumes.append({'name': 'certs', 'emptyDir': {}})
            db['volumeMounts'].append({'name': 'certs', 'mountPath': '/certs', 'readOnly': True})
            script = ('/cockroach/cockroach cert create-ca --certs-dir=/certs --ca-key=/certs/ca.key && '
                      '/cockroach/cockroach cert create-node localhost 127.0.0.1 ' + self.name + '-0 ' + self.name + '-0.' + self.name + '.' + self.namespace + '.svc.cluster.local '
                      '--certs-dir=/certs --ca-key=/certs/ca.key && '
                      '/cockroach/cockroach cert create-client root --certs-dir=/certs --ca-key=/certs/ca.key')
            spec['initContainers'] = [{'name': 'certificates', 'image': image, 'command': ['/bin/sh', '-ec', script],
                                      'volumeMounts': [{'name': 'certs', 'mountPath': '/certs'}],
                                      'resources': {'requests': {'cpu': '10m', 'memory': '32Mi'}, 'limits': {'memory': '256Mi'}}}]
        self.create('Service', self.name, spec={'clusterIP': 'None', 'publishNotReadyAddresses': True,
                    'selector': {'karma.dev/database': self.token}, 'ports': [{'name': 'sql', 'port': 26257}]})
        self.create('StatefulSet', self.name, spec={'serviceName': self.name, 'replicas': 1,
                    'selector': {'matchLabels': {'karma.dev/database': self.token}},
                    'template': {'metadata': {'labels': {'karma.dev/database': self.token}}, 'spec': spec}})
        self.wait(lambda: self.sql('SELECT 1;').returncode == 0, 180)
        self.wait(lambda: any(c.get('type') == 'Ready' and c.get('status') == 'True' for c in self.get('pod', self.name + '-0').get('status', {}).get('conditions', [])), 90)
        self.seed()

    def seed(self):
        scenario = self.baseline['scenario']
        self.default_rate = int(self.value("SELECT crdb_internal.cluster_setting_encoded_default('" + RATE + "');"))
        if self.default_rate != scenario['rate_default']:
            raise RuntimeError('fixture/source setting defaults differ for the selected version')
        # Reproduce root inheritance context; root GC itself is outside rollback scope.
        self.require(self.sql('ALTER RANGE default CONFIGURE ZONE USING gc.ttlseconds=' + str(scenario['root_gc']) + ';'))
        self.expected_rate = self.default_rate if scenario['reset_rate'] else self.default_rate * 2
        seed_rate = scenario['rate'] if scenario['reset_rate'] else self.expected_rate
        self.require(self.sql('SET CLUSTER SETTING ' + RATE + "='" + str(seed_rate) + "B';"))
        created = set()
        for zone in scenario['zones']:
            db = zone['database']
            if db not in created:
                self.require(self.sql('CREATE DATABASE IF NOT EXISTS ' + quote(db) + ';'))
                created.add(db)
            if zone['kind'] == 'TABLE':
                self.require(self.sql('CREATE SCHEMA IF NOT EXISTS ' + quote(db) + '.' + quote(zone['schema']) + ';'))
                table = '.'.join(quote(zone[k]) for k in ('database', 'schema', 'table'))
                self.require(self.sql('CREATE TABLE ' + table + '(id INT PRIMARY KEY, payload STRING); INSERT INTO ' + table + " VALUES(1,'fixture-witness');"))
                self.witnesses.append(table)
            # Sentinel fields expose accidental whole-zone reset, without copying
            # source placement constraints or creating unavailable replicas.
            fields = 'range_min_bytes=67108864, range_max_bytes=268435456'
            if zone['gc'] is not None: fields += ', gc.ttlseconds=' + str(zone['gc'])
            self.require(self.sql('ALTER ' + object_sql(zone) + ' CONFIGURE ZONE USING ' + fields + ';'))
        guard_db = 'guard_' + self.token
        self.require(self.sql('CREATE DATABASE ' + quote(guard_db) + '; CREATE TABLE ' + quote(guard_db) + ".public.witness(id INT PRIMARY KEY,payload STRING); INSERT INTO " + quote(guard_db) + ".public.witness VALUES(1,'fixture-witness');"))
        self.witnesses.append(quote(guard_db) + '.public.witness')
        self.require(self.sql('ALTER TABLE ' + self.witnesses[-1] + ' CONFIGURE ZONE USING gc.ttlseconds=' + str(scenario['root_gc'] + 1000) + ';'))
        self.before = self.snapshot()

    def snapshot(self):
        settings = {r['variable']: r['value'] for r in self.rows('SELECT variable,value FROM crdb_internal.cluster_settings ORDER BY variable;')}
        zones = {r['target']: yaml.safe_load(r['raw_config_yaml']) for r in self.rows('SELECT target,raw_config_yaml FROM crdb_internal.zones WHERE subzone_id=0;')}
        rate_bytes = int(self.value("SELECT COALESCE((SELECT value::INT8 FROM system.settings WHERE name='" + RATE + "'), "
                                    "crdb_internal.cluster_setting_encoded_default('" + RATE + "')::INT8);"))
        encoded = self.rows("SELECT name,value FROM system.settings WHERE name!='" + RATE + "' ORDER BY name;")
        return {'settings': settings, 'encoded_settings': encoded, 'rate_bytes': rate_bytes, 'zones': zones, 'spec': self.get('statefulset', self.name)['spec'],
                'pod_uid': self.get('pod', self.name + '-0')['metadata']['uid'],
                'data': {table: self.rows('SELECT * FROM ' + table + ' ORDER BY id;') for table in self.witnesses}}

    def run_script(self):
        self.create('ConfigMap', 'candidate', data={'rollback.sh': self.script})
        self.create('ServiceAccount', 'runner')
        self.create('Role', 'runner', rules=[
            {'apiGroups': [''], 'resources': ['pods'], 'verbs': ['get', 'list']},
            {'apiGroups': ['apps'], 'resources': ['statefulsets'], 'verbs': ['get', 'list']},
            {'apiGroups': [''], 'resources': ['pods/exec'], 'resourceNames': [self.name + '-0'], 'verbs': ['create']}])
        self.create('RoleBinding', 'runner', roleRef={'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'Role', 'name': 'runner'},
                    subjects=[{'kind': 'ServiceAccount', 'name': 'runner', 'namespace': self.namespace}])
        self.create('Pod', 'runner', spec={'serviceAccountName': 'runner', 'restartPolicy': 'Never',
                    'activeDeadlineSeconds': 180, 'terminationGracePeriodSeconds': 2,
                    'securityContext': {'runAsNonRoot': True, 'runAsUser': 65532, 'runAsGroup': 65532},
                    'containers': [{'name': 'runner', 'image': RUNNER_IMAGE, 'imagePullPolicy': 'IfNotPresent',
                      'command': ['/bin/sh', '-ec', '/bin/sh -n /candidate/rollback.sh; exec /bin/sh /candidate/rollback.sh "$1" "$2"', 'runner', self.namespace, self.name],
                      'env': [{'name': 'HOME', 'value': '/tmp'}, {'name': 'BENCH_NAMESPACE', 'value': self.namespace},
                              {'name': 'BENCH_PARAM_CLUSTER_NAME', 'value': self.name}],
                      'securityContext': {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True,
                                          'capabilities': {'drop': ['ALL']}},
                      'volumeMounts': [{'name': 'candidate', 'mountPath': '/candidate', 'readOnly': True}, {'name': 'tmp', 'mountPath': '/tmp'}],
                      'resources': {'requests': {'cpu': '10m', 'memory': '32Mi'}, 'limits': {'memory': '128Mi'}}}],
                    'volumes': [{'name': 'candidate', 'configMap': {'name': 'candidate'}}, {'name': 'tmp', 'emptyDir': {}}]})
        def finished():
            pod = self.get('pod', 'runner')
            return pod and pod.get('status', {}).get('phase') in ('Succeeded', 'Failed')
        self.wait(finished, 210)
        logs = self.require(self.k('logs', 'runner', timeout=15))
        if logs: print(logs[-4000:], flush=True)
        if self.get('pod', 'runner')['status']['phase'] != 'Succeeded':
            raise RuntimeError('rollback script failed in isolated fixture runner')

    def verify(self):
        actual = self.snapshot()
        expected = copy.deepcopy(self.before)
        # Compare exact bytes separately because SHOW rounds the display value.
        if actual['rate_bytes'] != self.expected_rate:
            raise RuntimeError('rollback script did not restore the expected snapshot rate')
        expected['settings'][RATE] = actual['settings'][RATE]
        expected['rate_bytes'] = self.expected_rate
        for target in self.baseline['scenario']['gc_targets']:
            key = object_sql(target)
            # SHOW uses minimally quoted SQL identifiers; match the target through
            # the fixture's own zone metadata instead of guessing its rendering.
            rows = self.rows("SELECT target FROM crdb_internal.zones WHERE database_name='" + target['database'].replace("'", "''") + "' AND " +
                             ("target LIKE 'DATABASE %'" if target['kind'] == 'DATABASE' else "schema_name='" + target['schema'].replace("'", "''") + "' AND table_name='" + target['table'].replace("'", "''") + "' AND subzone_id=0") + ';')
            if len(rows) != 1: raise RuntimeError('selected rollback zone disappeared')
            key = rows[0]['target']
            expected['zones'][key]['gc'] = {'ttlseconds': self.baseline['scenario']['root_gc']}
        if actual != expected:
            changed = [part for part in expected if expected[part] != actual[part]]
            raise RuntimeError('rollback missed a target or changed unrelated fixture state: ' + ', '.join(changed))
        if self.value('SELECT 1;') != '1': raise RuntimeError('fixture no longer serves SQL')
        print('Rollback executed correctly; unrelated fixture settings/zones/data preserved.', flush=True)

    def cleanup(self):
        if not self.created: return
        obj = self.get('namespace', self.namespace)
        if not obj: return
        if (self.uid is not None and obj['metadata']['uid'] != self.uid) or any(obj['metadata'].get('labels', {}).get(k) != v for k, v in self.labels.items()):
            raise RuntimeError('fixture namespace ownership changed; refusing cleanup')
        self.uid = obj['metadata']['uid']
        options = {'apiVersion': 'v1', 'kind': 'DeleteOptions', 'preconditions': {'uid': self.uid}}
        self.require(self.k('delete', '--raw=/api/v1/namespaces/' + self.namespace, '-f', '-', input_text=json.dumps(options)))
        self.require(self.k('wait', '--for=delete', 'namespace/' + self.namespace, '--timeout=90s', timeout=100))
        print('Cleaned owned rollback fixture namespace ' + self.namespace, flush=True)

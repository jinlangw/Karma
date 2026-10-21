"""Owned store/PKI guards and resumable fresh-store preparation."""
import json
import re
import shlex

from cluster import UnsafeState, database_container, flag_value
from karma.crdb.security import mounted_secret_signatures


def signatures(cluster, template):
    return mounted_secret_signatures(
        template,
        lambda name: cluster.get('secret', name),
        error_type=UnsafeState,
    )


class Stores:
    def preflight(self, sts, baseline=None):
        cluster = self.cluster
        stores = cluster.stores(sts)
        db = database_container(sts['spec']['template'])
        port = flag_value(db, '--listen-addr', flag_value(db, '--port', '26257')).rsplit(':', 1)[-1]
        service = sts['spec']['serviceName']
        hosts = {f'{cluster.name}-{i}.{service}{suffix}' for i in range(int(sts['spec'].get('replicas', 1)))
                 for suffix in ('', '.' + cluster.namespace, '.' + cluster.namespace + '.svc', '.' + cluster.namespace + '.svc.cluster.local')}
        join = flag_value(db, '--join', '')
        shell = (db.get('command') or [None])[0] in ('/bin/bash', '/bin/sh', 'bash', 'sh')
        for env in db.get('env', []):
            if env.get('valueFrom', {}).get('fieldRef', {}).get('fieldPath') == 'metadata.namespace' or env.get('value') == cluster.namespace:
                name = env['name']
                join = join.replace('$(' + name + ')', cluster.namespace)
                if shell:
                    join = join.replace('${' + name + '}', cluster.namespace)
                    join = re.sub(r'\$' + re.escape(name) + r'(?![a-zA-Z0-9_])', lambda _: cluster.namespace, join)
        seeds = [seed.strip() for seed in join.split(',')]
        endpoints = [seed.rsplit(':', 1) if ':' in seed else (seed, '26257') for seed in seeds]
        if not endpoints or any(host not in hosts or seed_port != port for host, seed_port in endpoints):
            raise UnsafeState('join seeds must resolve exclusively to selected nodes before stores can be reset')
        cluster.require(cluster.kubectl('exec', cluster.name + '-0', '-c', db['name'], '--', '/bin/bash', '-ec', 'command -v readlink mkdir rm touch', timeout=10))
        for pod in cluster.pods(sts):
            actual = database_container({'spec': pod['spec']})
            if any(actual.get(k, []) != db.get(k, []) for k in ('command', 'args')):
                raise UnsafeState('selected pods have not converged to the inherited startup template')
            expected = {v['metadata']['name']: f'{v["metadata"]["name"]}-{cluster.name}-{pod["metadata"]["name"].rsplit("-", 1)[1]}' for v in sts['spec'].get('volumeClaimTemplates', [])}
            volumes = {v['name']: v.get('persistentVolumeClaim', {}).get('claimName') for v in pod['spec'].get('volumes', [])}
            if any(volumes.get(k) != v for k, v in expected.items()):
                raise UnsafeState('selected pod does not mount its expected owned claims')
        if cluster.connection_flags(db)[0] != '--insecure':
            directory = cluster.certificate_directory(db)
            mounts = sorted((m for m in db.get('volumeMounts', []) if directory == m['mountPath'].rstrip('/') or directory.startswith(m['mountPath'].rstrip('/') + '/')), key=lambda m: len(m['mountPath']), reverse=True)
            volumes = {v['name']: v for v in sts['spec']['template']['spec'].get('volumes', [])}
            if not mounts or not any(k in volumes.get(mounts[0]['name'], {}) for k in ('secret', 'projected')):
                raise UnsafeState('TLS initialization reset requires Secret-backed certificate material')
            checks = ' && '.join('test -s ' + shlex.quote(directory.rstrip('/') + '/' + file) for file in ('ca.crt', 'node.crt', 'node.key', 'client.root.crt', 'client.root.key'))
            cluster.require(cluster.kubectl('exec', cluster.name + '-0', '-c', db['name'], '--', '/bin/bash', '-ec', checks, timeout=10))
            cluster.require(cluster.kubectl('exec', cluster.name + '-0', '-c', db['name'], '--', './cockroach', 'cert', 'list', '--certs-dir=' + directory, timeout=10))
            probe = db.get('readinessProbe', {}).get('httpGet', {})
            ports = {item.get('name'): item['containerPort'] for item in db.get('ports', [])}
            http_port = ports.get(probe.get('port'), probe.get('port'))
            if probe.get('scheme', 'HTTP') != 'HTTPS':
                raise UnsafeState('TLS initialization preparation requires an HTTPS health listener')
            cluster.require(cluster.kubectl('exec', cluster.name + '-0', '-c', db['name'], '--', 'curl',
                '--silent', '--show-error', '--connect-timeout', '2', '--max-time', '5',
                '--cacert', directory + '/ca.crt', '--cert', directory + '/client.root.crt', '--key', directory + '/client.root.key',
                f'https://{cluster.host(0, sts)}:{http_port}/health?ready=1', timeout=10))
        signatures(cluster, sts['spec']['template'])
        self.exclusive(sts, stores)
        for index in range(len(stores)):
            helper = cluster.get('pod', f'{cluster.name}-upgrade-reset-{index}')
            if helper and (baseline is None or not any(ref.get('uid') == baseline['metadata']['uid'] for ref in helper['metadata'].get('ownerReferences', []))):
                raise UnsafeState('reset helper name is occupied by another resource')
        if sts['spec'].get('persistentVolumeClaimRetentionPolicy', {}).get('whenScaled', 'Retain') != 'Retain':
            raise UnsafeState('scale-down would delete selected PVCs')
        if sts['spec'].get('updateStrategy', {}).get('type', 'RollingUpdate') not in ('RollingUpdate', 'OnDelete'):
            raise UnsafeState('unsupported update strategy')
        return stores

    def exclusive(self, sts, stores, baseline=None):
        cluster = self.cluster
        claims = {s['claim'] for s in stores}
        for pod in cluster.get('pods')['items']:
            used = {v['persistentVolumeClaim']['claimName'] for v in pod['spec'].get('volumes', []) if 'persistentVolumeClaim' in v}
            if baseline and pod['metadata'].get('annotations', {}).get('karma.dev/reset-nonce') == baseline['data']['nonce'] and any(ref.get('uid') == baseline['metadata']['uid'] for ref in pod['metadata'].get('ownerReferences', [])):
                continue
            if used & claims and not any(ref.get('uid') == sts['metadata']['uid'] for ref in pod['metadata'].get('ownerReferences', [])):
                raise UnsafeState('selected PVC is also mounted by another workload')
        for kind in ('statefulsets', 'deployments', 'daemonsets', 'jobs', 'replicasets', 'replicationcontrollers', 'cronjobs'):
            for obj in cluster.get(kind)['items']:
                if obj['metadata']['uid'] == sts['metadata']['uid']:
                    continue
                spec = obj['spec']['jobTemplate']['spec'] if kind == 'cronjobs' else obj['spec']
                used = {v['persistentVolumeClaim']['claimName'] for v in spec.get('template', {}).get('spec', {}).get('volumes', []) if 'persistentVolumeClaim' in v}
                if used & claims:
                    raise UnsafeState('selected PVC is referenced by another controller')

    def reset_store(self, baseline, store, index):
        cluster = self.cluster
        self.preserved(baseline, cluster.statefulset(), paused=True)
        self.exclusive(cluster.statefulset(), json.loads(baseline['data']['stores']), baseline)
        name = f'{cluster.name}-upgrade-reset-{index}'
        nonce = baseline['data']['nonce']
        marker = '.karma-upgrade-reset-' + nonce + '-' + str(index)
        directory = '/volume' + ('/' + store['relative'] if store['relative'] else '')
        script = ('set -eu\n'
                  + 'directory=' + shlex.quote(directory) + '\n'
                  + 'marker=/volume/' + marker + '\n'
                  + 'mkdir -p "$directory"\n'
                  + '[ "$(readlink -f "$directory")" = "$directory" ] || exit 21\n'
                  + 'if [ ! -f "$marker" ]; then\n'
                  + '  shopt -s dotglob nullglob\n'
                  + '  for entry in "$directory"/*; do\n'
                  + '    [ "${entry##*/}" = lost+found ] && continue\n'
                  + '    rm -rf -- "$entry"\n'
                  + '  done\n'
                  + '  touch "$marker"\nfi\n')
        pod = cluster.get('pod', name)
        if pod:
            if pod['metadata'].get('annotations', {}).get('karma.dev/reset-nonce') != nonce or not any(ref.get('uid') == baseline['metadata']['uid'] for ref in pod['metadata'].get('ownerReferences', [])):
                raise UnsafeState('reset helper belongs to another fixture')
            if pod.get('status', {}).get('phase') == 'Failed':
                cluster.delete_pod(pod)
                pod = None
        if pod is None:
            db = database_container(json.loads(baseline['data']['original_template']))
            cluster.create({'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': name, 'namespace': cluster.namespace,
                'labels': {'karma.dev/fixture': 'upgrade-reset'}, 'annotations': {'karma.dev/reset-nonce': nonce},
                'ownerReferences': [{'apiVersion': 'v1', 'kind': 'ConfigMap', 'name': self.name, 'uid': baseline['metadata']['uid']}]},
                'spec': {'restartPolicy': 'Never', 'automountServiceAccountToken': False,
                    'securityContext': json.loads(baseline['data']['original_template'])['spec'].get('securityContext', {}),
                    'containers': [{'name': 'reset', 'image': db['image'], 'command': ['/bin/bash', '-ec', script],
                        'securityContext': db.get('securityContext', {}),
                        'resources': {'requests': {'cpu': '10m', 'memory': '32Mi'}, 'limits': {'memory': '128Mi'}},
                        'volumeMounts': [{'name': 'store', 'mountPath': '/volume'}]}],
                    'volumes': [{'name': 'store', 'persistentVolumeClaim': {'claimName': store['claim']}}]}})
        def complete():
            obj = cluster.get('pod', name)
            if obj and obj.get('status', {}).get('phase') == 'Failed':
                raise UnsafeState('store reset helper failed; workload remains stopped')
            return obj and obj.get('status', {}).get('phase') == 'Succeeded'
        cluster.wait(complete, 180)
        cluster.delete_pod(cluster.get('pod', name))

"""Owned store/PKI guards and resumable fresh-store preparation."""
import hashlib
import json
import re
import shlex

from cluster import UnsafeState, database_container


def signatures(cluster, template):
    names = set()
    for volume in template['spec'].get('volumes', []):
        if 'secret' in volume:
            names.add(volume['secret']['secretName'])
        names |= {s['secret']['name'] for s in volume.get('projected', {}).get('sources', []) if 'secret' in s}
    result = {}
    for name in sorted(names):
        secret = cluster.get('secret', name)
        if secret is None:
            raise UnsafeState('mounted Secret is missing')
        result[name] = {'uid': secret['metadata']['uid'], 'sha256': hashlib.sha256(json.dumps(secret.get('data', {}), sort_keys=True).encode()).hexdigest()}
    return result


class Stores:
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
        name = f'{cluster.name}-monitoring-reset-{index}'
        nonce = baseline['data']['nonce']
        marker = '.karma-monitoring-reset-' + nonce + '-' + str(index)
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
                'labels': {'karma.dev/fixture': 'monitoring-reset'}, 'annotations': {'karma.dev/reset-nonce': nonce},
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

#!/usr/bin/env python3
"""Three independently verified units, with resumable target-only preparation."""
import argparse
import copy
import json
import re
import shlex
import subprocess
import sys
import uuid

from cluster import Cluster, UnsafeState, arguments, database_container, flag_value
from cases.common.cockroachdb.security import mounted_secret_signatures


def signatures(cluster, template):
    return mounted_secret_signatures(
        template,
        lambda name: cluster.get('secret', name),
        error_type=UnsafeState,
    )


def fault_template(template, value):
    result = copy.deepcopy(template)
    db = database_container(result)
    before = arguments(db)
    flag_value(db, '--join')  # Reject ambiguous flags before rewriting.
    command = db.get('command', [])
    if len(command) == 3 and command[0] in ('/bin/bash', '/bin/sh', 'bash', 'sh') and command[1] in ('-c', '-ec'):
        if any(t == '--join' or t.startswith('--join=') for t in db.get('args', [])):
            raise UnsafeState('join flag in shell positional arguments is unsupported')
        pattern = r'''(?<!\S)--join(?:=(?:'[^']*'|"[^"]*"|\S+)|\s+(?:'[^']*'|"[^"]*"|\S+))(?=\s|$)'''
        updated, count = re.subn(pattern, '--join=' + value, command[2])
        command[2] = updated if count else command[2].rstrip() + ' --join=' + value
    else:
        for key in ('command', 'args'):
            tokens = db.get(key, [])
            for i, token in enumerate(tokens):
                if token.startswith('--join='):
                    tokens[i] = '--join=' + value
                elif token == '--join':
                    if i + 1 == len(tokens):
                        raise UnsafeState('join flag crosses command/args boundary')
                    tokens[i + 1] = value
        if flag_value(db, '--join') is None:
            db.setdefault('args', []).append('--join=' + value)
    def without_join(tokens):
        result = []
        index = 0
        while index < len(tokens):
            if tokens[index] == '--join':
                index += 2
            elif tokens[index].startswith('--join='):
                index += 1
            else:
                result.append(tokens[index]); index += 1
        return result
    if without_join(before) != without_join(arguments(db)) or flag_value(db, '--join') != value:
        raise UnsafeState('could not preserve unrelated startup arguments')
    return result


def _manual_init_template(template, cluster_name):
    """Remove only the observed hook that auto-initializes node zero."""
    result = copy.deepcopy(template)
    db = database_container(result)
    lifecycle = db.get('lifecycle')
    post_start = lifecycle.get('postStart') if isinstance(lifecycle, dict) else None
    action = post_start.get('exec') if isinstance(post_start, dict) else None
    command = action.get('command') if isinstance(action, dict) else None
    if not isinstance(command, list) or not all(isinstance(token, str) for token in command):
        return result

    source = (
        command[2]
        if len(command) == 3 and command[0] in ('/bin/bash', '/bin/sh', 'bash', 'sh')
        and command[1] in ('-c', '-ec')
        else ' '.join(command)
    )
    try:
        tokens = shlex.split(source)
    except ValueError:
        if 'cockroach' in source and re.search(r'\binit\b', source):
            raise UnsafeState('unsupported Cockroach init postStart hook')
        tokens = []
    command_starts = {'if', 'then', 'until', 'do', 'else', 'exec', '&&', '||', ';', '!'}
    invokes_init = any(
        token.rsplit('/', 1)[-1] == 'cockroach'
        and tokens[index + 1] == 'init'
        and (index == 0 or tokens[index - 1] in command_starts)
        for index, token in enumerate(tokens[:-1])
    )
    if not invokes_init:
        return result

    expected_script = (
        f'if [ "$POD_NAME" = "{cluster_name}-0" ]; then '
        'until /cockroach/cockroach init --insecure --host=127.0.0.1:26257 >/dev/null 2>&1; do '
        'if /cockroach/cockroach node status --insecure --host=127.0.0.1:26257 >/dev/null 2>&1; then '
        'break fi sleep 2 done fi'
    )
    if (
        len(command) != 3
        or command[:2] != ['/bin/sh', '-ec']
        or re.sub(r'\s+', ' ', command[2]).strip() != expected_script
    ):
        raise UnsafeState('unsupported Cockroach init postStart hook')

    del lifecycle['postStart']
    return result


class Preparation:
    def __init__(self, cluster):
        self.cluster = cluster
        self.name = cluster.name + '-initialize-baseline'
        self.fault_value = cluster.name + '-initialize-missing.invalid:26257'

    def load(self):
        baseline = self.cluster.get('configmap', self.name)
        if baseline is None:
            return None
        if baseline['metadata'].get('labels', {}).get('karma.dev/fixture') != 'initialize-baseline' or baseline['metadata']['labels'].get('app.kubernetes.io/instance') != self.cluster.name:
            raise UnsafeState('initialize baseline belongs to another resource')
        if baseline['data']['statefulset_uid'] != self.cluster.statefulset()['metadata']['uid']:
            raise UnsafeState('initialize baseline belongs to another workload incarnation')
        return baseline

    def update(self, baseline, values):
        data = {**baseline['data'], **values}
        patch = [{'op': 'test', 'path': '/metadata/uid', 'value': baseline['metadata']['uid']},
                 {'op': 'test', 'path': '/metadata/resourceVersion', 'value': baseline['metadata']['resourceVersion']},
                 {'op': 'replace', 'path': '/data', 'value': data}]
        self.cluster.require(self.cluster.kubectl('patch', 'configmap', self.name, '--type=json', '-p', json.dumps(patch)))
        return self.load()

    def preserved(self, baseline, sts, paused=False):
        data = baseline['data']
        count = int(data['replicas'])
        if int(sts['spec'].get('replicas', 1)) not in ((0, count) if paused else (count,)):
            raise UnsafeState('selected replica count changed during preparation')
        if self.cluster.connection_flags(sts=sts) != json.loads(data['connection_flags']):
            raise UnsafeState('selected security mode or certificate path changed')
        if self.cluster.stores(sts, count) != json.loads(data['stores']):
            raise UnsafeState('selected store configuration or PVC identity changed')
        if signatures(self.cluster, sts['spec']['template']) != json.loads(data['secret_signatures']):
            raise UnsafeState('mounted Secret identity or contents changed during preparation')

    def preflight(self, sts):
        cluster = self.cluster
        _manual_init_template(sts['spec']['template'], cluster.name)
        stores = cluster.stores(sts)
        db = database_container(sts['spec']['template'])
        fault_template(sts['spec']['template'], self.fault_value)
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
            if any(actual.get(k, []) != db.get(k, []) for k in ('command', 'args')) or actual['image'] != db['image']:
                raise UnsafeState('selected pods have not converged to the inherited startup template')
            expected = {v['metadata']['name']: f'{v["metadata"]["name"]}-{cluster.name}-{pod["metadata"]["name"].rsplit("-", 1)[1]}' for v in sts['spec'].get('volumeClaimTemplates', [])}
            volumes = {v['name']: v.get('persistentVolumeClaim', {}).get('claimName') for v in pod['spec'].get('volumes', [])}
            if any(volumes.get(k) != v for k, v in expected.items()):
                raise UnsafeState('selected pod does not mount its expected owned claims')
        if cluster.connection_flags(db, sts=sts)[0] != '--insecure':
            directory = cluster.certificate_directory(db, sts=sts)
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
        baseline = self.load()
        for index in range(len(stores)):
            helper = cluster.get('pod', f'{cluster.name}-initialize-reset-{index}')
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

    def environment_ready(self):
        sts = self.cluster.statefulset()
        baseline = self.load()
        if baseline and baseline['data']['phase'] == 'resetting':
            raise RuntimeError('owned store reset requires resumption')
        if baseline and baseline['data']['phase'] == 'injecting':
            self.preserved(baseline, sts)
            raise RuntimeError('owned join rollout requires resumption')
        return self.cluster.deployment_ready()

    def environment_apply(self):
        if self.cluster.get('statefulset', self.cluster.name) is None:
            self.cluster.bootstrap()
        baseline = self.load()
        if baseline and baseline['data']['phase'] == 'resetting':
            self.resume_reset(baseline)
        elif baseline and baseline['data']['phase'] == 'injecting':
            self.inject()
        self.cluster.wait(self.environment_ready, 180)

    def uninitialized(self):
        baseline = self.load()
        if not baseline or baseline['data']['phase'] not in ('uninitialized', 'injecting', 'faulted'):
            raise RuntimeError('uninitialized baseline has not been prepared')
        sts = self.cluster.statefulset()
        self.preserved(baseline, sts)
        if self.cluster.deployment_ready() != 'uninitialized':
            raise RuntimeError('selected database is already initialized')
        return True

    def reset(self):
        cluster = self.cluster
        baseline = self.load()
        if baseline and baseline['data']['phase'] == 'resetting':
            self.resume_reset(baseline)
            return
        state = cluster.deployment_ready()  # Every destructive apply checks its own prerequisite.
        sts = cluster.statefulset()
        if baseline and baseline['data']['phase'] in ('uninitialized', 'injecting', 'faulted') and state == 'uninitialized':
            self.uninitialized()
            return
        stores = self.preflight(sts)
        if self.fault_value in ' '.join(arguments(database_container(sts['spec']['template']))):
            if baseline and state == 'uninitialized':
                self.uninitialized()
                return
            raise UnsafeState('unrecognized or partially solved join fault; refusing a data reset')
        data = {'statefulset_uid': sts['metadata']['uid'], 'replicas': str(sts['spec'].get('replicas', 1)),
                'original_template': json.dumps(sts['spec']['template'], sort_keys=True),
                'original_strategy': json.dumps(sts['spec'].get('updateStrategy', {'type': 'RollingUpdate'}), sort_keys=True),
                'connection_flags': json.dumps(cluster.connection_flags(sts=sts)), 'stores': json.dumps(stores, sort_keys=True),
                'secret_signatures': json.dumps(signatures(cluster, sts['spec']['template']), sort_keys=True),
                'old_cluster_id': cluster.cluster_id() if state == 'initialized' else '',
                'nonce': uuid.uuid4().hex[:12], 'phase': 'resetting' if state == 'initialized' else 'uninitialized'}
        if baseline:
            baseline = self.update(baseline, data)
        else:
            cluster.create({'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': self.name, 'namespace': cluster.namespace,
                'labels': {**cluster.labels, 'karma.dev/fixture': 'initialize-baseline'}}, 'data': data})
            baseline = self.load()
        if state == 'initialized':
            self.resume_reset(baseline)
        else:
            self.uninitialized()

    def resume_reset(self, baseline):
        cluster = self.cluster
        sts = cluster.statefulset()
        self.preserved(baseline, sts, paused=True)
        original_template = json.loads(baseline['data']['original_template'])
        manual_template = _manual_init_template(original_template, cluster.name)
        if sts['spec']['template'] not in (original_template, manual_template):
            raise UnsafeState('selected template changed during store reset')
        self.exclusive(sts, json.loads(baseline['data']['stores']), baseline)
        cluster.patch_spec(sts, {'replicas': 0, 'updateStrategy': {'type': 'OnDelete'}})
        def stopped():
            return not any(any(ref.get('uid') == sts['metadata']['uid'] for ref in pod['metadata'].get('ownerReferences', [])) for pod in cluster.get('pods')['items'])
        cluster.wait(stopped, 180)
        for index, store in enumerate(json.loads(baseline['data']['stores'])):
            self.reset_store(baseline, store, index)
        sts = cluster.statefulset()
        self.preserved(baseline, sts, paused=True)
        if sts['spec']['template'] == original_template and manual_template != original_template:
            cluster.patch_spec(sts, {'template': manual_template})
            sts = cluster.statefulset()
        if sts['spec']['template'] != manual_template:
            raise UnsafeState('selected template changed during store reset')
        cluster.patch_spec(sts, {'replicas': int(baseline['data']['replicas'])})
        cluster.wait(lambda: cluster.deployment_ready() == 'uninitialized', 240)
        self.update(self.load(), {'phase': 'uninitialized'})

    def reset_store(self, baseline, store, index):
        cluster = self.cluster
        self.preserved(baseline, cluster.statefulset(), paused=True)
        self.exclusive(cluster.statefulset(), json.loads(baseline['data']['stores']), baseline)
        name = f'{cluster.name}-initialize-reset-{index}'
        nonce = baseline['data']['nonce']
        marker = '.karma-initialize-reset-' + nonce + '-' + str(index)
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
                'labels': {'karma.dev/fixture': 'initialize-reset'}, 'annotations': {'karma.dev/reset-nonce': nonce},
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

    def fault_active(self):
        self.uninitialized()
        baseline = self.load()
        sts = self.cluster.statefulset()
        expected = json.loads(baseline['data']['fault_template']) if 'fault_template' in baseline['data'] else None
        if baseline['data']['phase'] != 'faulted' or sts['spec']['template'] != expected or sts['spec'].get('updateStrategy') != {'type': 'OnDelete'}:
            raise RuntimeError('join fault has not been prepared')
        for pod in self.cluster.pods(sts):
            actual = database_container({'spec': pod['spec']})
            desired = database_container(expected)
            if actual.get('command') != desired.get('command') or actual.get('args', []) != desired.get('args', []):
                raise RuntimeError('join fault has not reached every selected pod')
            logs = self.cluster.require(self.cluster.kubectl('logs', pod['metadata']['name'], '-c', actual['name'], '--tail=80'))
            signature = (self.fault_value, 'outgoing join rpc', 'no such host')
            if not all(token in logs for token in signature):
                # CockroachDB v24.1 defaults to file logging under the store
                # directory and does not send INFO logs to stderr. Only use
                # that known layout for the literal store path or CockroachDB's
                # default store path; do not guess when logging is customized.
                try:
                    store = flag_value(actual, '--store', '/cockroach/cockroach-data')
                    startup = arguments(actual)
                except UnsafeState:
                    store, startup = None, []
                custom_log = any(
                    token in ('--log', '--log-dir')
                    or token.startswith('--log=')
                    or token.startswith('--log-dir=')
                    for token in startup
                )
                if (
                    store
                    and store.startswith('/')
                    and not any(character in store for character in (',', '$', '\n', '\r'))
                    and not custom_log
                ):
                    log_path = store.rstrip('/') + '/logs/cockroach.log'
                    result = self.cluster.kubectl(
                        'exec', pod['metadata']['name'], '-c', actual['name'], '--',
                        'tail', '-n', '80', '--', log_path, timeout=10,
                    )
                    if result.returncode == 0:
                        logs = result.stdout
            if not all(token in logs for token in signature):
                raise RuntimeError('expected join DNS error is not visible in selected pod logs')
        return True

    def inject(self):
        cluster = self.cluster
        baseline = self.load()
        if not baseline or baseline['data']['phase'] not in ('uninitialized', 'injecting', 'faulted'):
            raise UnsafeState('join injection blocked: uninitialized unit has not completed')
        if baseline['data']['phase'] == 'faulted':
            try:
                self.fault_active()
                return
            except UnsafeState:
                raise
            except RuntimeError:
                pass
        sts = cluster.statefulset()
        self.preserved(baseline, sts)
        if baseline['data']['phase'] in ('uninitialized', 'faulted'):
            self.uninitialized()
        original_template = json.loads(baseline['data']['original_template'])
        manual_template = _manual_init_template(original_template, cluster.name)
        if baseline['data']['phase'] == 'uninitialized':
            expected = fault_template(manual_template, self.fault_value)
            baseline = self.update(baseline, {'fault_template': json.dumps(expected, sort_keys=True), 'phase': 'injecting'})
        else:
            expected = json.loads(baseline['data']['fault_template'])
        if sts['spec']['template'] not in (original_template, manual_template, expected):
            raise UnsafeState('selected startup changed during join injection')
        cluster.patch_spec(sts, {'template': expected, 'updateStrategy': {'type': 'OnDelete'}})
        cluster.wait(lambda: bool(cluster.pods(cluster.statefulset())), 120)
        for pod in cluster.pods(cluster.statefulset()):
            db = database_container({'spec': pod['spec']})
            desired = database_container(expected)
            if db.get('command') != desired.get('command') or db.get('args', []) != desired.get('args', []):
                cluster.delete_pod(pod)
        cluster.wait(lambda: cluster.deployment_ready() == 'uninitialized', 240)
        self.update(self.load(), {'phase': 'faulted'})
        cluster.wait(self.fault_active, 90)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('unit', choices=('cluster', 'reset', 'fault'))
    parser.add_argument('mode', choices=('probe', 'apply', 'verify'))
    args = parser.parse_args()
    preparation = Preparation(Cluster())
    if args.unit == 'cluster':
        if args.mode != 'apply' and preparation.cluster.get('statefulset', preparation.cluster.name) is None:
            raise RuntimeError('selected StatefulSet is absent')
        preparation.environment_apply() if args.mode == 'apply' else preparation.cluster.wait(preparation.environment_ready, 90)
    elif args.unit == 'reset':
        preparation.reset() if args.mode == 'apply' else preparation.cluster.wait(preparation.uninitialized, 30)
    else:
        preparation.inject() if args.mode == 'apply' else preparation.cluster.wait(preparation.fault_active, 30)
    print(f'{args.unit} {args.mode}: ready', flush=True)


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, ValueError, KeyError, OSError, subprocess.TimeoutExpired) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)

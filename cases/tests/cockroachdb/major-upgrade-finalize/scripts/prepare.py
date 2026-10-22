#!/usr/bin/env python3
"""Three state-based units with scoped, resumable version preparation."""
import argparse
import copy
import hashlib
import json
import re
import subprocess
import sys
import time
import uuid

from cluster import Cluster, UnsafeState, arguments, database_container
from storage import Stores, signatures
from versions import RELEASES, PINNED, image, image_version, parameters, patch_upgrade, release, series, source_ready, source_version, state


def without_image(template):
    result = copy.deepcopy(template)
    database_container(result).pop('image')
    return result


def workload_spec(sts):
    return {key: value for key, value in sts['spec'].items()
            if key not in ('template', 'replicas', 'updateStrategy')}


def enabled(value):
    return value.lower() in ('true', 't')


class Preparation(Stores):
    def __init__(self, cluster):
        self.cluster = cluster
        self.source, self.target = parameters()
        self.source_release = release(self.source)
        self.patch = patch_upgrade(self.source, self.target)
        self.name = cluster.name + '-major-upgrade-baseline'

    def load(self):
        baseline = self.cluster.get('configmap', self.name)
        if baseline is None:
            return None
        labels = baseline['metadata'].get('labels', {})
        if labels.get('karma.dev/fixture') != 'major-upgrade-baseline' or labels.get('app.kubernetes.io/instance') != self.cluster.name:
            raise UnsafeState('upgrade baseline belongs to another resource')
        if baseline.get('data', {}).get('statefulset_uid') != self.cluster.statefulset()['metadata']['uid']:
            raise UnsafeState('upgrade baseline belongs to another workload incarnation')
        return baseline

    def update(self, baseline, values):
        patch = [{'op': 'test', 'path': '/metadata/uid', 'value': baseline['metadata']['uid']},
                 {'op': 'test', 'path': '/metadata/resourceVersion', 'value': baseline['metadata']['resourceVersion']},
                 {'op': 'replace', 'path': '/data', 'value': {**baseline['data'], **values}}]
        self.cluster.require(self.cluster.kubectl('patch', 'configmap', self.name, '--type=json', '-p', json.dumps(patch)))
        return self.load()

    def preserved(self, baseline, sts, paused=False):
        data = baseline['data']
        count = int(data['replicas'])
        if int(sts['spec'].get('replicas', 1)) not in ((0, count) if paused else (count,)):
            raise UnsafeState('selected replica count changed during preparation')
        if without_image(sts['spec']['template']) != without_image(json.loads(data['original_template'])):
            raise UnsafeState('selected non-version startup configuration changed during preparation')
        if workload_spec(sts) != json.loads(data['workload_spec']):
            raise UnsafeState('selected non-version workload configuration changed during preparation')
        if self.cluster.connection_flags() != json.loads(data['connection_flags']):
            raise UnsafeState('selected security mode or certificate path changed')
        if self.cluster.stores(sts, count) != json.loads(data['stores']):
            raise UnsafeState('selected store configuration or PVC identity changed')
        if signatures(self.cluster, sts['spec']['template']) != json.loads(data['secret_signatures']):
            raise UnsafeState('mounted Secret identity or contents changed')

    def same_task(self, baseline):
        data = baseline['data']
        if data['source'] != self.source or data['target_series'] != release(self.target):
            return False
        if self.patch:
            return data.get('upgrade_kind') == 'patch' and data.get('target') == self.target
        return data.get('upgrade_kind', 'major') == 'major'

    @staticmethod
    def task_key(data):
        kind = data.get('upgrade_kind', 'major')
        target = data.get('target') if kind == 'patch' else data['target_series']
        return kind + ':' + data['source'] + '->' + target

    def load_for_task(self):
        baseline = self.load()
        if baseline is None or self.same_task(baseline):
            return baseline
        task = {'source': self.source, 'target': self.target,
                'target_series': release(self.target), 'upgrade_kind': 'patch' if self.patch else 'major'}
        data = json.loads(baseline['data'].get('history', '{}')).get(self.task_key(task))
        if data is None or data.get('statefulset_uid') != baseline['data']['statefulset_uid']:
            return None
        return {**baseline, 'data': data}

    def environment_probe(self):
        baseline = self.load()
        if baseline and baseline['data']['phase'] in ('rolling', 'finalizing', 'resetting', 'starting', 'replan'):
            raise RuntimeError('owned preparation requires resumption')
        return self.cluster.ready()

    def environment_apply(self):
        c = self.cluster
        if c.get('statefulset', c.name) is None:
            c.bootstrap()
        baseline = self.load()
        if baseline and baseline['data']['phase'] in ('rolling', 'finalizing', 'resetting', 'starting', 'replan'):
            self.source_apply()
        elif c.deployment_ready() == 'uninitialized':
            c.require(c.client('init'))
        c.wait(self.environment_probe, 240)

    def source_probe(self):
        baseline = self.load()
        if baseline is None or not self.same_task(baseline) or baseline['data']['phase'] not in ('prepared', 'held'):
            raise RuntimeError('source baseline is not prepared')
        self.preserved(baseline, self.cluster.statefulset())
        if not source_ready(self.cluster) or self.cluster.cluster_id() != baseline['data']['normalized_uuid']:
            raise RuntimeError('selected database is not at the recorded source state')
        if self.cluster.statefulset()['spec'].get('updateStrategy', {'type': 'RollingUpdate'}) != json.loads(baseline['data']['original_strategy']):
            raise RuntimeError('original update strategy has not been restored')
        return True

    def source_binary(self, current, release):
        if release == self.source_release and (self.patch or self.source.count('.') == 2):
            return source_version(self.source)
        candidates = [v for v in current['binaries'] if series(v) == series(release)]
        if not candidates:
            # A held newer-binary cluster can retain the original source patch
            # in owned ControllerRevisions. Never use another workload's history.
            uid = self.cluster.statefulset()['metadata']['uid']
            revisions = self.cluster.get('controllerrevisions')['items']
            for revision in sorted(revisions, key=lambda r: r['metadata'].get('creationTimestamp', ''), reverse=True):
                if not any(ref.get('uid') == uid for ref in revision['metadata'].get('ownerReferences', [])):
                    continue
                try:
                    version = image_version(database_container(revision['data']['spec']['template'])['image'])
                    if series(version) == series(release):
                        return version
                except (KeyError, RuntimeError):
                    continue
        return max(candidates, key=lambda v: tuple(map(int, v.split('.')))) if candidates else PINNED[release]

    def plan(self, current):
        logical = current['logical']
        if series(logical) > series(self.source):
            return {'reset': True, 'steps': [{'binary': source_version(self.source), 'logical': self.source_release}]}
        if logical not in RELEASES:
            raise UnsafeState('no documented prerequisite upgrade path for inherited logical version')
        index = RELEASES.index(logical)
        permitted = {series(logical)} | ({series(RELEASES[index + 1])} if index + 1 < len(RELEASES) else set())
        if any(series(v) not in permitted for v in current['binaries']):
            raise UnsafeState('inherited binaries are outside a supported rolling compatibility window')
        if logical == self.source_release:
            return {'reset': False, 'steps': [{'binary': self.source_binary(current, self.source_release), 'logical': self.source_release}]}
        return {'reset': False, 'steps': [{'binary': self.source_binary(current, release), 'logical': release}
                for release in RELEASES[index + 1:RELEASES.index(self.source_release) + 1]]}

    def validate_binary(self, version, sts):
        """Parse inherited startup using the chosen binary, without any stores."""
        c = self.cluster
        db = copy.deepcopy(database_container(sts['spec']['template']))
        tokens = arguments(db)
        executable = tokens[1:] if tokens and tokens[0] == 'exec' else tokens
        if not executable or executable[0] not in ('/cockroach/cockroach', './cockroach', 'cockroach', 'start'):
            raise UnsafeState('unsupported server executable')
        command = db.get('command', [])
        if len(command) == 3 and command[0] in ('/bin/bash', '/bin/sh', 'bash', 'sh'):
            if db.get('args'):
                raise UnsafeState('shell positional startup arguments are unsupported')
            command[2] = command[2].rstrip() + ' --help'
        else:
            db.setdefault('args', []).append('--help')
        db['image'] = image(version)
        db.pop('volumeMounts', None)
        for key in ('livenessProbe', 'readinessProbe', 'startupProbe', 'ports', 'lifecycle'):
            db.pop(key, None)
        db['resources'] = {'requests': {'cpu': '10m', 'memory': '32Mi'}, 'limits': {'memory': '256Mi'}}
        name = c.name + '-upgrade-check'
        fingerprint = hashlib.sha256(json.dumps(db, sort_keys=True).encode()).hexdigest()
        pod = c.get('pod', name)
        if pod:
            if pod['metadata'].get('annotations', {}).get('karma.dev/upgrade-check') != fingerprint or not any(ref.get('uid') == sts['metadata']['uid'] for ref in pod['metadata'].get('ownerReferences', [])):
                raise UnsafeState('binary compatibility helper name is occupied by another resource')
            c.delete_pod(pod)
        c.create({'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': name, 'namespace': c.namespace,
            'labels': {'karma.dev/fixture': 'upgrade-check'}, 'annotations': {'karma.dev/upgrade-check': fingerprint},
            'ownerReferences': [{'apiVersion': 'apps/v1', 'kind': 'StatefulSet', 'name': c.name, 'uid': sts['metadata']['uid']}]},
            'spec': {'restartPolicy': 'Never', 'automountServiceAccountToken': False,
                'terminationGracePeriodSeconds': 1, 'securityContext': sts['spec']['template']['spec'].get('securityContext', {}),
                'containers': [db]}})
        def finished():
            return c.get('pod', name).get('status', {}).get('phase') in ('Succeeded', 'Failed')
        c.wait(finished, 240)
        obj = c.get('pod', name)
        logs = c.require(c.kubectl('logs', name, '-c', db['name'], '--tail=15'))
        c.delete_pod(obj)
        if obj['status']['phase'] != 'Succeeded':
            raise UnsafeState('inherited startup is incompatible with selected binary: ' + logs)

    def source_apply(self):
        c = self.cluster
        baseline = self.load()
        if baseline and baseline['data']['phase'] == 'replan' and not self.same_task(baseline):
            raise UnsafeState('pending replan belongs to a different upgrade task')
        if baseline and baseline['data']['phase'] in ('rolling', 'finalizing', 'resetting', 'starting'):
            if not self.same_task(baseline):
                raise UnsafeState('pending preparation belongs to a different upgrade task')
        else:
            if baseline and baseline['data']['phase'] in ('prepared', 'held'):
                try:
                    self.source_probe()
                    return
                except RuntimeError:
                    if baseline['data']['phase'] != 'held' and baseline['data'].get('upgrade_kind') != 'patch':
                        raise
            c.wait(c.ready, 180)
            current = state(c)
            sts = c.statefulset()
            plan = self.plan(current)
            stores = self.preflight(sts, baseline)
            for version in dict.fromkeys(step['binary'] for step in plan['steps']):
                self.validate_binary(version, sts)
            data = {'source': self.source, 'target_series': release(self.target),
                'target': self.target, 'upgrade_kind': 'patch' if self.patch else 'major',
                'statefulset_uid': sts['metadata']['uid'], 'namespace_uid': c.get('namespace', c.namespace, namespace='')['metadata']['uid'],
                'replicas': str(sts['spec']['replicas']), 'original_template': json.dumps(sts['spec']['template'], sort_keys=True),
                'workload_spec': json.dumps(workload_spec(sts), sort_keys=True),
                'original_strategy': json.dumps(sts['spec'].get('updateStrategy', {'type': 'RollingUpdate'}), sort_keys=True),
                'connection_flags': json.dumps(c.connection_flags()), 'stores': json.dumps(stores, sort_keys=True),
                'secret_signatures': json.dumps(signatures(c, sts['spec']['template']), sort_keys=True),
                'initial_preserve': c.setting('cluster.preserve_downgrade_option'),
                'initial_auto_upgrade': c.setting('cluster.auto_upgrade.enabled') if series(current['binaries'][0]) >= (23, 2) else '(unavailable)',
                'initial_state': json.dumps(current, sort_keys=True), 'plan': json.dumps(plan, sort_keys=True),
                'nonce': uuid.uuid4().hex[:12], 'step_index': '0', 'phase': 'resetting' if plan['reset'] else 'rolling'}
            if baseline:
                # Keep completed task records for earlier workflow oracles.
                # The active record alone is used to resume preparation.
                if not self.same_task(baseline) and baseline['data']['phase'] in ('prepared', 'held'):
                    history = json.loads(baseline['data'].get('history', '{}'))
                    history[self.task_key(baseline['data'])] = {k: v for k, v in baseline['data'].items() if k != 'history'}
                    data['history'] = json.dumps(history, sort_keys=True)
                baseline = self.update(baseline, data)
            else:
                c.create({'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': self.name, 'namespace': c.namespace,
                    'labels': {**c.labels, 'karma.dev/fixture': 'major-upgrade-baseline'}}, 'data': data})
                baseline = self.load()
        self.preserved(baseline, c.statefulset(), paused=True)
        plan = json.loads(baseline['data']['plan'])
        if plan['reset']:
            self.resume_reset(baseline)
        else:
            if self.resume_steps(baseline) is False:
                return self.source_apply()
        baseline = self.load()
        c.wait(lambda: source_ready(c), 180)
        identity = c.cluster_id()
        old = json.loads(baseline['data']['initial_state'])['cluster_id']
        if (identity == old) == plan['reset']:
            raise UnsafeState('database identity changed contrary to the recorded reset policy')
        c.patch_spec(c.statefulset(), {'updateStrategy': json.loads(baseline['data']['original_strategy'])})
        values = {'phase': 'prepared', 'normalized_uuid': identity}
        if self.patch:
            # A held newer binary can roll back while its logical release stays
            # put. Restore that inherited policy after the source is coherent.
            initial = json.loads(baseline['data']['initial_state'])
            if initial['logical'] == self.source_release:
                hold = baseline['data']['initial_preserve']
                if c.setting('cluster.preserve_downgrade_option') != hold:
                    c.require(c.sql("SET CLUSTER SETTING cluster.preserve_downgrade_option='" + hold + "';" if hold else "RESET CLUSTER SETTING cluster.preserve_downgrade_option;"))
            values['source_preserve'] = c.setting('cluster.preserve_downgrade_option')
            values['source_auto_upgrade'] = c.setting('cluster.auto_upgrade.enabled') if series(self.source) >= (23, 2) else '(unavailable)'
        self.update(self.load(), values)
        self.source_probe()

    def hold(self, logical):
        if self.cluster.setting('version') != logical:
            raise UnsafeState('logical version changed before establishing upgrade hold')
        if self.cluster.setting('cluster.preserve_downgrade_option') != logical:
            self.cluster.require(self.cluster.sql("SET CLUSTER SETTING cluster.preserve_downgrade_option='" + logical + "';"))
        if self.cluster.setting('version') != logical or self.cluster.setting('cluster.preserve_downgrade_option') != logical:
            raise UnsafeState('upgrade hold did not protect the recorded logical version')

    def roll_to(self, baseline, version):
        c = self.cluster
        self.preserved(baseline, c.statefulset())
        template = json.loads(baseline['data']['original_template'])
        database_container(template)['image'] = image(version)
        sts = c.statefulset()
        if sts['spec']['template'] != template or sts['spec'].get('updateStrategy') != {'type': 'OnDelete'}:
            c.patch_spec(sts, {'template': template, 'updateStrategy': {'type': 'OnDelete'}})
        def stabilize(peer):
            def healthy():
                c.ready()
                c.require(c.sql('SELECT 1;', peer))
                return True
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                c.wait(healthy, 60)
                time.sleep(3)
        for ordinal in reversed(range(int(baseline['data']['replicas']))):
            c.wait(c.ready, 240)
            pod = c.pods(c.statefulset())[ordinal]
            peer = 1 if ordinal == 0 else 0
            if image_version(database_container({'spec': pod['spec']})['image']) == version:
                # An interruption may have happened after replacement but
                # before stabilization. Protect the next node even on retry.
                if any(image_version(database_container({'spec': other['spec']})['image']) != version
                       for other in c.pods(c.statefulset())[:ordinal]):
                    print(f'Stabilizing inherited or resumed node {ordinal} before the next replacement', flush=True)
                    stabilize(peer)
                continue
            c.require(c.sql('SELECT 1;', peer))
            print(f'Rolling selected node {ordinal} to {version}', flush=True)
            c.delete_pod(pod)
            c.wait(c.ready, 300)
            # Follow the documented one-minute stabilization between nodes,
            # checking real health throughout instead of an unchecked sleep.
            stabilize(peer)
        current = state(c)
        if any(v != version for v in current['binaries']):
            raise RuntimeError('selected binary rollout has not converged')
        self.preserved(self.load(), c.statefulset())

    def resume_steps(self, baseline):
        c = self.cluster
        steps = json.loads(baseline['data']['plan'])['steps']
        for index in range(int(baseline['data']['step_index']), len(steps)):
            step = steps[index]
            c.wait(c.ready, 240)
            if c.cluster_id() != json.loads(baseline['data']['initial_state'])['cluster_id']:
                raise UnsafeState('database identity changed before resuming version preparation')
            if baseline['data']['phase'] == 'finalizing':
                self.finalize(step['logical'])
            else:
                logical = c.setting('version')
                series(logical)
                if series(logical) > series(step['logical']):
                    initial = json.loads(baseline['data']['initial_state'])
                    if (index == 0 and baseline['data']['phase'] == 'rolling'
                            and series(logical) > series(self.source)
                            and c.statefulset()['spec']['template'] == json.loads(baseline['data']['original_template'])
                            and state(c)['binaries'] == initial['binaries']):
                        # Automatic finalization can advance after preflight
                        # but before our hold. No image/store changes occurred;
                        # durably replan from the newly finalized state.
                        self.update(self.load(), {'phase': 'replan'})
                        print('Logical version advanced before any selected image/store change; replanning verified source preparation', flush=True)
                        return False
                    raise UnsafeState('logical version advanced beyond a pending rolling step')
                # Same-release binaries cannot advance the logical release.
                # Keep patch-only preparation from changing inherited policies.
                if (not self.patch or logical != step['logical']
                        or any(series(image_version(database_container({'spec': pod['spec']})['image'])) > series(logical)
                               for pod in c.pods(c.statefulset()))):
                    self.hold(logical)
                self.roll_to(baseline, step['binary'])
                if logical != step['logical']:
                    baseline = self.update(self.load(), {'phase': 'finalizing'})
                    self.finalize(step['logical'])
            baseline = self.update(self.load(), {'phase': 'rolling', 'step_index': str(index + 1)})
            print('Verified prerequisite logical version ' + step['logical'], flush=True)
        return True

    def finalize(self, target):
        c = self.cluster
        logical = c.setting('version')
        if logical == target:
            return
        try:
            series(logical)
        except RuntimeError:
            # A previously issued SET may still be migrating after interruption.
            c.wait(lambda: c.setting('version') == target, 300)
            return
        if logical not in RELEASES or RELEASES.index(target) != RELEASES.index(logical) + 1:
            raise UnsafeState('pending finalization is outside a supported adjacent release')
        hold = c.setting('cluster.preserve_downgrade_option')
        if hold and hold != logical:
            raise UnsafeState('pending finalization has an unexpected hold')
        if hold:
            c.require(c.sql('RESET CLUSTER SETTING cluster.preserve_downgrade_option;'))
        c.require(c.sql("SET CLUSTER SETTING version='" + target + "';", timeout=240))
        c.wait(lambda: c.setting('version') == target, 300)

    def resume_reset(self, baseline):
        c = self.cluster
        template = json.loads(baseline['data']['original_template'])
        database_container(template)['image'] = image(json.loads(baseline['data']['plan'])['steps'][0]['binary'])
        if baseline['data']['phase'] == 'resetting':
            self.exclusive(c.statefulset(), json.loads(baseline['data']['stores']), baseline)
            c.patch_spec(c.statefulset(), {'replicas': 0, 'updateStrategy': {'type': 'OnDelete'}})
            uid = baseline['data']['statefulset_uid']
            c.wait(lambda: not any(any(ref.get('uid') == uid for ref in p['metadata'].get('ownerReferences', [])) for p in c.get('pods')['items']), 180)
            for index, store in enumerate(json.loads(baseline['data']['stores'])):
                self.reset_store(baseline, store, index)
            baseline = self.update(self.load(), {'phase': 'starting'})
        self.preserved(baseline, c.statefulset(), paused=True)
        c.patch_spec(c.statefulset(), {'template': template, 'replicas': int(baseline['data']['replicas'])})
        c.wait(c.deployment_ready, 240)
        if c.deployment_ready() == 'uninitialized':
            c.require(c.client('init'))
        c.wait(c.ready, 240)

    def hold_probe(self):
        self.source_probe()
        baseline = self.load()
        if self.patch:
            return True
        if baseline['data']['phase'] != 'held' or self.cluster.setting('cluster.preserve_downgrade_option') != self.source_release:
            raise RuntimeError('upgrade finalization hold is not prepared')
        if series(self.source) >= (23, 2) and not enabled(self.cluster.setting('cluster.auto_upgrade.enabled')):
            raise RuntimeError('automatic upgrade policy would block finalization after hold release')
        return True

    def hold_apply(self):
        self.source_probe()  # Independently block after an earlier unit failed.
        if self.patch:
            return
        self.hold(self.source_release)
        if series(self.source) >= (23, 2) and not enabled(self.cluster.setting('cluster.auto_upgrade.enabled')):
            self.cluster.require(self.cluster.sql('SET CLUSTER SETTING cluster.auto_upgrade.enabled=true;'))
        baseline = self.load()
        if baseline['data']['phase'] != 'held':
            self.update(baseline, {'phase': 'held'})
        self.hold_probe()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('unit', choices=('environment', 'source', 'hold'))
    parser.add_argument('mode', choices=('probe', 'apply', 'verify'))
    args = parser.parse_args()
    p = Preparation(Cluster())
    check, apply = {'environment': (p.environment_probe, p.environment_apply),
                    'source': (p.source_probe, p.source_apply), 'hold': (p.hold_probe, p.hold_apply)}[args.unit]
    if args.mode == 'apply':
        apply()
    else:
        p.cluster.wait(check, 30)
    print(f'{args.unit} {args.mode}: ready', flush=True)


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, ValueError, KeyError, OSError, subprocess.TimeoutExpired) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)

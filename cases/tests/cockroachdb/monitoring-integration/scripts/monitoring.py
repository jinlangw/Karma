"""Ensure an additive stack and remove only the selected database's scraping."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import re
from urllib.parse import urlparse

import yaml

from cluster import UnsafeState


def matches(selector, labels):
    if any(labels.get(k) != v for k, v in selector.get('matchLabels', {}).items()): return False
    for expr in selector.get('matchExpressions', []):
        key, op, values = expr['key'], expr['operator'], expr.get('values', [])
        if op == 'In' and labels.get(key) not in values: return False
        if op == 'NotIn' and labels.get(key) in values: return False
        if op == 'Exists' and key not in labels: return False
        if op == 'DoesNotExist' and key in labels: return False
    return True


class Monitoring:
    def __init__(self, cluster):
        self.c = cluster
        self.namespace = os.environ.get('BENCH_PARAM_MONITORING_NAMESPACE') or os.environ.get('BENCH_NS_MONITORING', cluster.namespace)
        if not re.fullmatch(r'[a-z0-9]([-a-z0-9]*[a-z0-9])?', self.namespace) or len(self.namespace) > 63:
            raise ValueError('invalid monitoring namespace')
        self.prefix = 'karma-mon-' + hashlib.sha256(self.namespace.encode()).hexdigest()[:12]
        self.helper = cluster.name + '-monitoring-curl'
        self.port = int(os.environ.get('BENCH_PARAM_METRICS_PORT', '8080'))
        self.path = os.environ.get('BENCH_PARAM_METRICS_PATH', '/_status/vars')
        self.record_name = cluster.name + '-monitoring-baseline'

    def patch(self, obj, fields):
        c = self.c
        changes = [{'op': 'test', 'path': '/metadata/uid', 'value': obj['metadata']['uid']},
                   {'op': 'test', 'path': '/metadata/resourceVersion', 'value': obj['metadata']['resourceVersion']}]
        changes += [{'op': 'add', 'path': '/' + key, 'value': value} for key, value in fields.items()]
        c.require(c.kubectl('patch', obj['kind'], obj['metadata']['name'], '--type=json', '-p', json.dumps(changes), namespace=obj['metadata'].get('namespace', '')))

    def delete(self, obj, plural):
        ns = obj['metadata']['namespace']
        path = '/apis/monitoring.coreos.com/' + obj['apiVersion'].split('/')[1] + '/namespaces/' + ns + '/' + plural + '/' + obj['metadata']['name']
        options = {'apiVersion': 'v1', 'kind': 'DeleteOptions', 'preconditions': {'uid': obj['metadata']['uid']}}
        self.c.require(self.c.kubectl('delete', '--raw=' + path, '-f', '-', input_text=json.dumps(options)))
        print('Removed dedicated ' + obj['kind'] + '/' + obj['metadata']['name'], flush=True)

    def request(self, path):
        result = self.c.kubectl('exec', self.helper, '--', 'curl', '-fsS', '--connect-timeout', '3', '--max-time', '12',
                                'http://prometheus.' + self.namespace + '.svc:9090' + path, timeout=18)
        payload = json.loads(self.c.require(result))
        if payload.get('status') != 'success': raise RuntimeError('Prometheus API did not succeed')
        return payload['data']

    def targets(self):
        return self.request('/api/v1/targets').get('activeTargets', [])

    def selected(self, target):
        labels = target.get('discoveredLabels', {})
        if labels.get('__meta_kubernetes_namespace') == self.c.namespace and labels.get('__meta_kubernetes_pod_controller_kind') == 'StatefulSet' and labels.get('__meta_kubernetes_pod_controller_name') == self.c.name:
            return True
        return urlparse(target.get('scrapeUrl', '')).hostname in self.hosts()

    def hosts(self):
        if hasattr(self, '_hosts'): return self._hosts
        c = self.c
        sts = c.statefulset()
        hosts = {p['status']['podIP'] for p in c.pods(sts) if p.get('status', {}).get('podIP')}
        names = [c.name + '-public', sts['spec']['serviceName']] + [f'{c.name}-{i}.{sts["spec"]["serviceName"]}' for i in range(int(sts['spec']['replicas']))]
        for name in names:
            hosts.update(name + suffix for suffix in ('.' + c.namespace, '.' + c.namespace + '.svc', '.' + c.namespace + '.svc.cluster.local'))
            if self.namespace == c.namespace: hosts.add(name)
        for service in c.get('services')['items']:
            selector = service['spec'].get('selector', {})
            if selector and all(sts['spec']['template']['metadata']['labels'].get(k) == v for k, v in selector.items()):
                # Only endpoints owned by this workload qualify as selected addresses.
                pods = [p for p in c.get('pods')['items'] if all(p['metadata'].get('labels', {}).get(k) == v for k, v in selector.items())]
                if pods and all(any(ref.get('uid') == sts['metadata']['uid'] for ref in p['metadata'].get('ownerReferences', [])) for p in pods):
                    hosts.update(ip for ip in service['spec'].get('clusterIPs', []) if ip != 'None')
        self._hosts = hosts
        return hosts

    def helper_ready(self):
        pod = self.c.get('pod', self.helper)
        if not pod or not any(x.get('type') == 'Ready' and x.get('status') == 'True' for x in pod.get('status', {}).get('conditions', [])):
            raise RuntimeError('metrics helper is not ready')
        return True

    def probe(self):
        self.helper_ready()
        prom = self.c.get('prometheus', 'crdb', namespace=self.namespace)
        if prom is None: raise RuntimeError('Prometheus resource is missing')
        if not self.operator_ready(): raise RuntimeError('compatible Prometheus Operator is not ready')
        if prom['spec'].get('serviceMonitorSelector') is None:
            raise RuntimeError('Prometheus has no enabled ServiceMonitor discovery')
        self.discovery_namespace(prom)
        self.request('/api/v1/status/config')
        self.metrics()
        return True

    def discovery_namespace(self, prom=None):
        prom = prom or self.c.get('prometheus', 'crdb', namespace=self.namespace)
        selector = prom['spec'].get('serviceMonitorNamespaceSelector')
        if selector is None: return self.namespace
        namespaces = self.c.get('namespaces', namespace='')['items']
        selected = {n['metadata']['name'] for n in namespaces if matches(selector, n['metadata'].get('labels', {}))}
        for name in (self.c.namespace, self.namespace):
            if name in selected: return name
        if selected: return sorted(selected)[0]
        raise RuntimeError('Prometheus namespace selector currently matches no monitor namespace')

    def operator_ready(self):
        prom = self.c.get('prometheus', 'crdb', namespace=self.namespace)
        required = {self.namespace, self.discovery_namespace(prom) if prom else self.c.namespace}
        result = self.c.kubectl('get', 'deployments', '-A', '-o', 'json')
        for dep in json.loads(self.c.require(result))['items']:
            for container in dep['spec']['template']['spec']['containers']:
                if 'prometheus-operator' not in container.get('image', ''): continue
                args = container.get('args', [])
                scope = next((arg.split('=', 1)[1] for arg in args if arg.startswith('--namespaces=')), '')
                denied = next((arg.split('=', 1)[1] for arg in args if arg.startswith('--deny-namespaces=')), '')
                prom_scope = next((arg.split('=', 1)[1] for arg in args if arg.startswith('--prometheus-instance-namespaces=')), '')
                if (not scope or required <= set(scope.split(','))) and not required.intersection(denied.split(',')) and (not prom_scope or self.namespace in prom_scope.split(',')) and dep.get('status', {}).get('availableReplicas', 0) and dep.get('status', {}).get('observedGeneration', 0) >= dep['metadata'].get('generation', 0): return True
        return False

    def metrics(self):
        errors = []
        for scheme in ('https', 'http'):
            result = self.c.kubectl('exec', self.helper, '--', 'curl', '-kfsSL', '--connect-timeout', '3', '--max-time', '8',
                f'{scheme}://{self.c.name}-public.{self.c.namespace}.svc:{self.port}{self.path}', timeout=12)
            if result.returncode == 0 and re.search(r'^sys_uptime(?:\{|\s)', result.stdout, re.M): return True
            errors.append(result.stderr)
        raise RuntimeError('metrics endpoint is unreachable: ' + '; '.join(errors))

    def manifests(self, name):
        text = (Path(__file__).resolve().parents[1] / 'resource' / name).read_text()
        values = {'BENCH_NAMESPACE': self.c.namespace, 'BENCH_PARAM_CLUSTER_NAME': self.c.name,
                  'BENCH_PARAM_MONITORING_NAMESPACE': self.namespace, 'BENCH_MONITORING_RBAC_PREFIX': self.prefix}
        for key, value in values.items(): text = text.replace('${' + key + '}', value)
        return list(yaml.safe_load_all(text))

    def ensure(self, obj):
        c = self.c
        ns = obj['metadata'].get('namespace', '')
        current = c.get(obj['kind'], obj['metadata']['name'], namespace=ns)
        if current is None:
            obj['metadata'].setdefault('labels', {})['karma.dev/fixture'] = 'monitoring-stack'
            c.require(c.kubectl('create', '-f', '-', input_text=json.dumps(obj), namespace=ns))
            print('Created ' + obj['kind'] + '/' + obj['metadata']['name'], flush=True)
        return current

    def apply(self):
        c = self.c
        self.ensure({'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': self.namespace}})
        for obj in self.manifests('monitoring-crds.yaml'):
            self.ensure(obj)
            c.require(c.kubectl('wait', '--for=condition=Established', 'crd/' + obj['metadata']['name'], '--timeout=90s', timeout=95, namespace=''))
        if not self.operator_ready():
            for obj in self.manifests('prometheus-operator.yaml'):
                current = self.ensure(obj)
                if current and obj['kind'] == 'Deployment':
                    spec = copy.deepcopy(current['spec'])
                    for container in spec['template']['spec']['containers']:
                        if 'prometheus-operator' not in container.get('image', ''): continue
                        for index, arg in enumerate(container.get('args', [])):
                            if arg.startswith('--namespaces='):
                                scope = arg.split('=', 1)[1]
                                if scope and not {self.namespace, c.namespace} <= set(scope.split(',')):
                                    container['args'][index] = '--namespaces=' + ','.join(sorted(set(scope.split(',')) | {self.namespace, c.namespace}))
                            elif arg.startswith('--prometheus-instance-namespaces='):
                                container['args'][index] = '--prometheus-instance-namespaces=' + ','.join(sorted(set(arg.split('=', 1)[1].split(',')) | {self.namespace}))
                            elif arg.startswith('--deny-namespaces='):
                                container['args'][index] = '--deny-namespaces=' + ','.join(sorted(set(arg.split('=', 1)[1].split(',')) - {self.namespace, c.namespace}))
                    if spec != current['spec']: self.patch(current, {'spec': spec})
        for obj in self.manifests('prometheus-rbac.yaml'): self.ensure(obj)
        for obj in self.manifests('prometheus.yaml'): self.ensure(obj)
        prom = c.get('prometheus', 'crdb', namespace=self.namespace)
        spec = copy.deepcopy(prom['spec'])
        # Keep inherited discovery selectors intact whenever they already
        # select a usable namespace. The dedicated monitor can live there and
        # explicitly target this database namespace without broadening discovery.
        try: self.discovery_namespace(prom)
        except RuntimeError:
            spec['serviceMonitorNamespaceSelector'] = {'matchLabels': {'kubernetes.io/metadata.name': c.namespace}}
        if spec.get('serviceMonitorSelector') is None:
            marker = hashlib.sha256((c.namespace + '/' + c.name).encode()).hexdigest()[:16]
            spec['serviceMonitorSelector'] = {'matchLabels': {'karma.dev/monitoring-integration': marker}}
        if spec != prom['spec']: self.patch(prom, {'spec': spec})
        # Bind scoped discovery permissions to the inherited Prometheus account.
        account = spec.get('serviceAccountName') or 'default'
        binding = c.get('clusterrolebinding', self.prefix + '-prometheus', namespace='')
        subject = {'kind': 'ServiceAccount', 'name': account, 'namespace': self.namespace}
        subjects = binding.get('subjects', [])
        if subject not in subjects: self.patch(binding, {'subjects': subjects + [subject]})
        for obj in self.manifests('curl-test.yaml'):
            pod = c.get('pod', self.helper)
            if pod and pod.get('status', {}).get('phase') in ('Succeeded', 'Failed'):
                if pod['metadata'].get('labels', {}).get('karma.dev/fixture') != 'monitoring-stack':
                    raise UnsafeState('helper name belongs to an unrelated pod')
                c.delete_pod(pod)
            self.ensure(obj)
        c.wait(self.probe, 360)

    def resources(self, kind):
        if self.c.get('crd', kind + '.monitoring.coreos.com', namespace='') is None: return []
        return json.loads(self.c.require(self.c.kubectl('get', kind, '-A', '-o', 'json')))['items']

    def selected_objects(self, obj, kind):
        selector = obj['spec'].get('selector', {})
        ns = obj['spec'].get('namespaceSelector', {})
        namespaces = [n['metadata']['name'] for n in self.c.get('namespaces', namespace='')['items']] if ns.get('any') else ns.get('matchNames') or [obj['metadata']['namespace']]
        selected, foreign = [], []
        sts = self.c.statefulset()
        for namespace in namespaces:
            for item in self.c.get(kind, namespace=namespace)['items']:
                if not matches(selector, item['metadata'].get('labels', {})): continue
                own = False
                if namespace == self.c.namespace:
                    if kind == 'pods': own = any(ref.get('uid') == sts['metadata']['uid'] for ref in item['metadata'].get('ownerReferences', []))
                    else:
                        pods = self.c.get('pods')['items']
                        labels = item['spec'].get('selector', {})
                        backing = [p for p in pods if labels and all(p['metadata'].get('labels', {}).get(k) == v for k, v in labels.items())]
                        own = any(any(ref.get('controller') and ref.get('uid') == sts['metadata']['uid'] for ref in p['metadata'].get('ownerReferences', [])) for p in backing)
                        if own and any(not any(ref.get('controller') and ref.get('uid') == sts['metadata']['uid'] for ref in p['metadata'].get('ownerReferences', [])) for p in backing): foreign.append(item)
                (selected if own else foreign).append(item)
        return selected, foreign

    def drop_rules(self, raw=False):
        source = 'source_labels' if raw else 'sourceLabels'
        regex = re.escape(self.c.namespace) + ';StatefulSet;' + re.escape(self.c.name)
        addresses = '|'.join(re.escape(host) for host in sorted(self.hosts()))
        return [{source: ['__meta_kubernetes_namespace', '__meta_kubernetes_pod_controller_kind', '__meta_kubernetes_pod_controller_name'], 'regex': regex, 'action': 'drop'},
                {source: ['__address__'], 'regex': '(' + addresses + '):[0-9]+', 'action': 'drop'}]

    def baseline(self):
        obj = self.c.get('configmap', self.record_name)
        if obj and (obj['metadata'].get('labels', {}).get('karma.dev/fixture') != 'monitoring-baseline' or obj['metadata'].get('labels', {}).get('app.kubernetes.io/instance') != self.c.name):
            raise UnsafeState('monitoring baseline name belongs to another resource')
        return obj

    def configured(self):
        rules = self.drop_rules()
        for plural, kind, endpoints in [('servicemonitors', 'services', 'endpoints'), ('podmonitors', 'pods', 'podMetricsEndpoints')]:
            for obj in self.resources(plural):
                selected, _ = self.selected_objects(obj, kind)
                if selected and any(rules[0] not in ep.get('relabelings', []) for ep in obj['spec'].get(endpoints, [])):
                    return True
        return False

    def absent(self, pending_ok=False):
        self.probe()
        record = self.baseline()
        if not pending_ok and record and record['data'].get('phase') == 'resetting' and record['data'].get('statefulset_uid') == self.c.statefulset()['metadata']['uid'] and record['data'].get('monitoring_namespace') == self.namespace:
            raise RuntimeError('owned scrape reset requires resumption')
        if self.configured(): raise RuntimeError('selected monitor configuration still requires reset')
        if any(self.selected(target) for target in self.targets()): raise RuntimeError('selected cluster still has active scrape configuration')
        return True

    def reset(self):
        self.probe()
        initial = self.targets()
        record = self.baseline()
        if record is None or record['data'].get('phase') == 'ready' or record['data'].get('statefulset_uid') != self.c.statefulset()['metadata']['uid'] or record['data'].get('monitoring_namespace') != self.namespace:
            other = [{'pool': t['scrapePool'], 'url': t['scrapeUrl'], 'labels': t.get('labels', {})} for t in initial if t.get('health') == 'up' and not self.selected(t)]
            data = {'phase': 'resetting', 'statefulset_uid': self.c.statefulset()['metadata']['uid'], 'monitoring_namespace': self.namespace, 'unrelated_up_targets': json.dumps(other)}
            if record: self.patch(record, {'data': data})
            else: self.c.create({'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': self.record_name,
                               'namespace': self.c.namespace, 'labels': {**self.c.labels, 'karma.dev/fixture': 'monitoring-baseline'}}, 'data': data})
        rules = self.drop_rules()
        for plural, kind, endpoints in [('servicemonitors', 'services', 'endpoints'), ('podmonitors', 'pods', 'podMetricsEndpoints')]:
            for obj in self.resources(plural):
                selected, foreign = self.selected_objects(obj, kind)
                if not selected: continue
                if not foreign:
                    self.delete(obj, plural)
                else:
                    spec = copy.deepcopy(obj['spec'])
                    for endpoint in spec.get(endpoints, []):
                        relabel = endpoint.setdefault('relabelings', [])
                        for rule in rules[:1]:
                            if rule not in relabel: relabel.insert(0, rule)
                    if spec != obj['spec']: self.patch(obj, {'spec': spec})
                    print('Excluded only selected nodes from shared ' + obj['kind'] + '/' + obj['metadata']['name'], flush=True)
        for obj in self.resources('scrapeconfigs'):
            spec = copy.deepcopy(obj['spec'])
            configs = spec.get('staticConfigs', [])
            relevant = any(urlparse('http://' + target).hostname in self.hosts() for config in configs for target in config.get('targets', []))
            active = any(self.selected(t) and ('scrapeConfig/' + obj['metadata']['namespace'] + '/' + obj['metadata']['name']) == t.get('scrapePool') for t in initial)
            discovery = any(not cfg.get('namespaces', {}).get('names') or self.c.namespace in cfg['namespaces']['names'] for cfg in spec.get('kubernetesSDConfigs', []))
            if relevant or active or discovery:
                relabel = spec.setdefault('relabelings', [])
                for rule in rules:
                    if rule not in relabel: relabel.insert(0, rule)
                if spec != obj['spec']: self.patch(obj, {'spec': spec})
        prom = self.c.get('prometheus', 'crdb', namespace=self.namespace)
        ref = prom['spec'].get('additionalScrapeConfigs')
        if ref:
            secret = self.c.get('secret', ref['name'], namespace=self.namespace)
            text = base64.b64decode(secret['data'][ref['key']]).decode()
            jobs = yaml.safe_load(text) or []
            modified = False
            for job in jobs:
                relevant = any(urlparse('http://' + target).hostname in self.hosts() for config in job.get('static_configs', []) for target in config.get('targets', []))
                active = any(self.selected(t) and t.get('scrapePool') == job.get('job_name') for t in initial)
                discovery = any(not cfg.get('namespaces', {}).get('names') or self.c.namespace in cfg['namespaces']['names'] for cfg in job.get('kubernetes_sd_configs', []))
                if relevant or active or discovery:
                    relabel = job.setdefault('relabel_configs', [])
                    for rule in self.drop_rules(raw=True):
                        if rule not in relabel: relabel.insert(0, rule); modified = True
            if modified:
                data = {**secret['data'], ref['key']: base64.b64encode(yaml.safe_dump(jobs, sort_keys=False).encode()).decode()}
                self.patch(secret, {'data': data})
        expected = json.loads(self.baseline()['data']['unrelated_up_targets'])
        def complete():
            self.absent(pending_ok=True)
            actual = [{'pool': t['scrapePool'], 'url': t['scrapeUrl'], 'labels': t.get('labels', {})} for t in self.targets() if t.get('health') == 'up']
            if any(item not in actual if isinstance(item, dict) else not any(t['url'] == item for t in actual) for item in expected):
                raise RuntimeError('unrelated scrape targets have not recovered after reload')
            return True
        self.c.wait(complete, 360)
        record = self.baseline()
        self.patch(record, {'data': {**record['data'], 'phase': 'ready'}})

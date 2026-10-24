"""Stage-bound authenticated baseline for a table-zone mutation task."""
import hashlib
import json
import os
import sys

from cryptography.fernet import Fernet, InvalidToken

from cluster import UnsafeState, database_container
from storage import signatures
from zones import Zones, without_requested


class Snapshot:
    def __init__(self, cluster):
        self.cluster = cluster
        self.zones = Zones(cluster)
        self.context = {'namespace':cluster.namespace,'cluster_name':cluster.name,
                        'run_id':os.environ['BENCH_RUN_ID'],'stage_id':os.environ['BENCH_STAGE_ID']}
        digest = hashlib.sha256('/'.join(self.context.values()).encode()).hexdigest()[:20]
        self.name = 'crdb-zone-baseline-'+digest
        self.labels = {**cluster.labels,'karma.dev/fixture':'zone-config','karma.dev/zone-id':digest}

    def snapshot(self):
        c,z = self.cluster,self.zones
        c.usable()
        z.fixture_ready()
        relations = z.relations()
        tables = [row for row in relations if row['relkind']=='r' and row['schema_name'] in (z.target,z.protected)]
        protected,other = {},{}
        for table in tables:
            config = z.effective(table)
            if table['schema_name']==z.protected:
                protected[table['table_id']] = config
            else:
                other[table['table_id']] = without_requested(config)
        sts = c.statefulset()
        return {'identity':{**self.context,'cluster_id':c.cluster_id()},
                'parameters':{'target_schema':z.target,'protected_schema':z.protected,'desired':z.desired},
                'relations':relations,'protected_effective':protected,'target_other_effective':other,
                'sparse_preserved':z.preserved_sparse(z.sparse(),tables),
                'workload':{'uid':sts['metadata']['uid'],'spec':sts['spec'],
                    'images':[database_container({'spec':p['spec']})['image'] for p in c.pods(sts)],
                    'stores':c.stores(sts),'secrets':signatures(c,sts['spec']['template'])}}

    def owned(self, obj):
        if obj and any(obj['metadata'].get('labels',{}).get(k)!=v for k,v in self.labels.items()):
            raise UnsafeState('zone baseline name belongs to a different resource')

    def load(self, private):
        obj = self.cluster.get('configmap',self.name)
        self.owned(obj)
        if not obj or set(obj.get('data',{}))!={'snapshot.enc'}:
            raise RuntimeError('encrypted zone baseline is missing or malformed')
        try:
            value = json.loads(Fernet(private['key'].encode()).decrypt(obj['data']['snapshot.enc'].encode()))
        except (InvalidToken,ValueError,TypeError,KeyError) as error:
            raise RuntimeError('encrypted zone baseline authentication failed') from error
        if value.get('identity')!={**self.context,'cluster_id':self.cluster.cluster_id()}:
            raise RuntimeError('zone baseline belongs to a different stage or cluster incarnation')
        return value

    def preserved(self, private):
        before = self.load(private)
        now = self.snapshot()
        for field in before:
            if before[field]!=now.get(field):
                if field == 'workload' and os.environ.get('BENCH_ORACLE_PHASE') == 'final_sweep':
                    old, current = before[field], now['workload']
                    durable_spec_fields = ('replicas', 'serviceName', 'selector', 'volumeClaimTemplates')
                    if (old.get('uid') == current.get('uid')
                            and old.get('stores') == current.get('stores')
                            and all(old.get('spec', {}).get(key) == current.get('spec', {}).get(key)
                                    for key in durable_spec_fields)):
                        continue
                raise RuntimeError('zone task changed protected state: '+field)
        return before

    def record(self, private):
        if private['frozen']:
            self.preserved(private)
            return
        from topology import Capacity
        Capacity(self.cluster,self.zones.desired['num_replicas']).ready()
        self.zones.trial()
        if not self.zones.needs_change():
            raise RuntimeError('zone task has no remaining configuration work')
        snapshot = self.snapshot()
        encrypted = Fernet(private['key'].encode()).encrypt(json.dumps(snapshot,sort_keys=True).encode()).decode()
        obj = self.cluster.get('configmap',self.name)
        self.owned(obj)
        data = {'snapshot.enc':encrypted}
        if obj:
            patch = [{'op':'test','path':'/metadata/uid','value':obj['metadata']['uid']},
                     {'op':'test','path':'/metadata/resourceVersion','value':obj['metadata']['resourceVersion']},
                     {'op':'add','path':'/data','value':data}]
            self.cluster.require(self.cluster.kubectl('patch','configmap',self.name,'--type=json','-p',json.dumps(patch)))
        else:
            self.cluster.create({'apiVersion':'v1','kind':'ConfigMap','metadata':{'name':self.name,'namespace':self.cluster.namespace,'labels':self.labels},'data':data})
        self.load(private)
        Capacity(self.cluster,self.zones.desired['num_replicas']).clear_completed()
        print('Refreshed encrypted pre-agent zone baseline',flush=True)

    def verify(self, private):
        self.preserved(private)
        if self.zones.needs_change():
            raise RuntimeError('one or more target tables do not have the four requested zone values')
        self.cluster.wait(self.cluster.usable,120)
        # Under-replication in an inherited protected/parent policy is outside
        # this table-configuration task. Check usable quorum and preserve it.
        self.preserved(private)
        print('Target zone values correct; protected, parent and unrequested configurations preserved.')


def private_input():
    value = json.load(sys.stdin)
    if set(value)!={'key','frozen'} or not isinstance(value['frozen'],bool):
        raise ValueError('invalid trusted framework input')
    return value

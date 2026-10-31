"""Resumable minimum node expansion; existing stores are never reset here."""
import hashlib
import json
import uuid

from cluster import UnsafeState, database_container
from pki import Certificates
from storage import signatures


def workload(sts):
    return {k:v for k,v in sts['spec'].items() if k not in ('replicas','template','updateStrategy')}


class Capacity:
    def __init__(self, cluster, required):
        self.cluster,self.required=cluster,int(required)
        self.name=cluster.name+'-zone-capacity'

    def load(self):
        obj=self.cluster.get('configmap',self.name)
        if obj:
            if obj['metadata'].get('labels',{}).get('karma.dev/fixture')!='zone-capacity' or obj['metadata'].get('labels',{}).get('app.kubernetes.io/instance')!=self.cluster.name:
                raise UnsafeState('node-capacity record belongs to another resource')
            if obj['data']['statefulset_uid']!=self.cluster.statefulset()['metadata']['uid']:return None
        return obj

    def pending(self):
        record=self.load()
        return record and record['data']['phase']!='ready'

    def update(self, record, values):
        patch=[{'op':'test','path':'/metadata/uid','value':record['metadata']['uid']},
               {'op':'test','path':'/metadata/resourceVersion','value':record['metadata']['resourceVersion']},
               {'op':'replace','path':'/data','value':{**record['data'],**values}}]
        self.cluster.require(self.cluster.kubectl('patch','configmap',self.name,'--type=json','-p',json.dumps(patch)))
        return self.load()

    def ready(self):
        if self.pending():raise RuntimeError('selected node-capacity preparation requires resumption')
        if int(self.cluster.statefulset()['spec']['replicas'])<self.required:
            raise RuntimeError('not enough selected nodes for the requested replica count')
        return self.cluster.usable()

    def begin(self):
        c=self.cluster
        c.wait(c.usable,180)
        sts=c.statefulset()
        count=int(sts['spec']['replicas'])
        expected=database_container(sts['spec']['template'])
        for pod in c.pods(sts):
            actual=database_container({'spec':pod['spec']})
            if any(actual.get(key,[])!=expected.get(key,[]) for key in ('image','command','args','env')):
                raise UnsafeState('finish the inherited server rollout before adding nodes')
        data={'statefulset_uid':sts['metadata']['uid'],'namespace_uid':c.get('namespace',c.namespace,namespace='')['metadata']['uid'],
              'original_count':str(count),'target_count':str(max(count,self.required)),
              'template':json.dumps(sts['spec']['template'],sort_keys=True),'workload':json.dumps(workload(sts),sort_keys=True),
              'strategy':json.dumps(sts['spec']['updateStrategy'],sort_keys=True),'stores':json.dumps(c.stores(sts),sort_keys=True),
              'source_secrets':json.dumps(signatures(c,sts['spec']['template']),sort_keys=True),
              'cluster_id':c.cluster_id(),'nonce':uuid.uuid4().hex[:8],'phase':'planning'}
        obj=c.get('configmap',self.name)
        if obj:return self.update(obj,data)
        c.create({'apiVersion':'v1','kind':'ConfigMap','metadata':{'name':self.name,'namespace':c.namespace,
            'labels':{**c.labels,'karma.dev/fixture':'zone-capacity'}},'data':data})
        return self.load()

    def preserved(self, record):
        c=self.cluster;data=record['data'];sts=c.statefulset()
        if sts['metadata']['uid']!=data['statefulset_uid'] or c.get('namespace',c.namespace,namespace='')['metadata']['uid']!=data['namespace_uid']:
            raise UnsafeState('selected workload or namespace identity changed during expansion')
        allowed=[json.loads(data[k]) for k in ('template','trust_template','final_template') if k in data]
        if sts['spec']['template'] not in allowed or workload(sts)!=json.loads(data['workload']):
            raise UnsafeState('selected workload configuration changed during expansion')
        if int(sts['spec']['replicas']) not in (int(data['original_count']),int(data['target_count'])):
            raise UnsafeState('selected replica count changed outside capacity preparation')
        if c.stores(sts,int(data['original_count']))!=json.loads(data['stores']):
            raise UnsafeState('inherited store identities changed during expansion')
        if signatures(c,json.loads(data['template']))!=json.loads(data['source_secrets']):
            raise UnsafeState('inherited certificate material changed during expansion')
        for name,digest in json.loads(data.get('pki_hashes','{}')).items():
            secret=c.get('secret',name)
            if not secret or hashlib.sha256(json.dumps(secret['data'],sort_keys=True).encode()).hexdigest()!=digest:
                raise UnsafeState('owned capacity certificate material changed during preparation')

    def roll(self, record, key):
        c=self.cluster
        self.preserved(record)
        template=json.loads(record['data'][key])
        sts=c.statefulset()
        if sts['spec']['template']!=template or sts['spec']['updateStrategy']!={'type':'OnDelete'}:
            c.patch_spec(sts,{'template':template,'updateStrategy':{'type':'OnDelete'}})
        for ordinal in reversed(range(int(record['data']['original_count']))):
            c.wait(c.usable,240)
            pod=c.get('pod',c.name+'-'+str(ordinal))
            expected=template['spec'].get('volumes',[])
            actual=pod['spec'].get('volumes',[])
            expected_secrets={v['name']:v['secret']['secretName'] for v in expected if 'secret' in v}
            actual_secrets={v['name']:v['secret']['secretName'] for v in actual if 'secret' in v}
            if actual_secrets!=expected_secrets:
                print('Reloading selected certificate trust on node '+str(ordinal),flush=True)
                c.delete_pod(pod)
                c.wait(c.usable,300)
            if c.cluster_id()!=record['data']['cluster_id']:
                raise UnsafeState('database identity changed during certificate reload')
        self.preserved(record)

    def apply(self):
        c=self.cluster
        record=self.load()
        if not record or record['data']['phase']=='ready':
            if int(c.statefulset()['spec']['replicas'])>=self.required:
                self.ready();return
            record=self.begin()
        if int(record['data']['target_count'])<self.required:
            raise UnsafeState('pending capacity plan belongs to a different replica request')
        self.preserved(record)
        if record['data']['phase']=='planning':
            material=Certificates(c,record).prepare()
            record=self.update(record,{key:json.dumps(value,sort_keys=True) if key!='rotate' else value for key,value in material.items()})
            record=self.update(record,{'phase':'trust' if material['rotate']=='true' else 'certificate'})
        if record['data']['phase']=='trust':
            # First trust the additional CA while every server still presents
            # its existing certificate. Original/shared Secrets stay untouched.
            self.roll(record,'trust_template')
            record=self.update(record,{'phase':'certificate'})
        if record['data']['phase']=='certificate':
            self.roll(record,'final_template')
            record=self.update(record,{'phase':'scaling'})
        if record['data']['phase']=='scaling':
            self.preserved(record)
            c.patch_spec(c.statefulset(),{'replicas':int(record['data']['target_count'])})
            c.wait(c.usable,360)
            if c.cluster_id()!=record['data']['cluster_id']:
                raise UnsafeState('database identity changed during expansion')
            self.preserved(record)
            c.patch_spec(c.statefulset(),{'updateStrategy':json.loads(record['data']['strategy'])})
            record=self.update(record,{'phase':'ready'})
        self.ready()

    def clear_completed(self):
        record=self.load()
        if record and record['data']['phase']=='ready':
            options={'apiVersion':'v1','kind':'DeleteOptions','preconditions':{'uid':record['metadata']['uid'],'resourceVersion':record['metadata']['resourceVersion']}}
            self.cluster.require(self.cluster.kubectl('delete','--raw='+f'/api/v1/namespaces/{self.cluster.namespace}/configmaps/{self.name}',
                '-f','-',input_text=json.dumps(options)))

"""Extend only selected server trust when new node names need certificates."""
import base64
import copy
import datetime
import hashlib
import json
import re

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, ed448, rsa
from cryptography.x509.oid import NameOID

from cluster import UnsafeState, database_container


def decode(data, key):
    try: return base64.b64decode(data[key],validate=True)
    except (KeyError,ValueError) as error: raise UnsafeState('certificate Secret is missing valid '+key) from error


def certificates(pem):
    return [x509.load_pem_x509_certificate(value) for value in re.findall(b'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',pem,re.S)]


def public_key(key):
    return key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)


def covered(certificate, host):
    try: names=certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound: return False
    return any(host==name or name.startswith('*.') and host.split('.',1)[1:]==[name[2:]] for name in names)


class Certificates:
    def __init__(self, cluster, record):
        self.cluster,self.record=cluster,record
        self.template=json.loads(record['data']['template'])
        self.db=database_container(self.template)
        self.count=int(record['data']['target_count'])

    def source(self):
        c=self.cluster
        directory=c.certificate_directory(self.db)
        mounts=[m for m in self.db.get('volumeMounts',[]) if m['mountPath']==directory and not m.get('subPath') and not m.get('subPathExpr')]
        volumes={v['name']:v for v in self.template['spec'].get('volumes',[])}
        if len(mounts)!=1 or 'secret' not in volumes.get(mounts[0]['name'],{}):
            raise UnsafeState('certificate expansion requires a full Secret-backed certificate directory')
        volume=volumes[mounts[0]['name']]
        secret=c.get('secret',volume['secret']['secretName'])
        if not secret:raise UnsafeState('selected certificate Secret is missing')
        items=volume['secret'].get('items')
        keys={item['path']:item['key'] for item in items} if items else {key:key for key in secret.get('data',{})}
        for path in ('ca.crt','node.crt','node.key','client.root.crt','client.root.key'):
            if path not in keys:raise UnsafeState('selected certificate projection lacks '+path)
            decode(secret['data'],keys[path])
        return volume['name'],secret,keys

    def needs_extension(self):
        if self.cluster.connection_flags(self.db)[0]=='--insecure':return False
        directory=self.cluster.certificate_directory(self.db)
        pem=self.cluster.require(self.cluster.kubectl('exec',self.cluster.name+'-0','-c',self.db['name'],'--','cat',directory+'/node.crt')).encode()
        parsed=certificates(pem)
        if not parsed:raise UnsafeState('selected node certificate cannot be inspected')
        return not all(covered(parsed[0],self.cluster.host(i)) for i in range(self.count))

    def signer(self, secret, ca, node):
        candidates=[secret]
        # Read only selected-cluster Secrets when looking for its CA signer.
        value=self.cluster.require(self.cluster.kubectl('get','secrets','-l','app.kubernetes.io/instance='+self.cluster.name,'-o','json'))
        candidates+=json.loads(value)['items']
        for candidate in candidates:
            if 'ca.key' not in candidate.get('data',{}):continue
            try:key=serialization.load_pem_private_key(decode(candidate['data'],'ca.key'),password=None)
            except (ValueError,TypeError):continue
            for certificate in certificates(ca):
                if certificate.subject==node.issuer and public_key(key)==certificate.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo):
                    return certificate,key
        return None,None

    def material(self, source, keys):
        data=copy.deepcopy(source['data']);ca=decode(data,keys['ca.crt'])
        node=certificates(decode(data,keys['node.crt']))[0]
        key=serialization.load_pem_private_key(decode(data,keys['node.key']),password=None)
        if public_key(key)!=node.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo):
            raise UnsafeState('selected node certificate and key do not match')
        signer,ca_key=self.signer(source,ca,node)
        rotated=signer is None
        now=datetime.datetime.now(datetime.timezone.utc)
        if rotated:
            ca_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
            subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'karma-zone-capacity-'+self.record['data']['nonce'])])
            signer=(x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(ca_key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=5))
                .not_valid_after(now+datetime.timedelta(days=3650)).add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True)
                .add_extension(x509.KeyUsage(True,False,False,False,False,True,True,False,False),critical=True).sign(ca_key,hashes.SHA256()))
            ca=ca.rstrip()+b'\n'+signer.public_bytes(serialization.Encoding.PEM)
        expires=signer.not_valid_after_utc if hasattr(signer,'not_valid_after_utc') else signer.not_valid_after.replace(tzinfo=datetime.timezone.utc)
        expiration=min(now+datetime.timedelta(days=365),expires)
        builder=(x509.CertificateBuilder().subject_name(node.subject).issuer_name(signer.subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=5)).not_valid_after(expiration))
        names=[]
        for extension in node.extensions:
            if isinstance(extension.value,x509.SubjectAlternativeName):names=list(extension.value)
            elif isinstance(extension.value,x509.AuthorityKeyIdentifier):
                builder=builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),extension.critical)
            else:builder=builder.add_extension(extension.value,extension.critical)
        existing={name.value for name in names if isinstance(name,x509.DNSName)}
        for ordinal in range(self.count):
            host=self.cluster.host(ordinal)
            if host not in existing:names.append(x509.DNSName(host))
        builder=builder.add_extension(x509.SubjectAlternativeName(names),critical=False)
        algorithm=None if isinstance(ca_key,(ed25519.Ed25519PrivateKey,ed448.Ed448PrivateKey)) else hashes.SHA256()
        certificate=builder.sign(ca_key,algorithm)
        data[keys['ca.crt']]=base64.b64encode(ca).decode()
        data[keys['node.crt']]=base64.b64encode(certificate.public_bytes(serialization.Encoding.PEM)).decode()
        data['ca.key']=base64.b64encode(ca_key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())).decode()
        return data,rotated

    def owned_secret(self, name, data=None):
        c=self.cluster
        labels={**c.labels,'karma.dev/fixture':'zone-capacity-pki','karma.dev/capacity-nonce':self.record['data']['nonce']}
        obj=c.get('secret',name)
        if obj:
            if any(obj['metadata'].get('labels',{}).get(k)!=v for k,v in labels.items()) or not any(r.get('uid')==self.record['data']['statefulset_uid'] for r in obj['metadata'].get('ownerReferences',[])):
                raise UnsafeState('capacity certificate name belongs to another resource')
            return obj
        if data is None:return None
        c.create({'apiVersion':'v1','kind':'Secret','metadata':{'name':name,'namespace':c.namespace,'labels':labels,
            'ownerReferences':[{'apiVersion':'apps/v1','kind':'StatefulSet','name':c.name,'uid':self.record['data']['statefulset_uid']}]},'type':'Opaque','data':data})
        return self.owned_secret(name)

    def prepare(self):
        if not self.needs_extension():return {'trust_template':self.template,'final_template':self.template,'pki_hashes':{},'rotate':'false'}
        volume,source,keys=self.source()
        nonce=self.record['data']['nonce']
        final_name=self.cluster.name+'-zone-'+nonce+'-certs'
        trust_name=self.cluster.name+'-zone-'+nonce+'-trust'
        final=self.owned_secret(final_name)
        if final is None:
            data,rotated=self.material(source,keys)
            final=self.owned_secret(final_name,data)
        else:rotated=decode(final['data'],keys['ca.crt'])!=decode(source['data'],keys['ca.crt'])
        final_template=copy.deepcopy(self.template)
        next(v for v in final_template['spec']['volumes'] if v['name']==volume)['secret']['secretName']=final_name
        trust_template=copy.deepcopy(self.template)
        pki={final_name:hashlib.sha256(json.dumps(final['data'],sort_keys=True).encode()).hexdigest()}
        if rotated:
            data=copy.deepcopy(source['data'])
            data[keys['ca.crt']]=final['data'][keys['ca.crt']]
            data['ca.key']=final['data']['ca.key']
            trust=self.owned_secret(trust_name,data)
            next(v for v in trust_template['spec']['volumes'] if v['name']==volume)['secret']['secretName']=trust_name
            pki[trust_name]=hashlib.sha256(json.dumps(trust['data'],sort_keys=True).encode()).hexdigest()
        return {'trust_template':trust_template,'final_template':final_template,'pki_hashes':pki,'rotate':'true' if rotated else 'false'}

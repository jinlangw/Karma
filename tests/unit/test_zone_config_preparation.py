"""Boundary checks for SQL quoting, inherited policies and placement protection."""
import importlib.util
import sys
from pathlib import Path

import pytest

SCRIPTS=Path(__file__).resolve().parents[2]/'cases/cockroachdb/zone-config/scripts'

# Cases intentionally use local module names. Isolate this case from other case
# helpers loaded by the unit suite.
@pytest.fixture
def modules(monkeypatch):
    names=('cluster','placement','zones')
    for name in names:monkeypatch.delitem(sys.modules,name,raising=False)
    monkeypatch.syspath_prepend(str(SCRIPTS))
    import zones,placement
    yield zones,placement
    for name in names:sys.modules.pop(name,None)


def test_sparse_literals_and_quoted_table_names(modules):
    z,_=modules
    sql='ALTER TABLE "a.b"."tenant,one"."t""x" CONFIGURE ZONE USING constraints = \'+region=east,-ssd\', num_replicas = 3;'
    assert z.assignments(sql)=={'constraints':"'+region=east,-ssd'",'num_replicas':'3'}
    assert z.table_target('TABLE "a.b"."tenant,one"."t""x"')==('a.b','tenant,one','t"x')
    assert z.identifier('x"; DROP DATABASE x;--')=='"x""; DROP DATABASE x;--"'
    assert z.assignments('ALTER TABLE "CONFIGURE ZONE USING pretend" CONFIGURE ZONE USING num_replicas=3;')=={'num_replicas':'3'}


def test_mask_only_requested_values_on_exact_target_tables(modules,monkeypatch):
    z,_=modules;zone=z.Zones(None)
    tables=[{'schema_name':'tenant_b','table_name':'table_c','table_id':'101'}]
    sparse={'TABLE defaultdb.tenant_b.table_c':{'num_replicas':'3','num_voters':'1'},
            'TABLE defaultdb.tenant_b.table_c2':{'num_replicas':'5'},
            'DATABASE defaultdb':{'gc.ttlseconds':'7200'},
            'TABLE defaultdb.tenant_a.table_a':{'gc.ttlseconds':'600'}}
    assert zone.preserved_sparse(sparse,tables)=={**sparse,'TABLE defaultdb.tenant_b.table_c':{'num_voters':'1'}}
    assert z.requested({'num_replicas':30,'gc':{'ttlseconds':14400},'range_min_bytes':1,'range_max_bytes':2})['num_replicas']!=3


def test_real_yaml_constraint_shapes_and_overlapping_groups(modules):
    _,p=modules
    east={'locality':{'region':'east'},'attrs':{'ssd'}}
    west={'locality':{'region':'west'},'attrs':set()}
    assert p.feasible({'constraints':{'+region=east':1,'+ssd':1}},[east,west],1,1) is False # sum exceeds replicas
    assert p.feasible({'constraints':{'+region=east':1,'+ssd':1}},[east,east],2,1)
    assert not p.feasible({'constraints':['+region=east']},[east,west],2,1)
    assert p.feasible({'constraints':['-region=missing'],'voter_constraints':['+ssd']},[east,west],2,1)
    assert not p.feasible({'voter_constraints':{'+region=east':2}},[east,west],2,2)


def test_preserve_unrequested_nested_values(modules):
    z,_=modules
    assert z.without_requested({'gc':{'ttlseconds':10,'other':'keep'},'num_voters':1,'constraints':['+ssd'],'range_min_bytes':1,'num_replicas':3})=={'gc':{'other':'keep'},'num_voters':1,'constraints':['+ssd']}


def test_reject_ambiguous_sql_and_schema_parameters(modules,monkeypatch):
    z,_=modules
    with pytest.raises(RuntimeError):z.assignments('ALTER TABLE t CONFIGURE ZONE USING num_replicas=3,num_replicas=5;')
    monkeypatch.setenv('BENCH_PARAM_TARGET_SCHEMA','tenant_a')
    with pytest.raises(ValueError):z.Zones(None)

@pytest.mark.parametrize('replicas,voters,expected',[(2,None,1),(3,5,3),(5,None,None),(4,1,None)])
def test_voter_repair_preserves_compatible_customization(modules,monkeypatch,replicas,voters,expected):
    z,p=modules
    monkeypatch.setenv('BENCH_PARAM_NUM_REPLICAS',str(replicas))
    monkeypatch.setattr(z,'selected_nodes',lambda _: [{'locality':{},'attrs':set()} for _ in range(replicas)])
    zone=z.Zones(None);table={'table_id':'1','table_name':'t','schema_name':'tenant_b'}
    zone.tables=lambda:[table]
    zone.effective=lambda _: {'num_voters':voters,'constraints':[],'voter_constraints':[]}
    plans=[];zone.trial=lambda extras=None:plans.append(extras or {})
    mutations=[];zone.sql=lambda sql:mutations.append(sql)
    zone.compatibility()
    assert plans[0]==({'1':{'num_voters':expected}} if expected is not None else {})
    assert bool(mutations)==(expected is not None)


def test_only_blocking_target_constraint_is_repaired(modules,monkeypatch):
    z,p=modules
    monkeypatch.setattr(z,'selected_nodes',lambda _: [{'locality':{},'attrs':set()} for _ in range(3)])
    zone=z.Zones(None);table={'table_id':'1','table_name':'t','schema_name':'tenant_b'}
    zone.tables=lambda:[table]
    zone.effective=lambda _: {'num_voters':1,'constraints':{'+region=east':3},'voter_constraints':['-ssd']}
    plans=[];zone.trial=lambda extras=None:plans.append(extras or {})
    zone.sql=lambda _:None
    zone.compatibility()
    assert plans[0]=={'1':{'constraints':"'[]'"}}

@pytest.mark.parametrize('keep_signer',[True,False])
def test_certificate_extension_preserves_original_client_and_shared_secret(modules,monkeypatch,keep_signer):
    import base64,copy,datetime,json
    from types import SimpleNamespace
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes,serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    monkeypatch.delitem(sys.modules,'pki',raising=False)
    import pki
    now=datetime.datetime.utcnow();ca_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    ca_name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'original')])
    ca=(x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key()).serial_number(1).not_valid_before(now-datetime.timedelta(days=1)).not_valid_after(now+datetime.timedelta(days=365)).add_extension(x509.BasicConstraints(ca=True,path_length=None),True).sign(ca_key,hashes.SHA256()))
    node_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    node=(x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'node')])).issuer_name(ca_name).public_key(node_key.public_key()).serial_number(2).not_valid_before(now-datetime.timedelta(days=1)).not_valid_after(now+datetime.timedelta(days=60)).add_extension(x509.SubjectAlternativeName([x509.DNSName('old.example')]),False).sign(ca_key,hashes.SHA256()))
    private=lambda key:key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
    raw={'ca.crt':ca.public_bytes(serialization.Encoding.PEM),'node.crt':node.public_bytes(serialization.Encoding.PEM),'node.key':private(node_key),'client.root.crt':b'unchanged-client','client.root.key':b'unchanged-key'}
    if keep_signer:raw['ca.key']=private(ca_key)
    data={key:base64.b64encode(value).decode() for key,value in raw.items()};before=copy.deepcopy(data)
    c=SimpleNamespace(name='orders',kubectl=lambda *args:json.dumps({'items':[]}),require=lambda value:value,host=lambda i:'node-'+str(i)+'.example')
    record={'data':{'template':json.dumps({'spec':{'containers':[{'name':'db','image':'cockroachdb/cockroach:v24.1.0','command':['cockroach','start']}]}}),'target_count':'3','nonce':'test'}}
    material,rotated=pki.Certificates(c,record).material({'data':data},{key:key for key in raw})
    assert rotated is (not keep_signer) and data==before
    assert material['client.root.crt']==data['client.root.crt'] and material['client.root.key']==data['client.root.key']
    leaf=pki.certificates(pki.decode(material,'node.crt'))[0]
    assert all(pki.covered(leaf,c.host(i)) for i in range(3)) and pki.covered(leaf,'old.example')
    assert len(pki.certificates(pki.decode(material,'ca.crt')))==(1 if keep_signer else 2)
    if keep_signer:assert material['ca.crt']==data['ca.crt']
    sys.modules.pop('pki',None)


def test_catalog_filter_does_not_hide_valid_pg_prefixed_schema(modules):
    import sqlite3
    z,_=modules;zone=z.Zones(None)
    db=sqlite3.connect(':memory:');db.row_factory=sqlite3.Row
    db.execute("ATTACH DATABASE ':memory:' AS pg_catalog")
    db.executescript('CREATE TABLE pg_catalog.pg_namespace(oid INTEGER,nspname TEXT); CREATE TABLE pg_catalog.pg_class(oid INTEGER,relname TEXT,relnamespace INTEGER,relkind TEXT);')
    for index,name in enumerate(('pgtenant','pg_catalog','pg_extension','tenant_b')):
        db.execute('INSERT INTO pg_catalog.pg_namespace VALUES(?,?)',(index,name))
        db.execute('INSERT INTO pg_catalog.pg_class VALUES(?,?,?,?)',(index+100,'orders',index,'r'))
    db.create_function('left',2,lambda value,count:value[:count])
    # Adapt only PostgreSQL casting and SQLite's reserved LEFT function token;
    # execute the real discovery predicates against a valid pg-prefixed schema.
    zone.rows=lambda query:[dict(row) for row in db.execute(query.replace('c.oid::INT8','CAST(c.oid AS BIGINT)').replace('left(', '"left"('))]
    assert [row['schema_name'] for row in zone.relations()]==['pgtenant','tenant_b']
    db.close()

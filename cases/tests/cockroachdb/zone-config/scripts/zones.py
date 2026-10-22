"""Selected-table zone inspection and the four-field policy challenge."""
import csv
import io
import itertools
import os
import re

import yaml

from cluster import UnsafeState
from placement import feasible, selected_nodes


DATABASE = 'defaultdb'
FIELDS = ('num_replicas', 'gc.ttlseconds', 'range_min_bytes', 'range_max_bytes')


def identifier(value):
    if not value or '\x00' in value or len(value.encode()) > 63:
        raise ValueError('SQL identifiers must be nonempty and at most 63 bytes')
    return '"' + value.replace('"', '""') + '"'


def literal(value):
    return "'" + value.replace("'", "''") + "'"


def split_sql(value, separator=','):
    """Split vendor-produced literals without splitting quoted constraint lists."""
    parts, start, quote, index = [], 0, None, 0
    while index < len(value):
        char = value[index]
        if quote:
            if char == quote:
                if index + 1 < len(value) and value[index + 1] == quote:
                    index += 1
                else:
                    quote = None
        elif char in ('"', "'"):
            quote = char
        elif char == separator:
            parts.append(value[start:index].strip())
            start = index + 1
        index += 1
    if quote:
        raise UnsafeState('zone inspection returned an unterminated SQL literal')
    parts.append(value[start:].strip())
    return parts


def table_target(value):
    if not value.startswith('TABLE '):
        return None
    parts = split_sql(value[6:].strip(), '.')
    names = [p[1:-1].replace('""', '"') if p.startswith('"') and p.endswith('"') else p for p in parts]
    if len(names) == 2:
        names.insert(0, DATABASE)
    return tuple(names) if len(names) == 3 else None


def assignments(sql):
    # A quoted table name can itself contain "CONFIGURE ZONE USING".
    # Match vendor keywords only outside SQL identifiers and string literals.
    tokens=list(re.finditer(r'''"(?:[^"]|"")*"|'(?:[^']|'')*'|[A-Za-z_][A-Za-z_0-9]*|[^\s]''',sql))
    start=None
    for index in range(len(tokens)-2):
        if [token.group().upper() for token in tokens[index:index+3]]==['CONFIGURE','ZONE','USING']:
            start=tokens[index+2].end()
            break
    if start is None:
        raise UnsafeState('zone inspection returned an unsupported sparse configuration')
    result = {}
    for entry in split_sql(sql[start:].strip().rstrip(';')):
        key, equals, value = entry.partition('=')
        if not equals or not key.strip() or not value.strip() or key.strip() in result:
            raise UnsafeState('zone inspection returned malformed or duplicate assignments')
        result[key.strip()] = value.strip()
    return result


def without_requested(config):
    result = dict(config)
    for name in ('num_replicas', 'range_min_bytes', 'range_max_bytes'):
        result.pop(name, None)
    if 'gc' in result:
        result['gc'] = {k:v for k,v in result['gc'].items() if k != 'ttlseconds'}
        if not result['gc']:
            result.pop('gc')
    return result


def requested(config):
    try:
        return {'num_replicas':int(config['num_replicas']), 'gc.ttlseconds':int(config['gc']['ttlseconds']),
                'range_min_bytes':int(config['range_min_bytes']), 'range_max_bytes':int(config['range_max_bytes'])}
    except (KeyError, TypeError, ValueError) as error:
        raise UnsafeState('effective zone configuration omitted a required field') from error


class Zones:
    def __init__(self, cluster):
        self.cluster = cluster
        self.target = os.environ.get('BENCH_PARAM_TARGET_SCHEMA', 'tenant_b')
        self.protected = os.environ.get('BENCH_PARAM_PROTECTED_SCHEMA', 'tenant_a')
        identifier(self.target); identifier(self.protected)
        if self.target == self.protected or any(v in ('public','pg_catalog','information_schema','crdb_internal','pg_extension') or v.startswith('pg_') for v in (self.target,self.protected)):
            raise ValueError('target and protected schemas must be distinct user schemas')
        self.desired = dict(zip(FIELDS,(int(os.environ.get('BENCH_PARAM_'+name,default)) for name,default in
            [('NUM_REPLICAS','3'),('GC_TTL_SECONDS','14400'),('RANGE_MIN_BYTES','134217728'),('RANGE_MAX_BYTES','536870912')])))
        if not 1 <= self.desired['num_replicas'] <= 2147483647 or not 1 <= self.desired['gc.ttlseconds'] <= 2147483647:
            raise ValueError('replicas and GC TTL must be positive signed 32-bit integers')
        if not 0 < self.desired['range_min_bytes'] < self.desired['range_max_bytes'] <= 9223372036854775807:
            raise ValueError('range bounds must be positive, ordered signed 64-bit integers')

    def sql(self, query, timeout=30):
        result = self.cluster.client('sql','--database='+DATABASE,'-e',query,timeout=timeout)
        if result.returncode:
            raise UnsafeState('zone SQL failed without permission to reset stores: '+result.stderr.strip())
        return result.stdout

    def rows(self, query):
        return list(csv.DictReader(io.StringIO(self.sql(query))))

    def relations(self):
        return self.rows("SELECT n.nspname AS schema_name,c.relname AS table_name,c.oid::INT8 AS table_id,c.relkind "
                         "FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace "
                         "WHERE n.nspname NOT IN ('pg_catalog','information_schema','crdb_internal','pg_extension') "
                         "AND left(n.nspname,3) <> 'pg_' AND c.relkind IN ('r','v','m','S') ORDER BY n.nspname,c.relname;")

    def tables(self):
        return [row for row in self.relations() if row['relkind']=='r' and row['schema_name'] in (self.target,self.protected)]

    @staticmethod
    def key(table):
        return tuple(table[k] for k in ('schema_name','table_name','table_id'))

    @staticmethod
    def qualified(table):
        return '.'.join(identifier(v) for v in (DATABASE,table['schema_name'],table['table_name']))

    def fixture_ready(self):
        tables = self.tables()
        if any(sum(row['schema_name']==schema for row in tables)<2 for schema in (self.target,self.protected)):
            raise RuntimeError('both tenant schemas require at least two ordinary tables')
        return True

    def ensure_fixtures(self):
        self.cluster.require(self.cluster.sql('CREATE DATABASE IF NOT EXISTS '+identifier(DATABASE)+';'))
        for schema,names in [(self.protected,('table_a','table_b')),(self.target,('table_c','table_d'))]:
            self.sql('CREATE SCHEMA IF NOT EXISTS '+identifier(schema)+';')
            while True:
                relations = self.relations()
                if sum(row['schema_name']==schema and row['relkind']=='r' for row in relations)>=2:
                    break
                occupied = {row['table_name'] for row in relations if row['schema_name']==schema}
                candidates = list(names)+['karma_zone_'+str(i) for i in range(1,len(occupied)+3)]
                name = next(value for value in candidates if value not in occupied)
                qualified = self.qualified({'schema_name':schema,'table_name':name})
                self.sql('CREATE TABLE '+qualified+' (id INT PRIMARY KEY,value STRING);')
                self.sql('INSERT INTO '+qualified+" VALUES (1,'47');")
        self.fixture_ready()

    def effective(self, table):
        rows = self.rows('SELECT full_config_yaml FROM [SHOW ZONE CONFIGURATION FOR TABLE '+self.qualified(table)+'];')
        if len(rows)!=1 or not rows[0].get('full_config_yaml'):
            raise UnsafeState('zone inspection did not return exactly one effective table configuration')
        value = yaml.safe_load(rows[0]['full_config_yaml'])
        if not isinstance(value,dict):
            raise UnsafeState('effective zone configuration is not a mapping')
        requested(value)
        return value

    def sparse(self):
        rows = self.rows('SHOW ALL ZONE CONFIGURATIONS;')
        result = {}
        for row in rows:
            target,sql = row['target'],row['raw_config_sql']
            if target in result:
                raise UnsafeState('duplicate sparse zone target')
            result[target] = assignments(sql)
        return result

    def preserved_sparse(self, sparse, tables):
        targets = {(DATABASE,t['schema_name'],t['table_name']) for t in tables if t['schema_name']==self.target}
        result = {}
        for target,values in sparse.items():
            remaining = {k:v for k,v in values.items() if k not in FIELDS} if table_target(target) in targets else values
            if remaining:
                result[target] = remaining
        return result

    def desired_sql(self, table, values=None):
        values = self.desired if values is None else values
        return 'ALTER TABLE '+self.qualified(table)+' CONFIGURE ZONE USING '+','.join(k+'='+str(v) for k,v in values.items())+';'

    def matching(self, table):
        return requested(self.effective(table)) == self.desired

    def needs_change(self):
        self.fixture_ready()
        return any(not self.matching(t) for t in self.tables() if t['schema_name']==self.target)

    def trial(self, extras=None):
        """Validate all four assignments without committing a zone change."""
        before = self.sparse()
        settings = self.rows("SELECT setting FROM pg_catalog.pg_settings WHERE name='autocommit_before_ddl';")
        prefix = 'SET autocommit_before_ddl=off; ' if settings else ''
        sql = prefix+'BEGIN; '+''.join(self.desired_sql(t,{**self.desired,**(extras or {}).get(t['table_id'],{})}) for t in self.tables() if t['schema_name']==self.target)+' ROLLBACK;'
        result = self.cluster.client('sql','--database='+DATABASE,'-e',sql,timeout=45)
        after = self.sparse()
        if before != after:
            raise UnsafeState('zone trial changed stored configuration despite rollback')
        if result.returncode:
            raise UnsafeState('requested zone configuration is incompatible: '+result.stderr.strip())

    def compatibility(self, apply=True):
        # Inspect actual selected nodes. Only target overrides which block the
        # requested replica policy may change, and only before the baseline.
        nodes=selected_nodes(self.cluster)
        replicas=self.desired['num_replicas']
        plans={}
        for table in self.tables():
            if table['schema_name']!=self.target:continue
            config=self.effective(table)
            voters=config.get('num_voters')
            extras={}
            if voters is None:
                voters=replicas
                if voters==2:voters=1;extras['num_voters']=1
            elif voters>replicas:
                voters=1 if replicas==2 else replicas
                extras['num_voters']=voters
            if not feasible(config,nodes,replicas,voters):
                fields=('constraints','voter_constraints')
                for size in (1,2):
                    for clearing in itertools.combinations(fields,size):
                        candidate={**config,**{field:[] for field in clearing}}
                        if feasible(candidate,nodes,replicas,voters):
                            extras.update({field:"'[]'" for field in clearing})
                            break
                    else:continue
                    break
                else:raise UnsafeState('selected nodes cannot satisfy requested placement')
            if extras:plans[table['table_id']]=extras
        # A single transaction validates the full final policy before any
        # auxiliary override is committed. Failures never justify resetting data.
        self.trial(plans)
        if plans and not apply:
            raise RuntimeError('target placement compatibility requires preparation')
        for table in self.tables():
            if table['table_id'] in plans:
                print('Repairing blocking target placement fields: '+','.join(plans[table['table_id']]),flush=True)
                self.sql(self.desired_sql(table,plans[table['table_id']]))
        self.trial()

    def prepare_change(self):
        self.fixture_ready()
        self.compatibility()
        if self.needs_change():
            return
        table = next(t for t in self.tables() if t['schema_name']==self.target)
        ttl = self.desired['gc.ttlseconds']
        if ttl==2147483647:
            # Do not shorten retention just to create a challenge at the TTL
            # ceiling. A larger range maximum is a harmless alternative.
            maximum = self.desired['range_max_bytes']
            if maximum==9223372036854775807:
                minimum = self.desired['range_min_bytes']
                changed = {'range_min_bytes':minimum+1 if minimum+1<maximum else minimum-1}
            else:
                changed = {'range_max_bytes':maximum+1}
        else:
            changed = {'gc.ttlseconds':ttl+1}
        self.sql(self.desired_sql(table,changed))
        if not self.needs_change():
            raise RuntimeError('target mismatch preparation did not create work')

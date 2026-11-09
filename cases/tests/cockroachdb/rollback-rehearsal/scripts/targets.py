"""Two supported rollback field types; discover actual defaults and explicit overrides."""
import csv
import io

import yaml

RATE = 'kv.snapshot_rebalance.max_rate'


def quote(value):
    return '"' + value.replace('"', '""') + '"'


def object_sql(row):
    if row['kind'] == 'DATABASE': return 'DATABASE ' + quote(row['database'])
    return 'TABLE ' + '.'.join(quote(row[k]) for k in ('database', 'schema', 'table'))



class Targets:
    def __init__(self, cluster): self.cluster = cluster

    def rows(self, query):
        return list(csv.DictReader(io.StringIO(self.cluster.require(self.cluster.sql(query, timeout=30)))))

    def inspect(self):
        c = self.cluster
        # Present in the supported release matrix, verified by live capability tests.
        default = int(c.value("SELECT crdb_internal.cluster_setting_encoded_default('" + RATE + "');"))
        # SHOW formats bytes with rounding (33554433B displays as 32 MiB).
        # Persisted bytes, or the encoded factory default after RESET, are exact.
        value = int(c.value("SELECT COALESCE((SELECT value::INT8 FROM system.settings WHERE name='" + RATE + "'), "
                            "crdb_internal.cluster_setting_encoded_default('" + RATE + "')::INT8);"))
        if default <= 0: raise RuntimeError('snapshot-rate default is invalid')
        roots = self.rows("SELECT full_config_yaml FROM crdb_internal.zones WHERE target='RANGE default';")
        if len(roots) != 1: raise RuntimeError('default zone is unavailable')
        root_gc = int(yaml.safe_load(roots[0]['full_config_yaml'])['gc']['ttlseconds'])
        rows = self.rows("SELECT target, database_name, schema_name, table_name, raw_config_yaml "
                         "FROM crdb_internal.zones WHERE subzone_id=0 AND database_name!='system' "
                         "AND (target LIKE 'DATABASE %' OR target LIKE 'TABLE %') ORDER BY target;")
        zones, selected = [], []
        for row in rows:
            raw = yaml.safe_load(row['raw_config_yaml']) or {}
            ttl = (raw.get('gc') or {}).get('ttlseconds')
            kind = 'DATABASE' if row['target'].startswith('DATABASE ') else 'TABLE'
            item = {'kind': kind, 'database': row['database_name'],
                    'schema': row['schema_name'] if kind == 'TABLE' else None,
                    'table': row['table_name'] if kind == 'TABLE' else None,
                    'gc': int(ttl) if ttl is not None else None}
            zones.append(item)
            # Resetting all eligible user database parents makes this the final
            # parent TTL. Equal-value explicit pins need no value rollback.
            if ttl is not None and int(ttl) != root_gc: selected.append(item)
        selected.sort(key=lambda z: (z['kind'] != 'DATABASE', object_sql(z)))
        return {'rate': value, 'rate_default': default, 'reset_rate': value != default,
                'root_gc': root_gc, 'zones': zones, 'gc_targets': selected}

    def ready(self):
        scenario = self.inspect()
        return scenario['reset_rate'] or bool(scenario['gc_targets'])

    def apply(self):
        scenario = self.inspect()
        if scenario['reset_rate'] or scenario['gc_targets']: return
        # Deterministic and bounded. Never overwrite inherited non-default work.
        fallback = 1048576 if scenario['rate_default'] != 1048576 else 2097152
        self.cluster.require(self.cluster.sql('SET CLUSTER SETTING ' + RATE + "='" + str(fallback) + "B';"))
        if not self.ready(): raise RuntimeError('rollback fallback did not establish a target')

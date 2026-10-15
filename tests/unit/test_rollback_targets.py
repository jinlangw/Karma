"""Rollback target selection respects actual defaults and inherited configuration."""
import csv
import importlib.util
import io
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

path = Path(__file__).resolve().parents[2] / 'cases/cockroachdb/rollback-rehearsal/scripts/targets.py'
spec = importlib.util.spec_from_file_location('rollback_targets', path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class Database:
    def __init__(self, rate='32 MiB', default=33554432, zones=(), encoded_rate=None):
        self.rate, self.default, self.zones = rate, default, zones
        self.encoded_rate = encoded_rate if encoded_rate is not None else {'32 MiB':33554432, '1 MiB':1048576, '96 MiB':100663296}[rate]
        self.mutations = []

    def value(self, query):
        return str(self.encoded_rate if 'FROM system.settings' in query else self.default)
    def setting(self, name): return self.rate
    def require(self, result): return result.stdout

    def sql(self, query, **kwargs):
        if query.startswith('SET CLUSTER'):
            self.mutations.append(query)
            self.rate = query.split("'")[1]
            self.encoded_rate = int(self.rate.removesuffix('B'))
            return SimpleNamespace(stdout='SET CLUSTER SETTING\n')
        rows = ([{'full_config_yaml': 'gc:\n  ttlseconds: 90000\n'}]
                if "target='RANGE default'" in query else list(self.zones))
        out = io.StringIO()
        if rows:
            writer = csv.DictWriter(out, rows[0].keys()); writer.writeheader(); writer.writerows(rows)
        return SimpleNamespace(stdout=out.getvalue())


def zone(kind, ttl=None, table='t'):
    raw = {'range_min_bytes': 67108864, 'range_max_bytes': 268435456}
    if ttl is not None: raw['gc'] = {'ttlseconds': ttl}
    return {'target': kind + ' tenant.public.' + table, 'database_name': 'tenant',
            'schema_name': 'public', 'table_name': table, 'raw_config_yaml': yaml.safe_dump(raw)}


@pytest.mark.parametrize('rate,default,fallback', [('32 MiB', 33554432, 1048576), ('1 MiB', 1048576, 2097152)])
def test_defaults_get_one_deterministic_nondefault_fallback(rate, default, fallback):
    c = Database(rate, default)
    t = module.Targets(c)
    assert not t.ready()
    t.apply()
    assert c.mutations == ["SET CLUSTER SETTING kv.snapshot_rebalance.max_rate='" + str(fallback) + "B';"]
    assert t.ready()


def test_inherited_rate_is_reused_without_mutation():
    c = Database('96 MiB')
    t = module.Targets(c)
    t.apply()
    assert t.inspect()['reset_rate'] and c.rate == '96 MiB' and not c.mutations


def test_gc_only_reuses_inherited_work_and_does_not_plant_rate():
    c = Database(zones=[zone('TABLE', 7200)])
    t = module.Targets(c)
    t.apply()
    assert not t.inspect()['reset_rate'] and len(t.inspect()['gc_targets']) == 1
    assert c.rate == '32 MiB' and not c.mutations


def test_nested_database_and_table_pins_use_final_parent_value():
    c = Database(zones=[zone('TABLE', 3600), zone('DATABASE', 3600), zone('TABLE', 90000, 'already_default'), zone('TABLE', None, 'inherits')])
    targets = module.Targets(c).inspect()['gc_targets']
    assert [row['kind'] for row in targets] == ['DATABASE', 'TABLE']
    assert targets[1]['table'] == 't'
    assert not c.mutations


def test_sql_identifier_quoting_preserves_names():
    assert module.object_sql({'kind': 'TABLE', 'database': 'a b', 'schema': 's"x', 'table': 't.dot'}) == 'TABLE "a b"."s""x"."t.dot"'


def test_rounded_default_display_does_not_hide_nondefault_bytes():
    c = Database(rate='32 MiB', encoded_rate=33554433)
    t = module.Targets(c)
    assert t.inspect()['rate'] == 33554433 and t.ready()
    t.apply()
    assert not c.mutations

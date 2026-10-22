"""Policy boundaries for version-report challenges, independent of Kubernetes."""
import importlib.util
import os
from pathlib import Path
import sys
from types import ModuleType

import pytest

path = Path(__file__).resolve().parents[2] / 'cases/tests/cockroachdb/version-check/scripts/versions.py'
# Load the policy with its own exception type; do not pollute other cases' modules.
stub = ModuleType('cluster')
stub.UnsafeState = type('UnsafeState',(RuntimeError,),{})
stub.database_container = lambda obj: obj['spec']['containers'][0]
previous = sys.modules.get('cluster')
sys.modules['cluster'] = stub
try:
    spec = importlib.util.spec_from_file_location('version_check_policy',path)
    policy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(policy)
finally:
    if previous is None: sys.modules.pop('cluster',None)
    else: sys.modules['cluster'] = previous


@pytest.mark.parametrize('family,target',[('22.2','23.1'),('23.1','23.2'),('23.2','24.1'),('24.1','24.2'),('24.2','24.3'),('24.3','25.1'),('25.1','25.2'),('25.2','25.3'),('25.3','25.4'),('25.4','26.1'),('26.1','26.2'),('26.2','26.3')])
def test_each_documented_release_uses_one_edge_without_finalization(family,target):
    current={'logical':family,'binaries':[policy.PINNED[family]]*3}
    plan=policy.choose_plan(current)
    assert not plan['reset'] and plan['logical']==family
    assert policy.release(plan['binary'])==target


def test_inherited_newer_patch_survives_partial_rollout():
    result=policy.choose_plan({'logical':'23.2','binaries':['23.2.3','24.1.1','24.1.1']})
    assert not result['reset'] and result['binary']=='24.1.1'


def test_inherited_regular_skip_gap_is_preserved():
    result=policy.choose_plan({'logical':'24.1','binaries':['24.3.36']*3})
    assert not result['reset'] and result['binary']=='24.3.36'


def test_highest_finalized_release_requires_fresh_stores(monkeypatch):
    monkeypatch.setenv('BENCH_PARAM_FROM_VERSION','23.2.0')
    monkeypatch.setenv('BENCH_PARAM_TO_VERSION','24.1.0')
    plan=policy.choose_plan({'logical':'26.3','binaries':['26.3.2']*3})
    assert plan['reset'] and plan['source']=='23.2.0' and plan['binary']=='24.1.0'


def test_unknown_future_release_uses_bounded_fallback(monkeypatch):
    monkeypatch.delenv('BENCH_PARAM_FROM_VERSION',raising=False)
    monkeypatch.delenv('BENCH_PARAM_TO_VERSION',raising=False)
    assert policy.choose_plan({'logical':'99.1','binaries':['99.1.0']})['reset']


@pytest.mark.parametrize('source,target',[('23.2','23.2.3'),('24.1.0','24.1.1')])
def test_legacy_patch_parameters_still_establish_a_real_gap(monkeypatch,source,target):
    monkeypatch.setenv('BENCH_PARAM_FROM_VERSION',source)
    monkeypatch.setenv('BENCH_PARAM_TO_VERSION',target)
    a,b=policy.fallback_pair()
    assert policy.series(b)>policy.series(a)


@pytest.mark.parametrize('source,target',[('26.3','26.3.2'),('24.1','23.2.3'),('23.2','26.3.2'),('23.2.0-alpha','24.1.0')])
def test_invalid_fallback_never_reaches_store_reset(monkeypatch,source,target):
    monkeypatch.setenv('BENCH_PARAM_FROM_VERSION',source)
    monkeypatch.setenv('BENCH_PARAM_TO_VERSION',target)
    with pytest.raises(RuntimeError):policy.fallback_pair()


def test_patch_version_is_not_a_feature_gap():
    plan=policy.choose_plan({'logical':'24.1','binaries':['24.1.1']*4})
    assert not plan['reset'] and policy.series(plan['binary'])>policy.series('24.1')


@pytest.mark.parametrize('value',['24.1-upgrading-to-24.2','24.1-2','24.1.0-beta.1','latest'])
def test_transitional_or_testing_versions_are_not_completed_setups(value):
    with pytest.raises(RuntimeError):policy.series(value)


def test_current_vendor_support_and_historical_compatibility_are_distinct():
    assert set(policy.CURRENT_SUPPORTED)<=set(policy.RELEASES)
    assert '23.2' not in policy.CURRENT_SUPPORTED
    assert '26.3' in policy.CURRENT_SUPPORTED and '26.4' not in policy.RELEASES


def load_method(file, owner, method, scope):
    """Exercise just a boundary method without importing case-local module names."""
    import ast
    tree=ast.parse(path.with_name(file).read_text())
    node=next(n for cls in tree.body if isinstance(cls,ast.ClassDef) and cls.name==owner for n in cls.body if isinstance(n,ast.FunctionDef) and n.name==method)
    exec(compile(ast.Module(body=[node],type_ignores=[]),str(path.with_name(file)),'exec'),scope)
    return scope[method]


@pytest.mark.parametrize('state',['42501','42601','42703','42P01','42883','23514','22023'])
def test_query_capability_or_permission_error_cannot_authorize_reset(state):
    from types import SimpleNamespace
    sql=load_method('cluster.py','Cluster','sql',{'UnsafeState':policy.UnsafeState})
    database=SimpleNamespace(client=lambda *a,**k:SimpleNamespace(returncode=1,stderr='SQLSTATE: '+state,stdout=''))
    with pytest.raises(policy.UnsafeState):sql(database,'SELECT unsupported_diagnostic();')


def test_environment_propagates_unsafe_diagnostic_without_recovery():
    from types import SimpleNamespace
    def unsafe():raise policy.UnsafeState('SQL capability failure')
    database=SimpleNamespace(name='selected',get=lambda *a:{},deployment_ready=lambda:'initialized',ready=unsafe,wait=lambda check,seconds:check())
    resets=[]
    environment=SimpleNamespace(cluster=database,load=lambda:None,services=lambda:None,reset=lambda *a:resets.append(a))
    apply=load_method('environment.py','Environment','apply',{'UnsafeState':policy.UnsafeState})
    with pytest.raises(policy.UnsafeState):apply(environment)
    assert not resets


@pytest.mark.parametrize('count,expected',[(1,'num_replicas=1'),(2,'num_replicas=2, num_voters=1'),(3,None),(5,None)])
def test_only_fresh_small_topologies_receive_valid_replication(count,expected):
    from types import SimpleNamespace
    statements=[]
    database=SimpleNamespace(statefulset=lambda:{'spec':{'replicas':count}},sql=lambda q:statements.append(q),require=lambda r:r)
    configure=load_method('cluster.py','Cluster','configure_fresh_replication',{})
    configure(database)
    if expected is None:assert statements==[]
    else:
        assert len(statements)==5 and all(expected in q for q in statements)
        assert any('RANGE liveness' in q for q in statements) and any('DATABASE system' in q for q in statements)

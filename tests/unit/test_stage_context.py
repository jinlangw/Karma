"""Private baseline inputs stay outside the public stage/agent environment."""
import json
import shlex
import sys

import pytest

from karma.definitions.cases import _normalize_command_item
from karma.oracle import _run_commands
from karma.runtime.case import _run_operation_units
from karma.stage_context import freeze_stage, stage_env, trusted_input


def test_distinct_stage_keys_and_freeze_survive_retries(tmp_path):
    env = stage_env(tmp_path / 'run-one', 'audit-a')
    entry = {'trusted_stdin': 'stage_key'}
    first = json.loads(trusted_input(entry, env, create=True))
    assert not first['frozen']
    assert json.loads(trusted_input(entry, env)) == first
    freeze_stage(tmp_path / 'run-one', 'audit-a')
    retry = json.loads(trusted_input(entry, env, create=True))
    assert retry == {**first, 'frozen': True}
    other_stage = stage_env(tmp_path / 'run-one', 'audit-b')
    other_run = stage_env(tmp_path / 'run-two', 'audit-a')
    assert len({first['key'], json.loads(trusted_input(entry, other_stage, create=True))['key'],
                json.loads(trusted_input(entry, other_run, create=True))['key']}) == 3
    assert set(env) == {'BENCH_RUN_ID', 'BENCH_STAGE_ID'}


def test_trusted_setup_oracle_receive_stdin_without_environment_or_log_key(tmp_path):
    env = stage_env(tmp_path / 'pipe-test', 'audit')
    code = ("import os,sys,json; p=json.load(sys.stdin); "
            "assert set(p)=={'key','frozen'}; "
            "assert p['key'] not in os.environ.values(); print('private input received')")
    command = {'command': shlex.join([sys.executable, '-c', code]), 'trusted_stdin': 'stage_key'}
    unit = {'name': 'baseline', 'probe_commands': [{'command': 'false'}], 'apply_commands': [command], 'verify_commands': []}
    result = _run_operation_units([unit], role_bindings={}, env_vars=env, log_path=tmp_path / 'setup.log')
    assert result['ok']
    key = json.loads(trusted_input(command, env))['key']
    assert key not in (tmp_path / 'setup.log').read_text()
    freeze_stage(tmp_path / 'pipe-test', 'audit')
    ok, output = _run_commands([command], env=env, timeout_sec=10)
    assert ok and 'private input received' in output and key not in output
    # A normal agent command cannot obtain the key by inheriting the public env.
    public_command = {'command': shlex.join([sys.executable, '-c', 'import sys; assert sys.stdin.read()==""; print("public input only")'])}
    ok, output = _run_commands([public_command], env=env, timeout_sec=10)
    assert ok and key not in output


def test_unavailable_key_fails_closed_and_normalization_keeps_opt_in(tmp_path):
    env = stage_env(tmp_path / 'missing-key', 'audit')
    entry = {'command': 'true', 'trusted_stdin': 'stage_key'}
    with pytest.raises(RuntimeError, match='key unavailable'):
        trusted_input(entry, env)
    ok, output = _run_commands([entry], env=env, timeout_sec=5)
    assert not ok and 'key unavailable' in output
    assert _normalize_command_item(entry)['trusted_stdin'] == 'stage_key'
    with pytest.raises(RuntimeError, match='trusted_stdin'):
        _normalize_command_item({'command': 'true', 'trusted_stdin': 'typo'})


def test_regression_result_suffix_preserves_original_private_stage_identity(tmp_path):
    from karma.oracle import run_regression_sweep

    env = stage_env(tmp_path / 'sweep-run', 'audit')
    entry = {'trusted_stdin': 'stage_key'}
    trusted_input(entry, env, create=True)
    freeze_stage(tmp_path / 'sweep-run', 'audit')
    code = ("import sys,json,os; p=json.load(sys.stdin); "
            "assert p['frozen']; assert os.environ['BENCH_STAGE_ID']=='audit'; "
            "assert os.environ['BENCH_RUN_ID']=='sweep-run'; print('original identity retained')")
    config = {'verify_commands': [{'command': shlex.join([sys.executable, '-c', code]),
                                   'trusted_stdin': 'stage_key'}]}
    result = run_regression_sweep([('audit', config)], role_bindings_map={'audit': {}},
                                  run_dir=tmp_path / 'sweep-run')
    assert result['audit']['verdict'] == 'pass'
    assert (tmp_path / 'sweep-run/stages/audit__regression/oracle.json').exists()

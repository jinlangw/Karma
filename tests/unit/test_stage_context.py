"""Private baseline inputs stay outside the public stage/agent environment."""
import hashlib
import json
import shlex
import sys

import pytest

from karma.definitions.cases import _normalize_command_item
from karma.oracle import _run_commands, run_oracle, run_regression_sweep
from karma.runtime.case import _run_operation_units
from karma.stage_context import freeze_stage, stage_env, trusted_input


def test_distinct_stage_keys_and_freeze_survive_retries(tmp_path):
    run_dir = tmp_path / 'team-a' / 'run-42'
    first_stage = (run_dir, 'audit')
    other_stage = (run_dir, 'review')
    other_run = (tmp_path / 'team-b' / 'run-42', 'audit')
    entry = {'trusted_stdin': 'stage_key'}

    first = json.loads(trusted_input(entry, first_stage, create=True))
    second = json.loads(trusted_input(entry, other_run, create=True))
    third = json.loads(trusted_input(entry, other_stage, create=True))
    assert len({first['key'], second['key'], third['key']}) == 3
    assert not first['frozen'] and not second['frozen']

    freeze_stage(*first_stage)
    alias = (run_dir / '..' / 'run-42', 'audit')
    assert json.loads(trusted_input(entry, alias, create=True)) == {**first, 'frozen': True}
    assert json.loads(trusted_input(entry, other_run)) == second
    assert json.loads(trusted_input(entry, other_stage)) == third


def test_setup_and_final_sweep_receive_the_same_stage_key_privately(tmp_path):
    run_dir = tmp_path / 'run'
    stage_identity = (run_dir, 'audit')
    env = stage_env(*stage_identity)
    code = (
        "import os, sys, json, hashlib; payload = json.load(sys.stdin); "
        "assert payload['key'] not in os.environ.values(); "
        "assert os.environ['BENCH_RUN_ID'] == 'run'; "
        "assert os.environ['BENCH_STAGE_ID'] == 'audit'; "
        "print(hashlib.sha256(payload['key'].encode()).hexdigest(), payload['frozen'])"
    )
    command = _normalize_command_item({
        'command': shlex.join([sys.executable, '-c', code]),
        'trusted_stdin': 'stage_key',
    })
    unit = {
        'name': 'baseline',
        'probe_commands': [{'command': 'false'}],
        'apply_commands': [command],
    }

    result = _run_operation_units(
        [unit], role_bindings={}, env_vars=env, stage=stage_identity,
        log_path=tmp_path / 'setup.log',
    )
    assert result['ok']
    key = json.loads(trusted_input(command, stage_identity))['key']
    digest = hashlib.sha256(key.encode()).hexdigest()
    setup_output = (tmp_path / 'setup.log').read_text()
    assert f'{digest} False' in setup_output
    assert key not in setup_output

    freeze_stage(run_dir, 'audit')
    config = {'verify_commands': [command]}
    stage = run_oracle(
        config, role_bindings={}, run_dir=run_dir, stage_id='audit',
        env_vars={'BENCH_RUN_ID': 'other-run', 'BENCH_STAGE_ID': 'other-stage'},
    )
    sweep = run_regression_sweep([('audit', config)], role_bindings_map={}, run_dir=run_dir)
    for verdict in (stage, sweep['audit']):
        assert verdict['verdict'] == 'pass'
        assert verdict['output'].splitlines()[-1] == f'{digest} True'
        assert key not in verdict['output']
    assert (run_dir / 'stages/audit__regression/oracle.json').exists()


def test_trusted_command_fails_closed_when_key_is_unavailable(tmp_path):
    stage = (tmp_path / 'missing-key', 'audit')
    entry = {'command': 'true', 'trusted_stdin': 'stage_key'}
    ok, output = _run_commands([entry], env=stage_env(*stage), stage=stage, timeout_sec=5)
    assert not ok and 'key unavailable' in output
    with pytest.raises(RuntimeError, match='trusted_stdin'):
        _normalize_command_item({'command': 'true', 'trusted_stdin': 'typo'})

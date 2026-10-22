#!/usr/bin/env python3
"""Grade a submitted rollback on a disposable target; preserve the original cluster."""
import json
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from cluster import Cluster
from fixture import Fixture
from snapshot import Snapshot, private_input


def main():
    c = Cluster()
    snapshot = Snapshot(c)
    baseline = snapshot.load(private_input())
    expected = {k: baseline[k] for k in ('report', 'state')}
    if snapshot.snapshot() != expected:
        raise RuntimeError('original cluster configuration changed after baseline capture')
    obj = c.get('configmap', snapshot.script_name)
    if not obj: raise RuntimeError('current-stage rollback script ConfigMap is missing')
    script = obj.get('data', {}).get('rollback.sh')
    if not isinstance(script, str) or not script.startswith('#!/bin/sh\n') or '\x00' in script:
        raise RuntimeError('rollback.sh must be a nonempty POSIX shell script with #!/bin/sh')
    fixture = Fixture(c, baseline, script)
    failures = []
    try:
        fixture.setup()
        fixture.run_script()
        fixture.verify()
    except (RuntimeError, ValueError, KeyError, OSError, subprocess.TimeoutExpired) as error:
        failures.append(str(error))
    finally:
        try: fixture.cleanup()
        except (RuntimeError, ValueError, KeyError, OSError, subprocess.TimeoutExpired) as error:
            failures.append('fixture cleanup: ' + str(error))
        try:
            if snapshot.snapshot() != expected: failures.append('original cluster changed during rollback validation')
        except (RuntimeError, ValueError, KeyError, OSError, subprocess.TimeoutExpired) as error:
            failures.append('could not verify original cluster after validation: ' + str(error))
    if failures: raise RuntimeError('; '.join(failures))
    print('Rollback script executed successfully on isolated target; original cluster unchanged.')
    return 0


if __name__ == '__main__':
    try: sys.exit(main())
    except (RuntimeError, ValueError, KeyError, OSError, subprocess.TimeoutExpired) as error:
        print('rollback-rehearsal verification failed: ' + str(error), file=sys.stderr)
        sys.exit(1)

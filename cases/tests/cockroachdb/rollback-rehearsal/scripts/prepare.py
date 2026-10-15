#!/usr/bin/env python3
"""Independent environment, target, script-artifact and authenticated baseline units."""
import argparse
import subprocess
import sys

from cluster import Cluster
from environment import Environment
from snapshot import Snapshot, private_input
from targets import Targets


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('unit', choices=('environment', 'targets', 'script', 'baseline'))
    parser.add_argument('mode', choices=('probe', 'apply', 'verify'))
    args = parser.parse_args()
    c = Cluster()
    if args.unit == 'environment':
        environment = Environment(c)
        if args.mode == 'apply': environment.apply()
        else: environment.probe()
    elif args.unit == 'targets':
        targets = Targets(c)
        private = private_input()
        if private['frozen']:
            snapshot = Snapshot(c)
            baseline = snapshot.load(private)
            if snapshot.snapshot() != {k: baseline[k] for k in ('report', 'state')}:
                raise RuntimeError('source changed after solver started; cannot introduce new rollback targets')
        if args.mode == 'apply': targets.apply()
        elif not targets.ready(): raise RuntimeError('selected rollback fields are already at defaults')
    else:
        snapshot = Snapshot(c)
        if args.unit == 'script':
            if args.mode == 'apply': snapshot.clear_script()
            elif not snapshot.script_absent(): raise RuntimeError('current-stage rollback script exists')
        else:
            private = private_input()
            if args.mode == 'probe':
                if not private['frozen']: raise RuntimeError('refresh rollback baseline before solver starts')
                snapshot.load(private)
            elif args.mode == 'apply': snapshot.record(private)
            else: snapshot.load(private)
    print(f'{args.unit} {args.mode}: ready', flush=True)


if __name__ == '__main__':
    try: main()
    except (RuntimeError, ValueError, KeyError, OSError, subprocess.TimeoutExpired) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)

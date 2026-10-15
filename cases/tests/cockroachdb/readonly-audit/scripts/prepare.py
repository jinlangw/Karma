#!/usr/bin/env python3
"""Three independently verified, selected-cluster audit precondition units."""
import argparse
import subprocess
import sys

from audit import Audit, private_input
from cluster import Cluster
from environment import Environment


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('unit', choices=('environment', 'report', 'baseline'))
    parser.add_argument('mode', choices=('probe', 'apply', 'verify'))
    args = parser.parse_args()
    c = Cluster()
    if args.unit == 'environment':
        environment = Environment(c)
        if args.mode == 'apply': environment.apply()
        else: environment.probe()
    else:
        audit = Audit(c)
        if args.unit == 'report':
            if args.mode == 'apply': audit.clear_report()
            elif not audit.report_absent(): raise RuntimeError('current-stage audit report exists')
        else:
            private = private_input()
            if args.mode == 'probe':
                if not private['frozen']: raise RuntimeError('refresh baseline before solver execution')
                audit.load(private)
            elif args.mode == 'apply': audit.record(private)
            else: audit.load(private)
    print(f'{args.unit} {args.mode}: ready', flush=True)


if __name__ == '__main__':
    try: main()
    except (RuntimeError, ValueError, KeyError, OSError, subprocess.TimeoutExpired) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)

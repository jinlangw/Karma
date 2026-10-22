#!/usr/bin/env python3
"""Four independently verified units; frozen retries cannot rewrite the challenge."""
import argparse
import subprocess
import sys

from cluster import Cluster
from environment import Environment
from gap import Gap
from snapshot import Snapshot, private_input


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('unit',choices=('environment','gap','report','baseline'))
    parser.add_argument('mode',choices=('probe','apply','verify'))
    args = parser.parse_args()
    c = Cluster()
    private = private_input()
    snapshot = Snapshot(c)
    if private['frozen']:
        # A retry may inspect the original setup but must never reset a modified
        # database, delete its submission or re-baseline agent changes.
        snapshot.load(private)
        snapshot.unchanged(private)
        print('Preserved frozen version-check setup and report',flush=True)
        return
    if args.unit == 'environment':
        gap = Gap(c) if c.get('statefulset',c.name) else None
        if args.mode == 'apply':
            if gap and gap.pending(): gap.apply()
            Environment(c).apply()
        else:
            if gap and gap.pending(): raise RuntimeError('version-gap preparation requires resumption')
            Environment(c).probe()
    elif args.unit == 'gap':
        if args.mode == 'apply': Gap(c).apply()
        else: Gap(c).ready()
    elif args.unit == 'report':
        if args.mode == 'apply': snapshot.clear_report()
        elif not snapshot.report_absent(): raise RuntimeError('current-stage version report exists')
    else:
        if args.mode == 'probe': raise RuntimeError('refresh baseline before solver execution')
        if args.mode == 'apply': snapshot.record(private)
        else: snapshot.load(private)
    print(f'{args.unit} {args.mode}: ready',flush=True)


if __name__ == '__main__':
    try: main()
    except (RuntimeError,ValueError,KeyError,OSError,subprocess.TimeoutExpired) as error:
        print(str(error),file=sys.stderr)
        sys.exit(1)

#!/usr/bin/env python3
"""Independent setup units with frozen, authenticated retry semantics."""
import argparse
import subprocess
import sys

from cluster import Cluster
from environment import Environment
from snapshot import Snapshot, private_input
from topology import Capacity
from zones import Zones


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('unit',choices=('environment','fixture','change','baseline'))
    parser.add_argument('mode',choices=('probe','apply','verify'))
    args=parser.parse_args()
    c=Cluster();private=private_input();snapshot=Snapshot(c);z=Zones(c)
    if private['frozen']:
        snapshot.preserved(private)
        print('Preserved frozen zone setup; target progress remains solver-owned',flush=True)
        return
    if args.unit=='environment':
        capacity=Capacity(c,z.desired['num_replicas'])
        exists=c.get('statefulset',c.name)
        if args.mode=='apply':
            # An interrupted certificate/scale operation must resume before a
            # generic health recovery can classify the intermediate state.
            if exists and capacity.pending():capacity.apply()
            Environment(c).apply()
            capacity.apply()
        else:
            if exists and capacity.pending():raise RuntimeError('node expansion requires resumption')
            Environment(c).probe();capacity.ready()
    elif args.unit=='fixture':
        if args.mode=='apply':z.ensure_fixtures()
        else:z.fixture_ready()
    elif args.unit=='change':
        if args.mode=='apply':z.prepare_change()
        else:
            z.compatibility(apply=False)
            if not z.needs_change():raise RuntimeError('target policy already complete; prepare a small mismatch')
    else:
        if args.mode=='probe':raise RuntimeError('refresh current baseline before solver execution')
        if args.mode=='apply':snapshot.record(private)
        else:snapshot.load(private)
    print(args.unit+' '+args.mode+': ready',flush=True)


if __name__=='__main__':
    try:main()
    except (RuntimeError,ValueError,KeyError,OSError,subprocess.TimeoutExpired) as error:
        print(str(error),file=sys.stderr);sys.exit(1)

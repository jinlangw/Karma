#!/usr/bin/env python3
"""Verify the reported active feature version and unchanged, held version gap."""
from pathlib import Path
import subprocess
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1] / 'scripts'))
from cluster import Cluster
from snapshot import Snapshot, private_input


def normalized(value):
    value = value.strip()
    return value[1:] if value[:1] in ('v','V') else value


def main():
    snapshot = Snapshot(Cluster())
    baseline = snapshot.unchanged(private_input())
    obj = snapshot.cluster.get('configmap',snapshot.report_name)
    snapshot.owned(obj)
    if obj is None: raise RuntimeError('current-stage version report is missing')
    answer = obj.get('data',{}).get(snapshot.report_key,'')
    if not answer or normalized(answer) != baseline['report']['feature_version']:
        raise RuntimeError('reported version does not match the original active feature version')
    print('Accurate active feature version; authentic baseline; held version gap unchanged.')
    return 0


if __name__ == '__main__':
    try: sys.exit(main())
    except (RuntimeError,ValueError,KeyError,OSError,subprocess.TimeoutExpired) as error:
        print('version-check verification failed: '+str(error),file=sys.stderr)
        sys.exit(1)

#!/usr/bin/env python3
"""Compare exact target values and authenticated pre-agent protected state."""
from pathlib import Path
import subprocess
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from cluster import Cluster
from snapshot import Snapshot, private_input

if __name__=='__main__':
    try:Snapshot(Cluster()).verify(private_input())
    except (RuntimeError,ValueError,KeyError,OSError,subprocess.TimeoutExpired) as error:
        print('Zone verification failed: '+str(error),file=sys.stderr);sys.exit(1)

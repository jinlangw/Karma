#!/usr/bin/env python3
"""Three independent probes with minimal, selected-cluster preparation."""
import argparse
import subprocess
import sys

from cluster import Cluster
from environment import Environment
from monitoring import Monitoring


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('unit', choices=('environment', 'stack', 'scraping'))
    parser.add_argument('mode', choices=('probe', 'apply', 'verify'))
    args = parser.parse_args()
    c = Cluster()
    environment, monitoring = Environment(c), Monitoring(c)
    check, apply = {'environment': (environment.probe, environment.apply),
                    'stack': (monitoring.probe, monitoring.apply),
                    'scraping': (monitoring.absent, monitoring.reset)}[args.unit]
    if args.mode == 'apply':
        if args.unit != 'environment': environment.probe()
        apply()
    else: check()
    print(f'{args.unit} {args.mode}: ready', flush=True)


if __name__ == '__main__':
    try: main()
    except (RuntimeError, ValueError, KeyError, OSError, subprocess.TimeoutExpired) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)

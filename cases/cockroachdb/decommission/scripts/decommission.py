#!/usr/bin/env python3
"""Decommission highest-ordinal nodes before scaling the StatefulSet down."""
import argparse
import sys
from cluster import Cluster


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--replicas", type=int, required=True)
    args = parser.parse_args()
    if args.replicas < 1:
        parser.error("replicas must be positive")
    cluster = Cluster()
    cluster.decommission(args.replicas)
    cluster.ready()


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, ValueError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)

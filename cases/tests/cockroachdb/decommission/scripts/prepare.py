#!/usr/bin/env python3
"""Four independently reusable probe/apply/verify preparation units."""
import argparse
import sys

from cluster import Cluster


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("unit", choices=("ready", "seed", "up", "down"))
    parser.add_argument("mode", choices=("probe", "apply", "verify"))
    args = parser.parse_args()
    cluster = Cluster()
    apply = args.mode == "apply"
    if args.unit == "ready":
        if apply:
            cluster.recover()
        else:
            cluster.sts()  # An absent cluster is not a slow-starting cluster.
            cluster.wait("selected cluster SQL and active membership", cluster.ready,
                         60 if args.mode == "probe" else 15)
    elif args.unit == "seed":
        if apply:
            cluster.seed()
        if not cluster.seed_ready():
            raise RuntimeError("seed fixture or effective replication settings need preparation")
    elif args.unit == "up":
        if apply:
            before = cluster.data()
            cluster.commission(cluster.source)
            if cluster.data() != before:
                raise RuntimeError("seed data changed while adding nodes")
        if cluster.count() < cluster.source:
            raise RuntimeError("selected cluster needs additional nodes")
        cluster.ready()
    else:
        if apply:
            cluster.decommission(cluster.source)
        if cluster.count() != cluster.source:
            raise RuntimeError("selected cluster needs safe removal of excess nodes")
        cluster.ready()
        if not cluster.seed_ready():
            raise RuntimeError("seed/replication preparation did not survive resizing")
        # Refresh this case-private Oracle fixture for each invocation, even
        # when no resize is needed. This does not change the database.
        cluster.capture_baseline()
    print(f"{args.unit} {args.mode}: ready", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, ValueError, KeyError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)

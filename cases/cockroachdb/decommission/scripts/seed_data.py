#!/usr/bin/env python3
"""Compatibility entrypoint for additive, parameterized seed preparation."""
import sys
from cluster import Cluster


if __name__ == "__main__":
    try:
        Cluster().seed()
    except (RuntimeError, ValueError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)

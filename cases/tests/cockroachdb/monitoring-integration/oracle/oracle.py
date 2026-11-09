#!/usr/bin/env python3
"""Verify a real selected-node scrape target and reachable CockroachDB metrics."""
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from cluster import Cluster
from monitoring import Monitoring
from urllib.parse import urlparse


def evaluate():
    m = Monitoring(Cluster())
    m.helper_ready()
    # Preserve the original at-least-one target contract, tied to the selected
    # workload's actual pod addresses rather than labels or a foreign endpoint.
    ips = {p['status']['podIP'] for p in m.c.pods(m.c.statefulset()) if p.get('status', {}).get('podIP')}
    targets = m.targets()
    if not any(t.get('health') == 'up' and urlparse(t.get('scrapeUrl', '')).hostname in ips
               and urlparse(t['scrapeUrl']).path == m.path and urlparse(t['scrapeUrl']).port == m.port for t in targets):
        raise RuntimeError('No up selected CockroachDB target at the requested metrics path and port')
    m.metrics()
    return True


def main():
    deadline = time.monotonic() + 300
    error = 'monitoring not ready'
    while time.monotonic() < deadline:
        try:
            evaluate()
            print('Monitoring integration configured successfully')
            return 0
        except (RuntimeError, ValueError, KeyError, OSError) as caught:
            error = str(caught)
            time.sleep(5)
    print('Monitoring integration verification failed: ' + error, file=sys.stderr)
    return 1


if __name__ == '__main__':
    sys.exit(main())

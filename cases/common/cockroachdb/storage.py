"""Pure storage-path parsing shared by CockroachDB case preparation."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Type

from .startup import arguments, database_container


def pvc_store_mappings(sts, *, error_type: Type[Exception]) -> list[dict[str, str]]:
    """Map configured CockroachDB stores onto exclusive claim-template volumes.

    The returned mappings contain only the volume name and path relative to its
    mount. PVC lookup, ownership checks, and reset policy remain with the case.
    """
    db = database_container(sts['spec']['template'], error_type=error_type)
    tokens = arguments(db, error_type=error_type)
    stores = [t.split('=', 1)[1] for t in tokens if t.startswith(('--store=', '-s='))]
    stores += [t[2:] for t in tokens if t.startswith('-s') and not t.startswith('-s=') and t != '-s']
    stores += [tokens[i + 1] for i, t in enumerate(tokens[:-1]) if t in ('--store', '-s')]
    claims = {v['metadata']['name'] for v in sts['spec'].get('volumeClaimTemplates', [])}
    mappings = []
    default_store = str(PurePosixPath(db.get('workingDir', '/cockroach')) / 'cockroach-data')
    for store in stores or [default_store]:
        options = dict(p.split('=', 1) for p in store.split(',') if '=' in p)
        path = options.get('path', store.split(',', 1)[0])
        mounts = sorted(
            (m for m in db.get('volumeMounts', []) if path == m['mountPath'].rstrip('/') or path.startswith(m['mountPath'].rstrip('/') + '/')),
            key=lambda m: len(m['mountPath']),
            reverse=True,
        )
        if options.get('type') == 'mem' or not path.startswith('/') or str(PurePosixPath(path)) != path or '..' in PurePosixPath(path).parts or not mounts:
            raise error_type('reset requires absolute normalized PVC-backed store paths')
        mount = mounts[0]
        if mount['name'] not in claims or any(mount.get(k) for k in ('subPath', 'subPathExpr', 'readOnly')):
            raise error_type('reset only supports exclusive volumeClaimTemplate stores without subPath')
        for container in sts['spec']['template']['spec'].get('containers', []) + sts['spec']['template']['spec'].get('initContainers', []):
            if container['name'] != db['name'] and any(m['name'] == mount['name'] for m in container.get('volumeMounts', [])):
                raise error_type('database store is shared with another container')
        relative = path[len(mount['mountPath'].rstrip('/')):].lstrip('/')
        if any(old['volume'] == mount['name'] and (not relative or not old['relative'] or relative == old['relative'] or relative.startswith(old['relative'] + '/') or old['relative'].startswith(relative + '/')) for old in mappings):
            raise error_type('overlapping database stores are unsupported')
        mappings.append({'volume': mount['name'], 'relative': relative})
    return mappings

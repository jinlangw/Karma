"""Read CockroachDB startup commands without executing their shell wrappers."""

from __future__ import annotations

import posixpath
import re
import shlex
from typing import Callable, Type


def official_image_version(value: str) -> str | None:
    match = re.fullmatch(r'(?:docker\.io/)?cockroachdb/cockroach:v(\d+\.\d+\.\d+)', value)
    return match.group(1) if match else None


def database_container(template, *, error_type: Type[Exception]) -> dict:
    candidates = [c for c in template['spec']['containers']
                  if 'cockroach' in (c.get('image', '') + ' '.join(c.get('command', []) + c.get('args', [])))
                  and re.search(r'\bstart\b', ' '.join(c.get('command', []) + c.get('args', [])))]
    if len(candidates) != 1:
        raise error_type("expected exactly one multi-node CockroachDB server container")
    return candidates[0]


def arguments(container, *, error_type: Type[Exception]) -> list[str]:
    command = container.get("command", [])
    if len(command) == 3 and command[0] in ('/bin/bash', '/bin/sh', 'bash', 'sh') and command[1] in ('-c', '-ec'):
        lexer = shlex.shlex(command[2], posix=True, punctuation_chars=';&|<>')
        lexer.whitespace_split = True
        if any(re.fullmatch(r'[;&|<>]+', token) for token in lexer):
            raise error_type('compound server startup is unsupported')
        command = shlex.split(command[2])
    if not any(token == "start" for token in command + container.get("args", [])):
        raise error_type('multi-node cockroach start command is required')
    return command + container.get("args", [])


def flag_value(
    container,
    name,
    default=None,
    *,
    error_type: Type[Exception],
):
    tokens = arguments(container, error_type=error_type)
    values = [t.split('=', 1)[1] for t in tokens if t.startswith(name + '=')]
    values += [tokens[i + 1] for i, t in enumerate(tokens[:-1]) if t == name]
    if len(values) > 1:
        raise error_type("ambiguous startup flag: " + name)
    return values[0] if values else default


def certificate_directory(
    container,
    configured_directory,
    *,
    pod_security_context,
    error_type: Type[Exception],
) -> str:
    """Resolve the original case TLS certificate-path conventions.

    ``configured_directory`` is parsed by the caller so the shared resolver
    does not impose a startup-shell grammar on its callers. The callback is
    evaluated only for the guarded official-image root default.
    """
    directory = configured_directory
    if directory is None:
        homes = [env for env in container.get('env', []) if env['name'] == 'HOME']
        if len(homes) > 1 or homes and ('value' not in homes[0] or not homes[0]['value'].startswith('/')):
            raise error_type('implicit TLS certificate path requires a literal absolute HOME')
        if homes:
            home = homes[0]['value']
        else:
            pod_context = pod_security_context()
            user = container.get('securityContext', {}).get('runAsUser', pod_context.get('runAsUser', 0))
            if container.get('envFrom') or user != 0:
                raise error_type('implicit TLS certificate path needs literal HOME or explicit certs-dir for this startup')
            # Every supported official image defaults to root. The native
            # CLI resolves its default as HOME/.cockroach-certs.
            home = '/root'
        directory = home.rstrip('/') + '/.cockroach-certs'
    if not directory.startswith('/'):
        directory = (container.get('workingDir') or '/cockroach').rstrip('/') + '/' + directory
    return posixpath.normpath(directory)


def client_connection_flags(
    container,
    *,
    certificate_directory: Callable[[], str],
    error_type: Type[Exception],
) -> list[str]:
    """Assemble the original SQL client security and optional cluster flags.

    The case supplies a lazy certificate-directory resolver so insecure
    workloads do not trigger certificate or Kubernetes inspection.
    """
    tokens = arguments(container, error_type=error_type)
    insecure = '--insecure' in tokens or '--insecure=true' in tokens
    flags = ['--insecure'] if insecure else ['--certs-dir=' + certificate_directory()]
    name = flag_value(container, '--cluster-name', error_type=error_type)
    return flags + (['--cluster-name=' + name] if name else [])

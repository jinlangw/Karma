#!/usr/bin/env python3
# Verify TLS was enabled: insecure SQL is rejected, secure SQL works, AND the
# cert material lives in the canonical Secret the StatefulSet actually mounts.
# The canonical name (BENCH_PARAM_CERT_SECRET_NAME, default crdb-cluster-certs)
# is the C2 identity contract: fixing the NAME here means a downstream
# certificate-rotation stage rotates the very secret the pods serve, instead of
# an agent-chosen name (e.g. crdb-certs) that rotation would never touch. A
# workflow overriding the param is honored; standalone this behaves identically.
import os
import subprocess
import sys


CERT_SECRET = os.environ.get("BENCH_PARAM_CERT_SECRET_NAME", "crdb-cluster-certs")
STS_NAME = "crdb-cluster"


def run(cmd):
    return subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def main():
    errors = []

    insecure_cmd = [
        "kubectl",
        "-n",
        "cockroachdb",
        "exec",
        "crdb-cluster-0",
        "--",
        "./cockroach",
        "sql",
        "--insecure",
        "-e",
        "SELECT 1;",
    ]
    insecure_result = run(insecure_cmd)
    if insecure_result.returncode == 0:
        errors.append("Insecure SQL connection unexpectedly succeeded")

    secure_cmd = [
        "kubectl",
        "-n",
        "cockroachdb",
        "exec",
        "crdb-cluster-0",
        "--",
        "./cockroach",
        "sql",
        "--certs-dir=/cockroach/cockroach-certs",
        "-e",
        "SELECT 1;",
    ]
    secure_result = run(secure_cmd)
    if secure_result.returncode != 0:
        errors.append("Secure SQL connection failed")
        errors.append(f"Error: {secure_result.stderr.strip()}")

    # C2 identity contract: the cert material must live in the canonical Secret
    # AND that Secret must be the one the StatefulSet mounts, so the leaf the
    # nodes serve is the one a downstream cert-rotation stage will rotate.
    secret_get = run([
        "kubectl", "-n", "cockroachdb", "get", "secret", CERT_SECRET,
        "-o", "jsonpath={.metadata.name}",
    ])
    if secret_get.returncode != 0 or secret_get.stdout.strip() != CERT_SECRET:
        errors.append(f"Expected TLS Secret '{CERT_SECRET}' not found")
        if secret_get.stderr.strip():
            errors.append(f"Error: {secret_get.stderr.strip()}")
    else:
        mounted = run([
            "kubectl", "-n", "cockroachdb", "get", "statefulset", STS_NAME,
            "-o", "jsonpath={.spec.template.spec.volumes[*].secret.secretName}",
        ])
        names = mounted.stdout.split() if mounted.returncode == 0 else []
        if CERT_SECRET not in names:
            errors.append(
                f"StatefulSet '{STS_NAME}' does not mount Secret '{CERT_SECRET}' "
                f"(mounts: {' '.join(names) or 'none'})"
            )

    if errors:
        print("Certificate generation verification failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print("Certificates generated successfully")
    return 0


if __name__ == "__main__":
    sys.exit(main())

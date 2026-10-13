#!/usr/bin/env python3
"""Verify target routing, HTTPS console access, and SQL cluster identity."""
import csv
import io
from pathlib import Path
import re
import ssl
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from cluster import Cluster
from routes import CONTROLLER_HOST, Routes


def validate_ui_certificate(cluster):
    for ingress in cluster.get_all_ingresses():
        if ingress["metadata"]["namespace"] != cluster.namespace:
            continue
        for entry in ingress["spec"].get("tls", []):
            if cluster.ui_host not in entry.get("hosts", []) or not entry.get("secretName"):
                continue
            secret = cluster.get("secret", entry["secretName"])
            if secret is None:
                continue
            import base64
            with tempfile.TemporaryDirectory(prefix="karma-ui-cert-") as directory:
                root = Path(directory)
                try:
                    for field in ("tls.crt", "tls.key"):
                        (root / field).write_bytes(base64.b64decode(secret["data"][field], validate=True))
                    ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_cert_chain(root / "tls.crt", root / "tls.key")
                except (KeyError, ValueError, ssl.SSLError):
                    continue
            return
    raise RuntimeError("requested UI hostname has no usable TLS certificate/key pair")


def cluster_id(result):
    rows = list(csv.reader(io.StringIO(Cluster.require(result))))
    if len(rows) != 2 or len(rows[1]) != 1 or not re.fullmatch(r"[0-9a-fA-F-]{36}", rows[1][0]):
        raise RuntimeError("SQL did not return a CockroachDB cluster identity")
    return rows[1][0]


def evaluate():
    cluster = Cluster()
    try:
        sts = cluster.get("statefulset", cluster.name)
        if sts is None:
            raise RuntimeError("selected StatefulSet is missing")
        cluster.service_ready(sts)
        Routes(cluster).configured()
        validate_ui_certificate(cluster)
        # Route with the requested SNI/Host while connecting inside Kubernetes.
        response = cluster.require(cluster.kubectl("exec", cluster.name + "-curl-test", "--",
            "curl", "-sS", "-k", "--connect-timeout", "5", "--max-time", "20",
            "--connect-to", f"{cluster.ui_host}:443:{CONTROLLER_HOST}:443",
            "-o", "/dev/null", "-w", "%{http_code}", f"https://{cluster.ui_host}/", timeout=30)).strip()
        if not response.isdigit() or not 200 <= int(response) < 400:
            raise RuntimeError(f"UI ingress returned HTTP {response}")
        # A SELECT 1 against a different healthy DB must not earn a pass.
        query = "SELECT crdb_internal.cluster_id();"
        direct = cluster_id(cluster.sql(query))
        forwarded = cluster_id(cluster.sql(query, through_ingress=True, timeout=20))
        if direct != forwarded:
            raise RuntimeError("SQL forwarding reaches a different CockroachDB cluster")
        cluster.require(cluster.sql("SELECT 1;", through_ingress=True, timeout=20))
        return []
    except (RuntimeError, ValueError, KeyError, OSError) as error:
        return [str(error)]


def main():
    deadline = time.monotonic() + 80
    errors = evaluate()
    while errors and time.monotonic() < deadline:
        time.sleep(7)
        errors = evaluate()
    if errors:
        print("Expose ingress verification failed:", file=sys.stderr)
        for error in errors:
            print("  - " + error, file=sys.stderr)
        return 1
    print("HTTPS console and SQL traffic verified through ingress-nginx for the selected cluster")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Fresh generated PKI, actual served certificates, and secure SQL on all nodes."""
import base64
import json
from pathlib import Path
import re
import ssl
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from cluster import CERT_DIR, TOOLBOX, WORKSPACE, Cluster, database_container
from pki import Reset, fingerprint, toolbox_ready


def evaluate():
    cluster = Cluster()
    try:
        sts = cluster.statefulset()
        pods = cluster.pods(sts)
        if any(not any(c["type"] == "Ready" and c["status"] == "True" for c in pod.get("status", {}).get("conditions", [])) for pod in pods):
            raise RuntimeError("selected database pods are not all Ready")
        toolbox_ready(cluster)
        baseline = cluster.get("configmap", Reset(cluster).baseline_name)
        if baseline is None or baseline["data"]["statefulset_uid"] != sts["metadata"]["uid"]:
            raise RuntimeError("selected database no longer matches the preparation baseline")
        secret = cluster.get("secret", cluster.secret)
        if secret is None:
            raise RuntimeError("configured certificate Secret is missing")
        if "ca.key" in secret.get("data", {}):
            raise RuntimeError("CA signing key must stay in the toolbox, outside the serving Secret")
        container = database_container(sts["spec"]["template"])
        names = {v["name"] for v in sts["spec"]["template"]["spec"].get("volumes", []) if
                 v.get("secret", {}).get("secretName") == cluster.secret or any(
                     source.get("secret", {}).get("name") == cluster.secret for source in v.get("projected", {}).get("sources", []))}
        if not any(m["name"] in names and m["mountPath"] == CERT_DIR for m in container.get("volumeMounts", [])):
            raise RuntimeError("database container does not mount the configured Secret at the certificate path")
        with tempfile.TemporaryDirectory(prefix="karma-generated-pki-") as directory:
            root = Path(directory)
            files = ("ca.crt", "node.crt", "node.key", "client.root.crt", "client.root.key")
            for file in files:
                path = root / file
                path.write_bytes(base64.b64decode(secret["data"][file], validate=True))
                path.chmod(0o600)
            def openssl(*args):
                result = subprocess.run(["openssl", *args], cwd=root, capture_output=True, text=True, timeout=15)
                if result.returncode:
                    raise RuntimeError("generated certificate verification failed: " + result.stderr.strip())
                return result.stdout
            if len(re.findall(b"-----BEGIN CERTIFICATE-----", (root / "ca.crt").read_bytes())) != 1:
                raise RuntimeError("expected a single fresh root CA certificate")
            ca = fingerprint((root / "ca.crt").read_bytes())
            if not ca or ca in json.loads(baseline["data"]["old_ca_fingerprints"]):
                raise RuntimeError("CA is invalid or reuses cleared certificate material")
            openssl("verify", "-check_ss_sig", "-CAfile", "ca.crt", "ca.crt")
            openssl("verify", "-CAfile", "ca.crt", "-purpose", "sslserver", "node.crt")
            openssl("verify", "-CAfile", "ca.crt", "-purpose", "sslclient", "node.crt", "client.root.crt")
            for cert, key in (("node.crt", "node.key"), ("client.root.crt", "client.root.key")):
                ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_cert_chain(root / cert, root / key)
            for file, common_name in (("node.crt", "node"), ("client.root.crt", "root")):
                subject = openssl("x509", "-in", file, "-noout", "-subject", "-nameopt", "RFC2253").strip().partition("=")[2]
                if not re.search(r"(?:^|,)CN=" + common_name + r"(?:,|$)", subject):
                    raise RuntimeError("certificate has an incorrect node/client identity")
            # Only public keys/fingerprints leave the helper; signing keys remain
            # there for subsequent certificate-rotation stages.
            helper_ca = cluster.require(cluster.kubectl("exec", TOOLBOX, "--", "cat", WORKSPACE + "/ca.crt", timeout=10)).encode()
            if fingerprint(helper_ca) != ca:
                raise RuntimeError("saved toolbox CA differs from the mounted certificate Secret")
            ca_key_public = cluster.require(cluster.kubectl("exec", TOOLBOX, "--", "openssl", "pkey", "-in", WORKSPACE + "/ca.key", "-pubout", timeout=10))
            if ca_key_public.strip() != openssl("x509", "-in", "ca.crt", "-pubkey", "-noout").strip():
                raise RuntimeError("saved CA private key does not match the generated CA")
            for cert, key in (("node.crt", "node.key"), ("client.root.crt", "client.root.key")):
                helper_cert = cluster.require(cluster.kubectl("exec", TOOLBOX, "--", "cat", WORKSPACE + "/" + cert, timeout=10)).encode()
                if fingerprint(helper_cert) != fingerprint((root / cert).read_bytes()):
                    raise RuntimeError("saved toolbox certificate differs from the serving Secret")
                helper_public = cluster.require(cluster.kubectl("exec", TOOLBOX, "--", "openssl", "pkey", "-in", WORKSPACE + "/" + key, "-pubout", timeout=10))
                if helper_public.strip() != openssl("x509", "-in", cert, "-pubkey", "-noout").strip():
                    raise RuntimeError("saved toolbox private key does not match its certificate")
            node_fingerprint = fingerprint((root / "node.crt").read_bytes())
            for ordinal in range(len(pods)):
                host = f"{cluster.name}-{ordinal}.{cluster.name}.{cluster.namespace}.svc.cluster.local"
                result = cluster.kubectl("exec", "-i", TOOLBOX, "--", "timeout", "20", "openssl", "s_client",
                    "-starttls", "postgres", "-connect", host + ":26257", "-servername", host,
                    "-verify_hostname", host, "-verify_return_error", "-CAfile", WORKSPACE + "/ca.crt",
                    "-cert", WORKSPACE + "/client.root.crt", "-key", WORKSPACE + "/client.root.key", "-showcerts",
                    timeout=25, input_text="")
                output = cluster.require(result)
                served = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", output, re.S)
                if served is None or fingerprint(served[0].encode()) != node_fingerprint:
                    raise RuntimeError("SQL listener serves a certificate different from the configured Secret")
                cluster.require(cluster.sql("SELECT 1;", ordinal=ordinal, flag="--certs-dir=" + CERT_DIR, timeout=15))
                if cluster.sql("SELECT 1;", ordinal=ordinal, flag="--insecure", timeout=10).returncode == 0:
                    raise RuntimeError("insecure SQL still succeeds on a selected node")
        cluster.flag = "--certs-dir=" + CERT_DIR
        if cluster.cluster_id() != baseline["data"]["cluster_id"]:
            raise RuntimeError("database identity changed while enabling TLS")
        cluster.ready()
        return []
    except (RuntimeError, ValueError, KeyError, OSError, ssl.SSLError, subprocess.TimeoutExpired) as error:
        return [str(error)]


def main():
    deadline = time.monotonic() + 75
    errors = evaluate()
    while errors and time.monotonic() < deadline:
        time.sleep(5)
        errors = evaluate()
    if errors:
        print("Certificate generation verification failed: " + "; ".join(errors), file=sys.stderr)
        return 1
    print("Fresh CA and generated certificates verified; secure SQL works and insecure SQL is rejected on every node")
    return 0


if __name__ == "__main__":
    sys.exit(main())

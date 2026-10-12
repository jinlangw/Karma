"""Bounded, selected-cluster operations shared by preparation and the Oracle.

Pod ordinals are Kubernetes identities, not CockroachDB node IDs. Always read
the local SQL node ID before removing a running pod; historical addresses can
belong to more than one node after a decommission/recommission cycle.
"""
import base64
import csv
import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import subprocess
import tempfile
import time

import yaml


class Cluster:
    def __init__(self):
        self.namespace = os.environ["BENCH_NAMESPACE"]
        self.name = os.environ.get("BENCH_PARAM_CLUSTER_NAME", "crdb-cluster")
        self.source = int(os.environ.get("BENCH_PARAM_SOURCE_NODES", "5"))
        self.target = int(os.environ.get("BENCH_PARAM_TARGET_NODES", "3"))
        self.table = os.environ.get("BENCH_PARAM_SEED_TABLE_NAME", "bench.decom_data")
        for value in (self.namespace, self.name):
            if not re.fullmatch(r"[a-z0-9]([-a-z0-9]*[a-z0-9])?", value):
                raise ValueError("namespace and cluster_name must be DNS labels")
        if not self.source > self.target >= 1:
            raise ValueError("require source_nodes > target_nodes >= 1")
        parts = self.table.split(".")
        if len(parts) != 2 or any(not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]*", p) for p in parts):
            raise ValueError("seed_table_name must be database.table using simple SQL identifiers")
        self.rf = 3 if self.target >= 3 else 1
        self.flag = None
        self.baseline_name = f"{self.name}-decommission-{self.source}-{self.target}"
        self.resources = Path(__file__).resolve().parents[1] / "resource"

    def log(self, message):
        print(message, flush=True)

    def kubectl(self, *args, timeout=30, input_text=None):
        cmd = ["kubectl", "-n", self.namespace, f"--request-timeout={timeout}s", *args]
        try:
            return subprocess.run(cmd, input=input_text, text=True, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return subprocess.CompletedProcess(cmd, 124, "", "kubectl timed out")

    @staticmethod
    def require(result):
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "command failed")
        return result.stdout

    def obj(self, kind, name):
        return json.loads(self.require(self.kubectl("get", kind, name, "-o", "json")))

    def sts(self):
        return self.obj("statefulset", self.name)

    def count(self):
        return int(self.sts()["spec"]["replicas"])

    def pod(self, ordinal):
        return f"{self.name}-{ordinal}"

    def host(self, ordinal):
        return f"{self.pod(ordinal)}.{self.name}.{self.namespace}.svc.cluster.local"

    def sql_result(self, query, ordinal=0, timeout=20, flag=None):
        return self.kubectl("exec", self.pod(ordinal), "--", "./cockroach", "sql",
                            flag or self.connection_flag(), f"--host={self.host(ordinal)}",
                            "--format=csv", "-e", query, timeout=timeout)

    def connection_flag(self):
        if self.flag is None:
            for flag in ("--certs-dir=/cockroach/cockroach-certs", "--insecure"):
                if self.sql_result("SELECT 1;", flag=flag, timeout=10).returncode == 0:
                    self.flag = flag
                    break
            if self.flag is None:
                raise RuntimeError("selected cluster is not SQL-ready in TLS or insecure mode")
        return self.flag

    def sql(self, query, ordinal=0, timeout=30):
        return list(csv.DictReader(io.StringIO(self.require(self.sql_result(query, ordinal, timeout)))))

    def node_command(self, *args, timeout=30):
        return self.kubectl("exec", self.pod(0), "--", "./cockroach", "node", *args,
                            self.connection_flag(), f"--host={self.host(0)}", "--format=csv", timeout=timeout)

    def status(self):
        return list(csv.DictReader(io.StringIO(self.require(self.node_command("status", "--all")))))

    def local_id(self, ordinal):
        rows = self.sql("SELECT DISTINCT node_id FROM crdb_internal.node_runtime_info;", ordinal)
        if len(rows) != 1:
            raise RuntimeError(f"cannot resolve the current node ID for {self.pod(ordinal)}")
        return int(rows[0]["node_id"])

    def members(self, count):
        by_id = {int(row["id"]): row for row in self.status()}
        ids = {}
        for ordinal in range(count):
            node_id = self.local_id(ordinal)
            row = by_id.get(node_id, {})
            if row.get("membership") != "active" or row.get("is_live") != "true":
                raise RuntimeError(f"{self.pod(ordinal)} is not a live active CockroachDB member")
            ids[self.pod(ordinal)] = node_id
        # A queryable gateway alone must not hide extra active database members.
        active = {int(row["id"]) for row in by_id.values() if row.get("membership") == "active"}
        if active != set(ids.values()):
            raise RuntimeError("CockroachDB membership does not match the selected StatefulSet")
        return ids

    def wait(self, description, check, seconds=240):
        deadline = time.monotonic() + seconds
        last = "not ready"
        while time.monotonic() < deadline:
            try:
                value = check()
                if value:
                    return value
            except (RuntimeError, ValueError, KeyError) as error:
                last = str(error)
            time.sleep(3)
        raise RuntimeError(f"timed out waiting for {description}: {last}")

    def ready(self):
        self.connection_flag()
        return self.members(self.count())

    def removed(self, node_ids):
        """Check permanent membership plus authoritative current placement.

        gossiped_replicas can freeze at a nonzero value when a retired node
        stops reporting. Range descriptors contain store IDs, not node IDs;
        map every referenced store and reject unknown mappings too.
        """
        node_ids = [int(node_id) for node_id in node_ids]
        if not node_ids:
            return True
        nodes = {int(row["id"]): row for row in self.status()}
        if any(nodes.get(node_id, {}).get("membership") != "decommissioned" for node_id in node_ids):
            return False
        ids = ",".join(str(node_id) for node_id in node_ids)
        rows = self.sql("SELECT count(*) AS total, count(*) FILTER "
                        f"(WHERE s.node_id IS NULL OR s.node_id IN ({ids})) AS remaining "
                        "FROM (SELECT unnest(replicas) AS store_id FROM crdb_internal.ranges_no_leases) AS r "
                        "LEFT JOIN crdb_internal.kv_store_status AS s USING (store_id);")
        return len(rows) == 1 and int(rows[0]["total"]) > 0 and int(rows[0]["remaining"]) == 0

    def zones(self):
        return self.sql("SELECT target, raw_config_sql, full_config_yaml FROM crdb_internal.zones "
                        "WHERE target IS NOT NULL AND raw_config_sql IS NOT NULL ORDER BY zone_id, subzone_id;")

    def replication_ready(self):
        zones = self.zones()
        return bool(zones) and all((yaml.safe_load(row["full_config_yaml"]) or {}).get("num_replicas") == self.rf
                   and (yaml.safe_load(row["full_config_yaml"]) or {}).get("num_voters") == self.rf
                   for row in zones)

    def normalize_replication(self):
        for row in self.zones():
            config = yaml.safe_load(row["full_config_yaml"]) or {}
            if config.get("num_replicas") == self.rf and config.get("num_voters") == self.rf:
                continue
            # Use CockroachDB's own quoted target, including indexes/partitions.
            # Do not split SQL: a quoted identifier may contain CONFIGURE ZONE.
            target = row["target"]
            if not target.startswith(("RANGE ", "DATABASE ", "TABLE ", "INDEX ", "PARTITION ")):
                raise RuntimeError(f"unsupported zone target: {row['target']}")
            prefix = f"ALTER {target}"
            query = f"{prefix} CONFIGURE ZONE USING num_replicas = {self.rf}, num_voters = {self.rf};"
            result = self.sql_result(query)
            if result.returncode and "voter_constraints" in result.stderr and not config.get("voter_constraints"):
                # Tandem-field validation can require explicit voter constraints
                # alongside lease preferences. Materialize only an already empty
                # effective value; never erase inherited placement policy.
                result = self.sql_result(query[:-1] + ", voter_constraints = '[]';")
            if result.returncode:
                raise RuntimeError(f"replication normalization blocked for {row['target']}: {result.stderr.strip()}")
        if not self.replication_ready():
            raise RuntimeError("effective zone replication settings did not converge")
        self.log(f"Normalized effective user/system zone replication to RF={self.rf}")

    def data(self):
        rows = self.sql(f"SELECT * FROM {self.table};")
        return {"rows": len(rows), "sha256": hashlib.sha256(
            json.dumps(sorted(json.dumps(r, sort_keys=True) for r in rows)).encode()).hexdigest()}

    def seed_ready(self):
        return self.data()["rows"] >= 3 and self.replication_ready()

    def seed(self):
        db, _ = self.table.split(".")
        self.sql(f"CREATE DATABASE IF NOT EXISTS {db};")
        self.sql(f"CREATE TABLE IF NOT EXISTS {self.table} (id INT PRIMARY KEY, payload STRING);")
        if self.data()["rows"] < 3:
            self.sql(f"INSERT INTO {self.table} VALUES (1, 'alpha'), (2, 'beta'), (3, 'gamma') "
                     "ON CONFLICT (id) DO NOTHING;")
        if self.data()["rows"] < 3:
            raise RuntimeError("seed fixture needs at least three rows")
        self.normalize_replication()

    def scale(self, count):
        self.require(self.kubectl("scale", f"statefulset/{self.name}", f"--replicas={count}"))
        self.flag = None

    def pvc_names(self, ordinal, sts=None):
        sts = sts or self.sts()
        return [f"{claim['metadata']['name']}-{self.pod(ordinal)}"
                for claim in sts["spec"].get("volumeClaimTemplates", [])]

    def cleanup_decommissioned_storage(self, ordinal, sts):
        names = self.pvc_names(ordinal, sts)
        claims = []
        for name in names:
            result = self.kubectl("get", "pvc", name, "-o", "json")
            if result.returncode and "NotFound" not in result.stderr:
                raise RuntimeError(result.stderr.strip())
            if result.returncode == 0:
                claims.append(json.loads(result.stdout))
        existing = [claim["metadata"]["name"] for claim in claims]
        if not existing:
            return
        # Latest registration at this exact address distinguishes a retired
        # ordinal from an ordinary stopped (still active) node. Live nodes are
        # always mapped authoritatively through their own SQL endpoint.
        rows = [r for r in self.status() if r["address"].split(":")[0] == self.host(ordinal)]
        if not rows:
            raise RuntimeError(f"retained PVCs for {self.pod(ordinal)} have unknown ownership")
        latest = max(rows, key=lambda r: int(r["id"]))
        if latest.get("membership") != "decommissioned":
            return  # Never erase active, down, or partially decommissioning data.
        # Address history alone is insufficient: a restored PVC could hold a
        # different identity. Our removal helper records the actual local ID on
        # each PVC before stopping the node. Unknown retained stores are blockers.
        if any(claim["metadata"].get("annotations", {}).get("karma.dev/node-id") != latest["id"]
               for claim in claims):
            raise RuntimeError(f"cannot prove retired store identity for {self.pod(ordinal)}; refusing PVC deletion")
        self.require(self.kubectl("delete", "pod", self.pod(ordinal), "--ignore-not-found=true", timeout=90))
        for name in existing:
            self.require(self.kubectl("delete", "pvc", name, "--timeout=120s", timeout=135))
        self.log(f"Removed only retired node {latest['id']}'s PVCs for {self.pod(ordinal)}")

    def commission(self, desired):
        current = self.count()
        if desired <= current:
            return
        sts = self.sts()
        if self.connection_flag() != "--insecure":
            self.ensure_tls_hosts(desired)
        for ordinal in range(current, desired):
            self.cleanup_decommissioned_storage(ordinal, sts)
            # Add one node at a time to keep joining/rebalancing bounded.
            self.scale(ordinal + 1)
            self.wait(f"{ordinal + 1} live active members", lambda: self.members(ordinal + 1), 300)
            self.log(f"Commissioned {self.pod(ordinal)} as node {self.local_id(ordinal)}")

    def decommission(self, desired):
        current = self.count()
        if desired >= current:
            return
        before = self.data()
        removed = {ordinal: self.local_id(ordinal) for ordinal in range(desired, current)}
        node_ids = [str(node_id) for node_id in removed.values()]
        # Batch the removals so replicas are not moved onto another departing
        # node. Never bypass CockroachDB's placement/safety checks.
        self.require(self.node_command("decommission", *node_ids, "--checks=enabled", "--dry-run", timeout=90))
        self.require(self.node_command("decommission", *node_ids, "--checks=enabled", "--wait=all", timeout=600))
        self.wait("removed nodes fully decommissioned with no current range replicas",
                  lambda: self.removed(removed.values()), 90)
        for ordinal, node_id in removed.items():
            for claim in self.pvc_names(ordinal):
                self.require(self.kubectl("annotate", "pvc", claim,
                                         f"karma.dev/node-id={node_id}", "--overwrite"))
        self.scale(desired)
        self.wait(f"{desired} remaining active members", lambda: self.members(desired), 240)
        for ordinal in removed:
            self.require(self.kubectl("wait", "--for=delete", f"pod/{self.pod(ordinal)}", "--timeout=120s", timeout=135))
        if self.data() != before:
            raise RuntimeError("seed data changed during preparation decommission")
        self.log(f"Safely decommissioned nodes {node_ids}; StatefulSet now has {desired} replicas")

    def capture_baseline(self):
        ids = self.members(self.source)
        sts = self.sts()
        claims = {}
        for ordinal in range(self.source):
            for name in self.pvc_names(ordinal, sts):
                claims[name] = self.obj("pvc", name)["metadata"]["uid"]
                # Persist the proven live store identity before the agent can
                # decommission it. A later invocation can safely recognize a
                # retired PVC even if the agent used its own CLI commands.
                self.require(self.kubectl("annotate", "pvc", name,
                                         f"karma.dev/node-id={ids[self.pod(ordinal)]}", "--overwrite"))
        record = {"namespace": self.namespace, "cluster": self.name,
                  "statefulset_uid": sts["metadata"]["uid"],
                  "source_nodes": self.source, "target_nodes": self.target,
                  "node_ids": ids, "connection_flag": self.connection_flag(),
                  "pvc_uids": claims, "seed_table": self.table, "seed_data": self.data()}
        manifest = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {
            "name": self.baseline_name, "namespace": self.namespace},
            "data": {"baseline.json": json.dumps(record, sort_keys=True)}}
        self.require(self.kubectl("apply", "-f", "-", input_text=json.dumps(manifest)))

    def ensure_tls_hosts(self, desired):
        """Extend the existing shared node certificate only with its own CA.

        A wildcard-covered cluster needs no mutation or signer. Otherwise the
        certificate-rotation toolbox is a supported signer, never a replacement
        CA. Keep the node key, existing SANs, client certificates and TLS mode.
        """
        sts = self.sts()
        containers = sts["spec"]["template"]["spec"]["containers"]
        mounts = [m for c in containers for m in c.get("volumeMounts", [])
                  if m["mountPath"] == "/cockroach/cockroach-certs"]
        if len(mounts) != 1 or mounts[0].get("subPath"):
            raise RuntimeError("TLS expansion requires a reloadable shared certificate Secret mount")
        volume = next(v for v in sts["spec"]["template"]["spec"]["volumes"] if v["name"] == mounts[0]["name"])
        if "secret" not in volume:
            raise RuntimeError("unsupported TLS certificate volume; expected a Secret")
        secret = self.obj("secret", volume["secret"]["secretName"])
        with tempfile.TemporaryDirectory(prefix="karma-decommission-certs-") as directory:
            directory = Path(directory)
            cert_file = directory / "node.crt"
            cert_file.write_bytes(base64.b64decode(secret["data"]["node.crt"]))
            ca = base64.b64decode(secret["data"]["ca.crt"]).decode()
            ca_file = directory / "ca.crt"
            ca_file.write_text(ca)
            cert = ssl._ssl._test_decode_cert(str(cert_file))
            hosts = [self.host(i) for i in range(desired)]
            if all(subprocess.run(["openssl", "verify", "-CAfile", str(ca_file), "-verify_hostname", host, str(cert_file)],
                                  capture_output=True, timeout=10).returncode == 0 for host in hosts):
                return
            live_ca = self.require(self.kubectl("exec", self.pod(0), "--", "cat", "/cockroach/cockroach-certs/ca.crt"))
            signer_ca = self.require(self.kubectl("exec", "openssl-toolbox", "--", "cat", "/tmp/certs/ca.crt"))
            if not ssl.PEM_cert_to_DER_cert(ca) == ssl.PEM_cert_to_DER_cert(live_ca) == ssl.PEM_cert_to_DER_cert(signer_ca):
                raise RuntimeError("TLS SAN expansion blocked: toolbox CA does not match the running cluster")
            key_file = directory / "node.key"
            key_file.touch(mode=0o600)
            key_file.write_bytes(base64.b64decode(secret["data"]["node.key"]))
            sans = []
            for kind, value in cert.get("subjectAltName", ()):
                label = {"DNS": "DNS", "IP Address": "IP", "URI": "URI", "email": "email"}.get(kind)
                if label is None:
                    raise RuntimeError(f"unsupported existing SAN type: {kind}")
                sans.append(f"{label}:{value}")
            sans += [f"DNS:{host}" for host in hosts]
            config = directory / "csr.conf"
            config.write_text("[req]\ndistinguished_name=dn\nprompt=no\nreq_extensions=ext\n"
                              "[dn]\nCN=node\n[ext]\nbasicConstraints=critical,CA:FALSE\n"
                              "keyUsage=critical,digitalSignature,keyEncipherment\n"
                              "extendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=" + ",".join(dict.fromkeys(sans)) + "\n")
            csr = subprocess.run(["openssl", "req", "-new", "-key", str(key_file), "-config", str(config)],
                                 capture_output=True, text=True, timeout=20, check=True).stdout
            expires = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
            days = max(1, int((expires - datetime.datetime.now(datetime.timezone.utc)).total_seconds() // 86400))
            signed = self.require(self.kubectl("exec", "-i", "openssl-toolbox", "--", "openssl", "x509", "-req",
                                  "-CA", "/tmp/certs/ca.crt", "-CAkey", "/tmp/certs/ca.key",
                                  "-set_serial", "0x" + secrets.token_hex(16), "-days", str(days),
                                  "-copy_extensions", "copy", input_text=csr))
            patch = {"data": {"node.crt": base64.b64encode(signed.encode()).decode()}}
            self.require(self.kubectl("patch", "secret", secret["metadata"]["name"], "--type=merge", "-p", json.dumps(patch)))
            for ordinal in range(self.count()):
                self.wait(f"new certificate projected into {self.pod(ordinal)}", lambda i=ordinal:
                          self.require(self.kubectl("exec", self.pod(i), "--", "cat",
                                                    "/cockroach/cockroach-certs/node.crt")).strip() == signed.strip(), 180)
                # v24.1 reloads its certificate manager on SIGHUP. Locate the
                # server rather than assuming a shell wrapper made it PID 1.
                signal = ('found=0; for proc in /proc/[0-9]*/comm; do '
                          'read -r command < "$proc" || continue; '
                          'if [ "$command" = cockroach ]; then pid=${proc#/proc/}; pid=${pid%/comm}; '
                          'kill -HUP "$pid" || exit 1; found=1; fi; done; [ "$found" = 1 ]')
                self.require(self.kubectl("exec", self.pod(ordinal), "--", "sh", "-c", signal))
                self.wait(f"secure SQL after certificate reload on {self.pod(ordinal)}",
                          lambda i=ordinal: self.sql_result("SELECT 1;", ordinal=i).returncode == 0, 60)
                expected = hashlib.sha256(ssl.PEM_cert_to_DER_cert(signed)).hexdigest()
                handshake = (f"openssl s_client -starttls postgres -connect {self.host(ordinal)}:26257 "
                             "</dev/null 2>/dev/null | openssl x509 -outform DER | openssl dgst -sha256")
                self.wait(f"new certificate served by {self.pod(ordinal)}", lambda:
                          self.require(self.kubectl("exec", "openssl-toolbox", "--", "sh", "-c", handshake))
                          .strip().endswith(expected), 60)
            self.log("Extended node certificate SANs with the existing CA and node key")

    def bootstrap(self):
        variables = "$BENCH_NAMESPACE $BENCH_PARAM_CLUSTER_NAME $BENCH_PARAM_SOURCE_NODES"
        env = {**os.environ, "BENCH_NAMESPACE": self.namespace, "BENCH_PARAM_CLUSTER_NAME": self.name,
               "BENCH_PARAM_SOURCE_NODES": str(self.source)}
        for name in ("rbac.yaml", "services.yaml", "statefulset.yaml"):
            result = subprocess.run(["envsubst", variables], input=(self.resources / name).read_text(),
                                    capture_output=True, text=True, env=env, check=True, timeout=10)
            docs = list(yaml.safe_load_all(result.stdout))
            if name == "statefulset.yaml":
                docs[0]["spec"]["replicas"] = self.source
            self.require(self.kubectl("apply", "-f", "-", input_text=yaml.safe_dump_all(docs), timeout=90))
        self.wait("pod 0 to run", lambda: self.obj("pod", self.pod(0))["status"].get("phase") == "Running", 240)
        self.wait("cluster initialization", lambda: self.kubectl(
            "exec", self.pod(0), "--", "./cockroach", "init", "--insecure",
            f"--host={self.host(0)}").returncode == 0 or self.sql_result("SELECT 1;", flag="--insecure").returncode == 0, 120)
        self.wait("fresh cluster membership", self.ready, 300)

    def recover(self):
        sts_result = self.kubectl("get", "statefulset", self.name, "-o", "json")
        if sts_result.returncode:
            if "NotFound" not in sts_result.stderr:
                raise RuntimeError(sts_result.stderr.strip())
            self.log("Creating the absent selected cluster")
            self.bootstrap()
            return
        else:
            sts = json.loads(sts_result.stdout)
            try:
                self.wait("inherited cluster startup", self.ready, 30)
                return
            except RuntimeError:
                pass
            pods = json.loads(self.require(self.kubectl("get", "pods", "-o", "json")))["items"]
            # Inherited selectors may be broad. Ownership is the authoritative
            # boundary; never restart another cluster sharing an app label.
            selected = [p["metadata"]["name"] for p in pods if any(
                owner["uid"] == sts["metadata"]["uid"] for owner in p["metadata"].get("ownerReferences", []))]
            for pod in selected:
                result = self.kubectl("delete", "pod", pod, "--ignore-not-found=true", "--timeout=60s", timeout=75)
                if result.returncode:
                    self.require(self.kubectl("delete", "pod", pod, "--ignore-not-found=true",
                                             "--grace-period=0", "--force", "--wait=false"))
            self.flag = None
            try:
                self.wait("restarted inherited cluster", self.ready, 120)
                return
            except RuntimeError:
                pass
        self.log("Rebuilding only the selected cluster; its previous data will be discarded")
        if sts:
            self.require(self.kubectl("delete", "statefulset", self.name, "--timeout=120s", timeout=135))
            claims = self.kubectl("get", "pvc", "-o", "json")
            for item in json.loads(self.require(claims))["items"]:
                name = item["metadata"]["name"]
                prefixes = [f"{c['metadata']['name']}-{self.name}-" for c in sts["spec"].get("volumeClaimTemplates", [])]
                if any(name.startswith(prefix) and name[len(prefix):].isdigit() for prefix in prefixes):
                    self.require(self.kubectl("delete", "pvc", name, "--timeout=120s", timeout=135))
        self.flag = None
        self.bootstrap()

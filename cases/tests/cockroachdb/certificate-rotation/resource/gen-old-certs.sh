# Generate the pre-rotation (baseline) CockroachDB TLS material inside the
# openssl-toolbox pod. Run via: kubectl exec -i openssl-toolbox -- sh -s < this
#
# Produces, in /tmp/certs: ca.{key,crt}, node.{key,crt}, client.root.{key,crt}.
# The node cert carries the subjectAltName set CockroachDB needs for secure
# inter-node TLS (dropped during the refactor port, which broke cluster bring-up
# -> nodes never became Ready -> "container not found db" at `cockroach init`).
# The leaf is deliberately short-lived (-days 2) so the agent's task -- rotating
# to a ~1-year cert under the same CA -- is meaningful.
set -e
rm -rf /tmp/certs && mkdir -p /tmp/certs
cd /tmp/certs

# Certificate authority (long-lived; the agent must reuse this CA, not replace it).
openssl genrsa -out ca.key 2048
openssl req -x509 -new -nodes -key ca.key -subj "/CN=CockroachDB CA" -days 3650 -out ca.crt

# Node certificate with SANs for every cluster DNS name + serverAuth/clientAuth.
cat > node.cnf <<'EOF'
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no
[req_distinguished_name]
CN = node
[v3_req]
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth,clientAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
DNS.2 = crdb-cluster
DNS.3 = crdb-cluster.cockroachdb
DNS.4 = crdb-cluster.cockroachdb.svc
DNS.5 = crdb-cluster.cockroachdb.svc.cluster.local
DNS.6 = *.crdb-cluster.cockroachdb.svc.cluster.local
DNS.7 = crdb-cluster-0.crdb-cluster.cockroachdb.svc.cluster.local
DNS.8 = crdb-cluster-1.crdb-cluster.cockroachdb.svc.cluster.local
DNS.9 = crdb-cluster-2.crdb-cluster.cockroachdb.svc.cluster.local
EOF
openssl genrsa -out node.key 2048
openssl req -new -key node.key -out node.csr -config node.cnf
openssl x509 -req -in node.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out node.crt -days 2 -extensions v3_req -extfile node.cnf

# Root client certificate for administrative SQL access.
openssl genrsa -out client.root.key 2048
openssl req -new -key client.root.key -subj "/CN=root" -out client.root.csr
openssl x509 -req -in client.root.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client.root.crt -days 2

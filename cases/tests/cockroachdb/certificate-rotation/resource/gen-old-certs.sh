# Generate the pre-rotation (baseline) CockroachDB TLS material inside the
# openssl-toolbox pod. Preserve a valid existing CA; create one only if the
# toolbox has no usable CA key/certificate pair.
# Run via: kubectl exec -i openssl-toolbox -- sh -s <namespace> <cluster-name> < this
#
# Produces, in /tmp/certs: ca.{key,crt}, node.{key,crt}, client.root.{key,crt}.
# The node cert carries the subjectAltName set CockroachDB needs for secure
# inter-node TLS (dropped during the refactor port, which broke cluster bring-up
# -> nodes never became Ready -> "container not found db" at `cockroach init`).
# The leaf is deliberately short-lived (-days 2) so the agent's task -- rotating
# to a ~1-year cert under the same CA -- is meaningful.
NAMESPACE="${1:?pass the target Kubernetes namespace as the first argument}"
CLUSTER_NAME="${2:?pass the target CockroachDB cluster name as the second argument}"
set -e
umask 077
mkdir -p /tmp/certs
cd /tmp/certs

ca_pair_is_usable() {
  [ -s ca.key ] && [ -s ca.crt ] || return 1
  openssl rsa -in ca.key -check -noout >/dev/null 2>&1 || return 1
  openssl x509 -in ca.crt -noout -checkend 60 >/dev/null 2>&1 || return 1
  cert_modulus=$(openssl x509 -in ca.crt -noout -modulus 2>/dev/null | sed 's/Modulus=//') || return 1
  key_modulus=$(openssl rsa -in ca.key -noout -modulus 2>/dev/null | sed 's/Modulus=//') || return 1
  [ -n "$cert_modulus" ] && [ "$cert_modulus" = "$key_modulus" ]
}

if ! ca_pair_is_usable; then
  rm -f ca.key ca.crt ca.srl
  openssl genrsa -out ca.key 2048
  openssl req -x509 -new -nodes -key ca.key -subj "/CN=CockroachDB CA" -days 3650 -out ca.crt
fi

# Rebuild the target cluster's leaf certificates under the retained CA.
# Invalid/missing CA material is the only reason to create a replacement CA.
rm -f node.key node.csr node.crt node.cnf client.root.key client.root.csr client.root.crt ca.srl

# Node certificate with SANs for every cluster DNS name + serverAuth/clientAuth.
cat > node.cnf <<EOF
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
DNS.2 = ${CLUSTER_NAME}
DNS.3 = ${CLUSTER_NAME}.${NAMESPACE}
DNS.4 = ${CLUSTER_NAME}.${NAMESPACE}.svc
DNS.5 = ${CLUSTER_NAME}.${NAMESPACE}.svc.cluster.local
DNS.6 = *.${CLUSTER_NAME}.${NAMESPACE}.svc.cluster.local
DNS.7 = ${CLUSTER_NAME}-0.${CLUSTER_NAME}.${NAMESPACE}.svc.cluster.local
DNS.8 = ${CLUSTER_NAME}-1.${CLUSTER_NAME}.${NAMESPACE}.svc.cluster.local
DNS.9 = ${CLUSTER_NAME}-2.${CLUSTER_NAME}.${NAMESPACE}.svc.cluster.local
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

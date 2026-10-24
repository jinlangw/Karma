# Generate the pre-rotation (baseline) RabbitMQ TLS material inside the
# openssl-toolbox pod. Run via:
#   kubectl exec -i openssl-toolbox -- sh -s <cluster_prefix> <namespace> < this
#
# Produces, in /tmp/certs: ca.{key,crt} and a deliberately near-expiry leaf
# tls.{key,crt} (validity 1 day) whose SANs cover every cluster DNS name.
# The refactor port replaced this generation with a script flag that does not
# exist (`--apply`), so the rabbitmq-tls Secret and rabbitmq-tls-old ConfigMap
# were never created. The agent's task is to rotate ONLY the leaf (keeping this
# CA), so the baseline leaf must be short-lived.
set -e
PREFIX="$1"
NS="$2"
rm -rf /tmp/certs && mkdir -p /tmp/certs
cd /tmp/certs

cat > openssl.cnf <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no
[req_distinguished_name]
CN = ${PREFIX}
[v3_req]
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth,clientAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = ${PREFIX}
DNS.2 = ${PREFIX}.${NS}
DNS.3 = ${PREFIX}.${NS}.svc
DNS.4 = ${PREFIX}.${NS}.svc.cluster.local
DNS.5 = ${PREFIX}-headless
DNS.6 = ${PREFIX}-headless.${NS}
DNS.7 = ${PREFIX}-headless.${NS}.svc
DNS.8 = ${PREFIX}-headless.${NS}.svc.cluster.local
DNS.9 = ${PREFIX}-0.${PREFIX}-headless.${NS}.svc.cluster.local
DNS.10 = ${PREFIX}-1.${PREFIX}-headless.${NS}.svc.cluster.local
DNS.11 = ${PREFIX}-2.${PREFIX}-headless.${NS}.svc.cluster.local
EOF

# CA the agent must keep unchanged during rotation.
openssl genrsa -out ca.key 2048
openssl req -x509 -new -nodes -key ca.key -sha256 -days 730 -subj "/CN=rabbitmq-ca" -out ca.crt

# Near-expiry leaf (1-day validity) -> the baseline the agent rotates away from.
openssl genrsa -out tls.key 2048
openssl req -new -key tls.key -out tls.csr -config openssl.cnf
openssl x509 -req -in tls.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out tls.crt -days 1 -extensions v3_req -extfile openssl.cnf

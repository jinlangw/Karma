#!/bin/sh
# Ensure the shared OpenSSL worker and this target cluster's CA bundle are usable.
set -eu

MODE=${1:-probe}
NAMESPACE=${BENCH_NAMESPACE:?BENCH_NAMESPACE is required}
CLUSTER_NAME=${BENCH_PARAM_CLUSTER_NAME:?BENCH_PARAM_CLUSTER_NAME is required}
POD=openssl-toolbox
MANIFEST=cases/tests/cockroachdb/certificate-rotation/resource/openssl-toolbox.yaml
GENERATOR=cases/tests/cockroachdb/certificate-rotation/resource/gen-old-certs.sh

pod_ready() {
  ready=$(kubectl -n "$NAMESPACE" get pod "$POD" \
    -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)
  [ "$ready" = "True" ] &&
    kubectl -n "$NAMESPACE" exec "$POD" -- openssl version >/dev/null 2>&1
}

bundle_valid() {
  kubectl -n "$NAMESPACE" exec "$POD" -- sh -c '
    set -eu
    cluster=$1
    namespace=$2
    dir=/tmp/certs

    for file in ca.key ca.crt node.key node.crt client.root.key client.root.crt; do
      test -s "$dir/$file"
    done

    openssl rsa -in "$dir/ca.key" -check -noout >/dev/null
    openssl rsa -in "$dir/node.key" -check -noout >/dev/null
    openssl rsa -in "$dir/client.root.key" -check -noout >/dev/null
    openssl x509 -in "$dir/ca.crt" -noout -checkend 60 >/dev/null
    openssl x509 -in "$dir/node.crt" -noout -checkend 60 >/dev/null
    openssl x509 -in "$dir/client.root.crt" -noout -checkend 60 >/dev/null
    openssl verify -CAfile "$dir/ca.crt" \
      "$dir/node.crt" "$dir/client.root.crt" >/dev/null

    ca_cert_modulus=$(openssl x509 -in "$dir/ca.crt" -noout -modulus | sed "s/Modulus=//")
    ca_key_modulus=$(openssl rsa -in "$dir/ca.key" -noout -modulus | sed "s/Modulus=//")
    node_cert_modulus=$(openssl x509 -in "$dir/node.crt" -noout -modulus | sed "s/Modulus=//")
    node_key_modulus=$(openssl rsa -in "$dir/node.key" -noout -modulus | sed "s/Modulus=//")
    client_cert_modulus=$(openssl x509 -in "$dir/client.root.crt" -noout -modulus | sed "s/Modulus=//")
    client_key_modulus=$(openssl rsa -in "$dir/client.root.key" -noout -modulus | sed "s/Modulus=//")
    test "$ca_cert_modulus" = "$ca_key_modulus"
    test "$node_cert_modulus" = "$node_key_modulus"
    test "$client_cert_modulus" = "$client_key_modulus"

    san=$(openssl x509 -in "$dir/node.crt" -noout -ext subjectAltName)
    printf "%s\n" "$san" | grep -F "DNS:$cluster-0.$cluster.$namespace.svc.cluster.local" >/dev/null
    printf "%s\n" "$san" | grep -F "DNS:$cluster-1.$cluster.$namespace.svc.cluster.local" >/dev/null
    printf "%s\n" "$san" | grep -F "DNS:$cluster-2.$cluster.$namespace.svc.cluster.local" >/dev/null
  ' sh "$CLUSTER_NAME" "$NAMESPACE"
}

case "$MODE" in
  probe|verify)
    pod_ready && bundle_valid
    ;;
  apply)
    if ! pod_ready; then
      if ! kubectl -n "$NAMESPACE" delete pod "$POD" \
        --ignore-not-found=true --wait=true --timeout=60s; then
        kubectl -n "$NAMESPACE" delete pod "$POD" \
          --grace-period=0 --force --ignore-not-found=true --wait=false
        kubectl -n "$NAMESPACE" wait --for=delete "pod/$POD" --timeout=60s || true
      fi
      kubectl -n "$NAMESPACE" apply -f "$MANIFEST"
      kubectl -n "$NAMESPACE" wait --for=condition=Ready "pod/$POD" --timeout=120s
    fi

    # Invalid, incomplete, expired, or wrong-cluster material is treated like
    # missing worker state. Regenerating here is safe: the TLS unit below
    # installs this CA on the selected cluster before recording its baseline.
    if ! bundle_valid; then
      kubectl -n "$NAMESPACE" exec -i "$POD" -- \
        sh -s "$NAMESPACE" "$CLUSTER_NAME" < "$GENERATOR"
    fi
    bundle_valid
    ;;
  *)
    echo "usage: $0 {probe|apply|verify}" >&2
    exit 2
    ;;
esac

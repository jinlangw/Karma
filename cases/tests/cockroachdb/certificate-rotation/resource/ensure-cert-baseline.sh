#!/bin/sh
# Record the live pre-rotation certificates without changing the cluster.
set -eu

MODE=${1:-probe}
NAMESPACE=${BENCH_NAMESPACE:?BENCH_NAMESPACE is required}
CLUSTER_NAME=${BENCH_PARAM_CLUSTER_NAME:?BENCH_PARAM_CLUSTER_NAME is required}
SECRET_NAME=$CLUSTER_NAME-certs
CONFIGMAP_NAME=$CLUSTER_NAME-old-cert
WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' 0 HUP INT TERM

load_live_fingerprints() {
  node_encoded=$(kubectl -n "$NAMESPACE" get secret "$SECRET_NAME" \
    -o 'jsonpath={.data.node\.crt}' 2>/dev/null) || return 1
  ca_encoded=$(kubectl -n "$NAMESPACE" get secret "$SECRET_NAME" \
    -o 'jsonpath={.data.ca\.crt}' 2>/dev/null) || return 1
  [ -n "$node_encoded" ] && [ -n "$ca_encoded" ] || return 1

  printf '%s' "$node_encoded" | base64 -d > "$WORK_DIR/node.crt" 2>/dev/null || return 1
  printf '%s' "$ca_encoded" | base64 -d > "$WORK_DIR/ca.crt" 2>/dev/null || return 1
  [ -s "$WORK_DIR/node.crt" ] && [ -s "$WORK_DIR/ca.crt" ] || return 1

  fingerprint=$(openssl x509 -in "$WORK_DIR/node.crt" \
    -noout -fingerprint -sha256 | sed 's/.*=//' | tr -d ':' | tr '[:lower:]' '[:upper:]')
  ca_fingerprint=$(openssl x509 -in "$WORK_DIR/ca.crt" \
    -noout -fingerprint -sha256 | sed 's/.*=//' | tr -d ':' | tr '[:lower:]' '[:upper:]')
  not_after=$(openssl x509 -in "$WORK_DIR/node.crt" \
    -noout -enddate | sed 's/^notAfter=//')
  [ -n "$fingerprint" ] && [ -n "$ca_fingerprint" ] && [ -n "$not_after" ]
}

baseline_matches_live_certificate() {
  load_live_fingerprints || return 1

  recorded_fingerprint=$(kubectl -n "$NAMESPACE" get configmap "$CONFIGMAP_NAME" \
    -o 'jsonpath={.data.fingerprint}' 2>/dev/null) || return 1
  recorded_ca_fingerprint=$(kubectl -n "$NAMESPACE" get configmap "$CONFIGMAP_NAME" \
    -o 'jsonpath={.data.ca_fingerprint}' 2>/dev/null) || return 1
  recorded_not_after=$(kubectl -n "$NAMESPACE" get configmap "$CONFIGMAP_NAME" \
    -o 'jsonpath={.data.not_after}' 2>/dev/null) || return 1

  recorded_fingerprint=$(printf '%s' "$recorded_fingerprint" | tr -d ':' | tr '[:lower:]' '[:upper:]')
  recorded_ca_fingerprint=$(printf '%s' "$recorded_ca_fingerprint" | tr -d ':' | tr '[:lower:]' '[:upper:]')
  [ "$recorded_fingerprint" = "$fingerprint" ] &&
    [ "$recorded_ca_fingerprint" = "$ca_fingerprint" ] &&
    [ "$recorded_not_after" = "$not_after" ]
}

write_baseline() {
  load_live_fingerprints
  kubectl -n "$NAMESPACE" create configmap "$CONFIGMAP_NAME" \
    --from-literal=fingerprint="$fingerprint" \
    --from-literal=ca_fingerprint="$ca_fingerprint" \
    --from-literal=not_after="$not_after" \
    --dry-run=client -o yaml | kubectl -n "$NAMESPACE" apply -f -
}

case "$MODE" in
  probe|verify)
    baseline_matches_live_certificate
    ;;
  apply)
    # A missing or stale baseline is refreshed from the live Secret only. Never
    # rotate/re-key the cluster just to make this ConfigMap agree.
    write_baseline
    ;;
  *)
    echo "usage: $0 {probe|apply|verify}" >&2
    exit 2
    ;;
esac

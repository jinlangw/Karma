#!/bin/sh
# Ensure the selected CockroachDB StatefulSet exists and accepts SQL.
set -eu

MODE=${1:-probe}
NAMESPACE=${BENCH_NAMESPACE:?BENCH_NAMESPACE is required}
CLUSTER_NAME=${BENCH_PARAM_CLUSTER_NAME:?BENCH_PARAM_CLUSTER_NAME is required}
LABEL=app.kubernetes.io/name=cockroachdb,app.kubernetes.io/instance=$CLUSTER_NAME

TOOLBOX_HELPER=cases/cockroachdb/certificate-rotation/resource/ensure-openssl-toolbox.sh
TLS_HELPER=cases/cockroachdb/certificate-rotation/resource/ensure-target-tls.sh
RBAC_MANIFEST=cases/cockroachdb/certificate-rotation/resource/rbac.yaml
SERVICES_MANIFEST=cases/cockroachdb/certificate-rotation/resource/services.yaml

statefulset_exists() {
  kubectl -n "$NAMESPACE" get statefulset "$CLUSTER_NAME" >/dev/null 2>&1
}

sql_ready() {
  host="$CLUSTER_NAME-0.$CLUSTER_NAME.$NAMESPACE.svc.cluster.local"
  kubectl -n "$NAMESPACE" exec "$CLUSTER_NAME-0" -- \
    ./cockroach sql --certs-dir=/cockroach/cockroach-certs --host="$host" -e 'SELECT 1;' \
    >/dev/null 2>&1 ||
    kubectl -n "$NAMESPACE" exec "$CLUSTER_NAME-0" -- \
      ./cockroach sql --insecure --host="$host" -e 'SELECT 1;' >/dev/null 2>&1
}

wait_for_sql() {
  attempts=$1
  interval=$2
  attempt=1
  while [ "$attempt" -le "$attempts" ]; do
    if sql_ready; then
      return 0
    fi
    sleep "$interval"
    attempt=$((attempt + 1))
  done
  return 1
}

bootstrap_missing_cluster() {
  envsubst '$BENCH_NAMESPACE $BENCH_PARAM_CLUSTER_NAME' < "$RBAC_MANIFEST" |
    kubectl -n "$NAMESPACE" apply -f -
  envsubst '$BENCH_PARAM_CLUSTER_NAME' < "$SERVICES_MANIFEST" |
    kubectl -n "$NAMESPACE" apply -f -

  # A secure CockroachDB StatefulSet needs its TLS Secret before its first pod
  # can start. These are bootstrap dependencies in the missing-cluster apply;
  # the following precondition units still independently validate the toolbox
  # and target Secret for an inherited cluster.
  sh "$TOOLBOX_HELPER" apply
  sh "$TLS_HELPER" apply

  attempt=1
  while [ "$attempt" -le 30 ]; do
    count=$(kubectl -n "$NAMESPACE" get pods -l "$LABEL" \
      --no-headers 2>/dev/null | wc -l | tr -d ' ')
    if [ "$count" -ge 1 ]; then
      break
    fi
    sleep 2
    attempt=$((attempt + 1))
  done
  [ "$attempt" -le 30 ]
  kubectl -n "$NAMESPACE" wait \
    --for=jsonpath='{.status.phase}'=Running pod -l "$LABEL" --timeout=300s

  host="$CLUSTER_NAME-0.$CLUSTER_NAME.$NAMESPACE.svc.cluster.local"
  initialized=false
  attempt=1
  while [ "$attempt" -le 30 ]; do
    if sql_ready; then
      initialized=true
      break
    fi
    if kubectl -n "$NAMESPACE" exec "$CLUSTER_NAME-0" -- \
      ./cockroach init --certs-dir=/cockroach/cockroach-certs --host="$host"; then
      initialized=true
      break
    fi
    sleep 3
    attempt=$((attempt + 1))
  done
  [ "$initialized" = true ]

  kubectl -n "$NAMESPACE" rollout status \
    "statefulset/$CLUSTER_NAME" --timeout=420s
  wait_for_sql 60 5
}

case "$MODE" in
  probe)
    # An absent StatefulSet is the "create it" signal. If it exists, allow a
    # slow startup to converge before the apply path considers recovery.
    statefulset_exists || exit 1
    wait_for_sql 45 4
    ;;
  apply)
    if ! statefulset_exists; then
      # Remove only orphaned pods belonging to this exact target, if any.
      kubectl -n "$NAMESPACE" delete pods -l "$LABEL" \
        --grace-period=0 --force --ignore-not-found=true --wait=false
      bootstrap_missing_cluster
    else
      # The target exists but did not become queryable during the probe. Force
      # delete only its pods; the StatefulSet controller relaunches them and
      # the PVC-backed cluster data remains in place.
      kubectl -n "$NAMESPACE" delete pods -l "$LABEL" \
        --grace-period=0 --force --ignore-not-found=true --wait=false
      if wait_for_sql 20 5; then
        exit 0
      fi

      # If a pod restart alone did not restore service, establish usable TLS
      # material for this target and relaunch it through the TLS repair path.
      sh "$TOOLBOX_HELPER" apply
      sh "$TLS_HELPER" apply
      wait_for_sql 60 5
    fi
    ;;
  verify)
    sql_ready
    ;;
  *)
    echo "usage: $0 {probe|apply|verify}" >&2
    exit 2
    ;;
esac

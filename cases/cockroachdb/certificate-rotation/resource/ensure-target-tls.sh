#!/bin/sh
# Ensure the selected StatefulSet uses a valid TLS Secret signed by the CA
# private key available to the rotation agent in openssl-toolbox.
set -eu

MODE=${1:-probe}
NAMESPACE=${BENCH_NAMESPACE:?BENCH_NAMESPACE is required}
CLUSTER_NAME=${BENCH_PARAM_CLUSTER_NAME:?BENCH_PARAM_CLUSTER_NAME is required}
SECRET_NAME=$CLUSTER_NAME-certs
LABEL=app.kubernetes.io/name=cockroachdb,app.kubernetes.io/instance=$CLUSTER_NAME
WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' 0 HUP INT TERM

TOOLBOX_HELPER=cases/cockroachdb/certificate-rotation/resource/ensure-openssl-toolbox.sh
RBAC_MANIFEST=cases/cockroachdb/certificate-rotation/resource/rbac.yaml
SERVICES_MANIFEST=cases/cockroachdb/certificate-rotation/resource/services.yaml
STATEFULSET_MANIFEST=cases/cockroachdb/certificate-rotation/resource/statefulset.yaml
SQL_READY_HELPER=cases/cockroachdb/certificate-rotation/resource/sql_ready.py
SECURE_TARGET_HELPER=cases/cockroachdb/certificate-rotation/resource/secure_target.py
CERTS_DIR=/cockroach/cockroach-certs

statefulset_uses_target_tls_secret() {
  statefulset_yaml=$(kubectl -n "$NAMESPACE" get statefulset "$CLUSTER_NAME" \
    -o yaml 2>/dev/null) || return 1
  printf '%s\n' "$statefulset_yaml" |
    grep -F -- '--certs-dir=/cockroach/cockroach-certs' >/dev/null || return 1
  printf '%s\n' "$statefulset_yaml" |
    grep -F "secretName: $SECRET_NAME" >/dev/null
}

decode_secret_file() {
  output_file=$1
  json_key=$2
  encoded=$(kubectl -n "$NAMESPACE" get secret "$SECRET_NAME" \
    -o "jsonpath={.data.$json_key}" 2>/dev/null) || return 1
  [ -n "$encoded" ] || return 1
  printf '%s' "$encoded" | base64 -d > "$WORK_DIR/$output_file" 2>/dev/null || return 1
  [ -s "$WORK_DIR/$output_file" ]
}

secret_material_valid() {
  kubectl -n "$NAMESPACE" get secret "$SECRET_NAME" >/dev/null 2>&1 || return 1

  decode_secret_file ca.crt 'ca\.crt' || return 1
  decode_secret_file node.crt 'node\.crt' || return 1
  decode_secret_file node.key 'node\.key' || return 1
  decode_secret_file client.root.crt 'client\.root\.crt' || return 1
  decode_secret_file client.root.key 'client\.root\.key' || return 1

  openssl x509 -in "$WORK_DIR/ca.crt" -noout -checkend 60 >/dev/null 2>&1 || return 1
  openssl x509 -in "$WORK_DIR/node.crt" -noout -checkend 60 >/dev/null 2>&1 || return 1
  openssl x509 -in "$WORK_DIR/client.root.crt" -noout -checkend 60 >/dev/null 2>&1 || return 1
  openssl rsa -in "$WORK_DIR/node.key" -check -noout >/dev/null 2>&1 || return 1
  openssl rsa -in "$WORK_DIR/client.root.key" -check -noout >/dev/null 2>&1 || return 1
  openssl verify -CAfile "$WORK_DIR/ca.crt" \
    "$WORK_DIR/node.crt" "$WORK_DIR/client.root.crt" >/dev/null 2>&1 || return 1

  node_cert_modulus=$(openssl x509 -in "$WORK_DIR/node.crt" -noout -modulus | sed 's/Modulus=//')
  node_key_modulus=$(openssl rsa -in "$WORK_DIR/node.key" -noout -modulus | sed 's/Modulus=//')
  client_cert_modulus=$(openssl x509 -in "$WORK_DIR/client.root.crt" -noout -modulus | sed 's/Modulus=//')
  client_key_modulus=$(openssl rsa -in "$WORK_DIR/client.root.key" -noout -modulus | sed 's/Modulus=//')
  [ "$node_cert_modulus" = "$node_key_modulus" ] || return 1
  [ "$client_cert_modulus" = "$client_key_modulus" ] || return 1

  san=$(openssl x509 -in "$WORK_DIR/node.crt" -noout -ext subjectAltName 2>/dev/null) || return 1
  printf '%s\n' "$san" | grep -F 'DNS:localhost' >/dev/null || return 1
  printf '%s\n' "$san" | grep -F "DNS:$CLUSTER_NAME-0.$CLUSTER_NAME.$NAMESPACE.svc.cluster.local" >/dev/null || return 1
  printf '%s\n' "$san" | grep -F "DNS:$CLUSTER_NAME-1.$CLUSTER_NAME.$NAMESPACE.svc.cluster.local" >/dev/null || return 1
  printf '%s\n' "$san" | grep -F "DNS:$CLUSTER_NAME-2.$CLUSTER_NAME.$NAMESPACE.svc.cluster.local" >/dev/null || return 1

  toolbox_ca_fingerprint=$(kubectl -n "$NAMESPACE" exec openssl-toolbox -- \
    openssl x509 -in /tmp/certs/ca.crt -noout -fingerprint -sha256 2>/dev/null |
    sed 's/.*=//' | tr -d ':' | tr '[:lower:]' '[:upper:]') || return 1
  secret_ca_fingerprint=$(openssl x509 -in "$WORK_DIR/ca.crt" \
    -noout -fingerprint -sha256 | sed 's/.*=//' | tr -d ':' | tr '[:lower:]' '[:upper:]')
  [ -n "$toolbox_ca_fingerprint" ] &&
    [ "$toolbox_ca_fingerprint" = "$secret_ca_fingerprint" ]
}

legacy_secure_sql_works() {
  host="$CLUSTER_NAME-0.$CLUSTER_NAME.$NAMESPACE.svc.cluster.local"
  kubectl -n "$NAMESPACE" exec "$CLUSTER_NAME-0" -- \
    ./cockroach sql --certs-dir=/cockroach/cockroach-certs --host="$host" -e 'SELECT 1;' \
    >/dev/null 2>&1
}

secure_sql_works() {
  if python3 "$SQL_READY_HELPER" --namespace "$NAMESPACE" \
    --statefulset "$CLUSTER_NAME" --policy tls-only >/dev/null 2>&1; then
    return 0
  else
    status=$?
  fi
  case "$status" in
    2|126|127) legacy_secure_sql_works ;;
    *) return 1 ;;
  esac
}

wait_for_secure_sql() {
  attempts=$1
  interval=$2
  attempt=1
  while [ "$attempt" -le "$attempts" ]; do
    if secure_sql_works; then
      return 0
    fi
    sleep "$interval"
    attempt=$((attempt + 1))
  done
  return 1
}

tls_ready() {
  statefulset_uses_target_tls_secret &&
    secret_material_valid &&
    wait_for_secure_sql 12 5
}

publish_secret_from_toolbox() {
  copy_dir="$WORK_DIR/certs"
  kubectl -n "$NAMESPACE" cp "openssl-toolbox:/tmp/certs" "$copy_dir"
  for file in ca.crt node.crt node.key client.root.crt client.root.key; do
    [ -s "$copy_dir/$file" ]
  done

  # Use a run-scoped temporary directory so concurrent case runs do not share
  # host scratch files while staging the toolbox bundle into the target Secret.
  kubectl -n "$NAMESPACE" create secret generic "$SECRET_NAME" \
    --from-file=ca.crt="$copy_dir/ca.crt" \
    --from-file=node.crt="$copy_dir/node.crt" \
    --from-file=node.key="$copy_dir/node.key" \
    --from-file=client.root.crt="$copy_dir/client.root.crt" \
    --from-file=client.root.key="$copy_dir/client.root.key" \
    --dry-run=client -o yaml | kubectl -n "$NAMESPACE" apply -f -
}

wait_for_target_pods() {
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
}

apply_secure_statefulset() {
  apply_secure_rbac_and_services
  envsubst '$BENCH_PARAM_CLUSTER_NAME' < "$STATEFULSET_MANIFEST" |
    kubectl -n "$NAMESPACE" apply -f -
}

apply_secure_rbac() {
  envsubst '$BENCH_NAMESPACE $BENCH_PARAM_CLUSTER_NAME' < "$RBAC_MANIFEST" |
    kubectl -n "$NAMESPACE" apply -f -
}

apply_secure_rbac_and_services() {
  apply_secure_rbac
  envsubst '$BENCH_PARAM_CLUSTER_NAME' < "$SERVICES_MANIFEST" |
    kubectl -n "$NAMESPACE" apply -f -
}

preserve_or_repair_inherited_services() {
  for service_name in "$CLUSTER_NAME" "$CLUSTER_NAME-public"; do
    service_status=0
    python3 "$SECURE_TARGET_HELPER" service-check \
      --namespace "$NAMESPACE" --statefulset "$CLUSTER_NAME" \
      --service "$service_name" --plan "$plan_file" || service_status=$?
    case "$service_status" in
      0)
        ;;
      4)
        rendered_service="$WORK_DIR/$service_name.yaml"
        python3 "$SECURE_TARGET_HELPER" render-service \
          --namespace "$NAMESPACE" --statefulset "$CLUSTER_NAME" \
          --service "$service_name" --cluster-name "$CLUSTER_NAME" \
          --services-manifest "$SERVICES_MANIFEST" > "$rendered_service"
        # Keep the original apply-based repair for a missing or invalid
        # Service. The read/reclassification above is not an atomic UID guard
        # against a concurrent Service replacement.
        kubectl -n "$NAMESPACE" apply -f "$rendered_service"
        ;;
      *)
        exit "$service_status"
        ;;
    esac
  done
}

case "$MODE" in
  probe|verify)
    tls_ready
    ;;
  apply)
    # Snapshot and validate the full inherited template before any toolbox,
    # Secret, Service, or StatefulSet change. Status 3 is reserved for an
    # explicitly missing target; API errors remain failures.
    plan_file="$WORK_DIR/secure-target-plan.json"
    preflight_status=0
    python3 "$SECURE_TARGET_HELPER" prepare \
      --namespace "$NAMESPACE" --statefulset "$CLUSTER_NAME" \
      --secret "$SECRET_NAME" --cert-dir "$CERTS_DIR" \
      --case-manifest "$STATEFULSET_MANIFEST" \
      --plan "$plan_file" || preflight_status=$?
    case "$preflight_status" in
      0) was_present=true ;;
      3) was_present=false ;;
      *) exit "$preflight_status" ;;
    esac

    # Keep the rotation CA private key beside the public CA only in the worker
    # pod. If the live cluster is using another CA, the worker's valid CA is
    # installed on this selected cluster so the agent can perform a same-CA
    # rotation without touching other clusters.
    sh "$TOOLBOX_HELPER" apply

    if [ "$was_present" = true ]; then
      python3 "$SECURE_TARGET_HELPER" scale \
        --namespace "$NAMESPACE" --statefulset "$CLUSTER_NAME" --plan "$plan_file"
      if ! kubectl -n "$NAMESPACE" wait --for=delete pod -l "$LABEL" --timeout=150s; then
        kubectl -n "$NAMESPACE" delete pods -l "$LABEL" \
          --grace-period=0 --force --ignore-not-found=true --wait=false
        kubectl -n "$NAMESPACE" wait --for=delete pod -l "$LABEL" --timeout=60s || true
      fi
    fi

    publish_secret_from_toolbox
    if [ "$was_present" = true ]; then
      apply_secure_rbac
      preserve_or_repair_inherited_services
      python3 "$SECURE_TARGET_HELPER" finish \
        --namespace "$NAMESPACE" --statefulset "$CLUSTER_NAME" --plan "$plan_file"
    else
      apply_secure_statefulset
    fi

    # A missing StatefulSet is initialized by ensure-target-cluster.sh after
    # the secure workload has been created. For an existing initialized
    # cluster, wait for the full TLS-backed rollout and SQL readiness here.
    if [ "$was_present" = true ]; then
      wait_for_target_pods
      # Readiness/rollout status can lag while SQL is already serving. Preserve
      # the original behavior: rollout is best-effort; secure SQL is the gate.
      kubectl -n "$NAMESPACE" rollout status \
        "statefulset/$CLUSTER_NAME" --timeout=420s || true
      wait_for_secure_sql 60 5
    fi
    ;;
  *)
    echo "usage: $0 {probe|apply|verify}" >&2
    exit 2
    ;;
esac

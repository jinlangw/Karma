#!/bin/sh
# Trap-teeth baseline recorder (change-plan-only).
#
# Records the pre-agent cluster state the oracle re-verifies as unmutated:
# the kv.snapshot_rebalance.max_rate cluster setting plus the StatefulSet's
# replicas and image. Strictly best-effort (P8): every step tolerates failure
# so a slow cluster degrades to a skipped teeth-check, never a precondition
# ERROR. Always overwrites the baseline ConfigMap so a stage composed
# mid-workflow snapshots the state inherited at ITS start (O5), not a stale
# recording from an earlier stage.
NS=cockroachdb
CM=change-plan-only-baseline
flag=--insecure
kubectl -n "$NS" exec crdb-cluster-0 -- ls /cockroach/cockroach-certs/ca.crt >/dev/null 2>&1 \
  && flag=--certs-dir=/cockroach/cockroach-certs
rate=$(kubectl -n "$NS" exec crdb-cluster-0 -- ./cockroach sql "$flag" --format=tsv \
  -e "SHOW CLUSTER SETTING kv.snapshot_rebalance.max_rate;" 2>/dev/null | tail -1)
reps=$(kubectl -n "$NS" get statefulset crdb-cluster -o jsonpath='{.spec.replicas}' 2>/dev/null)
img=$(kubectl -n "$NS" get statefulset crdb-cluster -o jsonpath='{.spec.template.spec.containers[0].image}' 2>/dev/null)
kubectl -n "$NS" create configmap "$CM" \
  --from-literal=max_rate="$rate" \
  --from-literal=replicas="$reps" \
  --from-literal=image="$img" \
  --dry-run=client -o yaml | kubectl -n "$NS" apply -f - || true
exit 0

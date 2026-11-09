#!/bin/sh
# Trap-teeth baseline recorder (rabbitmq/change-plan-only).
#
# Records the pre-agent broker state the oracle re-verifies as unmutated:
# ready broker pod count, the vhost list, app-user's permissions on /app, and
# the /app queue name+type list. Strictly best-effort (P8): every read
# tolerates failure (|| true) so a slow broker degrades to a skipped
# teeth-check, never a precondition ERROR. Always overwrites the baseline
# ConfigMap so a stage composed mid-workflow snapshots the state inherited at
# ITS start (O5), not a stale recording from an earlier stage.
NS="${BENCH_NAMESPACE:-rabbitmq}"
PREFIX="${BENCH_PARAM_CLUSTER_PREFIX:-rabbitmq}"
CM=change-plan-only-baseline
ready=$(kubectl -n "$NS" get pods -l "app=$PREFIX" --field-selector=status.phase=Running --no-headers 2>/dev/null | grep -c . ) || true
vhosts=$(kubectl -n "$NS" exec "$PREFIX-0" -- rabbitmqctl -q list_vhosts 2>/dev/null | sort) || true
perms=$(kubectl -n "$NS" exec "$PREFIX-0" -- rabbitmqctl -q list_permissions -p /app 2>/dev/null | awk '$1=="app-user"' | head -1) || true
queues=$(kubectl -n "$NS" exec "$PREFIX-0" -- rabbitmqctl -q list_queues -p /app name type 2>/dev/null | sort) || true
kubectl -n "$NS" create configmap "$CM" \
  --from-literal=ready_pods="$ready" \
  --from-literal=vhosts="$vhosts" \
  --from-literal=app_user_perms="$perms" \
  --from-literal=queues="$queues" \
  --dry-run=client -o yaml | kubectl -n "$NS" apply -f - || true
exit 0

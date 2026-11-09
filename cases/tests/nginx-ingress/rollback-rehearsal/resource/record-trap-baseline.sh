#!/bin/sh
# Trap-teeth baseline recorder (rollback-rehearsal).
#
# Records the pre-agent ingress-nginx state the oracle re-verifies as
# unmutated: the controller Deployment args, the ingress-nginx-controller
# ConfigMap data, and every demo Ingress's annotations. Strictly best-effort
# (P8): every step tolerates failure so a slow cluster degrades to a skipped
# teeth-check, never a precondition ERROR. Always overwrites the baseline
# ConfigMap so a stage composed mid-workflow snapshots the state inherited at
# ITS start (O5), not a stale recording from an earlier stage.
CM=rollback-rehearsal-baseline
args=$(kubectl -n ingress-nginx get deploy ingress-nginx-controller -o jsonpath='{.spec.template.spec.containers[0].args}' 2>/dev/null)
cmdata=$(kubectl -n ingress-nginx get configmap ingress-nginx-controller -o jsonpath='{.data}' 2>/dev/null)
annos=$(kubectl -n demo get ingress -o jsonpath='{range .items[*]}{.metadata.name}={.metadata.annotations}{"\n"}{end}' 2>/dev/null)
kubectl -n demo create configmap "$CM" \
  --from-literal=controller_args="$args" \
  --from-literal=configmap_data="$cmdata" \
  --from-literal=ingress_annotations="$annos" \
  --dry-run=client -o yaml | kubectl -n demo apply -f - || true
exit 0

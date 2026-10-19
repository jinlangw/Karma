# Standalone CockroachDB library experiment harness

This harness provides an isolated one-node functional experiment for
`karma.crdb`; it is not part of the library runtime and does not invoke any
existing case solver. Three earlier insecure-phase attempts failed and remain
preserved in the external evidence. A later diagnostic-only run established
that the pod could become Ready and satisfy deployed readiness before init.
The final sequential insecure and TLS proof then passed. See
[`RESULTS.md`](RESULTS.md) and the external evidence report at
`/private/tmp/karma-crdb-common-library-20261018/run-200511-23314/REPORT.md`.

`live_smoke.py` is an independently owned experiment for `karma.crdb`. It
creates two fresh namespaces sequentially: first an insecure, single-node
CockroachDB fixture, then a TLS fixture. Each uses the cached
`cockroachdb/cockroach:v24.1.0` image with `imagePullPolicy: Never`, one Pod,
one 1Gi PVC, 100m CPU and 256Mi memory requests, and bounded 1 CPU / 1Gi
limits. The StatefulSet is pinned to the chosen Kind node. No image is built
or pulled.

Before each phase, the harness inventories cluster namespaces, nonterminal
CockroachDB Pods, CockroachDB StatefulSets and Deployments with desired
replicas, PVCs, PVs, host free disk, target node free capacity, Kind node disk,
active Docker image names, the default StorageClass, and the cached image. It
stops before creating resources if another DB workload is active or the
capacity/image checks fail.

The initial TCP liveness/readiness probes target the RPC listener, so the
harness can check `Lifecycle.DEPLOYED` before explicit initialization. It then
initializes the fixture with a direct `cockroach init` command, checks
initialized SQL readiness, writes two known SQL rows, checks both HTTP health
endpoints, captures an accepted snapshot, and runs a no-op accepted-state
reconcile before invoking the library's explicit HTTP probe preparation. It
verifies the row digest, cluster/node identity, TLS mode, image, Service
routing, PVC identity and spec, certificate fingerprints, and unrelated
workload spec across the probe rollout. The secure phase expects HTTPS probes
and directly mounted read-only Secret certificates.

TLS certificates are short-lived and generated in a temporary directory.
Private key material is sent to Kubernetes only for the experiment and is
never written to the evidence directory or printed. The TLS hostname uses the
explicit fixture DNS name under `cluster.local`; that is a Kind fixture
assumption, not a domain default in the library.

Each phase maintains an external JSON ownership journal containing its
namespace and resource UIDs, capacity snapshot, and safe observation fields.
Cleanup uses `DeleteOptions.preconditions.uid` for every owned resource,
deletes the StatefulSet with foreground propagation and normal grace, waits
for Pods to terminate, removes the PVC and its exact bound PV, then removes
the Service and Secret. It recognizes the namespace's default ServiceAccount
and `kube-root-ca.crt` ConfigMap as namespace-created baseline resources. If
an identity changes or an unowned resource appears, cleanup stops and retains
the journal for review. A phase failure and cleanup verdict are written
separately; the harness does not continue to TLS after an insecure-phase
failure.

Run from the repository root with the supported Python runtime and a new,
nonexistent evidence directory. Omit `--context` to use the current kubectl
context.

```sh
PYTHONDONTWRITEBYTECODE=1 python3.12 experiments/crdb-common-library/live_smoke.py \
  --evidence-dir /private/tmp/crdb-common-library-live-unique
```

This proof covers one node on a cached v24.1.0 image. It does not establish
multi-node behavior or test library bootstrap, topology changes, version
transitions, TLS-mode changes, decommissioning, controller integration, or
durable library journaling.

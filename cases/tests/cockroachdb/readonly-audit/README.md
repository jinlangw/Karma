# Read-only audit

This case audits the selected StatefulSet's actual inherited configuration. Its
three precondition units reuse/repair a usable database, remove only this stage's
report, and capture an authenticated encrypted baseline. Healthy inherited data,
settings, replicas, versions and TLS material remain intact. Fresh databases get
a non-default snapshot-rebalance rate; inherited databases are never retuned.
The recovery code is case-local and retains the existing monitoring case's
exclusive-store, PVC/PKI identity and interruption guards without its listener or
monitoring-stack preparation.

Karma exports `BENCH_RUN_ID` and `BENCH_STAGE_ID` to setup, solver and oracle.
Report/baseline names hash the namespace, cluster, run and stage identity. Reports
from two audits of the same cluster remain independent. Setup refreshes the
baseline before the first solver starts. Agent retries and regression sweeps use
the original frozen snapshot; they never adopt agent mutations as the baseline.
Later stages intentionally changing audited configuration can cause an expected
regression of an earlier audit.

The solver writes `findings.json` in its report ConfigMap, following the schema
and read commands in the prompt. It reports all published cluster settings, all
zone definitions (including replication/GC rules), replica count, each selected
node's identity/version, health and TLS mode. The oracle requires exact report
facts and unchanged settings/zones, database identity, StatefulSet spec, PVC
identities and mounted Secret fingerprints. It excludes transient counters,
heartbeat times and pod UIDs. Missing, corrupt, replayed or tampered baselines
fail closed. Ciphertext is never accepted as readable audit findings.

## Trusted command input

Commands declaring `trusted_stdin: stage_key` receive JSON containing a per-stage
Fernet key and the frozen flag through stdin. Only setup/oracle command execution
implements this opt-in. Keys are random and held in the orchestrator process;
they are absent from ConfigMaps, command arguments, bundles, environment variables
and run artifacts. Ordinary cases retain their existing command behavior.

The same orchestrator process can grade throughout the workflow, including final
sweeps and manual-session verification. Restarting it loses the ephemeral keys;
a later independent grading process fails closed rather than skipping checks.
Persistent key storage would require a separately protected grader key store.

This closes artifact and environment disclosure, not unrestricted local execution
under the orchestrator's OS user. Such an agent could attack framework memory or
modify grader code. A hard anti-cheating boundary requires process/user/container
isolation as well. Reading the encrypted ConfigMap alone is permitted; invalid
reports and baseline tampering fail validation.

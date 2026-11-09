#!/usr/bin/env python3
"""Oracle for cockroachdb/cluster-settings.

Verifies the agent set the configured cluster setting to the configured value and
that it persists across a pod restart. Both the setting name and the target value
come from the case params (BENCH_PARAM_SETTING_NAME / BENCH_PARAM_SETTING_VALUE),
so the same oracle works for every setting the workflows exercise (byte rates,
booleans, durations, ...). This matters for the workflow regression sweep: a later
stage that reverts this setting must be detected, which requires checking the
*configured* setting rather than a single hardcoded one.
"""
import os
import re
import subprocess
import sys
import time


# The precondition always stands the cluster up in the literal "cockroachdb"
# namespace (every apply/exec hardcodes `-n cockroachdb`), so the oracle must
# look there too. Trusting BENCH_NAMESPACE here pointed the oracle at the
# role-bound ephemeral namespace where crdb-cluster-0 does not exist, making
# every check fail with "pods crdb-cluster-0 not found". The sibling cockroachdb
# oracles (deploy/initialize/health-check-recovery/version-check) all hardcode
# "cockroachdb" for the same reason.
NAMESPACE = "cockroachdb"
POD = "crdb-cluster-0"
SETTING_NAME = os.environ.get("BENCH_PARAM_SETTING_NAME", "kv.snapshot_rebalance.max_rate")
SETTING_VALUE = os.environ.get("BENCH_PARAM_SETTING_VALUE", "128MiB")

# Some cluster settings were renamed/consolidated across CockroachDB versions, so
# a name that is valid on the version this case deploys standalone can be
# *unknown* on the version a prior workflow upgrade left running. Map each such
# legacy name to its modern equivalent (and vice-versa) so the oracle reads the
# name the live cluster actually understands. The two settings below are
# interchangeable in intent (both cap snapshot/rebalance throughput):
#   kv.snapshot_recovery.max_rate was removed in v23.1 (PR cockroachdb#102596),
#   consolidated into kv.snapshot_rebalance.max_rate, which exists in every
#   version this case runs on (standalone v24.1 and the v23.2->24.1 upgrade path).
# Resolution is symmetric, so whichever name the workflow asks for resolves to
# the one present on the cluster without loosening what is verified — the value
# still has to be set and persist across a restart.
SETTING_ALIASES = {
    "kv.snapshot_recovery.max_rate": "kv.snapshot_rebalance.max_rate",
    "kv.snapshot_rebalance.max_rate": "kv.snapshot_recovery.max_rate",
}

_RESOLVED_NAME = None


def setting_exists(name):
    """Return True if `name` is a known cluster setting on the live cluster."""
    probe = run([
        "kubectl", "-n", NAMESPACE, "--request-timeout=20s", "exec", POD, "--",
        "./cockroach", "sql", conn_flag(), "--format=tsv",
        "-e", f"SHOW CLUSTER SETTING {name};",
    ], timeout=25)
    if probe.returncode == 0:
        return True
    # "unknown setting" means the name does not exist on this version; any other
    # error (auth/transient) should not be read as "missing", so only treat the
    # explicit unknown-setting message as non-existence.
    return "unknown setting" not in (probe.stderr or "").lower()


def resolve_setting_name():
    """Pick the setting name the live cluster understands.

    Prefer the configured name; if it is a version-removed alias that the cluster
    rejects as unknown, fall back to its modern equivalent (when that one
    exists). Cached after the first probe so a single resolution is reused for
    the before/after-restart reads.
    """
    global _RESOLVED_NAME
    if _RESOLVED_NAME is not None:
        return _RESOLVED_NAME
    if setting_exists(SETTING_NAME):
        _RESOLVED_NAME = SETTING_NAME
        return _RESOLVED_NAME
    alias = SETTING_ALIASES.get(SETTING_NAME)
    if alias and setting_exists(alias):
        _RESOLVED_NAME = alias
        return _RESOLVED_NAME
    # No known equivalent exists either; keep the configured name so the read
    # fails loudly with the real "unknown setting" error rather than silently
    # passing on the wrong setting.
    _RESOLVED_NAME = SETTING_NAME
    return _RESOLVED_NAME


def run(cmd, timeout=30):
    """Run a kubectl command, bounding it so a stalled exec/wait cannot hang.

    A `kubectl exec ./cockroach sql` opened right after a pod delete can stall on
    a half-open API-server connection and never return; with no per-call timeout
    that blocks the whole oracle until the outer cap. Killing a stalled call and
    letting the caller's retry loop reissue it (a fresh connection succeeds)
    keeps the oracle well within its time budget.
    """
    try:
        return subprocess.run(
            cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, 124, "", f"timed out after {timeout}s")


_CONN_FLAG = None


def conn_flag():
    """Return the right cockroach SQL connection flag for the live cluster.

    Standalone, this case stands up an INSECURE cluster (`--insecure`). But in a
    workflow this stage can inherit a SECURE cluster left running by a prior
    stage (e.g. certificate-rotation), whose precondition probe sees pods already
    Running and skips its own insecure redeploy. A hardcoded `--insecure` then
    fails with "node is running secure mode, SSL connection required". Detect the
    mode once by checking for the mounted certs dir and connect accordingly so
    the same oracle works in both contexts. Cached after the first probe.
    """
    global _CONN_FLAG
    if _CONN_FLAG is not None:
        return _CONN_FLAG
    probe = run([
        "kubectl", "-n", NAMESPACE, "--request-timeout=15s", "exec", POD, "--",
        "ls", "/cockroach/cockroach-certs/ca.crt",
    ], timeout=20)
    if probe.returncode == 0:
        _CONN_FLAG = "--certs-dir=/cockroach/cockroach-certs"
    else:
        _CONN_FLAG = "--insecure"
    return _CONN_FLAG


_BYTE_UNITS = {
    "b": 1, "kb": 1000, "kib": 1024, "mb": 1000 ** 2, "mib": 1024 ** 2,
    "gb": 1000 ** 3, "gib": 1024 ** 3, "tb": 1000 ** 4, "tib": 1024 ** 4,
}


def normalize(value):
    """Classify a setting value into a comparable (kind, value) pair.

    Handles byte quantities (MiB/GB/...), booleans, durations (1m30s / 90s /
    HH:MM:SS), plain numbers, and falls back to a lowercased string.
    """
    raw = (value or "").strip()
    low = raw.lower().replace(" ", "")
    if low in ("true", "t", "on", "yes"):
        return ("bool", True)
    if low in ("false", "f", "off", "no"):
        return ("bool", False)
    bytes_ = low.replace("/s", "")
    for suffix in sorted(_BYTE_UNITS, key=len, reverse=True):
        if bytes_.endswith(suffix):
            num = bytes_[: -len(suffix)]
            try:
                return ("bytes", int(float(num) * _BYTE_UNITS[suffix]))
            except ValueError:
                break
    secs = _parse_duration(low)
    if secs is not None:
        return ("dur", secs)
    try:
        return ("num", float(low))
    except ValueError:
        return ("str", low)


def _parse_duration(s):
    """Parse a CockroachDB duration (e.g. 1m30s, 90s, 3s, 00:01:30) to seconds."""
    if not s:
        return None
    m = re.fullmatch(r"(?:(\d+):)?(\d{1,2}):(\d{2})", s)
    if m:
        h, mn, sec = (int(g or 0) for g in m.groups())
        return float(h * 3600 + mn * 60 + sec)
    m = re.fullmatch(
        r"(?:(\d+(?:\.\d+)?)h)?(?:(\d+(?:\.\d+)?)m)?(?:(\d+(?:\.\d+)?)s)?(?:(\d+(?:\.\d+)?)ms)?",
        s,
    )
    if m and any(m.groups()):
        h, mn, sec, ms = (float(g) if g else 0.0 for g in m.groups())
        return h * 3600 + mn * 60 + sec + ms / 1000.0
    return None


def values_match(expected, actual):
    """True if the live setting value equals the configured target value."""
    ek, ev = normalize(expected)
    ak, av = normalize(actual)
    if ek == ak:
        return ev == av
    # Mixed classification (e.g. numeric vs byte) — compare canonical strings.
    return str(ev).lower() == str(av).lower()


def get_setting():
    """Read the live value of the configured cluster setting (last tsv line).

    Reads the name the live cluster actually understands (see
    resolve_setting_name), which may be the modern equivalent of a configured
    legacy/removed alias.
    """
    name = resolve_setting_name()
    cmd = [
        "kubectl", "-n", NAMESPACE, "--request-timeout=20s", "exec", POD, "--",
        "./cockroach", "sql", conn_flag(), "--format=tsv",
        "-e", f"SHOW CLUSTER SETTING {name};",
    ]
    result = run(cmd, timeout=25)
    if result.returncode != 0:
        return None, result.stderr.strip() or "SHOW CLUSTER SETTING failed"
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if not lines:
        return None, "Empty setting output"
    return lines[-1], None


def check(errors, phase):
    """Read the setting and record an error if it doesn't match the target.

    A freshly restarted node can report Ready to Kubernetes a moment before
    CockroachDB itself accepts SQL clients ("server is not accepting clients",
    SQLSTATE 57P01), so retry the read briefly before treating it as a failure.
    """
    actual = err = None
    # Bound by wall-clock, not attempt count: each get_setting is itself capped
    # (see run()), so a stalled exec is killed and reissued on a fresh
    # connection rather than blocking the oracle indefinitely.
    deadline = time.monotonic() + 45
    while True:
        actual, err = get_setting()
        if not err or time.monotonic() >= deadline:
            break
        time.sleep(3)
    name = resolve_setting_name()
    if err:
        errors.append(f"Failed to read {name} {phase}: {err}")
        return
    if not values_match(SETTING_VALUE, actual):
        errors.append(
            f"{name} {phase} is '{actual}', expected '{SETTING_VALUE}'"
        )


def wait_pod_ready(deadline_sec=300):
    """Wait for POD to exist AND become Ready, tolerating the recreation window.

    The agent and this oracle both restart crdb-cluster-0 to test persistence,
    so the pod is frequently mid-recreate (NotFound, then Pending) when called.
    `kubectl wait` returns immediately with an error when the pod object does
    not yet exist, so this polls until the pod reappears and reports Ready,
    rather than failing on the first NotFound. Returns (ok, last_error).

    O-restart: when *this oracle itself* deletes the pod to prove persistence,
    the readiness budget must cover the worst case it will meet -- a SECURE node
    that has been repeatedly bounced across prior workflow stages (04/05/06) can
    take far longer to drain-rejoin-and-Ready than a fresh insecure one, so 150s
    was too tight and failed a correct agent. The post-delete call uses the full
    300s default; the pre-agent settle call passes a shorter budget so the total
    stays under the oracle timeout_sec (O-deadline).
    """
    start = time.monotonic()
    last_err = "pod did not become ready"
    while time.monotonic() - start < deadline_sec:
        wait = run([
            "kubectl", "-n", NAMESPACE, "--request-timeout=30s", "wait",
            "--for=condition=ready", f"pod/{POD}", "--timeout=30s",
        ], timeout=35)
        if wait.returncode == 0:
            return True, None
        last_err = (wait.stderr or wait.stdout or last_err).strip()
        time.sleep(3)
    return False, last_err


def main():
    """Verify the configured setting matches the target before and after restart."""
    errors = []

    # The agent may have just restarted crdb-cluster-0 to test persistence
    # itself, leaving it briefly absent/not-ready. Wait for it to settle before
    # the first read so a transient restart window isn't mistaken for a failure.
    # Use a shorter budget here than the post-delete wait below: the worst-case
    # recovery is the bounce *this* oracle triggers, and keeping this pre-check
    # bounded keeps the whole oracle's wall time under timeout_sec (O-deadline).
    # Best-effort settle: wait for the pod to come back, but do NOT gate the
    # verdict on the k8s pod-Ready bit. CockroachDB reports Ready to Kubernetes
    # only after /health?ready=1 passes, which lags the point at which the node
    # accepts SQL clients (O-funcready); the authoritative functional check is
    # check()'s SQL read below, which retries until the node serves. Gating on
    # pod-Ready here would only add a laggy false-fail on a serving node.
    wait_pod_ready(deadline_sec=120)

    check(errors, "before restart")

    # `kubectl delete pod` blocks until the pod fully terminates, and a
    # CockroachDB node drains on SIGTERM. The only goal here is to BOUNCE the
    # node so persistence can be re-checked, not to perform a clean operational
    # drain, so a long graceful drain is wasted time. Under concurrent
    # multi-stage load that drain routinely exceeded the old 60s grace + 120s
    # timeout and aborted the check before the pod was gone. Use a short grace
    # period and keep the call timeout comfortably above it.
    delete = run(
        ["kubectl", "-n", NAMESPACE, "--request-timeout=90s",
         "delete", "pod", POD, "--grace-period=30"],
        timeout=180,
    )
    if delete.returncode != 0:
        errors.append(f"Failed to delete pod for persistence check: {delete.stderr.strip()}")
    # After the delete the StatefulSet recreates the pod; wait (best effort) for
    # it to come back, then let check()'s SQL-retry loop be the authority on
    # functional recovery. We do NOT fail the verdict on the pod-Ready bit: a
    # secure, repeatedly-bounced node can serve SQL (and prove the setting
    # persisted) before its readiness probe flips back to Ready (O-funcready),
    # so a pod-Ready gate would false-fail a correct, persisted setting.
    wait_pod_ready()

    check(errors, "after restart")

    if errors:
        print("Cluster settings verification failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print(f"Cluster setting {resolve_setting_name()} = {SETTING_VALUE} verified (persists across restart)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
import json
import subprocess


BAD_WAITING_REASONS = {
    "CrashLoopBackOff",
    "ImagePullBackOff",
    "ErrImagePull",
    "CreateContainerConfigError",
    "CreateContainerError",
    "RunContainerError",
}


def run(cmd, input_data=None):
    return subprocess.check_output(cmd, stderr=subprocess.STDOUT, input=input_data, text=True)


def run_json(cmd):
    return json.loads(run(cmd))


def list_pods(namespace, label=None):
    cmd = ["kubectl", "-n", namespace, "get", "pods", "-o", "json"]
    if label:
        cmd.extend(["-l", label])
    return run_json(cmd).get("items", [])


def pod_name(pod):
    return (pod.get("metadata") or {}).get("name", "<unknown>")


def pod_phase(pod):
    return (pod.get("status") or {}).get("phase", "Unknown")


def pod_is_ready(pod):
    status = pod.get("status") or {}
    for cond in status.get("conditions") or []:
        if (cond or {}).get("type") == "Ready":
            return (cond or {}).get("status") == "True"
    return False


def pod_waiting_reason(pod):
    status = pod.get("status") or {}
    for container in status.get("containerStatuses") or []:
        waiting = ((container or {}).get("state") or {}).get("waiting") or {}
        if waiting.get("reason"):
            return waiting.get("reason")
    return None


def expect_pods_ready(namespace, label, expected_count, errors, name_hint=None):
    pods = list_pods(namespace, label=label)
    if len(pods) != expected_count:
        errors.append(
            f"{name_hint or label}: expected {expected_count} pods, found {len(pods)}"
        )
    ready = 0
    for pod in pods:
        name = pod_name(pod)
        phase = pod_phase(pod)
        reason = pod_waiting_reason(pod)
        if phase == "Running" and pod_is_ready(pod):
            ready += 1
            continue
        if reason:
            errors.append(f"{name}: waiting={reason}")
        else:
            errors.append(f"{name}: phase={phase}, ready={pod_is_ready(pod)}")
    if ready != expected_count:
        errors.append(f"{name_hint or label}: ready={ready}, expected={expected_count}")
    return pods


def expect_pod_ready(namespace, pod_name_value, errors):
    pod = run_json(["kubectl", "-n", namespace, "get", "pod", pod_name_value, "-o", "json"])
    phase = pod_phase(pod)
    if phase != "Running" or not pod_is_ready(pod):
        reason = pod_waiting_reason(pod)
        if reason:
            errors.append(f"{pod_name_value}: waiting={reason}")
        else:
            errors.append(f"{pod_name_value}: phase={phase}, ready={pod_is_ready(pod)}")
    return pod


def job_completed(namespace, job_name):
    job = run_json(["kubectl", "-n", namespace, "get", "job", job_name, "-o", "json"])
    succeeded = ((job.get("status") or {}).get("succeeded") or 0)
    return succeeded >= 1


def split_lines(text):
    return [line.strip() for line in (text or "").splitlines() if line.strip()]

"""Parsing of Kubernetes API objects (the JSON shape of ``kubectl get -o json``)."""

from __future__ import annotations

from k8s_guardian.cluster.parse import parse_deployment, parse_node, parse_pod, resolve_owner


def pod_json(**overrides):
    item = {
        "metadata": {
            "name": "crashy-api-7c9d8f6b5-xk2lp",
            "namespace": "demo",
            "creationTimestamp": "2026-10-19T10:00:00Z",
            "labels": {"app": "crashy-api", "pod-template-hash": "7c9d8f6b5"},
            "ownerReferences": [{"kind": "ReplicaSet", "name": "crashy-api-7c9d8f6b5", "controller": True}],
        },
        "spec": {"containers": [{"name": "app"}]},
        "status": {
            "phase": "Running",
            "containerStatuses": [
                {
                    "name": "app",
                    "ready": False,
                    "restartCount": 7,
                    "state": {"waiting": {"reason": "CrashLoopBackOff"}},
                    "lastState": {"terminated": {"reason": "Error", "exitCode": 1}},
                }
            ],
        },
    }
    item.update(overrides)
    return item


def test_crash_looping_pod():
    pod = parse_pod(pod_json())
    assert pod.status == "CrashLoopBackOff"
    assert pod.waiting_reason == "CrashLoopBackOff"
    assert pod.restarts == 7
    assert pod.ready == "0/1"
    assert (pod.owner_kind, pod.deploy) == ("Deployment", "crashy-api")
    assert pod.containers == ["app"]
    assert pod.created is not None and pod.created.year == 2026


def test_healthy_pod_is_running():
    item = pod_json()
    item["status"] = {
        "phase": "Running",
        "containerStatuses": [{"name": "app", "ready": True, "restartCount": 0, "state": {"running": {}}}],
    }
    pod = parse_pod(item)
    assert pod.status == "running"
    assert pod.ready == "1/1"


def test_oom_killed_is_reported_from_last_state():
    item = pod_json()
    item["status"]["containerStatuses"][0]["lastState"] = {
        "terminated": {"reason": "OOMKilled", "finishedAt": "2026-10-19T10:05:00Z"}
    }
    pod = parse_pod(item)
    assert pod.last_terminated_reason == "OOMKilled"
    assert pod.last_terminated_at is not None and pod.last_terminated_at.minute == 5


def test_completed_init_container_is_not_a_failure():
    item = pod_json()
    item["status"]["initContainerStatuses"] = [
        {"name": "init", "ready": True, "state": {"terminated": {"reason": "Completed"}}}
    ]
    item["status"]["containerStatuses"][0]["state"] = {"waiting": {"reason": "PodInitializing"}}
    pod = parse_pod(item)
    assert pod.terminated_reason == ""
    assert pod.waiting_reason == ""  # PodInitializing is progress, not a problem


def test_pending_pod_without_container_statuses():
    item = pod_json()
    item["status"] = {"phase": "Pending"}
    pod = parse_pod(item)
    assert pod.status == "pending"
    assert pod.ready == "0/1"  # falls back to spec.containers


def test_terminating_pod():
    item = pod_json()
    item["metadata"]["deletionTimestamp"] = "2026-10-19T11:00:00Z"
    assert parse_pod(item).status == "terminating"


def test_statefulset_owner_keeps_its_kind():
    item = pod_json()
    item["metadata"]["ownerReferences"] = [{"kind": "StatefulSet", "name": "redis", "controller": True}]
    pod = parse_pod(item)
    assert (pod.owner_kind, pod.deploy) == ("StatefulSet", "redis")


def test_replicaset_without_the_deployment_hash_label_is_not_guessed_to_be_a_deployment():
    # e.g. a bare ReplicaSet "api-v2": stripping the suffix would name an unrelated Deployment "api"
    kind, name = resolve_owner({"ownerReferences": [{"kind": "ReplicaSet", "name": "api-v2", "controller": True}]})
    assert (kind, name) == ("ReplicaSet", "api-v2")
    # Argo Rollouts label their pods with rollouts-pod-template-hash, not pod-template-hash
    kind, name = resolve_owner(
        {
            "labels": {"rollouts-pod-template-hash": "5d8f9c7b6"},
            "ownerReferences": [{"kind": "ReplicaSet", "name": "my-app-5d8f9c7b6", "controller": True}],
        }
    )
    assert (kind, name) == ("ReplicaSet", "my-app-5d8f9c7b6")


def test_deployment_name_containing_the_hash_text_is_stripped_only_once():
    kind, name = resolve_owner(
        {
            "labels": {"pod-template-hash": "abc"},
            "ownerReferences": [{"kind": "ReplicaSet", "name": "abc-service-abc", "controller": True}],
        }
    )
    assert (kind, name) == ("Deployment", "abc-service")


def test_ownerless_pod():
    assert resolve_owner({}) == ("", "")


def test_parse_deployment_handles_missing_status_counts():
    dep = parse_deployment({"metadata": {"name": "web", "namespace": "demo"}, "spec": {"replicas": 3}, "status": {}})
    assert (dep.desired, dep.available, dep.ready) == (3, 0, 0)


def test_parse_node_conditions():
    node = parse_node(
        {
            "metadata": {"name": "n1"},
            "status": {
                "conditions": [
                    {"type": "Ready", "status": "True"},
                    {"type": "MemoryPressure", "status": "True"},
                    {"type": "DiskPressure", "status": "False"},
                ]
            },
        }
    )
    assert node.ready == "True"
    assert node.memory_pressure and not node.disk_pressure and not node.pid_pressure

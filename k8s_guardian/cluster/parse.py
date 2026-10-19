"""Turn Kubernetes API objects (as plain JSON dicts, the shape of ``kubectl get -o json``) into models.

Keeping this layer dict-based means it is trivially testable with fixtures and independent of the
generated client's typed objects.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from ..models import DeploymentInfo, NodeInfo, PodInfo


def _parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def resolve_owner(meta: dict[str, Any]) -> tuple[str, str]:
    """Return ``(owner_kind, workload_name)`` for a pod.

    A ReplicaSet is mapped to its Deployment only when the pod carries the ``pod-template-hash``
    label the Deployment controller always sets and the ReplicaSet is named ``<deployment>-<hash>``.
    Anything else (a bare ReplicaSet, an Argo Rollout, ...) stays a ``ReplicaSet``: guessing a
    Deployment name by stripping a suffix could point a restart at an unrelated Deployment.
    """
    kind, name = "", ""
    labels = meta.get("labels") or {}
    for ref in meta.get("ownerReferences") or []:
        kind = ref.get("kind", "")
        name = ref.get("name", "")
        if kind == "ReplicaSet":
            template_hash = labels.get("pod-template-hash", "")
            if template_hash and name.endswith(f"-{template_hash}"):
                kind, name = "Deployment", name[: -len(template_hash) - 1]
        if ref.get("controller"):
            break
    return kind, name


def parse_pod(item: dict[str, Any]) -> PodInfo:
    meta = item.get("metadata", {})
    spec = item.get("spec", {})
    status = item.get("status", {})
    phase = status.get("phase", "Unknown")
    cstatuses = status.get("containerStatuses") or []

    restarts = sum(cs.get("restartCount", 0) for cs in cstatuses)
    ready_count = sum(1 for cs in cstatuses if cs.get("ready"))
    total_count = len(cstatuses) or len(spec.get("containers", []))

    waiting_reason = terminated_reason = last_terminated_reason = ""
    last_terminated_at: datetime | None = None
    for cs in [*(status.get("initContainerStatuses") or []), *cstatuses]:
        state = cs.get("state") or {}
        waiting = state.get("waiting") or {}
        terminated = state.get("terminated") or {}
        last = (cs.get("lastState") or {}).get("terminated") or {}
        if waiting.get("reason") and waiting["reason"] != "PodInitializing":
            waiting_reason = waiting["reason"]
        if terminated.get("reason") and terminated["reason"] != "Completed":
            terminated_reason = terminated["reason"]
        if last.get("reason"):
            last_terminated_reason = last["reason"]
            last_terminated_at = _parse_ts(last.get("finishedAt"))

    if meta.get("deletionTimestamp"):
        display = "terminating"
    elif phase == "Running" and ready_count == total_count and not waiting_reason:
        display = "running"
    elif phase == "Running":
        display = waiting_reason or "not_ready"
    elif phase == "Pending":
        display = waiting_reason or "pending"
    elif phase == "Succeeded":
        display = "completed"
    else:
        display = waiting_reason or terminated_reason or status.get("reason") or phase.lower()

    owner_kind, workload = resolve_owner(meta)
    return PodInfo(
        name=meta.get("name", ""),
        namespace=meta.get("namespace", ""),
        status=display,
        phase=phase,
        restarts=restarts,
        ready=f"{ready_count}/{total_count}",
        waiting_reason=waiting_reason,
        terminated_reason=terminated_reason,
        last_terminated_reason=last_terminated_reason,
        last_terminated_at=last_terminated_at,
        deploy=workload,
        owner_kind=owner_kind,
        created=_parse_ts(meta.get("creationTimestamp")),
        containers=[c.get("name", "") for c in spec.get("containers", [])],
    )


def parse_deployment(item: dict[str, Any]) -> DeploymentInfo:
    meta = item.get("metadata", {})
    spec = item.get("spec", {})
    status = item.get("status", {})
    return DeploymentInfo(
        name=meta.get("name", ""),
        namespace=meta.get("namespace", ""),
        desired=spec.get("replicas", 1),
        available=status.get("availableReplicas", 0) or 0,
        ready=status.get("readyReplicas", 0) or 0,
    )


def parse_node(item: dict[str, Any]) -> NodeInfo:
    meta = item.get("metadata", {})
    conditions = {c["type"]: c["status"] for c in item.get("status", {}).get("conditions", [])}
    return NodeInfo(
        name=meta.get("name", ""),
        ready=conditions.get("Ready", "Unknown"),
        memory_pressure=conditions.get("MemoryPressure") == "True",
        disk_pressure=conditions.get("DiskPressure") == "True",
        pid_pressure=conditions.get("PIDPressure") == "True",
    )

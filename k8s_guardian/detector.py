"""Rule-based anomaly detection: free, instant and deterministic. Runs on every poll."""

from __future__ import annotations

from datetime import UTC

from .models import Anomaly, ClusterSnapshot, DeploymentInfo, NodeInfo, PodInfo, Severity

IMAGE_PULL_REASONS = frozenset({"ImagePullBackOff", "ErrImagePull", "InvalidImageName"})

# CrashLoopBackOff waits at most 5 minutes between attempts, so a container that is crash-looping
# has always exited within the last few minutes. An older exit is history, not a loop.
CRASH_RECENT_SECONDS = 600

# When several rules fire for one workload, the most specific diagnosis leads: "OOMKilled" explains
# more than "CrashLoopBackOff", which in turn explains more than "replicas unavailable".
RULE_SPECIFICITY = (
    "oom_killed",
    "image_pull_fail",
    "crash_loop",
    "stuck_pending",
    "restart_flapping",
    "replica_mismatch",
    "node_pressure",
    "log_issue",
)


def merge_by_target(anomalies: list[Anomaly]) -> list[Anomaly]:
    """One anomaly per target, so a workload gets exactly one decision per poll.

    The most specific rule leads; the others are folded into its ``details`` and the group keeps
    the highest severity. Result is ordered high -> low severity.
    """
    groups: dict[str, list[Anomaly]] = {}
    for a in anomalies:
        groups.setdefault(a.target, []).append(a)

    def specificity(a: Anomaly) -> int:
        return RULE_SPECIFICITY.index(a.rule) if a.rule in RULE_SPECIFICITY else len(RULE_SPECIFICITY)

    merged: list[Anomaly] = []
    for group in groups.values():
        group.sort(key=specificity)
        lead, rest = group[0], group[1:]
        update: dict[str, object] = {"severity": min((a.severity for a in group), key=lambda x: x.rank)}
        if rest:
            update["details"] = f"{lead.details} (also: {'; '.join(a.rule for a in rest)})"
        merged.append(lead.model_copy(update=update))
    return sorted(merged, key=lambda a: (a.severity.rank, a.target, a.rule))


class Detector:
    """Turns a :class:`ClusterSnapshot` into a de-duplicated, severity-ordered anomaly list.

    The only state is the first-seen time of each replica mismatch, so a rolling update does not
    trigger ``replica_mismatch`` until it has been unhealthy for ``replica_mismatch_grace_seconds``.
    """

    def __init__(
        self,
        *,
        pending_timeout_seconds: int = 300,
        restart_flap_threshold: int = 5,
        replica_mismatch_grace_seconds: int = 120,
        crash_loop_min_restarts: int = 3,
    ) -> None:
        self.crash_min_restarts = crash_loop_min_restarts
        self.pending_timeout = pending_timeout_seconds
        self.flap_threshold = restart_flap_threshold
        self.mismatch_grace = replica_mismatch_grace_seconds
        self._mismatch_since: dict[str, float] = {}

    def detect(
        self, snapshot: ClusterSnapshot, now: float, restart_baseline: dict[str, int] | None = None
    ) -> list[Anomaly]:
        """``restart_baseline`` maps ``namespace/pod`` to its restart count about an hour ago;
        ``None`` means no history yet, in which case flapping cannot be assessed."""
        found: list[Anomaly] = []
        for pod in snapshot.pods:
            found.extend(self._pod_anomalies(pod, now, restart_baseline))
        found.extend(self._deployment_anomalies(snapshot.deployments, now))
        for node in snapshot.nodes:
            found.extend(self._node_anomalies(node))
        return self._dedupe(found)

    # ----------------------------------------------------------------------------------------

    @staticmethod
    def _pod_anomaly(pod: PodInfo, rule: str, severity: Severity, details: str, actionable: bool) -> Anomaly:
        target = f"{pod.namespace}/{pod.deploy or pod.name}"
        return Anomaly(
            rule=rule,
            severity=severity,
            target=target,
            namespace=pod.namespace,
            pod_name=pod.name,
            deploy=pod.deploy,
            owner_kind=pod.owner_kind,
            details=details,
            # A rollout restart only makes sense for pods owned by a Deployment.
            actionable=actionable and pod.owner_kind == "Deployment" and bool(pod.deploy),
        )

    def _crashed_repeatedly(self, pod: PodInfo, now: float) -> bool:
        """Between back-off waits a crash-looping container is briefly *Terminated* (or Running again),
        not *Waiting/CrashLoopBackOff*. Catch that window so detection does not flicker, without
        mistaking a pod being deleted, or one whose last crash was long ago, for a crash loop."""
        if pod.phase != "Running" or pod.status in ("running", "terminating") or pod.restarts < self.crash_min_restarts:
            return False
        if pod.terminated_reason not in ("", "Completed"):  # exited just now
            return True
        last = pod.last_terminated_at
        return (
            pod.last_terminated_reason not in ("", "Completed")
            and last is not None
            and now - last.astimezone(UTC).timestamp() <= CRASH_RECENT_SECONDS
        )

    def _pod_anomalies(self, pod: PodInfo, now: float, baseline: dict[str, int] | None) -> list[Anomaly]:
        out: list[Anomaly] = []
        unhealthy = pod.status != "running"
        oom = pod.terminated_reason == "OOMKilled" or (unhealthy and pod.last_terminated_reason == "OOMKilled")

        # Most specific explanation first; a pod gets at most one of these.
        if oom:
            out.append(
                self._pod_anomaly(
                    pod,
                    "oom_killed",
                    Severity.HIGH,
                    f"Pod {pod.name} OOMKilled, {pod.restarts} restarts",
                    # Needs a memory-limit change, which the guardian never makes: human only.
                    actionable=False,
                )
            )
        elif pod.waiting_reason == "CrashLoopBackOff" or self._crashed_repeatedly(pod, now):
            out.append(
                self._pod_anomaly(
                    pod,
                    "crash_loop",
                    Severity.HIGH,
                    f"Pod {pod.name} in CrashLoopBackOff, {pod.restarts} restarts"
                    if pod.waiting_reason == "CrashLoopBackOff"
                    else f"Pod {pod.name} keeps crashing ({pod.terminated_reason or pod.last_terminated_reason}), "
                    f"{pod.restarts} restarts",
                    actionable=True,
                )
            )
        elif pod.waiting_reason in IMAGE_PULL_REASONS:
            out.append(
                self._pod_anomaly(
                    pod, "image_pull_fail", Severity.MEDIUM, f"Pod {pod.name} {pod.waiting_reason}", actionable=False
                )
            )
        elif pod.phase == "Pending" and pod.created is not None:
            age = now - pod.created.astimezone(UTC).timestamp()
            if age > self.pending_timeout:
                out.append(
                    self._pod_anomaly(
                        pod,
                        "stuck_pending",
                        Severity.MEDIUM,
                        f"Pod {pod.name} pending for {int(age)}s",
                        actionable=True,
                    )
                )

        if baseline is not None:
            before = baseline.get(f"{pod.namespace}/{pod.name}", 0)
            delta = pod.restarts - before
            if delta >= self.flap_threshold:
                out.append(
                    self._pod_anomaly(
                        pod,
                        "restart_flapping",
                        Severity.MEDIUM,
                        f"Pod {pod.name} restarted {delta} times in ~1h (total: {pod.restarts})",
                        actionable=True,
                    )
                )
        return out

    def _deployment_anomalies(self, deployments: list[DeploymentInfo], now: float) -> list[Anomaly]:
        out: list[Anomaly] = []
        live: set[str] = set()
        for dep in deployments:
            key = f"{dep.namespace}/{dep.name}"
            live.add(key)
            if dep.available >= dep.desired:
                self._mismatch_since.pop(key, None)
                continue
            first_seen = self._mismatch_since.setdefault(key, now)
            if now - first_seen > self.mismatch_grace:
                out.append(
                    Anomaly(
                        rule="replica_mismatch",
                        severity=Severity.HIGH,
                        target=key,
                        namespace=dep.namespace,
                        deploy=dep.name,
                        owner_kind="Deployment",
                        actionable=True,
                        details=f"Deployment {dep.name}: {dep.available}/{dep.desired} available "
                        f"for >{self.mismatch_grace}s",
                    )
                )
        for key in set(self._mismatch_since) - live:  # deployment was deleted
            del self._mismatch_since[key]
        return out

    @staticmethod
    def _node_anomalies(node: NodeInfo) -> list[Anomaly]:
        pressures = [
            name
            for name, on in (
                ("MemoryPressure", node.memory_pressure),
                ("DiskPressure", node.disk_pressure),
                ("PIDPressure", node.pid_pressure),
            )
            if on
        ]
        if node.ready in ("False", "Unknown"):
            pressures.append("NotReady")
        if not pressures:
            return []
        return [
            Anomaly(
                rule="node_pressure",
                severity=Severity.HIGH,
                target=f"node/{node.name}",
                details=f"Node {node.name}: {', '.join(pressures)}",
                actionable=False,
            )
        ]

    @staticmethod
    def _dedupe(anomalies: list[Anomaly]) -> list[Anomaly]:
        """One anomaly per (target, rule), keeping the most severe; ordered high -> low severity."""
        best: dict[tuple[str, str], Anomaly] = {}
        for a in anomalies:
            key = (a.target, a.rule)
            if key not in best or a.severity.rank < best[key].severity.rank:
                best[key] = a
        return sorted(best.values(), key=lambda a: (a.severity.rank, a.target, a.rule))

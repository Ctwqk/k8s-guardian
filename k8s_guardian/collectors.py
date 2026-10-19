"""Collect cluster state and pod logs, and turn raw logs into something safe to analyse.

Everything here is read-only. Log text is filtered (health-probe noise removed, repeats collapsed),
scanned for error lines, and *redacted* before it can reach the audit log or an external LLM.
"""

from __future__ import annotations

import asyncio
import re
from contextlib import suppress
from dataclasses import dataclass, field

from .cluster.base import ClusterBackend, ClusterError, LogUnavailable
from .models import Anomaly, ClusterSnapshot, PodInfo
from .policy import PolicyConfig

# Health-probe and other repetitive lines that carry no signal.
LOG_NOISE_PATTERNS = re.compile(
    r"GET /health|GET /healthz|GET /readyz|GET /livez|"
    r"health.*200 OK|readiness.*200 OK|liveness.*200 OK|"
    r'"GET /health HTTP/\d\.\d" 200',
    re.IGNORECASE,
)

# Lines that suggest a real problem. A pod with such a line skips the cheap triage tier.
ERROR_PATTERNS = re.compile(
    r"\bERROR\b|\bFATAL\b|\bPANIC\b|\bCRITICAL\b|"
    r"OOMKilled|CrashLoopBackOff|ImagePullBackOff|ErrImagePull|"
    r"Traceback \(most recent|Exception:|Error:",
    re.IGNORECASE,
)

# Best-effort secret scrubbing. Not a guarantee: it is a safety net, not a data-loss-prevention tool.
_REDACTIONS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 [REDACTED]"),
    (
        re.compile(
            r"(?i)\b([\w.-]*(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|auth)[\w.-]*)"
            r"(\s*[=:]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s,;&\"']+)"
        ),
        r"\1\2[REDACTED]",
    ),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED]"),
    (re.compile(r"\b(?:sk|pk|ghp|gho|xox[abp])[-_][A-Za-z0-9_-]{16,}\b"), "[REDACTED]"),
    (re.compile(r"(?i)\b(postgres(?:ql)?|mysql|mongodb|amqp|redis)://[^:@/\s]+:[^@/\s]+@"), r"\1://[REDACTED]@"),
    (re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), "[REDACTED-JWT]"),
)

MAX_CONTAINERS_PER_POD = 4


def redact(text: str) -> str:
    for pattern, replacement in _REDACTIONS:
        text = pattern.sub(replacement, text)
    return text


def filter_log_text(raw: str) -> str:
    """Drop blank/noise lines and collapse runs of identical lines."""
    out: list[str] = []
    prev: str | None = None
    repeats = 0
    for line in raw.splitlines():
        if not line.strip() or LOG_NOISE_PATTERNS.search(line):
            continue
        if line == prev:
            repeats += 1
            continue
        if repeats:
            out.append(f"  [... repeated {repeats} more times]")
        out.append(line)
        prev, repeats = line, 0
    if repeats:
        out.append(f"  [... repeated {repeats} more times]")
    return "\n".join(out)


def find_error_lines(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if ERROR_PATTERNS.search(line)]


@dataclass
class PodLog:
    namespace: str
    pod: str
    workload: str
    text: str
    error_lines: list[str] = field(default_factory=list)
    from_previous: bool = False  # logs of the previous (crashed) container instance

    @property
    def key(self) -> str:
        return f"{self.namespace}/{self.pod}"


@dataclass
class LogBundle:
    pods: list[PodLog] = field(default_factory=list)

    @property
    def total_error_lines(self) -> int:
        return sum(len(p.error_lines) for p in self.pods)

    def render(self, max_chars: int = 30_000) -> str:
        """All pod logs as one block of text, truncated to ``max_chars`` (≈8k tokens by default)."""
        text = "\n\n".join(f"=== {p.key} ===\n{p.text}" for p in self.pods if p.text)
        if len(text) > max_chars:
            text = text[:max_chars] + "\n[... truncated]"
        return text

    def _matches(self, pod: PodLog, anomaly: Anomaly) -> bool:
        if pod.namespace != anomaly.namespace:
            return False
        return bool(
            (anomaly.pod_name and pod.pod == anomaly.pod_name) or (anomaly.deploy and pod.workload == anomaly.deploy)
        )

    def errors_for(self, anomaly: Anomaly, limit: int = 20) -> list[str]:
        lines = [f"[{p.key}] {ln}" for p in self.pods if self._matches(p, anomaly) for ln in p.error_lines]
        return lines[:limit]

    def excerpt_for(self, anomaly: Anomaly, max_chars: int = 4_000) -> str:
        text = "\n\n".join(f"=== {p.key} ===\n{p.text}" for p in self.pods if self._matches(p, anomaly) and p.text)
        return text[-max_chars:] if len(text) > max_chars else text

    def orphan_error_pods(self, anomalies: list[Anomaly]) -> list[PodLog]:
        """Pods whose logs contain error lines but which no rule-based anomaly explains."""
        return [p for p in self.pods if p.error_lines and not any(self._matches(p, a) for a in anomalies)]


# --------------------------------------------------------------------------------------------
# Collection
# --------------------------------------------------------------------------------------------


def collect_snapshot(cluster: ClusterBackend, policy: PolicyConfig) -> ClusterSnapshot:
    """Blocking: list pods/deployments/nodes, keeping only the namespaces the policy watches."""
    return ClusterSnapshot(
        pods=[p for p in cluster.list_pods() if policy.is_watched(p.namespace)],
        deployments=[d for d in cluster.list_deployments() if policy.is_watched(d.namespace)],
        nodes=cluster.list_nodes(),
    )


def _fetch_pod_log(cluster: ClusterBackend, pod: PodInfo, *, since_seconds: int, tail_lines: int) -> PodLog:
    containers = pod.containers[:MAX_CONTAINERS_PER_POD] or [""]
    chunks: list[str] = []
    used_previous = False
    for container in containers:
        text, previous = "", False
        with suppress(LogUnavailable):
            text = cluster.pod_logs(
                pod.namespace, pod.name, container, since_seconds=since_seconds, tail_lines=tail_lines
            )
        if not text.strip() and pod.restarts > 0:
            # A crash-looping container often has no current output; the interesting lines are
            # in the previous instance.
            try:
                text = cluster.pod_logs(
                    pod.namespace,
                    pod.name,
                    container,
                    since_seconds=since_seconds,
                    tail_lines=tail_lines,
                    previous=True,
                )
                previous = bool(text.strip())
            except LogUnavailable:
                pass
        text = filter_log_text(redact(text))
        if not text:
            continue
        used_previous = used_previous or previous
        if len(containers) > 1:
            text = "\n".join(f"[{container}] {line}" for line in text.splitlines())
        chunks.append(text)
    text = "\n".join(chunks)
    return PodLog(
        namespace=pod.namespace,
        pod=pod.name,
        workload=pod.deploy,
        text=text,
        error_lines=find_error_lines(text),
        from_previous=used_previous,
    )


async def collect_logs(
    cluster: ClusterBackend,
    pods: list[PodInfo],
    *,
    since_seconds: int,
    tail_lines: int,
    concurrency: int = 5,
    max_pods: int = 100,
) -> LogBundle:
    """Fetch filtered, redacted logs for ``pods`` with bounded concurrency.

    Unhealthy pods are fetched first so the ``max_pods`` cap never starves the interesting ones.
    A failure for one pod is skipped; it never fails the whole poll.
    """
    ordered = sorted(pods, key=lambda p: (p.status == "running", p.namespace, p.name))[:max_pods]
    semaphore = asyncio.Semaphore(concurrency)

    async def one(pod: PodInfo) -> PodLog | None:
        async with semaphore:
            try:
                return await asyncio.to_thread(
                    _fetch_pod_log, cluster, pod, since_seconds=since_seconds, tail_lines=tail_lines
                )
            except ClusterError:
                return None

    results = await asyncio.gather(*(one(p) for p in ordered))
    return LogBundle(pods=[r for r in results if r is not None and r.text])

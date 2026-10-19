"""Plain data models shared by every stage of the pipeline."""

from __future__ import annotations

import math
from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field, field_validator

# The only actions the guardian can ever perform. This is a hard-coded allowlist:
# neither the policy file nor the LLM can add to it.
ACTION_ROLLOUT_RESTART = "rollout_restart"
ACTION_DO_NOTHING = "do_nothing"
ALLOWED_ACTIONS = frozenset({ACTION_ROLLOUT_RESTART, ACTION_DO_NOTHING})


class Severity(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        return {"high": 0, "medium": 1, "low": 2}[self.value]


class PodInfo(BaseModel):
    name: str
    namespace: str
    status: str  # display status: running / CrashLoopBackOff / pending / ...
    phase: str = "Unknown"
    restarts: int = 0
    ready: str = "0/0"
    waiting_reason: str = ""
    terminated_reason: str = ""
    last_terminated_reason: str = ""
    last_terminated_at: datetime | None = None  # when that previous instance exited
    deploy: str = ""  # owning workload name ("" when the pod has no controller)
    owner_kind: str = ""  # Deployment / StatefulSet / DaemonSet / Job / ...
    created: datetime | None = None
    containers: list[str] = Field(default_factory=list)


class DeploymentInfo(BaseModel):
    name: str
    namespace: str
    desired: int = 1
    available: int = 0
    ready: int = 0


class NodeInfo(BaseModel):
    name: str
    ready: str = "Unknown"
    memory_pressure: bool = False
    disk_pressure: bool = False
    pid_pressure: bool = False


class ClusterSnapshot(BaseModel):
    pods: list[PodInfo] = Field(default_factory=list)
    deployments: list[DeploymentInfo] = Field(default_factory=list)
    nodes: list[NodeInfo] = Field(default_factory=list)

    @property
    def healthy_pods(self) -> int:
        return sum(1 for p in self.pods if p.status == "running")


class Anomaly(BaseModel):
    rule: str
    severity: Severity
    target: str  # "namespace/workload" (or "node/<name>")
    namespace: str = ""
    pod_name: str = ""
    deploy: str = ""  # owning workload name ("" when unknown)
    owner_kind: str = ""  # Deployment / StatefulSet / ... ("Deployment" is the only restartable kind)
    details: str = ""
    actionable: bool = False  # can a Deployment restart plausibly address it?


class TriageIssue(BaseModel):
    pod: str = ""  # "namespace/pod-name"
    severity: Severity = Severity.MEDIUM
    summary: str = ""
    relevant_logs: str = ""

    @field_validator("severity", mode="before")
    @classmethod
    def _lenient_severity(cls, v: object) -> object:
        if isinstance(v, str):
            v = v.strip().lower()
            if v not in {s.value for s in Severity}:
                return Severity.MEDIUM
        return v


class TriageResult(BaseModel):
    has_issues: bool = False
    issues: list[TriageIssue] = Field(default_factory=list)
    overall_assessment: str = ""
    source: str = ""  # which analyzer produced it (rules / model name)


class Decision(BaseModel):
    """A *proposal* from the decision tier. Nothing here is trusted until the policy gate allows it."""

    action: str = ACTION_DO_NOTHING
    target: str = ""
    reasoning: str = ""
    confidence: float = 0.0
    needs_human: bool = False

    @field_validator("action", mode="before")
    @classmethod
    def _norm_action(cls, v: object) -> object:
        return v.strip().lower() if isinstance(v, str) else v

    @field_validator("confidence", mode="before")
    @classmethod
    def _clamp_confidence(cls, v: object) -> float:
        try:
            f = float(v)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return 0.0
        if not math.isfinite(f):  # NaN would slip through min/max as 1.0
            return 0.0
        return max(0.0, min(1.0, f))


class Outcome(StrEnum):
    """What finally happened to a decision. Stored in the audit log's ``result`` column."""

    ALLOWED = "allowed"  # gate verdict only; becomes EXECUTED / FAILED / DRY_RUN
    EXECUTED = "executed"
    FAILED = "failed"
    DRY_RUN = "dry_run"
    SKIPPED = "skipped"  # decision was do_nothing
    LOW_CONFIDENCE = "low_confidence"
    BLOCKED_ACTION = "blocked_action"  # action not in the hard allowlist
    BLOCKED_POLICY = "blocked_policy"  # workload policy forbids the action
    BLOCKED_NAMESPACE = "blocked_namespace"
    BLOCKED_NAME = "blocked_name"
    BLOCKED_TARGET = "blocked_target"  # decision does not refer to the observed issue
    BLOCKED_NOT_ACTIONABLE = "blocked_not_actionable"
    COOLDOWN = "cooldown"
    REPEAT_FAILURE = "repeat_failure"  # restarted recently and still unhealthy: escalate, do not loop
    RATE_LIMITED = "rate_limited"
    LLM_UNAVAILABLE = "llm_unavailable"
    TRIAGE_BENIGN = "triage_benign"
    DEFERRED = "deferred"


class PolicyVerdict(BaseModel):
    allowed: bool
    outcome: Outcome
    reason: str
    action: str  # effective action after the gate (may be downgraded to do_nothing)
    namespace: str = ""
    workload: str = ""
    target: str = ""
    needs_human: bool = False


class DecisionReport(BaseModel):
    target: str
    rule: str = ""
    decision: Decision | None
    verdict: PolicyVerdict | None
    outcome: Outcome
    detail: str = ""
    model: str = ""


class PollReport(BaseModel):
    ts: float
    ok: bool
    error: str = ""
    dry_run: bool = True
    pod_count: int = 0
    healthy_count: int = 0
    anomalies: list[Anomaly] = Field(default_factory=list)
    error_lines: int = 0
    triage: TriageResult | None = None
    decisions: list[DecisionReport] = Field(default_factory=list)

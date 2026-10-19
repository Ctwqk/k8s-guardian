"""Remediation policy: which namespaces are watched/writable, which actions each workload permits,
and the *gate* that every proposed action must pass before anything touches the cluster."""

from __future__ import annotations

import re
from dataclasses import dataclass
from fnmatch import fnmatchcase
from importlib import resources
from pathlib import Path
from typing import Protocol

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator

from .models import (
    ACTION_DO_NOTHING,
    ACTION_ROLLOUT_RESTART,
    ALLOWED_ACTIONS,
    Anomaly,
    Decision,
    Outcome,
    PolicyVerdict,
)

# Kubernetes DNS-1123 style names; also what we require before putting a name in an API call.
SAFE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{0,252}$")


class WorkloadRule(BaseModel):
    namespace: str = "*"  # fnmatch glob
    workload: str = "*"  # fnmatch glob
    allowed_actions: frozenset[str] = frozenset({ACTION_DO_NOTHING})
    reason: str = ""

    @field_validator("allowed_actions")
    @classmethod
    def _known_actions(cls, v: frozenset[str]) -> frozenset[str]:
        unknown = v - ALLOWED_ACTIONS
        if unknown:
            raise ValueError(f"unknown action(s) {sorted(unknown)}; allowed: {sorted(ALLOWED_ACTIONS)}")
        return v | {ACTION_DO_NOTHING}

    def matches(self, namespace: str, workload: str) -> bool:
        return fnmatchcase(namespace, self.namespace) and fnmatchcase(workload, self.workload)

    @property
    def can_restart(self) -> bool:
        return ACTION_ROLLOUT_RESTART in self.allowed_actions


_OBSERVE_ONLY = WorkloadRule(
    allowed_actions=frozenset({ACTION_DO_NOTHING}),
    reason="Unknown or side-effecting workload. Require human review.",
)


class PolicyConfig(BaseModel):
    version: str = "unversioned"
    watched_namespaces: list[str] = Field(default_factory=lambda: ["*"])
    ignored_namespaces: list[str] = Field(default_factory=lambda: ["kube-system", "kube-public", "kube-node-lease"])
    writable_namespaces: list[str] = Field(default_factory=list)  # exact names only, no globs
    rules: list[WorkloadRule] = Field(default_factory=list)  # first match wins
    default_rule: WorkloadRule = _OBSERVE_ONLY

    @model_validator(mode="after")
    def _validate_namespaces(self) -> PolicyConfig:
        for ns in self.writable_namespaces:
            if any(ch in ns for ch in "*?[]"):
                raise ValueError(f"writable_namespaces must be exact names, got glob {ns!r}")
            if not SAFE_NAME_RE.match(ns):
                raise ValueError(f"invalid namespace name {ns!r}")
            if ns in self.ignored_namespaces:
                raise ValueError(f"namespace {ns!r} is both ignored and writable")
        return self

    # -- queries ------------------------------------------------------------------------------
    def is_watched(self, namespace: str) -> bool:
        if any(fnmatchcase(namespace, pat) for pat in self.ignored_namespaces):
            return False
        return any(fnmatchcase(namespace, pat) for pat in self.watched_namespaces)

    def is_writable(self, namespace: str) -> bool:
        return namespace in self.writable_namespaces and namespace not in self.ignored_namespaces

    def rule_for(self, namespace: str, workload: str) -> WorkloadRule:
        for rule in self.rules:
            if rule.matches(namespace, workload):
                return rule
        return self.default_rule

    def guidance_lines(self) -> list[str]:
        """Human/LLM readable summary of the policy, embedded in decision prompts."""
        lines = [f"Writable namespaces: {', '.join(self.writable_namespaces) or '(none)'}"]
        for r in self.rules:
            acts = ", ".join(sorted(a for a in r.allowed_actions if a != ACTION_DO_NOTHING))
            lines.append(
                f"{r.namespace}/{r.workload} -> " + (f"{acts} only" if acts else "do_nothing + needs_human=true")
            )
        lines.append(f"Everything else -> {self.default_rule.reason or 'do_nothing + needs_human=true'}")
        lines.append("Automatic remediation never scales workloads and never deletes pods.")
        return lines

    def rows(self) -> list[dict[str, object]]:
        return [
            {
                "namespace": r.namespace,
                "workload": r.workload,
                "allowed_actions": sorted(r.allowed_actions),
                "reason": r.reason,
            }
            for r in self.rules
        ]


def load_policy(path: Path | None = None) -> PolicyConfig:
    """Load a policy YAML file, or the built-in observe-only default when ``path`` is None."""
    if path is None:
        text = resources.files("k8s_guardian").joinpath("default_policy.yaml").read_text("utf-8")
    else:
        text = Path(path).read_text("utf-8")
    data = yaml.safe_load(text) or {}
    return PolicyConfig.model_validate(data)


# --------------------------------------------------------------------------------------------
# The gate
# --------------------------------------------------------------------------------------------


class ActionHistory(Protocol):
    """Read side of the audit log, used for cooldowns and rate limits (survives restarts).

    Only *live* attempts (a restart that was issued, whether it succeeded or not) count; dry-run
    records do not.
    """

    def last_attempt_ts(self, target: str) -> float | None: ...

    def attempts_since(self, ts: float) -> int: ...


@dataclass(frozen=True)
class GateLimits:
    confidence_threshold: float = 0.6
    cooldown_seconds: int = 600  # after a restart: wait, it may still be rolling out
    repeat_window_seconds: int = 3600  # restarted within this window and still broken: escalate
    max_actions_per_hour: int = 5


class PolicyGate:
    """Deterministic, side-effect-free check applied to every :class:`Decision`.

    The LLM (or rule engine) only *proposes*. The order below is deliberate: structural checks
    (allowlist, target binding), then confidence, workload policy, namespace, name validity,
    actionability, and finally the stateful limits (cooldown, repeat-failure, hourly budget).
    """

    def __init__(self, policy: PolicyConfig, limits: GateLimits, history: ActionHistory) -> None:
        self.policy = policy
        self.limits = limits
        self.history = history

    def resolve_target(self, anomaly: Anomaly) -> tuple[str, str, str]:
        """Namespace/workload always come from the observed anomaly, never from model output."""
        namespace = anomaly.namespace
        workload = anomaly.deploy or ""
        target = f"{namespace}/{workload}" if namespace and workload else anomaly.target
        return namespace, workload, target

    def evaluate(self, decision: Decision, anomaly: Anomaly, now: float) -> PolicyVerdict:
        namespace, workload, target = self.resolve_target(anomaly)
        action = decision.action

        def verdict(
            allowed: bool, outcome: Outcome, reason: str, eff: str | None = None, needs_human: bool | None = None
        ) -> PolicyVerdict:
            return PolicyVerdict(
                allowed=allowed,
                outcome=outcome,
                reason=reason,
                action=eff or action,
                namespace=namespace,
                workload=workload,
                target=target,
                needs_human=decision.needs_human if needs_human is None else needs_human,
            )

        if action not in ALLOWED_ACTIONS:
            return verdict(
                False,
                Outcome.BLOCKED_ACTION,
                f"action {action!r} is not in the allowlist {sorted(ALLOWED_ACTIONS)}",
                eff=ACTION_DO_NOTHING,
                needs_human=True,
            )

        if action == ACTION_DO_NOTHING:
            return verdict(False, Outcome.SKIPPED, decision.reasoning or "no action proposed")

        claimed = decision.target.removeprefix("deployment/").removeprefix("deployment.apps/")
        if claimed and claimed not in (anomaly.target, target, workload):
            return verdict(
                False,
                Outcome.BLOCKED_TARGET,
                f"decision target {decision.target!r} does not match the observed issue {anomaly.target!r}",
                eff=ACTION_DO_NOTHING,
                needs_human=True,
            )

        if decision.confidence < self.limits.confidence_threshold:
            return verdict(
                False,
                Outcome.LOW_CONFIDENCE,
                f"confidence {decision.confidence:.2f} < threshold {self.limits.confidence_threshold:.2f}",
                eff=ACTION_DO_NOTHING,
            )

        rule = self.policy.rule_for(namespace, workload)
        if action not in rule.allowed_actions:
            return verdict(
                False,
                Outcome.BLOCKED_POLICY,
                f"policy forbids {action} on {target}: {rule.reason or 'observe-only'}",
                needs_human=True,
            )

        if not self.policy.is_writable(namespace):
            return verdict(
                False, Outcome.BLOCKED_NAMESPACE, f"namespace {namespace!r} is not writable", needs_human=True
            )

        if not workload or not SAFE_NAME_RE.match(workload):
            return verdict(
                False, Outcome.BLOCKED_NAME, f"invalid or unknown workload name {workload!r}", needs_human=True
            )

        if not anomaly.actionable or anomaly.owner_kind != "Deployment":
            return verdict(
                False,
                Outcome.BLOCKED_NOT_ACTIONABLE,
                f"{anomaly.rule} on {target} cannot be fixed by a Deployment restart",
                needs_human=True,
            )

        last = self.history.last_attempt_ts(target)
        if last is not None:
            age = now - last
            if age < self.limits.cooldown_seconds:
                wait = int(self.limits.cooldown_seconds - age)
                return verdict(False, Outcome.COOLDOWN, f"cooldown active for {target} ({wait}s remaining)")
            if age < self.limits.repeat_window_seconds:
                return verdict(
                    False,
                    Outcome.REPEAT_FAILURE,
                    f"{target} was already restarted {int(age)}s ago and is still unhealthy; "
                    "another restart is unlikely to help",
                    needs_human=True,
                )

        used = self.history.attempts_since(now - 3600)
        if used >= self.limits.max_actions_per_hour:
            return verdict(
                False,
                Outcome.RATE_LIMITED,
                f"hourly action limit reached ({used}/{self.limits.max_actions_per_hour})",
                needs_human=True,
            )

        return verdict(True, Outcome.ALLOWED, "allowed by policy")

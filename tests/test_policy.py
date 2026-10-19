"""Policy loading and, above all, the gate: every way a proposed action can be refused."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from k8s_guardian.models import Anomaly, Decision, Outcome, Severity
from k8s_guardian.policy import GateLimits, PolicyConfig, PolicyGate, WorkloadRule, load_policy

from .conftest import NOW, make_policy

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


class FakeHistory:
    def __init__(self, last: dict[str, float] | None = None, attempts: int = 0) -> None:
        self.last = last or {}
        self.attempts = attempts

    def last_attempt_ts(self, target: str) -> float | None:
        return self.last.get(target)

    def attempts_since(self, ts: float) -> int:
        return self.attempts


def anomaly(**kw) -> Anomaly:
    base = dict(
        rule="crash_loop",
        severity=Severity.HIGH,
        target="demo/api",
        namespace="demo",
        pod_name="api-1",
        deploy="api",
        owner_kind="Deployment",
        details="x",
        actionable=True,
    )
    base.update(kw)
    return Anomaly(**base)


def restart(**kw) -> Decision:
    base = dict(action="rollout_restart", target="demo/api", reasoning="r", confidence=0.9)
    base.update(kw)
    return Decision(**base)


def gate(history=None, policy=None, **limits) -> PolicyGate:
    return PolicyGate(policy or make_policy(), GateLimits(**limits), history or FakeHistory())


# ---- loading ---------------------------------------------------------------------------------


def test_default_policy_is_observe_only():
    policy = load_policy()
    assert policy.writable_namespaces == []
    assert policy.default_rule.allowed_actions == frozenset({"do_nothing"})
    assert not policy.is_writable("demo")


def test_shipped_example_policies_load():
    for name in ("policy.demo.yaml", "policy.constructure.yaml"):
        assert load_policy(EXAMPLES / name)


def test_constructure_policy_preserves_the_original_hard_coded_rules():
    p = load_policy(EXAMPLES / "policy.constructure.yaml")
    assert p.rule_for("constructure-arb", "collector").can_restart
    assert not p.rule_for("constructure-arb", "executor-kalshi").can_restart
    assert not p.rule_for("constructure-infra", "postgres").can_restart
    assert not p.is_writable("constructure-infra") and not p.is_writable("constructure-monitor")
    assert not p.is_watched("kube-system")


def test_unknown_action_in_a_policy_file_is_rejected():
    with pytest.raises(ValidationError, match="unknown action"):
        WorkloadRule(allowed_actions=frozenset({"delete_pod"}))
    with pytest.raises(ValidationError, match="unknown action"):
        WorkloadRule(allowed_actions=frozenset({"scale_up"}))


def test_writable_namespaces_must_be_exact_and_not_ignored():
    with pytest.raises(ValidationError, match="exact names"):
        PolicyConfig(writable_namespaces=["prod-*"])
    with pytest.raises(ValidationError, match="ignored and writable"):
        PolicyConfig(writable_namespaces=["kube-system"])


def test_first_matching_rule_wins_and_do_nothing_is_always_allowed():
    policy = make_policy()
    assert policy.rule_for("demo", "payments-api").allowed_actions == frozenset({"do_nothing"})
    assert policy.rule_for("demo", "web").can_restart
    assert not policy.rule_for("other", "web").can_restart  # falls through to the default rule


def test_watch_scope():
    p = PolicyConfig(watched_namespaces=["app-*"], ignored_namespaces=["app-system"])
    assert p.is_watched("app-1") and not p.is_watched("app-system") and not p.is_watched("other")


# ---- the gate --------------------------------------------------------------------------------


def test_happy_path_is_allowed():
    v = gate().evaluate(restart(), anomaly(), NOW)
    assert v.allowed and v.outcome is Outcome.ALLOWED
    assert (v.namespace, v.workload, v.target) == ("demo", "api", "demo/api")


def test_do_nothing_is_skipped_and_keeps_needs_human():
    v = gate().evaluate(Decision(action="do_nothing", needs_human=True, reasoning="why"), anomaly(), NOW)
    assert not v.allowed and v.outcome is Outcome.SKIPPED and v.needs_human


@pytest.mark.parametrize("action", ["delete_pod", "scale_up", "exec", "kubectl delete ns demo", ""])
def test_actions_outside_the_hard_allowlist_are_blocked(action):
    v = gate().evaluate(Decision(action=action, confidence=1.0), anomaly(), NOW)
    assert v.outcome is Outcome.BLOCKED_ACTION and not v.allowed and v.needs_human
    assert v.action == "do_nothing"


def test_action_matching_is_case_and_whitespace_insensitive_but_still_allowlisted():
    assert gate().evaluate(restart(action="  Rollout_Restart "), anomaly(), NOW).allowed


def test_decision_targeting_a_different_workload_is_blocked():
    v = gate().evaluate(restart(target="demo/payments-executor"), anomaly(), NOW)
    assert v.outcome is Outcome.BLOCKED_TARGET and not v.allowed


@pytest.mark.parametrize("target", ["demo/api", "api", "deployment/api", ""])
def test_equivalent_spellings_of_the_observed_target_are_accepted(target):
    assert gate().evaluate(restart(target=target), anomaly(), NOW).allowed


def test_the_target_comes_from_the_observation_not_from_model_output():
    v = gate().evaluate(restart(target="demo/api"), anomaly(), NOW)
    assert v.workload == "api"  # nothing the model said can change what gets restarted


def test_low_confidence_is_downgraded():
    v = gate(confidence_threshold=0.6).evaluate(restart(confidence=0.59), anomaly(), NOW)
    assert v.outcome is Outcome.LOW_CONFIDENCE and v.action == "do_nothing" and not v.allowed


def test_confidence_exactly_at_threshold_passes():
    assert gate(confidence_threshold=0.6).evaluate(restart(confidence=0.6), anomaly(), NOW).allowed


def test_policy_forbidden_workload_is_blocked_and_flagged_for_a_human():
    a = anomaly(target="demo/payments-executor", deploy="payments-executor")
    v = gate().evaluate(restart(target="demo/payments-executor"), a, NOW)
    assert v.outcome is Outcome.BLOCKED_POLICY and v.needs_human and "needs human" in v.reason


def test_unlisted_workload_falls_back_to_the_observe_only_default():
    p = make_policy(rules=[])
    v = gate(policy=p).evaluate(restart(), anomaly(), NOW)
    assert v.outcome is Outcome.BLOCKED_POLICY


def test_non_writable_namespace_is_blocked_even_if_a_rule_allows_restart():
    p = make_policy(writable=(), rules=[WorkloadRule(allowed_actions=frozenset({"rollout_restart"}))])
    v = gate(policy=p).evaluate(restart(), anomaly(), NOW)
    assert v.outcome is Outcome.BLOCKED_NAMESPACE


def test_ignored_namespaces_are_never_writable():
    p = PolicyConfig(
        writable_namespaces=["demo"],
        ignored_namespaces=["kube-system"],
        rules=[WorkloadRule(allowed_actions=frozenset({"rollout_restart"}))],
    )
    a = anomaly(namespace="kube-system", target="kube-system/coredns", deploy="coredns")
    assert gate(policy=p).evaluate(restart(target=""), a, NOW).outcome is Outcome.BLOCKED_NAMESPACE


@pytest.mark.parametrize("name", ["", "Bad_Name", "-lead", "a b", "x;rm -rf /", "../etc", "a" * 300])
def test_unsafe_or_missing_workload_names_are_blocked(name):
    p = make_policy(rules=[WorkloadRule(allowed_actions=frozenset({"rollout_restart"}))])
    v = gate(policy=p).evaluate(restart(target=""), anomaly(deploy=name, target="demo/x"), NOW)
    assert v.outcome is Outcome.BLOCKED_NAME


def test_non_actionable_anomalies_are_blocked():
    v = gate().evaluate(restart(), anomaly(actionable=False), NOW)
    assert v.outcome is Outcome.BLOCKED_NOT_ACTIONABLE


@pytest.mark.parametrize("kind", ["StatefulSet", "DaemonSet", "Job", ""])
def test_only_deployment_owned_workloads_can_be_restarted(kind):
    v = gate().evaluate(restart(), anomaly(owner_kind=kind), NOW)
    assert v.outcome is Outcome.BLOCKED_NOT_ACTIONABLE


def test_cooldown_after_a_recent_restart():
    v = gate(FakeHistory({"demo/api": NOW - 100}), cooldown_seconds=600).evaluate(restart(), anomaly(), NOW)
    assert v.outcome is Outcome.COOLDOWN and "500s remaining" in v.reason and not v.needs_human


def test_repeat_failure_escalates_instead_of_restarting_again():
    h = FakeHistory({"demo/api": NOW - 1200})
    v = gate(h, cooldown_seconds=600, repeat_window_seconds=3600).evaluate(restart(), anomaly(), NOW)
    assert v.outcome is Outcome.REPEAT_FAILURE and v.needs_human


def test_restart_allowed_again_after_the_repeat_window():
    h = FakeHistory({"demo/api": NOW - 4000})
    assert gate(h, cooldown_seconds=600, repeat_window_seconds=3600).evaluate(restart(), anomaly(), NOW).allowed


def test_cooldown_is_per_target():
    h = FakeHistory({"demo/other": NOW - 10})
    assert gate(h).evaluate(restart(), anomaly(), NOW).allowed


def test_hourly_rate_limit():
    v = gate(FakeHistory(attempts=5), max_actions_per_hour=5).evaluate(restart(), anomaly(), NOW)
    assert v.outcome is Outcome.RATE_LIMITED and v.needs_human
    assert gate(FakeHistory(attempts=4), max_actions_per_hour=5).evaluate(restart(), anomaly(), NOW).allowed


def test_zero_budget_disables_all_live_actions():
    assert gate(max_actions_per_hour=0).evaluate(restart(), anomaly(), NOW).outcome is Outcome.RATE_LIMITED


def test_policy_is_checked_before_stateful_limits():
    """A forbidden workload reports the policy reason, not 'cooldown'."""
    a = anomaly(target="demo/payments-x", deploy="payments-x")
    h = FakeHistory({"demo/payments-x": NOW - 5}, attempts=99)
    assert gate(h).evaluate(restart(target=""), a, NOW).outcome is Outcome.BLOCKED_POLICY


def test_guidance_lines_summarise_the_policy_for_the_prompt():
    lines = make_policy().guidance_lines()
    assert any("payments-*" in line and "do_nothing" in line for line in lines)
    assert any("never scales" in line for line in lines)

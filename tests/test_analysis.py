from __future__ import annotations

import httpx
import pytest

from k8s_guardian.analysis import (
    DecisionContext,
    LLMAnalyzer,
    RuleAnalyzer,
    TriageContext,
    build_decision_prompt,
    build_triage_prompt,
)
from k8s_guardian.llm import LLMClient
from k8s_guardian.models import Anomaly, NodeInfo, Severity
from k8s_guardian.policy import WorkloadRule

from .conftest import NOW

RESTART = WorkloadRule(allowed_actions=frozenset({"rollout_restart"}), reason="stateless")
OBSERVE = WorkloadRule(reason="pays money")


def anomaly(rule="crash_loop", **kw) -> Anomaly:
    base = dict(
        rule=rule,
        severity=Severity.HIGH,
        target="demo/api",
        namespace="demo",
        deploy="api",
        owner_kind="Deployment",
        details="Pod api-1 in CrashLoopBackOff",
        actionable=True,
    )
    base.update(kw)
    return Anomaly(**base)


def decision_ctx(a=None, rule=RESTART, **kw) -> DecisionContext:
    base = dict(
        anomaly=a or anomaly(),
        rule=rule,
        evidence=["[demo/api-1] ERROR: boom"],
        log_excerpt="line",
        pod_count=4,
        healthy_count=3,
        nodes=[NodeInfo(name="n1", ready="True")],
        recent_actions=[],
        policy_lines=["demo/* -> rollout_restart only"],
        cooldown_seconds=600,
        now=NOW,
    )
    base.update(kw)
    return DecisionContext(**base)


# ---- deterministic analyzer ------------------------------------------------------------------


@pytest.mark.parametrize("rule", ["crash_loop", "restart_flapping", "replica_mismatch"])
async def test_rule_analyzer_proposes_a_restart_for_restartable_rules(rule):
    d = await RuleAnalyzer().decide(decision_ctx(anomaly(rule)))
    assert d.action == "rollout_restart" and d.confidence >= 0.6 and not d.needs_human


@pytest.mark.parametrize("rule", ["oom_killed", "image_pull_fail", "stuck_pending", "node_pressure", "log_issue"])
async def test_rule_analyzer_escalates_what_a_restart_cannot_fix(rule):
    d = await RuleAnalyzer().decide(decision_ctx(anomaly(rule)))
    assert d.action == "do_nothing" and d.needs_human


async def test_rule_analyzer_respects_observe_only_policy():
    d = await RuleAnalyzer().decide(decision_ctx(rule=OBSERVE))
    assert d.action == "do_nothing" and d.needs_human and "observe-only" in d.reasoning


async def test_rule_triage_flags_anomalies_and_unexplained_errors():
    ctx = TriageContext(
        pod_count=2,
        healthy_count=1,
        anomalies=[anomaly()],
        logs="",
        unexplained_errors={"demo/web-1": ["ERROR: x", "ERROR: y"]},
    )
    r = await RuleAnalyzer().triage(ctx)
    assert r.has_issues and len(r.issues) == 2
    assert [i.severity for i in r.issues] == [Severity.HIGH, Severity.LOW]


async def test_rule_triage_all_clear():
    r = await RuleAnalyzer().triage(TriageContext(pod_count=1, healthy_count=1, anomalies=[], logs="x"))
    assert not r.has_issues and "no anomalies" in r.overall_assessment


# ---- prompts ---------------------------------------------------------------------------------


def test_decision_prompt_contains_what_the_model_needs_to_stay_in_bounds():
    ctx = decision_ctx(
        recent_actions=[{"ts": NOW, "action": "rollout_restart", "result": "executed", "reasoning": "r"}]
    )
    prompt = build_decision_prompt(ctx)
    for needle in (
        "demo/api",
        "crash_loop",
        "ERROR: boom",
        "demo/* -> rollout_restart only",
        "stateless",
        "RECENT ACTIONS ON THIS TARGET",
        "executed",
        "600s",
    ):
        assert needle in prompt


def test_triage_prompt_lists_anomalies_and_logs():
    prompt = build_triage_prompt(
        TriageContext(pod_count=4, healthy_count=3, anomalies=[anomaly()], logs="=== demo/api-1 ===\nboom")
    )
    assert "4 pods, 3 running, 1 unhealthy" in prompt and "crash_loop" in prompt and "boom" in prompt


# ---- LLM analyzer ----------------------------------------------------------------------------


def llm_analyzer(content: str | None, status: int = 200, calls: list | None = None) -> LLMAnalyzer:
    def handler(request: httpx.Request) -> httpx.Response:
        if calls is not None:
            calls.append(request)
        if status != 200:
            return httpx.Response(status)
        return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})

    client = LLMClient("https://x/v1", "k", transport=httpx.MockTransport(handler))
    return LLMAnalyzer(client, triage_model="cheap", decision_model="strong")


async def test_llm_decision_is_parsed_and_normalised():
    a = llm_analyzer(
        '```json\n{"action": " Rollout_Restart ", "target": "demo/api", "reasoning": "r", '
        '"confidence": "0.9", "needs_human": "false"}\n```'
    )
    d = await a.decide(decision_ctx())
    assert (d.action, d.confidence, d.needs_human) == ("rollout_restart", 0.9, False)


async def test_llm_confidence_is_clamped_and_garbage_confidence_is_zero():
    d1 = await llm_analyzer('{"action": "rollout_restart", "confidence": 7}').decide(decision_ctx())
    d2 = await llm_analyzer('{"action": "rollout_restart", "confidence": "very"}').decide(decision_ctx())
    assert d1.confidence == 1.0 and d2.confidence == 0.0


async def test_llm_decision_uses_the_decision_model_and_triage_uses_the_cheap_one():
    calls: list = []
    a = llm_analyzer('{"action": "do_nothing"}', calls=calls)
    await a.decide(decision_ctx())
    await a.triage(TriageContext(pod_count=1, healthy_count=1, anomalies=[], logs="x"))
    import json

    assert [json.loads(c.content)["model"] for c in calls] == ["strong", "cheap"]


async def test_llm_triage_result_is_validated_and_tagged():
    a = llm_analyzer(
        '{"has_issues": true, "overall_assessment": "bad", '
        '"issues": [{"pod": "demo/api-1", "severity": "CRITICAL", "summary": "s"}]}'
    )
    r = await a.triage(TriageContext(pod_count=1, healthy_count=0, anomalies=[], logs="x"))
    assert r.has_issues and r.source == "cheap"
    assert r.issues[0].severity is Severity.MEDIUM  # unknown severities degrade gracefully


@pytest.mark.parametrize("content", ['{"action": ["list"]}', '{"target": {"a": 1}}', "nope"])
async def test_llm_schema_violations_become_unavailable(content):
    assert await llm_analyzer(content).decide(decision_ctx()) is None


async def test_llm_http_failure_becomes_unavailable():
    a = llm_analyzer(None, status=503)
    assert await a.decide(decision_ctx()) is None
    assert await a.triage(TriageContext(pod_count=0, healthy_count=0, anomalies=[], logs="")) is None

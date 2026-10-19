from __future__ import annotations

import asyncio

from k8s_guardian.analysis import LLMAnalyzer, RuleAnalyzer
from k8s_guardian.bootstrap import build_analyzer, build_cluster, build_guardian, build_notifier
from k8s_guardian.cluster.fake import FakeCluster
from k8s_guardian.notify import DiscordNotifier, NullNotifier

from .conftest import crash_cluster, make_settings


def test_default_wiring_is_keyless_dry_run_and_observe_only(tmp_path):
    s = make_settings(tmp_path)
    assert isinstance(build_analyzer(s), RuleAnalyzer)
    assert isinstance(build_notifier(s), NullNotifier)
    assert isinstance(build_cluster(s), FakeCluster)
    g = build_guardian(s)
    assert g.executor.dry_run and g.policy.writable_namespaces == []
    g.audit.close()


def test_llm_and_discord_wiring(tmp_path):
    s = make_settings(
        tmp_path,
        analyzer="llm",
        llm_base_url="http://llm.local/v1",
        llm_triage_model="small",
        llm_decision_model="big",
        discord_webhook_url="https://discord.example/hook",
    )
    analyzer = build_analyzer(s)
    assert isinstance(analyzer, LLMAnalyzer)
    assert (analyzer.triage_model, analyzer.decision_model) == ("small", "big")
    assert isinstance(build_notifier(s), DiscordNotifier)


async def test_background_loop_polls_repeatedly_and_survives_a_crashing_cycle(make_guardian):
    g = make_guardian(crash_cluster(), poll_interval_seconds=1)
    calls = []
    original = g.poll_once

    async def flaky():
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("boom")
        return await original()

    g.poll_once = flaky  # type: ignore[method-assign]
    g.settings = g.settings.model_copy(update={"poll_interval_seconds": 0})
    task = asyncio.create_task(g.run_forever())
    await asyncio.sleep(0.3)
    task.cancel()
    assert len(calls) >= 2 and g.last_report is not None


async def test_log_collection_failure_does_not_abort_the_poll(make_guardian):
    cluster = crash_cluster()

    def explode(*a, **k):
        raise RuntimeError("logs exploded")

    cluster.pod_logs = explode  # type: ignore[method-assign]
    report = await make_guardian(cluster).poll_once()
    assert report.ok and report.anomalies  # still detected from pod state alone

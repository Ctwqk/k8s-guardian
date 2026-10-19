"""Wire settings into a ready-to-run :class:`Guardian`."""

from __future__ import annotations

from .analysis import Analyzer, LLMAnalyzer, RuleAnalyzer
from .audit import AuditLog
from .cluster.base import ClusterBackend
from .cluster.fake import demo_cluster
from .config import Settings
from .engine import Guardian
from .llm import LLMClient
from .notify import DiscordNotifier, Notifier, NullNotifier
from .policy import PolicyConfig, load_policy


def build_cluster(settings: Settings) -> ClusterBackend:
    if settings.backend == "fake":
        return demo_cluster()
    from .cluster.kube import KubernetesBackend  # imported lazily: needs a kubeconfig / service account

    return KubernetesBackend(settings.kubeconfig, settings.kube_context)


def build_analyzer(settings: Settings) -> Analyzer:
    if settings.analyzer == "rules":
        return RuleAnalyzer()
    client = LLMClient(
        settings.llm_base_url, settings.llm_api_key.get_secret_value(), timeout=settings.llm_timeout_seconds
    )
    return LLMAnalyzer(
        client,
        triage_model=settings.llm_triage_model,
        decision_model=settings.llm_decision_model,
        max_tokens=settings.llm_max_tokens,
    )


def build_notifier(settings: Settings) -> Notifier:
    url = settings.discord_webhook_url.get_secret_value()
    if not url:
        return NullNotifier()
    return DiscordNotifier(url, cooldown_seconds=settings.notify_cooldown_seconds)


def build_guardian(
    settings: Settings,
    *,
    cluster: ClusterBackend | None = None,
    policy: PolicyConfig | None = None,
    analyzer: Analyzer | None = None,
    notifier: Notifier | None = None,
    audit: AuditLog | None = None,
) -> Guardian:
    return Guardian(
        settings,
        cluster or build_cluster(settings),
        policy or load_policy(settings.policy_file),
        audit or AuditLog(settings.db_path),
        analyzer or build_analyzer(settings),
        notifier or build_notifier(settings),
    )

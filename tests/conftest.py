"""Shared helpers: tiny builders for pods/deployments/policies and a fully wired Guardian."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest

from k8s_guardian.analysis import Analyzer, RuleAnalyzer
from k8s_guardian.audit import AuditLog
from k8s_guardian.cluster.fake import FakeCluster
from k8s_guardian.config import Settings
from k8s_guardian.engine import Guardian
from k8s_guardian.models import DeploymentInfo, NodeInfo, PodInfo
from k8s_guardian.notify import Notifier
from k8s_guardian.policy import PolicyConfig, WorkloadRule

NOW = 1_800_000_000.0  # fixed "current time" for deterministic tests


def make_pod(
    name: str = "web-6d5f7c9b8-abcde",
    namespace: str = "demo",
    deploy: str = "web",
    *,
    status: str = "running",
    restarts: int = 0,
    owner_kind: str = "Deployment",
    age_seconds: float = 7200,
    **kwargs: object,
) -> PodInfo:
    healthy = status == "running"
    fields: dict[str, object] = {
        "phase": "Running" if healthy or "Crash" in status else "Pending",
        "ready": "1/1" if healthy else "0/1",
        "created": datetime.fromtimestamp(NOW - age_seconds, UTC),
        "containers": ["app"],
    }
    if status == "CrashLoopBackOff":
        fields["waiting_reason"] = "CrashLoopBackOff"
    fields.update(kwargs)
    return PodInfo(
        name=name,
        namespace=namespace,
        status=status,
        restarts=restarts,
        deploy=deploy,
        owner_kind=owner_kind,
        **fields,  # type: ignore[arg-type]
    )


def make_policy(*, writable: tuple[str, ...] = ("demo",), rules: list[WorkloadRule] | None = None) -> PolicyConfig:
    return PolicyConfig(
        version="test",
        writable_namespaces=list(writable),
        ignored_namespaces=["kube-system"],
        rules=rules
        if rules is not None
        else [
            WorkloadRule(
                namespace="demo", workload="payments-*", allowed_actions=frozenset({"do_nothing"}), reason="needs human"
            ),
            WorkloadRule(
                namespace="demo", workload="*", allowed_actions=frozenset({"rollout_restart"}), reason="stateless"
            ),
        ],
    )


def make_settings(tmp_path: Path, **overrides: object) -> Settings:
    base: dict[str, object] = {
        "backend": "fake",
        "db_path": tmp_path / "g.db",
        "cooldown_seconds": 600,
        "repeat_window_seconds": 3600,
        "max_actions_per_hour": 5,
        "dry_run": True,
    }
    base.update(overrides)
    return Settings(_env_file=None, **base)  # type: ignore[arg-type]


class Clock:
    def __init__(self, start: float = NOW) -> None:
        self.t = start

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


class RecordingNotifier:
    def __init__(self) -> None:
        self.sent: list[dict[str, str]] = []

    async def send(
        self, title: str, description: str, *, severity: str = "medium", target: str = "", rule: str = ""
    ) -> bool:
        self.sent.append(
            {"title": title, "description": description, "severity": severity, "target": target, "rule": rule}
        )
        return True


def crash_cluster() -> FakeCluster:
    """demo/crashy-api crash-loops (restartable by policy); demo/web is healthy."""
    return FakeCluster(
        pods=[
            make_pod(),
            make_pod("crashy-api-7c9d8f6b5-xk2lp", deploy="crashy-api", status="CrashLoopBackOff", restarts=7),
        ],
        deployments=[
            DeploymentInfo(name="web", namespace="demo", desired=1, available=1, ready=1),
            DeploymentInfo(name="crashy-api", namespace="demo", desired=1, available=0, ready=0),
        ],
        nodes=[NodeInfo(name="node-1", ready="True")],
        logs={
            ("demo", "web-6d5f7c9b8-abcde"): '10.0.0.1 "GET /healthz HTTP/1.1" 200\nserving request',
            ("demo", "crashy-api-7c9d8f6b5-xk2lp"): "starting\nERROR: cannot connect to redis:6379",
        },
    )


GuardianFactory = Callable[..., Guardian]


@pytest.fixture
def audit(tmp_path: Path) -> AuditLog:
    log = AuditLog(tmp_path / "audit.db")
    yield log  # type: ignore[misc]
    log.close()


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def make_guardian(tmp_path: Path, audit: AuditLog, clock: Clock) -> GuardianFactory:
    def build(
        cluster: FakeCluster | None = None,
        *,
        analyzer: Analyzer | None = None,
        policy: PolicyConfig | None = None,
        notifier: Notifier | None = None,
        **settings: object,
    ) -> Guardian:
        return Guardian(
            make_settings(tmp_path, **settings),
            cluster or crash_cluster(),
            policy or make_policy(),
            audit,
            analyzer or RuleAnalyzer(),
            notifier,
            clock=clock,
        )

    return build

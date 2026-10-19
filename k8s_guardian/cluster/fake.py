"""In-memory cluster used by the test-suite and by ``GUARDIAN_BACKEND=fake`` (try-it-without-a-cluster mode)."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from ..models import DeploymentInfo, NodeInfo, PodInfo
from .base import ClusterError, LogUnavailable


class FakeCluster:
    """Holds pods/deployments/nodes/logs as plain models and records every restart request."""

    def __init__(
        self,
        pods: list[PodInfo] | None = None,
        deployments: list[DeploymentInfo] | None = None,
        nodes: list[NodeInfo] | None = None,
        logs: dict[tuple[str, str], str] | None = None,
        previous_logs: dict[tuple[str, str], str] | None = None,
    ) -> None:
        self.pods = pods or []
        self.deployments = deployments or []
        self.nodes = nodes or []
        self.logs = logs or {}  # (namespace, pod) -> text
        self.previous_logs = previous_logs or {}
        self.restarts: list[tuple[str, str]] = []
        self.fail_listing = False
        self.fail_restart = False
        self.on_restart: Callable[[str, str], None] | None = None

    def list_pods(self) -> list[PodInfo]:
        if self.fail_listing:
            raise ClusterError("fake API server unavailable")
        return [p.model_copy() for p in self.pods]

    def list_deployments(self) -> list[DeploymentInfo]:
        return [d.model_copy() for d in self.deployments]

    def list_nodes(self) -> list[NodeInfo]:
        return [n.model_copy() for n in self.nodes]

    def pod_logs(
        self,
        namespace: str,
        pod: str,
        container: str,
        *,
        since_seconds: int,
        tail_lines: int,
        previous: bool = False,
    ) -> str:
        source = self.previous_logs if previous else self.logs
        if (namespace, pod) not in source:
            raise LogUnavailable(f"{namespace}/{pod}: no logs")
        return "\n".join(source[(namespace, pod)].splitlines()[-tail_lines:])

    def restart_deployment(self, namespace: str, name: str) -> str:
        if self.fail_restart:
            raise ClusterError("fake restart failure")
        self.restarts.append((namespace, name))
        if self.on_restart:
            self.on_restart(namespace, name)
        return f"deployment.apps/{name} restarted"


def demo_cluster() -> FakeCluster:
    """A small cluster with three problems: a crash-looping stateless API, a crash-looping
    workload that policy marks observe-only, and an OOMKilled worker. Used by the README demo."""
    created = datetime.now(UTC) - timedelta(hours=2)

    def pod(name: str, deploy: str, status: str = "running", restarts: int = 0, **kw: object) -> PodInfo:
        healthy = status == "running"
        return PodInfo(
            name=name,
            namespace="demo",
            status=status,
            phase="Running" if healthy or "Crash" in status else "Pending",
            restarts=restarts,
            ready="1/1" if healthy else "0/1",
            deploy=deploy,
            owner_kind="Deployment",
            created=created,
            containers=["app"],
            **kw,
        )

    pods = [
        pod("web-6d5f7c9b8-abcde", "web"),
        pod("crashy-api-7c9d8f6b5-xk2lp", "crashy-api", "CrashLoopBackOff", 7, waiting_reason="CrashLoopBackOff"),
        pod(
            "payments-executor-5b7c9d4f6-q8wzt",
            "payments-executor",
            "CrashLoopBackOff",
            4,
            waiting_reason="CrashLoopBackOff",
        ),
        pod(
            "batch-worker-84c6d5f7b-m4n2v",
            "batch-worker",
            "CrashLoopBackOff",
            3,
            waiting_reason="CrashLoopBackOff",
            last_terminated_reason="OOMKilled",
        ),
    ]
    deployments = [
        DeploymentInfo(name="web", namespace="demo", desired=1, available=1, ready=1),
        DeploymentInfo(name="crashy-api", namespace="demo", desired=1, available=0, ready=0),
        DeploymentInfo(name="payments-executor", namespace="demo", desired=1, available=0, ready=0),
        DeploymentInfo(name="batch-worker", namespace="demo", desired=1, available=0, ready=0),
    ]
    logs = {
        ("demo", "web-6d5f7c9b8-abcde"): '10.0.0.1 "GET /healthz HTTP/1.1" 200\nserving request id=17',
        (
            "demo",
            "crashy-api-7c9d8f6b5-xk2lp",
        ): "starting api\nERROR: cannot connect to redis:6379 (connection refused)",
        ("demo", "payments-executor-5b7c9d4f6-q8wzt"): "FATAL: order signature mismatch, aborting",
        ("demo", "batch-worker-84c6d5f7b-m4n2v"): "loading 2GB dataset\nKilled",
    }
    return FakeCluster(pods=pods, deployments=deployments, nodes=[NodeInfo(name="node-1", ready="True")], logs=logs)

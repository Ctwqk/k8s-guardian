"""The narrow interface the guardian needs from a cluster."""

from __future__ import annotations

from typing import Protocol

from ..models import DeploymentInfo, NodeInfo, PodInfo


class ClusterError(RuntimeError):
    """Raised when the cluster API cannot be reached or rejects a request."""


class LogUnavailable(ClusterError):
    """Logs could not be fetched for one container (not started yet, pod gone, ...)."""


class ClusterBackend(Protocol):
    """All methods are synchronous and blocking; the engine runs them in worker threads."""

    def list_pods(self) -> list[PodInfo]: ...

    def list_deployments(self) -> list[DeploymentInfo]: ...

    def list_nodes(self) -> list[NodeInfo]: ...

    def pod_logs(
        self,
        namespace: str,
        pod: str,
        container: str,
        *,
        since_seconds: int,
        tail_lines: int,
        previous: bool = False,
    ) -> str: ...

    def restart_deployment(self, namespace: str, name: str) -> str:
        """Trigger a rolling restart (equivalent to ``kubectl rollout restart``). Returns a message."""
        ...

"""Backend built on the official ``kubernetes`` Python client (no kubectl, no shell)."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import urllib3
from kubernetes import client, config
from kubernetes.client.exceptions import ApiException
from kubernetes.config.config_exception import ConfigException

from ..models import DeploymentInfo, NodeInfo, PodInfo
from .base import ClusterError, LogUnavailable
from .parse import parse_deployment, parse_node, parse_pod

RESTARTED_AT_ANNOTATION = "kubectl.kubernetes.io/restartedAt"
_TIMEOUT = (5, 20)  # (connect, read) seconds for every API call


@contextmanager
def _api_errors(what: str, *, api_error: type[ClusterError] = ClusterError) -> Iterator[None]:
    """Map every client failure (HTTP status, connection refused, timeout, TLS) to our own errors."""
    try:
        yield
    except ApiException as exc:
        raise api_error(f"{what}: {exc.status} {exc.reason}") from exc
    except (urllib3.exceptions.HTTPError, OSError) as exc:
        raise ClusterError(f"{what}: cluster unreachable ({type(exc).__name__})") from exc


class KubernetesBackend:
    def __init__(self, kubeconfig: Path | None = None, context: str | None = None) -> None:
        cfg = client.Configuration()
        try:
            if kubeconfig is not None:
                config.load_kube_config(config_file=str(kubeconfig), context=context, client_configuration=cfg)
            else:
                try:
                    config.load_incluster_config(client_configuration=cfg)
                except ConfigException:
                    config.load_kube_config(context=context, client_configuration=cfg)
        except Exception as exc:  # config errors are many and varied
            raise ClusterError(f"cannot load Kubernetes configuration: {exc}") from exc
        self._api = client.ApiClient(cfg)
        self._core = client.CoreV1Api(self._api)
        self._apps = client.AppsV1Api(self._api)

    def _items(self, result: Any) -> list[dict[str, Any]]:
        data = self._api.sanitize_for_serialization(result)
        return list(data.get("items", []))

    def list_pods(self) -> list[PodInfo]:
        with _api_errors("list pods"):
            result = self._core.list_pod_for_all_namespaces(_request_timeout=_TIMEOUT)
        return [parse_pod(i) for i in self._items(result)]

    def list_deployments(self) -> list[DeploymentInfo]:
        with _api_errors("list deployments"):
            result = self._apps.list_deployment_for_all_namespaces(_request_timeout=_TIMEOUT)
        return [parse_deployment(i) for i in self._items(result)]

    def list_nodes(self) -> list[NodeInfo]:
        with _api_errors("list nodes"):
            result = self._core.list_node(_request_timeout=_TIMEOUT)
        return [parse_node(i) for i in self._items(result)]

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
        with _api_errors(f"logs {namespace}/{pod}[{container}]", api_error=LogUnavailable):
            text = self._core.read_namespaced_pod_log(
                pod,
                namespace,
                container=container or None,
                since_seconds=since_seconds,
                tail_lines=tail_lines,
                previous=previous,
                _request_timeout=_TIMEOUT,
            )
        return text if isinstance(text, str) else str(text)

    def restart_deployment(self, namespace: str, name: str) -> str:
        """Same effect as ``kubectl rollout restart``: bump an annotation on the pod template."""
        stamp = datetime.now(UTC).isoformat(timespec="seconds")
        body = {"spec": {"template": {"metadata": {"annotations": {RESTARTED_AT_ANNOTATION: stamp}}}}}
        with _api_errors(f"restart deployment/{name} -n {namespace}"):
            self._apps.patch_namespaced_deployment(name, namespace, body, _request_timeout=_TIMEOUT)
        return f"deployment.apps/{name} restarted (restartedAt={stamp})"

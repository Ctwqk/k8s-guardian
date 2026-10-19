"""The real ``KubernetesBackend`` (official client) against a tiny in-process fake API server.

This exercises the generated client's (de)serialisation, camelCase field names, request timeouts,
error mapping and the exact PATCH that implements ``kubectl rollout restart``.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from k8s_guardian.cluster.base import ClusterError, LogUnavailable
from k8s_guardian.cluster.kube import RESTARTED_AT_ANNOTATION, KubernetesBackend

POD = {
    "metadata": {
        "name": "crashy-api-7c9d8f6b5-xk2lp",
        "namespace": "demo",
        "creationTimestamp": "2026-10-19T10:00:00Z",
        "labels": {"pod-template-hash": "7c9d8f6b5"},
        "ownerReferences": [
            {
                "apiVersion": "apps/v1",
                "kind": "ReplicaSet",
                "name": "crashy-api-7c9d8f6b5",
                "uid": "u",
                "controller": True,
            }
        ],
    },
    "spec": {"containers": [{"name": "app", "image": "x"}]},
    "status": {
        "phase": "Running",
        "containerStatuses": [
            {
                "name": "app",
                "ready": False,
                "restartCount": 7,
                "image": "x",
                "imageID": "",
                "state": {"waiting": {"reason": "CrashLoopBackOff"}},
                "lastState": {"terminated": {"reason": "OOMKilled", "exitCode": 137}},
            }
        ],
    },
}
DEPLOYMENT = {
    "metadata": {"name": "crashy-api", "namespace": "demo"},
    "spec": {"replicas": 2, "selector": {}, "template": {"spec": {"containers": []}}},
    "status": {"availableReplicas": 1, "readyReplicas": 1},
}
NODE = {
    "metadata": {"name": "node-1"},
    "status": {"conditions": [{"type": "Ready", "status": "True"}, {"type": "DiskPressure", "status": "True"}]},
}


class FakeApiServer:
    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: object) -> None:
                pass

            def _reply(self, code: int, body: Any, ctype: str = "application/json") -> None:
                data = body.encode() if isinstance(body, str) else json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _handle(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                outer.requests.append(
                    {
                        "method": self.command,
                        "path": self.path,
                        "auth": self.headers.get("Authorization"),
                        "ctype": self.headers.get("Content-Type"),
                        "body": json.loads(raw) if raw else None,
                    }
                )
                path = self.path.split("?")[0]
                if path == "/api/v1/pods":
                    self._reply(200, {"kind": "PodList", "apiVersion": "v1", "items": [POD]})
                elif path == "/apis/apps/v1/deployments":
                    self._reply(200, {"kind": "DeploymentList", "apiVersion": "apps/v1", "items": [DEPLOYMENT]})
                elif path == "/api/v1/nodes":
                    self._reply(200, {"kind": "NodeList", "apiVersion": "v1", "items": [NODE]})
                elif path.endswith("/log") and "/pods/ok-pod/" in path:
                    self._reply(200, "line one\nERROR: two\n", "text/plain")
                elif path.endswith("/log"):
                    self._reply(
                        400,
                        {
                            "kind": "Status",
                            "apiVersion": "v1",
                            "status": "Failure",
                            "message": "container is waiting to start",
                            "reason": "BadRequest",
                            "code": 400,
                        },
                    )
                elif self.command == "PATCH" and path.endswith("/deployments/crashy-api"):
                    self._reply(200, DEPLOYMENT)
                elif self.command == "PATCH" and path.endswith("/deployments/locked"):
                    self._reply(
                        403,
                        {
                            "kind": "Status",
                            "apiVersion": "v1",
                            "status": "Failure",
                            "message": "forbidden",
                            "reason": "Forbidden",
                            "code": 403,
                        },
                    )
                else:
                    self._reply(
                        404,
                        {"kind": "Status", "apiVersion": "v1", "status": "Failure", "reason": "NotFound", "code": 404},
                    )

            do_GET = do_PATCH = _handle

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def api() -> Iterator[FakeApiServer]:
    server = FakeApiServer()
    yield server
    server.close()


@pytest.fixture
def backend(api: FakeApiServer, tmp_path: Path) -> KubernetesBackend:
    kubeconfig = tmp_path / "kubeconfig"
    kubeconfig.write_text(
        f"""apiVersion: v1
kind: Config
current-context: t
clusters: [{{name: t, cluster: {{server: "{api.url}"}}}}]
users: [{{name: u, user: {{token: test-token}}}}]
contexts: [{{name: t, context: {{cluster: t, user: u}}}}]
"""
    )
    return KubernetesBackend(kubeconfig)


def test_list_pods_deserialises_the_real_wire_format(backend, api):
    [pod] = backend.list_pods()
    assert (pod.name, pod.namespace, pod.status) == ("crashy-api-7c9d8f6b5-xk2lp", "demo", "CrashLoopBackOff")
    assert (pod.owner_kind, pod.deploy, pod.restarts) == ("Deployment", "crashy-api", 7)
    assert pod.last_terminated_reason == "OOMKilled" and pod.containers == ["app"]
    assert api.requests[0]["auth"] == "Bearer test-token"


def test_list_deployments_and_nodes(backend):
    [dep] = backend.list_deployments()
    assert (dep.name, dep.desired, dep.available) == ("crashy-api", 2, 1)
    [node] = backend.list_nodes()
    assert node.ready == "True" and node.disk_pressure and not node.memory_pressure


def test_pod_logs_and_error_mapping(backend, api):
    text = backend.pod_logs("demo", "ok-pod", "app", since_seconds=900, tail_lines=50)
    assert "ERROR: two" in text
    query = api.requests[-1]["path"]
    assert "tailLines=50" in query and "sinceSeconds=900" in query and "container=app" in query
    with pytest.raises(LogUnavailable, match="400"):
        backend.pod_logs("demo", "waiting-pod", "app", since_seconds=900, tail_lines=50)


def test_restart_is_a_strategic_merge_patch_of_the_pod_template_annotation(backend, api):
    message = backend.restart_deployment("demo", "crashy-api")
    assert "crashy-api" in message
    req = api.requests[-1]
    assert req["method"] == "PATCH" and req["path"].startswith("/apis/apps/v1/namespaces/demo/deployments/crashy-api")
    assert req["ctype"] == "application/strategic-merge-patch+json"
    assert set(req["body"]) == {"spec"}  # nothing but the restart annotation is touched
    assert RESTARTED_AT_ANNOTATION in req["body"]["spec"]["template"]["metadata"]["annotations"]
    assert set(req["body"]["spec"]) == {"template"} and set(req["body"]["spec"]["template"]) == {"metadata"}


def test_api_errors_become_cluster_errors(backend):
    with pytest.raises(ClusterError, match="403"):
        backend.restart_deployment("demo", "locked")
    with pytest.raises(ClusterError, match="404"):
        backend.restart_deployment("demo", "missing")


def test_unreachable_api_server_raises_a_clean_error(tmp_path):
    kubeconfig = tmp_path / "kc"
    kubeconfig.write_text(
        """apiVersion: v1
kind: Config
current-context: t
clusters: [{name: t, cluster: {server: "http://127.0.0.1:9"}}]
users: [{name: u, user: {token: x}}]
contexts: [{name: t, context: {cluster: t, user: u}}]
"""
    )
    # connection errors from urllib3 are not ApiException: they must still be mapped, not leaked
    with pytest.raises(ClusterError):
        KubernetesBackend(kubeconfig).list_pods()


def test_missing_kubeconfig_is_a_cluster_error(tmp_path):
    with pytest.raises(ClusterError, match="cannot load Kubernetes configuration"):
        KubernetesBackend(tmp_path / "nope")

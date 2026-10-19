from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from k8s_guardian.api import create_app

from .conftest import crash_cluster, make_settings


@pytest.fixture
def client_factory(make_guardian, tmp_path):
    def build(**settings):
        guardian = make_guardian(crash_cluster(), **settings)
        app = create_app(make_settings(tmp_path, **settings), guardian, start_loop=False)
        return TestClient(app), guardian

    return build


def test_liveness_does_not_depend_on_the_cluster(client_factory):
    with client_factory()[0] as client:
        assert client.get("/healthz").json() == {"ok": True}
        assert client.get("/health").json()["ok"] is False  # nothing polled yet


def test_poll_status_policy_and_audit_flow(client_factory):
    client, _ = client_factory()
    with client:
        report = client.post("/api/poll").json()
        assert report["ok"] and report["dry_run"] is True
        assert [d["outcome"] for d in report["decisions"]] == ["dry_run"]

        status = client.get("/api/status").json()
        assert status["pod_count"] == 2 and status["anomaly_count"] == 1
        assert status["anomalies"][0]["rule"] == "crash_loop"
        assert status["dry_run"] is True and status["analyzer"] == "rules"
        assert client.get("/health").json()["ok"] is True

        policy = client.get("/api/policy").json()
        assert policy["writable_namespaces"] == ["demo"]
        assert policy["limits"]["max_actions_per_hour"] == 5
        assert any(t["workload"] == "payments-*" for t in policy["targets"])

        actions = client.get("/api/actions", params={"limit": 10}).json()
        assert actions["total"] == 1 and actions["actions"][0]["result"] == "dry_run"
        assert client.get("/api/actions", params={"limit": 0}).status_code == 422
        assert client.get("/api/actions", params={"limit": 500}).status_code == 422


def test_poll_requires_the_bearer_token_when_one_is_configured(client_factory):
    client, _ = client_factory(api_token="s3cret-token")
    with client:
        assert client.post("/api/poll").status_code == 401
        assert client.post("/api/poll", headers={"Authorization": "Bearer wrong"}).status_code == 401
        assert client.post("/api/poll", headers={"Authorization": "Bearer s3cret-token"}).status_code == 200
        # read-only endpoints stay open
        assert client.get("/api/status").status_code == 200


def test_unauthenticated_poll_cannot_trigger_a_live_action(client_factory):
    client, guardian = client_factory(api_token="tok", dry_run=False)
    with client:
        assert client.post("/api/poll").status_code == 401
        assert guardian.cluster.restarts == []
        assert client.post("/api/poll", headers={"Authorization": "Bearer tok"}).status_code == 200
        assert guardian.cluster.restarts == [("demo", "crashy-api")]


def test_config_endpoint_never_exposes_secrets(client_factory):
    client, _ = client_factory(api_token="tok-secret", llm_api_key="sk-secret", discord_webhook_url="https://x/secret")
    with client:
        body = client.get("/api/config").text
        assert "secret" not in body
        assert client.get("/api/config").json()["api_token"] is True

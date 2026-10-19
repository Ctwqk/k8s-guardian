from __future__ import annotations

import pytest
from pydantic import ValidationError

from k8s_guardian.config import Settings


def test_defaults_are_safe(monkeypatch):
    for key in list(__import__("os").environ):
        if key.startswith("GUARDIAN_"):
            monkeypatch.delenv(key)
    s = Settings(_env_file=None)
    assert s.dry_run is True
    assert s.analyzer == "rules"
    assert s.policy_file is None  # built-in policy is observe-only
    assert s.max_actions_per_hour == 5 and s.cooldown_seconds == 600


def test_environment_overrides(monkeypatch):
    monkeypatch.setenv("GUARDIAN_DRY_RUN", "false")
    monkeypatch.setenv("GUARDIAN_MAX_ACTIONS_PER_HOUR", "2")
    monkeypatch.setenv("GUARDIAN_POLL_INTERVAL_SECONDS", "30")
    s = Settings(_env_file=None)
    assert (s.dry_run, s.max_actions_per_hour, s.poll_interval_seconds) == (False, 2, 30)


def test_llm_analyzer_requires_endpoint_and_models():
    with pytest.raises(ValidationError) as exc:
        Settings(_env_file=None, analyzer="llm")
    for name in ("GUARDIAN_LLM_BASE_URL", "GUARDIAN_LLM_TRIAGE_MODEL", "GUARDIAN_LLM_DECISION_MODEL"):
        assert name in str(exc.value)
    ok = Settings(
        _env_file=None, analyzer="llm", llm_base_url="http://x/v1", llm_triage_model="a", llm_decision_model="b"
    )
    assert ok.analyzer == "llm"


@pytest.mark.parametrize(
    "field,value",
    [("confidence_threshold", 1.5), ("poll_interval_seconds", 0), ("cooldown_seconds", -1), ("backend", "nope")],
)
def test_invalid_values_are_rejected(field, value):
    with pytest.raises(ValidationError):
        Settings(_env_file=None, **{field: value})


def test_secrets_never_appear_in_the_public_view_or_repr():
    s = Settings(
        _env_file=None, llm_api_key="sk-secret", discord_webhook_url="https://hook/secret", api_token="tok-secret"
    )
    view = s.public_view()
    assert view["llm_api_key"] is True and view["discord_webhook_url"] is True and view["api_token"] is True
    assert "secret" not in str(view) and "secret" not in repr(s)

"""Typed runtime configuration, loaded from ``GUARDIAN_*`` environment variables (or a ``.env`` file)."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="GUARDIAN_", env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    # --- cluster access -------------------------------------------------------------------
    backend: Literal["kubernetes", "fake"] = "kubernetes"
    kubeconfig: Path | None = None  # None -> in-cluster config, then ~/.kube/config
    kube_context: str | None = None

    # --- safety ---------------------------------------------------------------------------
    dry_run: bool = True  # decisions are made and audited, but nothing is changed
    policy_file: Path | None = None  # None -> built-in observe-only policy
    confidence_threshold: float = Field(0.6, ge=0.0, le=1.0)
    cooldown_seconds: int = Field(600, ge=0)  # min gap between live actions on one target
    max_actions_per_hour: int = Field(5, ge=0)
    max_decisions_per_poll: int = Field(3, ge=1)  # bounds LLM calls and blast radius per cycle
    repeat_window_seconds: int = Field(3600, ge=0)  # "we already restarted this recently" horizon

    # --- polling --------------------------------------------------------------------------
    poll_interval_seconds: int = Field(900, ge=1)
    snapshot_interval_seconds: int = Field(900, ge=1)
    retention_days: int = Field(7, ge=1)
    db_path: Path = Path("data/guardian.db")

    # --- detection thresholds -------------------------------------------------------------
    pending_timeout_seconds: int = 300
    restart_flap_threshold: int = 5
    crash_loop_min_restarts: int = Field(3, ge=1)  # "Error" exits seen this often count as a crash loop
    replica_mismatch_grace_seconds: int = 120

    # --- log collection -------------------------------------------------------------------
    log_tail_lines: int = Field(50, ge=1)
    log_since_seconds: int = Field(900, ge=1)
    log_concurrency: int = Field(5, ge=1)
    log_max_pods: int = Field(100, ge=1)  # unhealthy pods are fetched first

    # --- analysis (triage + decision) -----------------------------------------------------
    analyzer: Literal["rules", "llm"] = "rules"
    llm_base_url: str = ""  # any OpenAI-compatible endpoint, e.g. https://api.openai.com/v1
    llm_api_key: SecretStr = SecretStr("")
    llm_triage_model: str = ""  # cheap, fast model
    llm_decision_model: str = ""  # stronger model
    llm_timeout_seconds: float = 30.0
    llm_max_tokens: int = Field(1024, ge=64)

    # --- notifications / API --------------------------------------------------------------
    discord_webhook_url: SecretStr = SecretStr("")
    notify_cooldown_seconds: int = 1800
    api_token: SecretStr = SecretStr("")  # when set, POST /api/poll requires "Authorization: Bearer <token>"
    host: str = "0.0.0.0"  # noqa: S104 - container default; restrict via GUARDIAN_HOST
    port: int = 8000
    log_level: str = "INFO"

    @model_validator(mode="after")
    def _check_llm(self) -> Settings:
        if self.analyzer == "llm":
            missing = [
                name
                for name, value in (
                    ("GUARDIAN_LLM_BASE_URL", self.llm_base_url),
                    ("GUARDIAN_LLM_TRIAGE_MODEL", self.llm_triage_model),
                    ("GUARDIAN_LLM_DECISION_MODEL", self.llm_decision_model),
                )
                if not value
            ]
            if missing:
                raise ValueError(f"GUARDIAN_ANALYZER=llm requires: {', '.join(missing)}")
        return self

    def public_view(self) -> dict[str, object]:
        """Settings safe to expose over the API (secrets reduced to booleans)."""
        data = self.model_dump(mode="json")
        for key in ("llm_api_key", "discord_webhook_url", "api_token"):
            data[key] = bool(getattr(self, key).get_secret_value())
        return data

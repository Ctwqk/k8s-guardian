"""HTTP API: status, policy, audit log and a manual poll trigger."""

from __future__ import annotations

import asyncio
import logging
import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request

from . import __version__
from .bootstrap import build_guardian
from .config import Settings
from .engine import Guardian

log = logging.getLogger("guardian.api")


def get_guardian(request: Request) -> Guardian:
    guardian: Guardian = request.app.state.guardian
    return guardian


GuardianDep = Annotated[Guardian, Depends(get_guardian)]


def create_app(
    settings: Settings | None = None, guardian: Guardian | None = None, *, start_loop: bool = True
) -> FastAPI:
    """Build the app. Tests pass a pre-wired ``guardian`` and ``start_loop=False``."""
    settings = settings or (guardian.settings if guardian else Settings())

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        g = guardian or build_guardian(settings)
        app.state.guardian = g
        task = asyncio.create_task(g.run_forever()) if start_loop else None
        log.info("k8s-guardian %s started (dry_run=%s)", __version__, g.executor.dry_run)
        try:
            yield
        finally:
            if task is not None:
                task.cancel()
                with suppress(asyncio.CancelledError):
                    await task
            g.audit.close()

    app = FastAPI(title="k8s-guardian", version=__version__, lifespan=lifespan)

    def require_token(authorization: Annotated[str | None, Header()] = None) -> None:
        expected = settings.api_token.get_secret_value()
        if not expected:
            return
        supplied = (authorization or "").removeprefix("Bearer ").strip()
        if not secrets.compare_digest(supplied.encode(), expected.encode()):
            raise HTTPException(status_code=401, detail="missing or invalid bearer token")

    @app.get("/healthz")
    async def healthz() -> dict[str, bool]:
        """Liveness/readiness: the process is up. Cluster problems must not restart the guardian."""
        return {"ok": True}

    @app.get("/health")
    async def health(g: GuardianDep) -> dict[str, Any]:
        report = g.last_report
        return {"ok": bool(report and report.ok), "last_poll_ts": report.ts if report else 0.0}

    @app.get("/api/status")
    async def status(g: GuardianDep) -> dict[str, Any]:
        return g.status()

    @app.get("/api/policy")
    async def policy(g: GuardianDep) -> dict[str, Any]:
        p, s = g.policy, g.settings
        return {
            "policy_version": p.version,
            "dry_run": g.executor.dry_run,
            "watched_namespaces": p.watched_namespaces,
            "ignored_namespaces": p.ignored_namespaces,
            "writable_namespaces": p.writable_namespaces,
            "default_rule": {
                "allowed_actions": sorted(p.default_rule.allowed_actions),
                "reason": p.default_rule.reason,
            },
            "targets": p.rows(),
            "limits": {
                "confidence_threshold": s.confidence_threshold,
                "cooldown_seconds": s.cooldown_seconds,
                "repeat_window_seconds": s.repeat_window_seconds,
                "max_actions_per_hour": s.max_actions_per_hour,
                "max_decisions_per_poll": s.max_decisions_per_poll,
            },
        }

    @app.get("/api/config")
    async def config() -> dict[str, object]:
        return settings.public_view()

    @app.get("/api/actions")
    async def actions(
        g: GuardianDep, limit: Annotated[int, Query(ge=1, le=200)] = 50, offset: Annotated[int, Query(ge=0)] = 0
    ) -> dict[str, Any]:
        return {"actions": g.audit.recent(limit, offset), "total": g.audit.count(), "limit": limit, "offset": offset}

    @app.post("/api/poll", dependencies=[Depends(require_token)])
    async def poll(g: GuardianDep) -> dict[str, Any]:
        report = await g.poll_once()
        return report.model_dump(mode="json")

    return app

"""Outbound notifications. Optional; a failure here must never affect remediation or the audit log."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from typing import Protocol

import httpx

log = logging.getLogger("guardian.notify")

_COLORS = {"high": 0xFF0000, "medium": 0xFF8C00, "low": 0xFFD700, "info": 0x3498DB}
_MARKERS = {"high": "[HIGH]", "medium": "[MEDIUM]", "low": "[LOW]", "info": "[INFO]"}


class Notifier(Protocol):
    async def send(
        self, title: str, description: str, *, severity: str = "medium", target: str = "", rule: str = ""
    ) -> bool:
        """Returns True when a message was actually delivered."""
        ...


class NullNotifier:
    async def send(
        self, title: str, description: str, *, severity: str = "medium", target: str = "", rule: str = ""
    ) -> bool:
        return False


class DiscordNotifier:
    """Discord webhook with a per-(target, rule) cooldown so a persistent problem is not re-announced
    on every poll."""

    def __init__(
        self,
        webhook_url: str,
        *,
        cooldown_seconds: int = 1800,
        timeout: float = 10.0,
        transport: httpx.AsyncBaseTransport | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._url = webhook_url
        self._cooldown = cooldown_seconds
        self._timeout = timeout
        self._transport = transport
        self._clock = clock
        self._last_sent: dict[str, float] = {}

    async def send(
        self, title: str, description: str, *, severity: str = "medium", target: str = "", rule: str = ""
    ) -> bool:
        key = f"{target}:{rule}" if target else title
        now = self._clock()
        last = self._last_sent.get(key)
        if last is not None and now - last < self._cooldown:
            log.debug("notification suppressed by cooldown: %s", key)
            return False

        embed: dict[str, object] = {
            "title": f"{_MARKERS.get(severity, '[INFO]')} Guardian: {title}",
            "description": description[:2000],
            "color": _COLORS.get(severity, _COLORS["medium"]),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
            "footer": {"text": "k8s-guardian"},
        }
        if target:
            embed["fields"] = [{"name": "Target", "value": target, "inline": True}]
        try:
            async with httpx.AsyncClient(timeout=self._timeout, transport=self._transport) as client:
                resp = await client.post(self._url, json={"embeds": [embed]})
        except httpx.HTTPError as exc:
            log.error("discord notification failed: %s", type(exc).__name__)  # URL contains a secret
            return False
        if resp.status_code not in (200, 204):
            log.warning("discord webhook returned HTTP %d", resp.status_code)
            return False
        self._last_sent[key] = now  # only start the cooldown after a successful delivery
        return True

from __future__ import annotations

import json

import httpx

from k8s_guardian.notify import DiscordNotifier, NullNotifier

from .conftest import Clock


def notifier(handler, clock=None, cooldown=1800) -> DiscordNotifier:
    return DiscordNotifier(
        "https://discord.example/api/webhooks/1/SECRET",
        cooldown_seconds=cooldown,
        transport=httpx.MockTransport(handler),
        clock=clock or Clock(),
    )


async def test_sends_an_embed_and_suppresses_repeats_within_the_cooldown():
    sent = []
    clock = Clock()

    def handler(request):
        sent.append(json.loads(request.content))
        return httpx.Response(204)

    n = notifier(handler, clock)
    assert await n.send("Human attention needed", "x" * 5000, severity="high", target="demo/api", rule="crash_loop")
    assert not await n.send("Human attention needed", "again", severity="high", target="demo/api", rule="crash_loop")
    assert await n.send("Other", "different rule", target="demo/api", rule="oom_killed")  # separate key
    clock.advance(1801)
    assert await n.send("Human attention needed", "later", target="demo/api", rule="crash_loop")

    assert len(sent) == 3
    embed = sent[0]["embeds"][0]
    assert len(embed["description"]) == 2000 and embed["fields"][0]["value"] == "demo/api"
    assert "[HIGH]" in embed["title"]


async def test_failed_delivery_does_not_start_the_cooldown_and_does_not_leak_the_url(caplog):
    attempts = []

    def handler(request):
        attempts.append(1)
        if len(attempts) == 1:
            raise httpx.ConnectError("boom", request=request)
        return httpx.Response(204)

    n = notifier(handler)
    assert not await n.send("t", "d", target="a/b", rule="r")
    assert await n.send("t", "d", target="a/b", rule="r")  # retried immediately
    assert "SECRET" not in caplog.text


async def test_non_2xx_is_reported_as_not_delivered():
    n = notifier(lambda r: httpx.Response(429))
    assert not await n.send("t", "d", target="a/b", rule="r")


async def test_null_notifier():
    assert not await NullNotifier().send("t", "d")

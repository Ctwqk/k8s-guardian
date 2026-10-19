from __future__ import annotations

import json

import httpx
import pytest

from k8s_guardian.llm import LLMClient, extract_json_object


@pytest.mark.parametrize(
    "content",
    [
        '{"a": 1}',
        '```json\n{"a": 1}\n```',
        '```\n{"a": 1}\n```',
        '<think>hmm, {"a": 2} maybe?</think>\n{"a": 1}',
        'Sure! Here is the JSON:\n{"a": 1}\nHope that helps.',
        '  \n {"a": 1} \n',
    ],
)
def test_extract_json_object_tolerates_common_model_chatter(content):
    assert extract_json_object(content) == {"a": 1}


@pytest.mark.parametrize("content", ["", "no json here", "[1, 2, 3]", '{"a": ', "{not json}"])
def test_extract_json_object_rejects_garbage(content):
    with pytest.raises(ValueError):
        extract_json_object(content)


def client_for(handler, key="sk-test") -> LLMClient:
    return LLMClient("https://llm.example/v1/", key, transport=httpx.MockTransport(handler))


def completion(content: str) -> httpx.Response:
    return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})


async def test_request_shape_and_auth_header():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["auth"] = request.headers.get("authorization")
        seen["body"] = json.loads(request.content)
        return completion('{"ok": true}')

    result = await client_for(handler).chat_json("m-small", "sys", "usr", max_tokens=77, temperature=0.3)
    assert result == {"ok": True}
    assert seen["url"] == "https://llm.example/v1/chat/completions"
    assert seen["auth"] == "Bearer sk-test"
    assert seen["body"]["model"] == "m-small"
    assert seen["body"]["max_tokens"] == 77
    assert seen["body"]["messages"] == [{"role": "system", "content": "sys"}, {"role": "user", "content": "usr"}]
    assert set(seen["body"]) == {"model", "messages", "max_tokens", "temperature"}  # strict servers reject extras


async def test_no_auth_header_without_a_key():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("authorization")
        return completion("{}")

    await client_for(handler, key="").chat_json("m", "s", "u")
    assert seen["auth"] is None


@pytest.mark.parametrize(
    "handler",
    [
        lambda r: httpx.Response(500, text="oops"),
        lambda r: httpx.Response(401, json={"error": "bad key"}),
        lambda r: httpx.Response(200, json={"unexpected": "shape"}),
        lambda r: httpx.Response(200, json={"choices": []}),
        lambda r: httpx.Response(200, text="<html>not json</html>"),
        lambda r: completion("I cannot help with that."),
        lambda r: (_ for _ in ()).throw(httpx.ConnectError("refused")),
        lambda r: (_ for _ in ()).throw(httpx.ReadTimeout("slow")),
    ],
)
async def test_every_failure_mode_yields_none(handler):
    assert await client_for(handler).chat_json("m", "s", "u") is None

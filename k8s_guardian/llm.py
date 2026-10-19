"""Minimal client for any OpenAI-compatible ``/chat/completions`` endpoint (OpenAI, vLLM, Ollama,
LiteLLM, MiniMax, ...). Model output is treated as untrusted text and parsed defensively."""

from __future__ import annotations

import json
import logging
import re
import uuid
from typing import Any

import httpx

log = logging.getLogger("guardian.llm")

_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)
_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.IGNORECASE)


def extract_json_object(content: str) -> dict[str, Any]:
    """Parse a JSON object out of model output.

    Tolerates reasoning ``<think>`` blocks, markdown fences and chatter around the object.
    Raises ``ValueError`` when no JSON object can be recovered.
    """
    text = _FENCE_RE.sub("", _THINK_RE.sub("", content).strip()).strip()
    candidates = [text]
    start, end = text.find("{"), text.rfind("}")
    if 0 <= start < end:
        candidates.append(text[start : end + 1])
    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed
    raise ValueError("no JSON object in model output")


class LLMClient:
    def __init__(
        self,
        base_url: str,
        api_key: str = "",
        *,
        timeout: float = 30.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._url = base_url.rstrip("/") + "/chat/completions"
        self._api_key = api_key
        self._timeout = timeout
        self._transport = transport

    async def chat_json(
        self, model: str, system: str, user: str, *, max_tokens: int = 500, temperature: float = 0.1
    ) -> dict[str, Any] | None:
        """One chat completion, parsed as a JSON object. Returns ``None`` on any failure."""
        request_id = str(uuid.uuid4())
        headers = {"Content-Type": "application/json", "X-Client-Request-Id": request_id}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        body = {
            "model": model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        try:
            async with httpx.AsyncClient(timeout=self._timeout, transport=self._transport) as client:
                resp = await client.post(self._url, headers=headers, json=body)
            resp.raise_for_status()
            content = resp.json()["choices"][0]["message"]["content"]
            result = extract_json_object(str(content))
        except httpx.HTTPStatusError as exc:
            log.error("LLM [%s] HTTP %d (request %s)", model, exc.response.status_code, request_id)
            return None
        except httpx.HTTPError as exc:
            log.error("LLM [%s] transport error %s (request %s)", model, type(exc).__name__, request_id)
            return None
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            log.error("LLM [%s] unusable response (%s) (request %s)", model, exc, request_id)
            return None
        log.info("LLM [%s] ok (request %s)", model, request_id)
        return result

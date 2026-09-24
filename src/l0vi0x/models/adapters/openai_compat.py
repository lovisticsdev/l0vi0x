"""Adapter for any OpenAI-compatible `/chat/completions` endpoint.

Uses only the standard library (`urllib`) rather than adding an HTTP
dependency, consistent with this project's minimal dependency footprint
(pydantic/pyyaml/eth-hash only, per pyproject.toml). This is what
`free_dev` (M2.11) exercises against real public/free endpoints; nothing
in this milestone calls it over a live network -- that's M2.11's job.
"""

from __future__ import annotations

import asyncio
import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from l0vi0x.core.models import PricingTier
from l0vi0x.models.adapters.base import (
    Capabilities,
    CompletionRequest,
    CompletionResponse,
    MalformedStructuredOutput,
    ModelUnavailable,
    NotFound,
    RateLimited,
    Timeout,
    Usage,
)


@dataclass
class OpenAICompatAdapter:
    """Satisfies the `Adapter` Protocol against a real, OpenAI-compatible
    HTTP endpoint. Every field the router/doctor need statically (family,
    context window, declared capabilities, pricing tier) is supplied at
    construction time from stack config; `probe()` confirms the model is
    actually reachable right now rather than trusting that config blindly."""

    provider: str
    model_id: str
    family: str
    base_url: str
    api_key: str | None = None
    roles: tuple[str, ...] = ()
    context_window: int = 0
    capabilities: dict[str, bool] = field(default_factory=dict)
    pricing_tier: PricingTier = "paid"
    timeout_s: float = 30.0

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        url = self.base_url.rstrip("/") + path
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=body, headers=self._headers(), method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            if exc.code == 429:
                raise RateLimited(f"{self.provider}/{self.model_id}: HTTP 429: {detail}") from exc
            if exc.code in (404, 410):
                raise NotFound(f"{self.provider}/{self.model_id}: HTTP {exc.code} (deprecated or removed): {detail}") from exc
            if exc.code in (401, 403):
                raise ModelUnavailable(f"{self.provider}/{self.model_id}: HTTP {exc.code} (auth/quota): {detail}") from exc
            raise ModelUnavailable(f"{self.provider}/{self.model_id}: HTTP {exc.code}: {detail}") from exc
        except TimeoutError as exc:
            raise Timeout(f"{self.provider}/{self.model_id}: timed out after {self.timeout_s}s") from exc
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, TimeoutError):
                raise Timeout(f"{self.provider}/{self.model_id}: timed out after {self.timeout_s}s") from exc
            raise ModelUnavailable(f"{self.provider}/{self.model_id}: unreachable: {exc.reason}") from exc

    async def complete(self, request: CompletionRequest) -> CompletionResponse:
        payload: dict[str, Any] = {
            "model": self.model_id,
            "messages": [{"role": m.role, "content": m.content} for m in request.messages],
        }
        if request.max_tokens is not None:
            payload["max_tokens"] = request.max_tokens
        if request.temperature is not None:
            payload["temperature"] = request.temperature
        if request.response_schema is not None:
            payload["response_format"] = {"type": "json_schema", "json_schema": request.response_schema}

        data = await asyncio.to_thread(self._post, "/chat/completions", payload)

        try:
            choice = data["choices"][0]
            text = choice["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise ModelUnavailable(f"{self.provider}/{self.model_id}: unexpected response shape: {data!r}") from exc

        structured: dict[str, Any] | None = None
        if request.response_schema is not None:
            try:
                structured = json.loads(text)
            except json.JSONDecodeError as exc:
                raise MalformedStructuredOutput(f"{self.provider}/{self.model_id}: response is not valid JSON: {text!r}") from exc

        usage_raw = data.get("usage", {}) or {}
        usage = Usage(
            prompt_tokens=int(usage_raw.get("prompt_tokens", 0)),
            completion_tokens=int(usage_raw.get("completion_tokens", 0)),
            total_tokens=int(usage_raw.get("total_tokens", 0)),
        )
        return CompletionResponse(
            provider=self.provider,
            model_id=self.model_id,
            text=text,
            structured=structured,
            usage=usage,
            raw=data,
        )

    async def probe(self) -> Capabilities:
        """Confirm the model is reachable right now with the cheapest
        possible real call, rather than trusting static config. A 404/410
        here (raised as `NotFound` by `_post`) is exactly the "deprecated
        model ID" case the router (M2.4) must fail over on -- `doctor`
        (M2.2) is what actually calls this in anger."""
        payload = {
            "model": self.model_id,
            "messages": [{"role": "user", "content": "ping"}],
            "max_tokens": 1,
        }
        try:
            await asyncio.to_thread(self._post, "/chat/completions", payload)
            deprecated = False
        except NotFound:
            deprecated = True
        return Capabilities(
            provider=self.provider,
            model_id=self.model_id,
            family=self.family,
            roles=self.roles,
            context_window=self.context_window,
            capabilities=dict(self.capabilities),
            pricing_tier=self.pricing_tier,
            deprecated=deprecated,
        )
"""Deterministic adapter with zero external dependency.

Built first, ahead of `openai_compat`, so every later M2 step (router,
gates, doctor) can be built and unit-tested immediately against
something that never touches the network, instead of blocking on
provider access. Failure modes are configured at construction time so
a test can reproduce exactly the acceptance-criteria failures (a
deprecated model ID, a rate limit, malformed structured output)
on demand, deterministically.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from typing import Literal

from l0vi0x.core.models import PricingTier
from l0vi0x.models.adapters.base import (
    Capabilities,
    CompletionRequest,
    CompletionResponse,
    ModelUnavailable,
    RateLimited,
    Timeout,
    Usage,
)

FailureMode = Literal["timeout", "rate_limit", "malformed_structured_output", "unavailable"]


@dataclass
class FakeAdapter:
    """Canned-response adapter satisfying the `Adapter` Protocol structurally
    (see `base.py`) -- no explicit inheritance needed, Protocols are
    structural.

    `responses` is consumed in order (cycling once exhausted) so a test can
    assert on successive calls deterministically; the default is a single
    fixed reply. `fail_mode`, when set, makes every `complete()` call raise
    (or return malformed output) instead of returning `responses` --
    configure a *fresh* `FakeAdapter` per failure-mode test rather than
    toggling this mid-test, to keep failure injection unambiguous.
    """

    provider: str = "fake"
    model_id: str = "fake-large-1"
    family: str = "fake-large"
    roles: tuple[str, ...] = ("worker", "skeptic")
    context_window: int = 128_000
    capabilities: dict[str, bool] = field(default_factory=lambda: {"structured_output": True, "tool_use": False})
    pricing_tier: PricingTier = "free"
    deprecated: bool = False
    responses: tuple[str, ...] = ("fake response",)
    fail_mode: FailureMode | None = None
    calls: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        self._response_cycle = itertools.cycle(self.responses)

    async def complete(self, request: CompletionRequest) -> CompletionResponse:
        self.calls += 1
        if self.fail_mode == "timeout":
            raise Timeout(f"{self.provider}/{self.model_id}: timed out")
        if self.fail_mode == "rate_limit":
            raise RateLimited(f"{self.provider}/{self.model_id}: rate limited")
        if self.fail_mode == "unavailable":
            raise ModelUnavailable(f"{self.provider}/{self.model_id}: unavailable")

        text = next(self._response_cycle)
        structured: dict | None = None
        if request.response_schema is not None:
            if self.fail_mode == "malformed_structured_output":
                # Deliberately shaped to fail a caller's schema check
                # (M2.7's job to detect) rather than raise here: an
                # adapter that returns *something* unparseable-against-
                # schema is a different failure than one that can't
                # produce structured output at all.
                structured = {"__fake_malformed__": True}
            else:
                structured = {"ok": True, "echo": text}
        return CompletionResponse(
            provider=self.provider,
            model_id=self.model_id,
            text=text,
            structured=structured,
            usage=Usage(prompt_tokens=len(request.messages), completion_tokens=1, total_tokens=len(request.messages) + 1),
            raw={"fake": True, "call_index": self.calls},
        )

    async def probe(self) -> Capabilities:
        if self.fail_mode == "timeout":
            raise Timeout(f"{self.provider}/{self.model_id}: probe timed out")
        return Capabilities(
            provider=self.provider,
            model_id=self.model_id,
            family=self.family,
            roles=self.roles,
            context_window=self.context_window,
            capabilities=dict(self.capabilities),
            pricing_tier=self.pricing_tier,
            deprecated=self.deprecated,
        )


def malformed_structured_output_would_fail_schema(structured: dict | None) -> bool:
    """Small shared helper so a test (or M2.7 later) can assert a
    `FakeAdapter(fail_mode="malformed_structured_output")` response is
    actually detectable as malformed, without hard-coding the sentinel
    shape at every call site."""
    return not isinstance(structured, dict) or "__fake_malformed__" in structured

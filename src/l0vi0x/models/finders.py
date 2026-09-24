"""A concrete example of the router's non-LLM finder slot (M2.4).

`route()` (router.py) only requires a candidate to satisfy the
`Adapter` Protocol -- `provider`, `model_id`, `async complete()`,
`async probe()`. Nothing in that contract says `complete()` has to call
a model. `StaticPatternFinder` "completes" a request by pattern-matching
its content instead, with no model call, no network, and none of the
adapter failure modes `fake.py`/`openai_compat.py` simulate -- included
to prove the router genuinely doesn't require an LLM-shaped candidate,
not because pattern matching is otherwise this codebase's job. A real
non-LLM finder (a static analyzer, a known-issue lookup, whatever M3+
ends up wanting) would be shaped like this, not like an LLM adapter with
network calls stubbed out.
"""

from __future__ import annotations

from dataclasses import dataclass

from l0vi0x.core.models import PricingTier
from l0vi0x.models.adapters.base import Capabilities, CompletionRequest, CompletionResponse, Usage


@dataclass
class StaticPatternFinder:
    """Router candidate that finds substring matches in the latest
    message instead of calling a model. Always "available" -- there is
    no failure mode to simulate for something that never leaves the
    process, so it never raises `ModelUnavailable`/`Timeout`."""

    provider: str = "static"
    model_id: str = "pattern-finder-1"
    family: str = "static-finder"
    patterns: tuple[str, ...] = ()
    pricing_tier: PricingTier = "free"

    async def complete(self, request: CompletionRequest) -> CompletionResponse:
        content = request.messages[-1].content if request.messages else ""
        hits = tuple(p for p in self.patterns if p in content)
        return CompletionResponse(
            provider=self.provider,
            model_id=self.model_id,
            text="; ".join(hits),
            structured={"hits": list(hits)} if request.response_schema is not None else None,
            usage=Usage(),
            raw={"pattern_matches": list(hits)},
        )

    async def probe(self) -> Capabilities:
        return Capabilities(
            provider=self.provider,
            model_id=self.model_id,
            family=self.family,
            roles=("finder",),
            context_window=0,
            capabilities={"structured_output": True},
            pricing_tier=self.pricing_tier,
            deprecated=False,
        )

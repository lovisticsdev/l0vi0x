"""Adapter contract shared by every M2 model backend.

`core.interfaces.LLMAdapter` already sketches a minimal Protocol
(`vendor`, `supports(feature)`, `chat(req)`), but it isn't wired to
anything yet and doesn't cover what `doctor` (M2.2) and the router
(M2.4+) actually need: a typed request/response envelope, an explicit
`probe()` for capability discovery, and a `Capabilities` record shaped
like `core.models.ModelProfile` so probe output can be written straight
into a lockfile (M2.3) with no translation layer. Rather than stretch
the existing scaffold Protocol to fit or leave two incompatible
adapter concepts standing, this module is the one adapter contract M2
actually builds against; `LLMAdapter` remains available but unused
until something is layered on top of it.

Field names (`provider`, `model_id`, `family`, `pricing_tier`, ...)
intentionally match `core.models.ModelProfile` rather than
`LLMAdapter`'s `vendor`, since `ModelProfile` is the actively-tested
M2.0 convention everything downstream (doctor, lockfile, router) keys
off of.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from l0vi0x.core.models import PricingTier


@dataclass(frozen=True, slots=True)
class Message:
    role: str
    content: str


@dataclass(frozen=True, slots=True)
class CompletionRequest:
    """A single request to route through an adapter.

    `response_schema`, when set, asks the adapter for structured output
    matching that JSON-schema-shaped dict. Whether the adapter can
    actually honor it is a capability (`capabilities["structured_output"]`
    on the `Capabilities` record returned by `probe()`); *validating*
    the response against the schema is M2.7's contract wrapper, not this
    layer's job. `role` is the routing role this request was dispatched
    for (e.g. "worker", "skeptic"), threaded through for logging/context,
    not interpreted by the adapter itself.
    """

    messages: tuple[Message, ...]
    role: str | None = None
    max_tokens: int | None = None
    temperature: float | None = None
    response_schema: dict[str, Any] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Usage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


@dataclass(frozen=True, slots=True)
class CompletionResponse:
    provider: str
    model_id: str
    text: str
    structured: dict[str, Any] | None = None
    usage: Usage = field(default_factory=Usage)
    raw: Any = None


@dataclass(frozen=True, slots=True)
class Capabilities:
    """What `probe()` found *right now* -- the shape `doctor` (M2.2) writes
    into `models.lock.yaml` (M2.3). Field names mirror
    `core.models.ModelProfile` deliberately, since a `Capabilities` record
    is exactly what gets turned into (or compared against) one."""

    provider: str
    model_id: str
    family: str
    roles: tuple[str, ...] = ()
    context_window: int = 0
    capabilities: dict[str, bool] = field(default_factory=dict)
    pricing_tier: PricingTier = "paid"
    deprecated: bool = False


class AdapterError(Exception):
    """Base for every adapter-raised failure."""


class ModelUnavailable(AdapterError):
    """The model can't serve this request right now.

    This is the exception the router (M2.4) catches to fail over to the
    next candidate and re-probe, rather than letting the failure raise
    to the caller -- deliberately including the "deprecated model ID"
    case (a deprecated model is unavailable, not an error condition the
    caller should see).
    """


class RateLimited(ModelUnavailable):
    """A 429 / quota-exhaustion-shaped failure specifically -- the router
    and `doctor` may want to distinguish this from a hard outage (e.g. for
    `quota_switch` vs `model_unavailable` event logging)."""


class Timeout(AdapterError):
    pass


class MalformedStructuredOutput(AdapterError):
    """The adapter was asked for structured output and produced something
    that doesn't parse as JSON at all. A response that parses but doesn't
    match the caller's schema is not this -- that's a schema-validation
    failure for M2.7's contract wrapper to raise, since only the caller
    knows the schema; this is for adapter-level "didn't even try"."""


@runtime_checkable
class Adapter(Protocol):
    """Structural contract every model backend satisfies. `fake` (this
    milestone) and `openai_compat` (this milestone) both implement it
    identically; the router (M2.4) is written against this Protocol only,
    never against a concrete adapter class, so a stack config can swap
    backends with no call-site changes."""

    provider: str
    model_id: str

    async def complete(self, request: CompletionRequest) -> CompletionResponse: ...

    async def probe(self) -> Capabilities: ...

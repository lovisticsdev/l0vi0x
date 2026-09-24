"""M2.2 -- capability/feature probing ("doctor" core).

`Adapter.probe()` gives a model's *self-reported* capabilities (what the
adapter was configured with, or what a bare reachability check found).
That's necessary but not sufficient: the acceptance clause is "native
probes -> models.lock.yaml" with "context-bearing structured output
verified" and "cache/feature measurements recorded" (build plan,
M2 acceptance row) -- verified and recorded, not merely declared.

So `probe_model()` does two things `Adapter.probe()` alone doesn't:
1. Actually calls `complete()` with a response_schema and confirms a
   parseable response comes back, rather than trusting the adapter's own
   `capabilities["structured_output"]` claim.
2. Times the probe round trip -- the one feature measurement every
   adapter (fake or real) can produce identically, and a natural place
   to hang provider-specific cache-hit detection later (M2.11, against
   a real endpoint) without changing this function's shape.

Doctor never raises for an *ordinary* probe failure (timeout, rate
limit, unavailable, deprecated) -- "the model can't currently serve" is
a result doctor records, not a doctor failure. It has nothing to build a
ModelProfile from in that case (family/context_window/capabilities are
only known once `probe()` actually returns), so it reports that as
`profile=None` with `probe_error` set, rather than fabricating
placeholder values to satisfy ModelProfile's field constraints.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime, timezone

from l0vi0x.core.models import ModelProfile
from l0vi0x.models.adapters.base import (
    Adapter,
    CompletionRequest,
    Message,
    ModelUnavailable,
    Timeout,
)

STRUCTURED_OUTPUT_PROBE_SCHEMA = {
    "type": "object",
    "properties": {"ack": {"type": "boolean"}},
    "required": ["ack"],
}


@dataclass(frozen=True, slots=True)
class ProbeResult:
    """What one probe_model() call found.

    `profile` is None exactly when `adapter.probe()` itself failed --
    everything else is only meaningful once we have a profile to attach
    measurements to. `structured_output_round_trip_ok` is None (not
    False) when the round trip was never attempted, so a caller can tell
    "didn't try" from "tried and failed"."""

    provider: str
    model_id: str
    profile: ModelProfile | None
    structured_output_round_trip_ok: bool | None
    probe_latency_s: float | None
    probe_error: str | None


async def probe_model(
    adapter: Adapter,
    *,
    terms_version: str,
    pricing_version: str,
    now: datetime | None = None,
) -> ProbeResult:
    observed_at = now or datetime.now(timezone.utc)
    started = time.monotonic()
    try:
        capabilities = await adapter.probe()
    except (ModelUnavailable, Timeout) as exc:
        return ProbeResult(
            provider=adapter.provider,
            model_id=adapter.model_id,
            profile=None,
            structured_output_round_trip_ok=None,
            probe_latency_s=time.monotonic() - started,
            probe_error=str(exc),
        )
    probe_latency_s = time.monotonic() - started

    round_trip_ok: bool | None = None
    declared_structured_output = bool(capabilities.capabilities.get("structured_output"))
    if declared_structured_output and not capabilities.deprecated:
        round_trip_ok = await _verify_structured_output(adapter)

    # A capability only a real call can confirm shouldn't be reported as
    # true on the adapter's word alone: if we attempted verification and
    # it failed, the recorded capability reflects what actually happened.
    verified_capabilities = dict(capabilities.capabilities)
    if round_trip_ok is not None:
        verified_capabilities["structured_output"] = round_trip_ok

    profile = ModelProfile(
        provider=capabilities.provider,
        model_id=capabilities.model_id,
        family=capabilities.family,
        roles=list(capabilities.roles),
        context_window=max(capabilities.context_window, 1),
        capabilities=verified_capabilities,
        pricing_tier=capabilities.pricing_tier,
        terms_version=terms_version,
        terms_observed_at=observed_at,
        pricing_version=pricing_version,
        pricing_observed_at=observed_at,
        deprecated=capabilities.deprecated,
    )
    return ProbeResult(
        provider=adapter.provider,
        model_id=adapter.model_id,
        profile=profile,
        structured_output_round_trip_ok=round_trip_ok,
        probe_latency_s=probe_latency_s,
        probe_error=None,
    )


async def _verify_structured_output(adapter: Adapter) -> bool:
    """Actually call complete() with a schema and confirm *some* parseable
    dict comes back -- confirming the adapter can produce structured
    output at all, not that the content matches the schema exactly.
    Full schema conformance is explicitly out of scope here: it's M2.7's
    contract wrapper's job (see fake.py's own malformed_structured_output
    docstring), not doctor's. Any adapter-raised failure (unavailable,
    rate limit, timeout, a literal JSON parse failure) means "not
    verified" -- doctor swallows it here rather than letting a single
    failed probe abort the whole battery; probe_model's caller (M2.3)
    sees the outcome through the capability flag, not an exception."""
    request = CompletionRequest(
        messages=(Message(role="user", content="Reply with a small JSON object."),),
        role="doctor_probe",
        max_tokens=32,
        response_schema=STRUCTURED_OUTPUT_PROBE_SCHEMA,
    )
    try:
        response = await adapter.complete(request)
    except Exception:  # noqa: BLE001 -- any adapter failure means "not verified"
        return False
    return isinstance(response.structured, dict)
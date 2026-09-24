from __future__ import annotations

import pytest

from l0vi0x.core.models import StackPolicy
from l0vi0x.models.adapters.base import CompletionRequest, Message
from l0vi0x.models.adapters.fake import FakeAdapter
from l0vi0x.models.finders import StaticPatternFinder
from l0vi0x.models.router import NoCandidatesAvailable, route

TERMS = "2026-01-01"
PRICING = "2026-01-01"


def _req(**overrides) -> CompletionRequest:
    fields = dict(messages=(Message(role="user", content="hello"),))
    fields.update(overrides)
    return CompletionRequest(**fields)


# --- the literal M2.4 stop condition --------------------------------------


@pytest.mark.asyncio
async def test_router_fails_over_to_next_candidate_when_primary_unavailable():
    """The stop condition itself: kill the primary mid-routing (via
    fake's configurable failure mode), assert the router recovers using
    the next candidate."""
    primary = FakeAdapter(provider="fake", model_id="primary-1", fail_mode="unavailable")
    backup = FakeAdapter(provider="fake", model_id="backup-1", responses=("backup response",))

    result = await route("worker", [primary, backup], _req(), terms_version=TERMS, pricing_version=PRICING)

    assert result.model_id == "backup-1"
    assert result.response.text == "backup response"
    assert [a.model_id for a in result.attempts] == ["primary-1", "backup-1"]
    assert result.attempts[0].ok is False
    assert result.attempts[1].ok is True


@pytest.mark.asyncio
async def test_router_deprecated_model_fails_over_and_reprobes_rather_than_raising():
    """The specific acceptance clause: a deprecated model ID fails over
    and re-probes, rather than raising. Both fake.py and openai_compat.py
    surface "this model is deprecated" the same way in practice: probe()
    reports deprecated=True *and* complete() fails (openai_compat.py maps
    a real 404/410 to ModelUnavailable for exactly this model) -- so a
    FakeAdapter combining fail_mode="unavailable" with deprecated=True
    models that pairing faithfully, not artificially."""
    deprecated = FakeAdapter(provider="fake", model_id="old-1", fail_mode="unavailable", deprecated=True)
    fresh = FakeAdapter(provider="fake", model_id="new-1", responses=("fresh response",))

    result = await route("worker", [deprecated, fresh], _req(), terms_version=TERMS, pricing_version=PRICING)

    assert result.model_id == "new-1"
    # No exception propagated -- and the re-probe actually happened and
    # confirmed the deprecation, rather than the router merely assuming it.
    assert result.attempts[0].reprobed_deprecated is True


@pytest.mark.asyncio
async def test_router_raises_only_once_every_candidate_has_failed():
    a = FakeAdapter(provider="fake", model_id="a", fail_mode="unavailable")
    b = FakeAdapter(provider="fake", model_id="b", fail_mode="rate_limit")

    with pytest.raises(NoCandidatesAvailable) as excinfo:
        await route("worker", [a, b], _req(), terms_version=TERMS, pricing_version=PRICING)
    assert "a" in str(excinfo.value) and "b" in str(excinfo.value)


@pytest.mark.asyncio
async def test_router_does_not_catch_unmodeled_exceptions():
    """Fail-over is for recoverable per-candidate failures
    (ModelUnavailable/Timeout), not a catch-all -- a genuine bug in a
    candidate must still propagate."""

    class ExplodingAdapter(FakeAdapter):
        async def complete(self, request):  # noqa: ANN001
            raise RuntimeError("not a modeled adapter failure")

    with pytest.raises(RuntimeError, match="not a modeled adapter failure"):
        await route("worker", [ExplodingAdapter(provider="fake", model_id="boom")], _req(), terms_version=TERMS, pricing_version=PRICING)


# --- stack policy filtering ------------------------------------------------


@pytest.mark.asyncio
async def test_router_skips_candidates_not_allowed_by_stack_policy():
    prod_policy = StackPolicy(stack="prod-main", kind="prod", decisions=True, allowed_pricing_tiers=["paid"])
    free_candidate = FakeAdapter(provider="fake", model_id="free-1", pricing_tier="free", responses=("should not be used",))
    paid_candidate = FakeAdapter(provider="fake", model_id="paid-1", pricing_tier="paid", responses=("paid response",))

    result = await route("worker", [free_candidate, paid_candidate], _req(), stack_policy=prod_policy, terms_version=TERMS, pricing_version=PRICING)

    assert result.model_id == "paid-1"
    assert [a.model_id for a in result.attempts] == ["paid-1"]  # free-1 never attempted


@pytest.mark.asyncio
async def test_router_raises_no_candidates_when_stack_policy_excludes_everything():
    prod_policy = StackPolicy(stack="prod-main", kind="prod", decisions=True, allowed_pricing_tiers=["paid"])
    free_candidate = FakeAdapter(provider="fake", model_id="free-1", pricing_tier="free")

    with pytest.raises(NoCandidatesAvailable):
        await route("worker", [free_candidate], _req(), stack_policy=prod_policy, terms_version=TERMS, pricing_version=PRICING)


# --- non-LLM finder candidate ----------------------------------------------


@pytest.mark.asyncio
async def test_router_routes_to_a_non_llm_finder_with_no_special_casing():
    finder = StaticPatternFinder(patterns=("reentrancy",))
    request = _req(messages=(Message(role="user", content="check this contract for reentrancy bugs"),))

    result = await route("worker", [finder], request, terms_version=TERMS, pricing_version=PRICING)

    assert result.model_id == "pattern-finder-1"
    assert result.response.text == "reentrancy"


@pytest.mark.asyncio
async def test_router_fails_over_from_llm_candidate_to_finder_candidate():
    """The candidate list can freely mix LLM and non-LLM entries -- the
    router doesn't know or care which is which."""
    broken_llm = FakeAdapter(provider="fake", model_id="broken-1", fail_mode="unavailable")
    finder = StaticPatternFinder(patterns=("oracle",))
    request = _req(messages=(Message(role="user", content="oracle manipulation risk?"),))

    result = await route("worker", [broken_llm, finder], request, terms_version=TERMS, pricing_version=PRICING)

    assert result.model_id == "pattern-finder-1"


# --- event emission ---------------------------------------------------------


@pytest.mark.asyncio
async def test_router_emits_model_unavailable_event_on_failover():
    events: list[tuple[str, dict]] = []
    primary = FakeAdapter(provider="fake", model_id="primary-1", fail_mode="unavailable")
    backup = FakeAdapter(provider="fake", model_id="backup-1")

    await route(
        "worker", [primary, backup], _req(),
        terms_version=TERMS, pricing_version=PRICING,
        on_event=lambda kind, payload: events.append((kind, payload)),
    )

    assert events[0][0] == "model_unavailable"
    assert events[0][1]["model_id"] == "primary-1"
    assert events[0][1]["role"] == "worker"


@pytest.mark.asyncio
async def test_router_emits_quota_switch_event_for_rate_limit_failover():
    """rate_limit is a distinct signal from a hard outage -- the router
    tags it separately so downstream logging can tell a quota-driven
    switch from a genuine unavailability."""
    events: list[tuple[str, dict]] = []
    primary = FakeAdapter(provider="fake", model_id="primary-1", fail_mode="rate_limit")
    backup = FakeAdapter(provider="fake", model_id="backup-1")

    await route(
        "worker", [primary, backup], _req(),
        terms_version=TERMS, pricing_version=PRICING,
        on_event=lambda kind, payload: events.append((kind, payload)),
    )

    assert events[0][0] == "quota_switch"


@pytest.mark.asyncio
async def test_router_emits_no_event_on_success():
    events: list[tuple[str, dict]] = []
    ok = FakeAdapter(provider="fake", model_id="ok-1")

    await route(
        "worker", [ok], _req(),
        terms_version=TERMS, pricing_version=PRICING,
        on_event=lambda kind, payload: events.append((kind, payload)),
    )

    assert events == []

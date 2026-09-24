from __future__ import annotations

import pytest

from l0vi0x.models.adapters.fake import FakeAdapter
from l0vi0x.models.doctor import probe_model

TERMS = "2026-01-01"
PRICING = "2026-01-01"


@pytest.mark.asyncio
async def test_probe_model_happy_path():
    adapter = FakeAdapter()  # default: capabilities={"structured_output": True, ...}
    result = await probe_model(adapter, terms_version=TERMS, pricing_version=PRICING)

    assert result.probe_error is None
    assert result.profile is not None
    assert result.structured_output_round_trip_ok is True
    assert result.profile.capabilities["structured_output"] is True
    assert result.probe_latency_s is not None and result.probe_latency_s >= 0


@pytest.mark.asyncio
async def test_probe_model_skips_round_trip_for_deprecated_model():
    adapter = FakeAdapter(deprecated=True)
    result = await probe_model(adapter, terms_version=TERMS, pricing_version=PRICING)

    assert result.profile is not None
    assert result.profile.deprecated is True
    assert result.structured_output_round_trip_ok is None


@pytest.mark.asyncio
async def test_probe_model_timeout_during_probe_yields_no_profile():
    """Only `timeout` makes FakeAdapter.probe() itself raise -- doctor has
    nothing to build a profile from in that case."""
    adapter = FakeAdapter(fail_mode="timeout")
    result = await probe_model(adapter, terms_version=TERMS, pricing_version=PRICING)

    assert result.profile is None
    assert result.probe_error is not None
    assert result.structured_output_round_trip_ok is None
    assert result.probe_latency_s is not None and result.probe_latency_s >= 0


@pytest.mark.parametrize("fail_mode", ["rate_limit", "unavailable"])
@pytest.mark.asyncio
async def test_probe_model_downgrades_capability_when_round_trip_fails(fail_mode):
    """rate_limit/unavailable don't affect FakeAdapter.probe() -- only
    complete(). So probe() still succeeds and declares structured_output
    support, but the round-trip verification call fails; doctor must
    report what it verified (False), not what was declared (True), while
    still producing a profile (the model itself is reachable, just this
    one call failed)."""
    adapter = FakeAdapter(fail_mode=fail_mode)
    result = await probe_model(adapter, terms_version=TERMS, pricing_version=PRICING)

    assert result.profile is not None
    assert result.structured_output_round_trip_ok is False
    assert result.profile.capabilities["structured_output"] is False


@pytest.mark.asyncio
async def test_probe_model_never_raises_on_genuinely_unexpected_adapter_failure():
    """A bug or unmodeled failure inside complete() during the round-trip
    check should still not abort the whole probe battery -- only propagate
    if probe() itself raises something doctor doesn't recognize."""

    class ExplodingCompleteAdapter(FakeAdapter):
        async def complete(self, request):  # noqa: ANN001
            raise RuntimeError("boom")

    adapter = ExplodingCompleteAdapter()
    result = await probe_model(adapter, terms_version=TERMS, pricing_version=PRICING)

    assert result.profile is not None
    assert result.structured_output_round_trip_ok is False


@pytest.mark.asyncio
async def test_probe_model_does_not_claim_full_schema_conformance():
    """M2.2's round trip confirms *some* parseable structured output comes
    back, not that it matches the schema exactly -- that's explicitly
    M2.7's job (see fake.py's malformed_structured_output docstring).
    FakeAdapter's "malformed" simulation returns a validly-shaped-but-
    wrong dict for exactly this reason, and M2.2 is not expected to catch
    it -- documenting the boundary here so it isn't mistaken for a gap
    later."""
    adapter = FakeAdapter(fail_mode="malformed_structured_output")
    result = await probe_model(adapter, terms_version=TERMS, pricing_version=PRICING)

    assert result.profile is not None
    assert result.structured_output_round_trip_ok is True  # not a false claim of full conformance -- see docstring above

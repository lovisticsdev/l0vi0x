from __future__ import annotations

import pytest

from l0vi0x.models.adapters import build_adapter
from l0vi0x.models.adapters.base import (
    Adapter,
    Capabilities,
    CompletionRequest,
    CompletionResponse,
    Message,
    ModelUnavailable,
    RateLimited,
    Timeout,
)
from l0vi0x.models.adapters.fake import FakeAdapter, malformed_structured_output_would_fail_schema
from l0vi0x.models.adapters.openai_compat import OpenAICompatAdapter


def _req(**overrides) -> CompletionRequest:
    fields = dict(messages=(Message(role="user", content="hello"),))
    fields.update(overrides)
    return CompletionRequest(**fields)


# --- structural contract -----------------------------------------------


def test_fake_and_openai_compat_satisfy_the_same_protocol():
    fake = FakeAdapter()
    real = OpenAICompatAdapter(provider="together", model_id="real-1", family="real", base_url="https://example.invalid")
    assert isinstance(fake, Adapter)
    assert isinstance(real, Adapter)


def test_build_adapter_swaps_backend_by_config_alone():
    """The M2.1 stop condition made concrete: only the config's `kind`
    changes, no call-site code does."""
    fake_cfg = {"kind": "fake", "provider": "fake", "model_id": "fake-large-1", "family": "fake-large"}
    real_cfg = {"kind": "openai_compat", "provider": "together", "model_id": "real-1", "family": "real", "base_url": "https://example.invalid"}

    fake = build_adapter(fake_cfg)
    real = build_adapter(real_cfg)

    assert isinstance(fake, FakeAdapter)
    assert isinstance(real, OpenAICompatAdapter)
    assert isinstance(fake, Adapter) and isinstance(real, Adapter)


def test_build_adapter_rejects_unknown_kind():
    with pytest.raises(ValueError, match="unknown adapter kind"):
        build_adapter({"kind": "nonexistent"})


# --- fake adapter: happy path -------------------------------------------


@pytest.mark.asyncio
async def test_fake_adapter_returns_deterministic_response():
    adapter = FakeAdapter(responses=("first", "second"))
    r1 = await adapter.complete(_req())
    r2 = await adapter.complete(_req())
    r3 = await adapter.complete(_req())  # cycles back to "first"
    assert isinstance(r1, CompletionResponse)
    assert (r1.text, r2.text, r3.text) == ("first", "second", "first")
    assert r1.provider == "fake"


@pytest.mark.asyncio
async def test_fake_adapter_probe_reports_configured_capabilities():
    adapter = FakeAdapter(family="fake-large", capabilities={"structured_output": True})
    caps = await adapter.probe()
    assert isinstance(caps, Capabilities)
    assert caps.family == "fake-large"
    assert caps.capabilities == {"structured_output": True}
    assert caps.deprecated is False


@pytest.mark.asyncio
async def test_fake_adapter_probe_reports_deprecated_flag():
    adapter = FakeAdapter(deprecated=True)
    caps = await adapter.probe()
    assert caps.deprecated is True


# --- fake adapter: failure-mode injection --------------------------------


@pytest.mark.asyncio
async def test_fake_adapter_timeout_mode_raises_timeout():
    adapter = FakeAdapter(fail_mode="timeout")
    with pytest.raises(Timeout):
        await adapter.complete(_req())


@pytest.mark.asyncio
async def test_fake_adapter_rate_limit_mode_raises_rate_limited():
    adapter = FakeAdapter(fail_mode="rate_limit")
    with pytest.raises(RateLimited):
        await adapter.complete(_req())
    # RateLimited is-a ModelUnavailable: the router (M2.4) should be able
    # to catch either the specific or the general case.
    with pytest.raises(ModelUnavailable):
        await adapter.complete(_req())


@pytest.mark.asyncio
async def test_fake_adapter_unavailable_mode_raises_model_unavailable():
    adapter = FakeAdapter(fail_mode="unavailable")
    with pytest.raises(ModelUnavailable):
        await adapter.complete(_req())


@pytest.mark.asyncio
async def test_fake_adapter_malformed_structured_output_mode_is_detectable():
    """The adapter doesn't raise here -- it returns *something*, and it's
    M2.7's contract wrapper that's supposed to catch a schema mismatch.
    What M2.1 needs to prove is that the failure mode is wired: a caller
    asking for structured output gets back something a schema check would
    reject."""
    adapter = FakeAdapter(fail_mode="malformed_structured_output")
    response = await adapter.complete(_req(response_schema={"type": "object", "required": ["ok", "echo"]}))
    assert malformed_structured_output_would_fail_schema(response.structured)


@pytest.mark.asyncio
async def test_fake_adapter_well_formed_structured_output_is_not_flagged_malformed():
    adapter = FakeAdapter()
    response = await adapter.complete(_req(response_schema={"type": "object"}))
    assert not malformed_structured_output_would_fail_schema(response.structured)
    assert response.structured == {"ok": True, "echo": "fake response"}


@pytest.mark.asyncio
async def test_fake_adapter_probe_timeout_mode_raises_timeout():
    adapter = FakeAdapter(fail_mode="timeout")
    with pytest.raises(Timeout):
        await adapter.probe()

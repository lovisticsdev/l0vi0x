from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from l0vi0x.core.models import ModelProfile, StackPolicy

NOW = datetime.now(timezone.utc)


def _profile(**overrides) -> ModelProfile:
    fields = dict(
        provider="fake",
        model_id="fake-large-1",
        family="fake-large",
        roles=["worker", "skeptic"],
        context_window=128_000,
        capabilities={"structured_output": True, "tool_use": False},
        pricing_tier="free",
        terms_version="2026-01-01",
        terms_observed_at=NOW,
        pricing_version="2026-01-01",
        pricing_observed_at=NOW,
    )
    fields.update(overrides)
    return ModelProfile(**fields)


def test_model_profile_round_trips_with_expected_defaults():
    profile = _profile()
    assert profile.deprecated is False
    assert profile.capabilities["structured_output"] is True


def test_model_profile_rejects_blank_identity():
    with pytest.raises(ValidationError):
        _profile(provider="  ")


def test_stack_policy_dev_stack_may_allow_free_models():
    policy = StackPolicy(stack="unit_fake", kind="dev", decisions=False, allowed_pricing_tiers=["free"])
    assert policy.decisions is False


def test_stack_policy_prod_stack_cannot_allow_free_or_shadow():
    """This is the acceptance clause itself, not just a schema nicety: 'a prod
    stack cannot select a free or shadow-priced model' must be unrepresentable,
    not merely unenforced at call sites."""
    with pytest.raises(ValidationError, match="prod stack cannot allow free or shadow"):
        StackPolicy(stack="prod-main", kind="prod", decisions=True, allowed_pricing_tiers=["paid", "free"])


def test_stack_policy_prod_stack_allows_paid_only():
    policy = StackPolicy(stack="prod-main", kind="prod", decisions=True, allowed_pricing_tiers=["paid"])
    assert policy.allowed_pricing_tiers == ["paid"]

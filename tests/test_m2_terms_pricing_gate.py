from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from l0vi0x.core.models import ModelProfile
from l0vi0x.core.policy import PolicyViolation
from l0vi0x.models.gates.terms_pricing import TermsPricingGate

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 6, 1, tzinfo=timezone.utc)
CONTEXT = {"audit_id": "audit-1", "requester": "worker-role"}


def gate() -> TermsPricingGate:
    return TermsPricingGate(ROOT / "config/policy/terms_pricing_policy.yaml")


def _profile(**overrides) -> ModelProfile:
    fields = dict(
        provider="fake",
        model_id="fake-large-1",
        family="fake-large",
        roles=["worker"],
        context_window=128_000,
        capabilities={"structured_output": True},
        pricing_tier="free",
        terms_version="2026-01-01",
        terms_observed_at=NOW - timedelta(days=1),
        pricing_version="2026-01-01",
        pricing_observed_at=NOW - timedelta(days=1),
    )
    fields.update(overrides)
    return ModelProfile(**fields)


# --- the three acceptance clauses, kept separate on purpose ---------------


def test_stale_terms_are_refused():
    stale = _profile(terms_observed_at=NOW - timedelta(days=45))
    with pytest.raises(PolicyViolation, match="stale terms"):
        gate().check(stale, authorization_context=CONTEXT, now=NOW)


def test_stale_pricing_is_refused():
    stale = _profile(pricing_observed_at=NOW - timedelta(days=45))
    with pytest.raises(PolicyViolation, match="stale pricing"):
        gate().check(stale, authorization_context=CONTEXT, now=NOW)


def test_missing_authorization_context_is_refused():
    fresh = _profile()
    with pytest.raises(PolicyViolation, match="missing authorization context"):
        gate().check(fresh, authorization_context=None, now=NOW)


def test_empty_authorization_context_dict_is_also_refused():
    """An empty dict is falsy -- "supplied but empty" is the same failure
    as "not supplied at all" for a completeness check."""
    fresh = _profile()
    with pytest.raises(PolicyViolation, match="missing authorization context"):
        gate().check(fresh, authorization_context={}, now=NOW)


# --- happy path + boundary ---------------------------------------------


def test_fresh_terms_and_pricing_with_context_is_allowed():
    fresh = _profile()
    gate().check(fresh, authorization_context=CONTEXT, now=NOW)  # does not raise
    assert gate().allowed(fresh, authorization_context=CONTEXT, now=NOW) is True


def test_terms_exactly_at_threshold_is_still_allowed():
    """max_terms_age_days: 30 in the checked-in policy -- exactly 30 days
    old should not be refused, only strictly older."""
    at_threshold = _profile(terms_observed_at=NOW - timedelta(days=30))
    gate().check(at_threshold, authorization_context=CONTEXT, now=NOW)


def test_allowed_returns_false_without_raising():
    stale = _profile(terms_observed_at=NOW - timedelta(days=45))
    assert gate().allowed(stale, authorization_context=CONTEXT, now=NOW) is False


# --- messages are unambiguous about which clause fired ---------------------


def test_violations_are_distinguishable_by_message():
    stale_terms = _profile(terms_observed_at=NOW - timedelta(days=45))
    stale_pricing = _profile(pricing_observed_at=NOW - timedelta(days=45))

    with pytest.raises(PolicyViolation) as terms_exc:
        gate().check(stale_terms, authorization_context=CONTEXT, now=NOW)
    with pytest.raises(PolicyViolation) as pricing_exc:
        gate().check(stale_pricing, authorization_context=CONTEXT, now=NOW)
    with pytest.raises(PolicyViolation) as context_exc:
        gate().check(_profile(), authorization_context=None, now=NOW)

    assert "stale terms" in str(terms_exc.value)
    assert "stale pricing" in str(pricing_exc.value)
    assert "missing authorization context" in str(context_exc.value)


# --- per-provider override -------------------------------------------------


def test_provider_override_widens_or_tightens_threshold(tmp_path):
    custom_policy = tmp_path / "terms_pricing_policy.yaml"
    custom_policy.write_text(
        "default:\n"
        "  max_terms_age_days: 30\n"
        "  max_pricing_age_days: 30\n"
        "providers:\n"
        "  fake:\n"
        "    max_terms_age_days: 5\n",
        encoding="utf-8",
    )
    tight_gate = TermsPricingGate(custom_policy)
    # 10 days old is within the *default* 30-day window, but the "fake"
    # provider override tightens it to 5.
    borderline = _profile(terms_observed_at=NOW - timedelta(days=10))
    with pytest.raises(PolicyViolation, match="stale terms"):
        tight_gate.check(borderline, authorization_context=CONTEXT, now=NOW)


def test_policy_file_is_present_and_nonempty():
    path = ROOT / "config/policy/terms_pricing_policy.yaml"
    assert path.exists()
    assert path.read_text(encoding="utf-8").strip()

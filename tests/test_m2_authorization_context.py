from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from l0vi0x.core.models import ModelProfile, StackPolicy
from l0vi0x.models.types import AuthorizationContext
from l0vi0x.models.gates.authorization import (
    AuthorizationContextMissing,
    AuthorizationGate,
    StackSelectionDenied,
)

NOW = datetime(2026, 6, 1, tzinfo=timezone.utc)
SCOPE_SHA = "a" * 64


def _context(**overrides) -> AuthorizationContext:
    fields = dict(
        audit_id="audit-1",
        scope_version=3,
        scope_sha256=SCOPE_SHA,
        target_commit="deadbeef",
        platform="immunefi",
        program_ref="program-1",
        confidentiality="public",
        witness_class="local_deployment",
        execution_boundary="local",
        allowed_artifact_roots=("/workspace/audit",),
        task_purpose="verify an in-scope hypothesis",
        disclosure_destination="security@program.example",
        prohibited_actions=("no_live_write_endpoints", "no_out_of_scope_targets"),
    )
    fields.update(overrides)
    return AuthorizationContext(**fields)


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
        terms_observed_at=NOW,
        pricing_version="2026-01-01",
        pricing_observed_at=NOW,
    )
    fields.update(overrides)
    return ModelProfile(**fields)


def test_private_audit_cannot_select_dev_stack():
    context = _context(confidentiality="private")
    dev = StackPolicy(
        stack="free_dev",
        kind="dev",
        decisions=False,
        allowed_pricing_tiers=["free"],
    )

    with pytest.raises(StackSelectionDenied, match="private audit cannot select dev stack"):
        AuthorizationGate().check(
            authorization_context=context,
            stack_policy=dev,
            candidate=_profile(pricing_tier="free"),
        )


@pytest.mark.parametrize("pricing_tier", ["free", "shadow"])
def test_prod_stack_cannot_select_free_or_shadow_priced_model(pricing_tier: str):
    context = _context(confidentiality="public")
    prod = StackPolicy(
        stack="prod-main",
        kind="prod",
        decisions=True,
        allowed_pricing_tiers=["paid"],
    )

    with pytest.raises(StackSelectionDenied, match="prod stack .* cannot select"):
        AuthorizationGate().check(
            authorization_context=context,
            stack_policy=prod,
            candidate=_profile(pricing_tier=pricing_tier),
        )


@pytest.mark.parametrize("stack", ["free_dev", "unit_fake"])
def test_public_audit_may_select_dev_stack(stack: str):
    dev = StackPolicy(
        stack=stack,
        kind="dev",
        decisions=False,
        allowed_pricing_tiers=["free"],
    )
    AuthorizationGate().check(
        authorization_context=_context(confidentiality="public"),
        stack_policy=dev,
        candidate=_profile(pricing_tier="free"),
    )


def test_prod_paid_selection_is_allowed():
    prod = StackPolicy(
        stack="prod-main",
        kind="prod",
        decisions=True,
        allowed_pricing_tiers=["paid"],
    )
    AuthorizationGate().check(
        authorization_context=_context(),
        stack_policy=prod,
        candidate=_profile(pricing_tier="paid"),
    )


def test_missing_context_has_dedicated_failure():
    dev = StackPolicy(
        stack="free_dev",
        kind="dev",
        decisions=False,
        allowed_pricing_tiers=["free"],
    )
    with pytest.raises(AuthorizationContextMissing, match="missing authorization context"):
        AuthorizationGate().check(
            authorization_context=None,
            stack_policy=dev,
            candidate=_profile(),
        )


def test_context_is_immutable_and_has_stable_hash():
    context = _context()
    clone = _context()
    assert context.context_hash() == clone.context_hash()
    with pytest.raises(ValidationError):
        context.audit_id = "changed"  # type: ignore[misc]
    with pytest.raises(ValidationError):
        context.allowed_artifact_roots += ("/other",)


def test_context_rejects_boundary_mismatch():
    with pytest.raises(ValidationError, match="deployed_fork requires"):
        _context(
            witness_class="deployed_fork",
            execution_boundary="local",
        )

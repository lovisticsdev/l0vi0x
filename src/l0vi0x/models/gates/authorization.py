"""M2.6 -- authorization-context and stack-selection gate.

This gate owns the security boundary between an audit's immutable
authorization context and model-stack selection.  It deliberately consumes
the already-typed ``StackPolicy`` and ``ModelProfile`` records instead of
reconstructing stack or pricing semantics from ad-hoc dictionaries.

The two M2 acceptance boundaries are enforced explicitly:
* private audits cannot select a dev stack;
* prod stacks cannot select free or shadow-priced models.

The gate also enforces the declared ``allowed_pricing_tiers`` list on the
selected stack so the stack policy is authoritative at the selection
boundary.  Terms/pricing freshness remains M2.5's responsibility.
"""

from __future__ import annotations

from l0vi0x.core.models import ModelProfile, StackPolicy
from l0vi0x.models.types import AuthorizationContext
from l0vi0x.core.policy import PolicyViolation


class AuthorizationContextMissing(PolicyViolation):
    """No authorization envelope was supplied for a target-touching call."""


class StackSelectionDenied(PolicyViolation):
    """The audit confidentiality or model tier is incompatible with a stack."""


class AuthorizationGate:
    """Validate authorization context before a model selection is allowed."""

    def check(
        self,
        *,
        authorization_context: AuthorizationContext | None,
        stack_policy: StackPolicy,
        candidate: ModelProfile | None = None,
    ) -> None:
        if authorization_context is None:
            raise AuthorizationContextMissing(
                "routing refused: missing authorization context"
            )

        if authorization_context.confidentiality == "private" and stack_policy.kind == "dev":
            raise StackSelectionDenied(
                f"routing refused: private audit cannot select dev stack "
                f"{stack_policy.stack!r}"
            )

        if candidate is None:
            return

        if stack_policy.kind == "prod" and candidate.pricing_tier in {"free", "shadow"}:
            # Keep the acceptance rule explicit even though StackPolicy also
            # forbids constructing a prod policy that advertises these tiers.
            raise StackSelectionDenied(
                f"routing refused: prod stack {stack_policy.stack!r} cannot select "
                f"{candidate.pricing_tier}-priced model "
                f"{candidate.provider}/{candidate.model_id}"
            )

        if candidate.pricing_tier not in stack_policy.allowed_pricing_tiers:
            raise StackSelectionDenied(
                f"routing refused: model {candidate.provider}/{candidate.model_id} "
                f"has pricing tier {candidate.pricing_tier!r}, not allowed by "
                f"stack {stack_policy.stack!r}"
            )

    def allowed(
        self,
        *,
        authorization_context: AuthorizationContext | None,
        stack_policy: StackPolicy,
        candidate: ModelProfile | None = None,
    ) -> bool:
        try:
            self.check(
                authorization_context=authorization_context,
                stack_policy=stack_policy,
                candidate=candidate,
            )
        except PolicyViolation:
            return False
        return True

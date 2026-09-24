"""M2.5 -- terms/pricing/privacy gate.

Mirrors `core.policy.CheatcodePolicy`'s shape deliberately: a YAML-driven
rules file plus `core.policy.PolicyViolation`, reusing that exception
directly rather than minting a parallel one -- this codebase already has
a working, tested template for "declarative rules file + typed
violation exception," so this gate is built on it rather than
alongside it.

This is a hard gate, not a warning: `check()` raises `PolicyViolation`
and refuses outright on stale terms, stale pricing, or a missing
authorization context. It composes with the router (M2.4) as a
precondition -- call `check()` before `route()`, the same way
`enforce_cheatcode_policy` is called as an explicit precondition rather
than folded into trace execution itself. It is deliberately not wired
into `route()`'s own call path here, since M2.6 (authorization-context
validator) composes with routing the same way and the two shouldn't
each independently reach into `route()`'s internals.

"Missing authorization context" here is a completeness check only --
was *any* authorization context supplied at all -- not the deeper
semantic rules ("a private audit cannot select a dev stack," etc.)
that consume this same context object's contents. Those are M2.6's job,
against the same `authorization_context` shape this gate merely
requires to be present.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from l0vi0x.core.models import ModelProfile
from l0vi0x.core.policy import PolicyViolation


class TermsPricingGate:
    def __init__(self, policy_file: str | Path):
        self.policy = yaml.safe_load(Path(policy_file).read_text(encoding="utf-8")) or {}
        self._default = self.policy.get("default", {}) or {}
        self._providers = self.policy.get("providers", {}) or {}

    def _thresholds(self, provider: str) -> dict[str, int]:
        override = self._providers.get(provider, {}) or {}
        return {
            "max_terms_age_days": int(override.get("max_terms_age_days", self._default.get("max_terms_age_days", 30))),
            "max_pricing_age_days": int(override.get("max_pricing_age_days", self._default.get("max_pricing_age_days", 30))),
        }

    def check(
        self,
        profile: ModelProfile,
        *,
        authorization_context: dict[str, Any] | None,
        now: datetime | None = None,
    ) -> None:
        """Raise `PolicyViolation` and refuse outright; return None (no
        exception) when the model is clear to route. Each of the three
        refusal conditions is checked independently and raises on its own,
        so a caller relying on the exception message to know *which*
        clause fired gets an unambiguous answer -- never a generic
        "denied" that conflates missing context with stale pricing."""
        if not authorization_context:
            raise PolicyViolation(
                f"{profile.provider}/{profile.model_id}: routing refused, missing authorization context"
            )

        now = now or datetime.now(timezone.utc)
        thresholds = self._thresholds(profile.provider)

        terms_age_days = (now - profile.terms_observed_at).days
        if terms_age_days > thresholds["max_terms_age_days"]:
            raise PolicyViolation(
                f"{profile.provider}/{profile.model_id}: routing refused, stale terms "
                f"(observed {profile.terms_observed_at.isoformat()}, {terms_age_days}d old, "
                f"max {thresholds['max_terms_age_days']}d)"
            )

        pricing_age_days = (now - profile.pricing_observed_at).days
        if pricing_age_days > thresholds["max_pricing_age_days"]:
            raise PolicyViolation(
                f"{profile.provider}/{profile.model_id}: routing refused, stale pricing "
                f"(observed {profile.pricing_observed_at.isoformat()}, {pricing_age_days}d old, "
                f"max {thresholds['max_pricing_age_days']}d)"
            )

    def allowed(
        self,
        profile: ModelProfile,
        *,
        authorization_context: dict[str, Any] | None,
        now: datetime | None = None,
    ) -> bool:
        try:
            self.check(profile, authorization_context=authorization_context, now=now)
        except PolicyViolation:
            return False
        return True

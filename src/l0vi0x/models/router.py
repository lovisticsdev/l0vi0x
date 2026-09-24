"""M2.4 -- router + ModelUnavailable failover.

Routes a request to a *role* (a candidate list already resolved for
that role -- resolving "worker" or "skeptic" to a ranked list of
adapters is out of scope here, this is purely the try-in-order/fail-
over/never-raise-for-a-recoverable-failure mechanism) rather than a
specific model.

The one acceptance clause this milestone exists to satisfy literally:
*a deprecated model ID fails over and re-probes rather than raising*.
Concretely: `complete()` raising `ModelUnavailable` (which is exactly
what both `fake.py` and `openai_compat.py` do for a deprecated model --
see `openai_compat.py`'s 404/410 mapping) never propagates past
`route()` as long as there's another candidate; the router calls
`doctor.probe_model()` on the failed candidate before moving on, so its
current status (still deprecated? recovered?) gets re-established
rather than assumed stale. Only when every candidate has failed does
`route()` raise -- there is genuinely nothing left to route to at that
point, which is a real failure the caller needs to see, not a
recoverable one.

Any candidate satisfying the `Adapter` Protocol works here, LLM-backed
or not -- `complete()`'s contract says nothing about calling a model.
See `models/finders.py` for a concrete non-LLM candidate
(`StaticPatternFinder`) proving the router doesn't require an
LLM-shaped candidate.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from l0vi0x.core.events import validate_kind
from l0vi0x.core.models import StackPolicy
from l0vi0x.models.adapters.base import (
    Adapter,
    CompletionRequest,
    CompletionResponse,
    ModelUnavailable,
    RateLimited,
    Timeout,
)
from l0vi0x.models.doctor import probe_model

# Both of these mean "this candidate can't serve right now" -- the
# router's job, not the caller's problem. Anything else (a genuine bug,
# an unmodeled exception) is deliberately left to propagate: fail-over
# is for recoverable per-candidate failures, not a catch-all.
_FAILOVER_EXCEPTIONS = (ModelUnavailable, Timeout)

EventSink = Callable[[str, dict[str, Any]], None]


@dataclass(frozen=True, slots=True)
class RouteAttempt:
    provider: str
    model_id: str
    ok: bool
    error: str | None = None
    # None when no re-probe happened (only ever true on failure); the
    # deprecated flag doctor's re-probe found, when it did happen.
    reprobed_deprecated: bool | None = None


@dataclass(frozen=True, slots=True)
class RouteResult:
    response: CompletionResponse
    provider: str
    model_id: str
    attempts: tuple[RouteAttempt, ...]


class NoCandidatesAvailable(ModelUnavailable):
    """Every candidate for this role failed, or none were eligible under
    the stack policy -- the one case `route()` itself raises, since
    there's no further candidate to fail over to."""


def _allowed_by_stack(candidate: Adapter, stack_policy: StackPolicy | None) -> bool:
    if stack_policy is None:
        return True
    pricing_tier = getattr(candidate, "pricing_tier", None)
    if pricing_tier is None:
        # A candidate that doesn't declare a pricing tier can't be
        # checked against the policy -- fail closed rather than
        # silently letting an unclassified model onto a restricted
        # stack (the same fail-closed posture StackPolicy itself takes
        # by construction, see core.models.StackPolicy).
        return False
    return pricing_tier in stack_policy.allowed_pricing_tiers


async def route(
    role: str,
    candidates: list[Adapter],
    request: CompletionRequest,
    *,
    stack_policy: StackPolicy | None = None,
    terms_version: str = "unknown",
    pricing_version: str = "unknown",
    on_event: EventSink | None = None,
) -> RouteResult:
    """Try each candidate for `role` in order; fail over to the next on
    `ModelUnavailable`/`Timeout` rather than raising. Raises
    `NoCandidatesAvailable` only once every eligible candidate has
    failed (or none were eligible under `stack_policy` to begin with).
    """
    eligible = [c for c in candidates if _allowed_by_stack(c, stack_policy)]
    if not eligible:
        raise NoCandidatesAvailable(f"no candidates for role={role!r} are allowed by the stack policy")

    attempts: list[RouteAttempt] = []
    for candidate in eligible:
        try:
            response = await candidate.complete(request)
        except _FAILOVER_EXCEPTIONS as exc:
            reprobe = await probe_model(candidate, terms_version=terms_version, pricing_version=pricing_version)
            reprobed_deprecated = reprobe.profile.deprecated if reprobe.profile is not None else None
            attempts.append(RouteAttempt(
                provider=candidate.provider, model_id=candidate.model_id,
                ok=False, error=str(exc), reprobed_deprecated=reprobed_deprecated,
            ))
            if on_event is not None:
                kind = validate_kind("quota_switch" if isinstance(exc, RateLimited) else "model_unavailable")
                on_event(kind, {
                    "role": role, "provider": candidate.provider, "model_id": candidate.model_id,
                    "error": str(exc), "reprobed_deprecated": reprobed_deprecated,
                })
            continue

        attempts.append(RouteAttempt(provider=candidate.provider, model_id=candidate.model_id, ok=True))
        return RouteResult(response=response, provider=candidate.provider, model_id=candidate.model_id, attempts=tuple(attempts))

    failures = "; ".join(f"{a.provider}/{a.model_id}: {a.error}" for a in attempts)
    raise NoCandidatesAvailable(f"all {len(eligible)} candidate(s) for role={role!r} failed: {failures}")

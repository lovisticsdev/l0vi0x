from __future__ import annotations

from datetime import datetime, timezone

from l0vi0x.core.interfaces import DriverToken
from l0vi0x.core.models import HState, Hypothesis


class IllegalTransition(ValueError):
    pass


LEGAL_TRANSITIONS: dict[HState, set[HState]] = {
    HState.OPEN: {HState.INVESTIGATING, HState.PARKED, HState.CLOSED, HState.CLOSED_DUPLICATE},
    HState.INVESTIGATING: {HState.CONFIRMED, HState.PARKED, HState.CLOSED, HState.CLOSED_DUPLICATE},
    HState.CONFIRMED: {HState.INVESTIGATING, HState.FINDING, HState.CLOSED_DUPLICATE, HState.PARKED, HState.CLOSED},
    HState.PARKED: {HState.INVESTIGATING, HState.CLOSED, HState.MERGED},
    HState.FINDING: {HState.CLOSED, HState.CLOSED_DUPLICATE, HState.MERGED},
    HState.CLOSED: {HState.INVESTIGATING},
    HState.CLOSED_DUPLICATE: {HState.INVESTIGATING},
    HState.MERGED: {HState.INVESTIGATING},
}

_HUMAN_ONLY_REOPENS = {
    (HState.CLOSED, HState.INVESTIGATING),
    (HState.CLOSED_DUPLICATE, HState.INVESTIGATING),
    (HState.MERGED, HState.INVESTIGATING),
}


def _clean_evidence(evidence: list[str]) -> list[str]:
    return [str(item).strip() for item in evidence if str(item).strip()]


def _has(evidence: list[str], prefix: str) -> bool:
    return any(item.startswith(prefix) and item[len(prefix):].strip() for item in evidence)


def _has_any(evidence: list[str], prefixes: tuple[str, ...]) -> bool:
    return any(_has(evidence, prefix) for prefix in prefixes)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise IllegalTransition(message)


def validate_transition(
    token: DriverToken,
    hypothesis: Hypothesis,
    new_state: HState,
    cause: str,
    evidence: list[str],
) -> None:
    if not isinstance(token, DriverToken) or not token.is_valid():
        raise IllegalTransition("valid driver token required")
    if not cause or not cause.strip():
        raise IllegalTransition("cause must be non-empty")
    evidence = _clean_evidence(evidence)
    if not evidence:
        raise IllegalTransition("every transition requires at least one evidence reference")
    old = hypothesis.state
    if old not in LEGAL_TRANSITIONS:
        raise IllegalTransition(f"unknown current state: {old}")
    if new_state not in LEGAL_TRANSITIONS[old]:
        raise IllegalTransition(f"illegal transition {old} -> {new_state}")

    pair = (old, new_state)
    if pair in _HUMAN_ONLY_REOPENS:
        _require(token.human_override, "reopening is human-override only")
        _require(_has(evidence, "human_reason:"), "reopening requires a human reason evidence reference")
        _require(_has(evidence, "new_evidence:"), "reopening requires new evidence")
        if hypothesis.reopen_count >= 3:
            _require(_has(evidence, "reviewer2:"), "a fourth or later reopen requires second-reviewer evidence")

    if pair == (HState.OPEN, HState.INVESTIGATING):
        _require(_has(evidence, "task:"), "OPEN -> INVESTIGATING requires an assigned task ID")
        _require(_has_any(evidence, ("scope:", "in_scope:")), "OPEN -> INVESTIGATING requires in-scope evidence")
    elif pair == (HState.OPEN, HState.PARKED):
        _require(_has_any(evidence, ("assumption:", "budget:", "human_reason:")), "OPEN -> PARKED requires a blocker assumption, budget reason, or explicit human reason")
    elif pair == (HState.OPEN, HState.CLOSED):
        _require(_has_any(evidence, ("disproof:", "scope:", "not_actionable:")), "OPEN -> CLOSED requires falsity, scope, or non-actionable evidence")
    elif pair == (HState.OPEN, HState.CLOSED_DUPLICATE):
        _require(_has_any(evidence, ("finding:", "hypothesis:")), "OPEN -> CLOSED_DUPLICATE requires an existing finding or hypothesis ID")
        _require(_has(evidence, "duplicate_reason:"), "duplicate closure requires duplicate rationale")
    elif pair == (HState.INVESTIGATING, HState.CONFIRMED):
        required = (
            "execution_l5:", "run_receipt:", "witness_assertion:", "build_pass:",
            "ast_pass:", "trace_policy_pass:", "mechanism_l1:", "reachability_l2:",
        )
        for prefix in required:
            _require(_has(evidence, prefix), f"INVESTIGATING -> CONFIRMED requires {prefix} evidence")
        _require(_has_any(evidence, ("economics_l5:", "impact:")), "CONFIRMED requires economics L5 or an applicable non-financial impact assertion")
    elif pair == (HState.INVESTIGATING, HState.PARKED):
        _require(_has_any(evidence, ("failure:", "human_reason:", "blocker:")), "INVESTIGATING -> PARKED requires a failure record or explicit blocker")
    elif pair == (HState.INVESTIGATING, HState.CLOSED):
        _require(_has_any(evidence, ("disproof:", "scope:", "not_actionable:")), "INVESTIGATING -> CLOSED requires invalidating evidence")
    elif pair == (HState.INVESTIGATING, HState.CLOSED_DUPLICATE):
        _require(_has(evidence, "finding:"), "INVESTIGATING -> CLOSED_DUPLICATE requires an existing finding ID")
        _require(_has(evidence, "duplicate_reason:"), "duplicate closure requires duplicate rationale")
    elif pair == (HState.CONFIRMED, HState.FINDING):
        required = (
            "execution_l6:", "hard_verifier_pass:",
        )
        for prefix in required:
            _require(_has(evidence, prefix), f"CONFIRMED -> FINDING requires {prefix} evidence")
        _require(_has_any(evidence, ("economics_l6:", "impact:")), "FINDING requires economics L6 or an applicable non-financial impact assertion")
        _require(_has_any(evidence, ("production_l7:", "production:not_applicable")), "FINDING requires production L7 or production:not_applicable")
        _require(_has_any(evidence, ("adjudication:", "human_override:")), "FINDING requires adjudication support or a documented human override")
    elif pair == (HState.CONFIRMED, HState.INVESTIGATING):
        _require(_has(evidence, "repair:"), "CONFIRMED -> INVESTIGATING requires a repair code")
    elif pair == (HState.CONFIRMED, HState.PARKED):
        _require(_has_any(evidence, ("economics:", "blocker:", "certification_failure:")), "CONFIRMED -> PARKED requires a blocker or certification/economics failure")
    elif pair == (HState.CONFIRMED, HState.CLOSED):
        _require(_has_any(evidence, ("disproof:", "scope:", "not_actionable:")), "CONFIRMED -> CLOSED requires invalidating evidence")
    elif pair == (HState.CONFIRMED, HState.CLOSED_DUPLICATE):
        _require(_has(evidence, "finding:"), "CONFIRMED -> CLOSED_DUPLICATE requires an existing finding ID")
        _require(_has(evidence, "duplicate_reason:"), "duplicate closure requires duplicate rationale")
    elif pair == (HState.PARKED, HState.INVESTIGATING):
        _require(_has(evidence, "unblocked:"), "PARKED -> INVESTIGATING requires unblock evidence")
    elif pair == (HState.PARKED, HState.CLOSED):
        _require(_has_any(evidence, ("permanent_blocker:", "scope:")), "PARKED -> CLOSED requires permanent blocker or scope evidence")
    elif pair == (HState.PARKED, HState.MERGED):
        _require(_has(evidence, "parent:"), "PARKED -> MERGED requires parent hypothesis evidence")
        _require(_has(evidence, "replacement:"), "PARKED -> MERGED requires replacement hypothesis evidence")
        _require(_has(evidence, "merge_rationale:"), "PARKED -> MERGED requires merge rationale")
    elif pair == (HState.FINDING, HState.CLOSED):
        _require(_has_any(evidence, ("disproof:", "invalidating:", "scope:")), "FINDING -> CLOSED requires invalidating evidence")
    elif pair == (HState.FINDING, HState.CLOSED_DUPLICATE):
        _require(_has(evidence, "finding:"), "FINDING -> CLOSED_DUPLICATE requires existing finding ID")
        _require(_has(evidence, "duplicate_reason:"), "duplicate closure requires duplicate rationale")
    elif pair == (HState.FINDING, HState.MERGED):
        _require(_has(evidence, "replacement:"), "FINDING -> MERGED requires replacement finding ID")
        _require(_has(evidence, "preserved_evidence:"), "finding merge requires preserved evidence link")


def transition(
    token: DriverToken,
    hypothesis: Hypothesis,
    new_state: HState,
    cause: str,
    evidence: list[str],
) -> Hypothesis:
    validate_transition(token, hypothesis, new_state, cause, evidence)
    old_state = hypothesis.state
    hypothesis.state = new_state
    hypothesis.updated_at = datetime.now(timezone.utc)
    if (old_state, new_state) in _HUMAN_ONLY_REOPENS:
        hypothesis.reopen_count += 1
    return hypothesis

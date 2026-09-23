from __future__ import annotations

from typing import Any

from l0vi0x.core.models import Witness
from .types import CheckResult, ControlEvidence


def _matches(assertion: Any, event: dict[str, Any]) -> bool:
    for key in ("id", "kind", "target"):
        if str(event.get(key)) != str(getattr(assertion, key)):
            return False
    if str(event.get("expected")) != str(assertion.expected):
        return False
    if assertion.actor is not None and str(event.get("actor", "")).lower() != assertion.actor.lower():
        return False
    if assertion.token is not None and str(event.get("token", "")).lower() != assertion.token.lower():
        return False
    if str(assertion.observed_record) != "AssertionChecked":
        return False
    if "observed" not in event:
        return False
    observed = event["observed"]
    expected = assertion.expected
    op = assertion.operator
    try:
        relation = {
            "eq": observed == expected,
            "neq": observed != expected,
            "gt": observed > expected,
            "gte": observed >= expected,
            "lt": observed < expected,
            "lte": observed <= expected,
            "holds": bool(observed),
            "violated": not bool(observed),
        }[op]
    except (KeyError, TypeError):
        return False
    return bool(event.get("ok")) and bool(relation)


def check(*, witness: Witness, assertion_events: tuple[dict[str, Any], ...], control: ControlEvidence | None) -> CheckResult:
    required = [a for a in witness.assertions if a.required]
    if len(assertion_events) != len(required):
        return CheckResult("V06", False, "ASSERT_MISMATCH", True, "attack replay assertion-event count does not exactly match required assertions")
    for assertion in required:
        matches = [event for event in assertion_events if _matches(assertion, event)]
        if len(matches) != 1:
            return CheckResult("V06", False, "ASSERT_MISMATCH", True, f"declared assertion {assertion.id} was not uniquely observed")
    if control is None or not control.passed:
        return CheckResult("V06", False, "ASSERT_VACUOUS", True, "control run is missing or failed")
    if control.matching_assertion or control.observed_state_changed:
        return CheckResult("V06", False, "ASSERT_VACUOUS", True, "control run reproduces the claimed state-changing effect")
    return CheckResult("V06", True, message="declared assertions match exactly and disappear under the mechanically observed control")

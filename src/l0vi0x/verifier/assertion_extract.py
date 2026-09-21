from __future__ import annotations

from typing import Any

from l0vi0x.core.models import Witness
from .types import CheckResult, ControlEvidence


def _matches(assertion: Any, event: dict[str, Any]) -> bool:
    fields = {
        "id": assertion.id,
        "kind": assertion.kind,
        "target": assertion.target,
        "operator": assertion.operator,
        "expected": assertion.expected,
    }
    for key, value in fields.items():
        if str(event.get(key)) != str(value):
            return False
    return bool(event.get("ok"))


def check(*, witness: Witness, assertion_events: tuple[dict[str, Any], ...], control: ControlEvidence | None) -> CheckResult:
    required = [a for a in witness.assertions if a.required]
    for assertion in required:
        if not any(_matches(assertion, event) for event in assertion_events):
            return CheckResult("V06", False, "ASSERT_MISMATCH", True, f"declared assertion {assertion.id} was not observed")
    if control is None or not control.passed:
        return CheckResult("V06", False, "ASSERT_VACUOUS", True, "control run is missing or failed")
    if control.matching_assertion:
        return CheckResult("V06", False, "ASSERT_VACUOUS", True, "control run also satisfies the claimed assertion")
    if control.observed_state_changed:
        return CheckResult("V06", False, "ASSERT_VACUOUS", True, "control run exhibits the same state-changing effect")
    return CheckResult("V06", True, message="declared assertions match attack run and disappear under control")

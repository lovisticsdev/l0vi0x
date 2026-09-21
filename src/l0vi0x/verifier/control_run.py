from __future__ import annotations

from .types import ControlEvidence


def build_control_evidence(*, passed: bool, assertion_events: tuple[dict, ...], observed_state_changed: bool) -> ControlEvidence:
    matching = any(bool(e.get("ok")) for e in assertion_events)
    return ControlEvidence(passed=passed, matching_assertion=matching, observed_state_changed=observed_state_changed, assertion_event_count=len(assertion_events))

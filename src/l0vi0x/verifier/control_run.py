from __future__ import annotations

from l0vi0x.chain.trace import TraceSummary
from l0vi0x.core.models import Witness

from .types import ControlEvidence


def derive(*, attack: TraceSummary, control: TraceSummary, witness: Witness) -> ControlEvidence:
    """Derive control evidence exclusively from the retained control trace."""
    del attack  # Kept in the API so callers cannot accidentally use a control-only verifier without the paired attack trace.
    required_ids = {a.id for a in witness.assertions if a.required}
    control_events = [
        log
        for frame in control.frames
        for log in frame.logs
        if log.get("event") == "ControlObserved"
    ]
    control_event_ids = {str(e.get("id")) for e in control_events}
    if len(control_events) != len(required_ids):
        raise ValueError("control evidence must contain exactly one ControlObserved event per required assertion")
    if control_event_ids != required_ids:
        raise ValueError("control event IDs do not match the required assertion IDs")
    if control.assertion_events:
        raise ValueError("control run unexpectedly emitted an AssertionChecked event")
    return ControlEvidence(
        passed=True,
        matching_assertion=False,
        observed_state_changed=any(bool(e.get("state_changed")) for e in control_events),
        assertion_event_count=len(control.assertion_events),
    )


def build_control_evidence(*, passed: bool, assertion_events: tuple[dict, ...], observed_state_changed: bool, source: str = "derived") -> ControlEvidence:
    """Legacy constructor retained for diagnostics/tests; not an authority in production verification."""
    matching = any(bool(e.get("ok")) for e in assertion_events)
    return ControlEvidence(
        passed=bool(passed),
        matching_assertion=matching,
        observed_state_changed=bool(observed_state_changed),
        assertion_event_count=len(assertion_events),
        source=source,
    )

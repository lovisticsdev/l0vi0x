from __future__ import annotations

from l0vi0x.core.models import HState

FIXABLE_FAILURE_CODES = {
    "POLICY_VIOLATION", "ASSERT_MISMATCH", "ASSERT_VACUOUS", "COVERAGE_INCOMPLETE",
    "HARNESS_TAMPERED", "TRACE_MISSING", "ECON_INCOMPLETE", "HEAD_REPLAY_FAIL",
}

FATAL_FAILURE_CODES = {"OUT_OF_SCOPE", "KNOWN_ISSUE", "SPAN_DRIFT", "UPSTREAM_STATE_MISMATCH"}


def route_verification_failure(current: HState | str, code: str) -> str:
    current_value = current.value if isinstance(current, HState) else str(current)
    if code in {"NONDETERMINISTIC_ENV", "POLICY_VIOLATION", "ASSERT_MISMATCH", "ASSERT_VACUOUS", "COVERAGE_INCOMPLETE", "HARNESS_TAMPERED", "TRACE_MISSING", "ECON_INCOMPLETE", "HEAD_REPLAY_FAIL"}:
        return "INVESTIGATING" if current_value in {"CONFIRMED", "INVESTIGATING"} else current_value
    if code == "NONDETERMINISTIC_TRACE":
        return "PARKED"
    if code == "KNOWN_ISSUE":
        return "CLOSED_DUPLICATE"
    if code in {"OUT_OF_SCOPE", "SPAN_DRIFT", "UPSTREAM_STATE_MISMATCH", "MECHANICALLY_REFUTED"}:
        return "CLOSED"
    if code in {"LIKELY_DUPLICATE", "FRAGILE", "PROVENANCE_UNCLEAR", "REFUTED_JUDGMENT", "INCONCLUSIVE"}:
        return "FINDING"
    return current_value

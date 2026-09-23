from __future__ import annotations

import math

from .types import CheckResult, EconomicEvidence


def check(evidence: EconomicEvidence | None, *, production_required: bool, pinned_impact_usd: float | None = None) -> CheckResult:
    if evidence is None:
        return CheckResult("V09", False, "ECON_INCOMPLETE", True, "economic evidence is unavailable")
    if not evidence.evidence_complete:
        return CheckResult("V09", False, "ECON_INCOMPLETE", True, "economic evidence did not satisfy the mandatory evidence contract")
    s = evidence.snapshot
    mandatory = (s.native_before_wei, s.native_after_wei, s.gas_used, s.gas_price_wei, s.observed_capital_wei)
    if any(value is None for value in mandatory):
        return CheckResult("V09", False, "ECON_INCOMPLETE", True, "native snapshots, gas, gas price and observed capital are required")
    if s.gas_used < 0 or s.gas_price_wei < 0 or s.declared_capital_wei < 0 or s.observed_capital_wei < 0:
        return CheckResult("V09", False, "ECON_INCOMPLETE", True, "economic integer evidence is invalid")
    if s.observed_capital_wei > s.declared_capital_wei:
        return CheckResult("V09", False, "CAPITAL_MISMATCH", True, "observed capital exceeds declared attacker capital")
    required_scenarios = {"minus_500bps", "base", "plus_500bps"}
    if set(evidence.sensitivity) != required_scenarios or set(evidence.sensitivity_scenarios) != required_scenarios:
        return CheckResult("V09", False, "SENSITIVITY_INCOMPLETE", True, "mandatory +/-5% sensitivity scenarios are missing")
    expected_bps = {"minus_500bps": -500, "base": 0, "plus_500bps": 500}
    for label, expected in expected_bps.items():
        scenario = evidence.sensitivity_scenarios.get(label) or {}
        if int(scenario.get("bps", 10_000)) != expected:
            return CheckResult("V09", False, "SENSITIVITY_INVALID", True, f"{label} has the wrong sensitivity basis")
        net = scenario.get("net_usd")
        if not isinstance(net, (int, float)) or not math.isfinite(float(net)):
            return CheckResult("V09", False, "ECON_INCOMPLETE", True, f"{label} lacks a finite independently-derived net USD result")
        if abs(float(net) - float(evidence.sensitivity[label])) > 1e-12:
            return CheckResult("V09", False, "SENSITIVITY_INVALID", True, f"{label} summary does not match the retained scenario result")
    if any(not math.isfinite(float(v)) for v in evidence.sensitivity.values()):
        return CheckResult("V09", False, "ECON_INCOMPLETE", True, "sensitivity contains non-finite values")
    if production_required:
        if s.protocol_assets_delta_wei is None:
            return CheckResult("V09", False, "ECON_INCOMPLETE", True, "protocol asset delta is required for production verification")
        if evidence.head_replay_passed is not True:
            return CheckResult("V09", False, "HEAD_REPLAY_FAIL", True, "production replay must explicitly reproduce at head")
        if evidence.upstream_state_match is not True:
            return CheckResult("V09", False, "UPSTREAM_STATE_MISMATCH", True, "independent provider state match must be explicitly confirmed")
    details = {
        "severity_basis": "pinned_block" if pinned_impact_usd is not None else "native_or_unmapped",
        "pinned_block_impact_usd": pinned_impact_usd,
        "pinned_block": evidence.pinned_block,
        "gas_used": s.gas_used,
        "gas_price_wei": s.gas_price_wei,
        "sensitivity": dict(evidence.sensitivity),
    }
    return CheckResult("V09", True, hard=True, message="mandatory economic snapshots, actual gas price, capital, pricing basis and sensitivity evidence pass", details=details)

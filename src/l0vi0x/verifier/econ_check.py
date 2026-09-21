from __future__ import annotations

import math

from .types import CheckResult, EconomicEvidence


def check(evidence: EconomicEvidence | None, *, production_required: bool, pinned_impact_usd: float | None = None) -> CheckResult:
    if evidence is None:
        return CheckResult("V09", False, "FRAGILE", False, "economic verification evidence is unavailable")
    s = evidence.snapshot
    if s.native_before_wei is None or s.native_after_wei is None:
        return CheckResult("V09", False, "ECON_INCOMPLETE", True, "native before/after snapshots are required")
    if s.gas_used is None or s.gas_used < 0 or s.gas_price_wei is None or s.gas_price_wei < 0:
        return CheckResult("V09", False, "ECON_INCOMPLETE", True, "gas evidence missing or invalid")
    if s.declared_capital_wei < 0 or (s.observed_capital_wei is not None and s.observed_capital_wei < 0):
        return CheckResult("V09", False, "ECON_INCOMPLETE", True, "capital evidence invalid")
    if s.observed_capital_wei is not None and s.observed_capital_wei > s.declared_capital_wei:
        return CheckResult("V09", False, "FRAGILE", False, "observed attacker capital exceeds declared capital")
    if s.slippage_bps is not None and s.slippage_bps < 0:
        return CheckResult("V09", False, "ECON_INCOMPLETE", True, "slippage evidence invalid")
    if any(not math.isfinite(float(v)) for v in s.sensitivity.values()):
        return CheckResult("V09", False, "ECON_INCOMPLETE", True, "sensitivity contains non-finite values")
    if production_required and not evidence.evidence_complete:
        return CheckResult("V09", False, "ECON_INCOMPLETE", True, "production economic evidence is incomplete")
    if production_required and s.protocol_assets_delta_wei is None:
        return CheckResult("V09", False, "ECON_INCOMPLETE", True, "protocol asset delta is required for production verification")
    if production_required and not evidence.price_sources:
        return CheckResult("V09", False, "ECON_INCOMPLETE", True, "price-source evidence is required for production verification")
    if production_required and evidence.head_replay_passed is False:
        return CheckResult("V09", False, "HEAD_REPLAY_FAIL", True, "production replay does not reproduce at head")
    if production_required and evidence.upstream_state_match is False:
        return CheckResult("V09", False, "UPSTREAM_STATE_MISMATCH", True, "independent provider state does not match")
    soft_flags = list(evidence.realism_flags)
    if s.slippage_bps is None:
        soft_flags.append("slippage_unmeasured")
    if pinned_impact_usd is None:
        soft_flags.append("pinned_block_impact_missing")
    details = {
        "severity_basis": "pinned_block" if pinned_impact_usd is not None else "unmapped",
        "pinned_block_impact_usd": pinned_impact_usd,
        "pinned_block": evidence.pinned_block,
        "gas_used": s.gas_used,
        "gas_price_wei": s.gas_price_wei,
    }
    if soft_flags:
        return CheckResult("V09", False, "FRAGILE", False, "economic realism requires human review", {**details, "flags": soft_flags})
    return CheckResult("V09", True, hard=False, message="economic realism, capital, gas, and production-state checks pass", details=details)

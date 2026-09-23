from __future__ import annotations

from l0vi0x.chain.trace import TraceSummary
from .types import CheckResult, HarnessEvidence, EconomicEvidence


def _norm(values: tuple[str, ...]) -> set[str]:
    return {value.lower() for value in values}


def check(*, harness: HarnessEvidence | None, trace: TraceSummary | None, witness_harness_address: str, economics: EconomicEvidence | None) -> CheckResult:
    if harness is None or trace is None or economics is None:
        return CheckResult("V07", False, "HARNESS_TAMPERED", True, "derived harness/economic evidence is missing")
    required_strings = (
        harness.harness_address, harness.wrapper_address, harness.create2_deployer,
        harness.create2_salt, harness.create2_init_code_sha256, harness.assertion_emitter,
        harness.assertion_event_caller, harness.observed_runtime_sha256, harness.expected_runtime_sha256,
        harness.observed_source_sha256, harness.expected_source_sha256, harness.wrapper_runtime_sha256,
        harness.expected_wrapper_runtime_sha256, harness.wrapper_source_sha256, harness.expected_wrapper_source_sha256,
    )
    if any(not value for value in required_strings):
        return CheckResult("V07", False, "HARNESS_TAMPERED", True, "mandatory harness identity evidence is absent")
    if harness.harness_address.lower() != witness_harness_address.lower():
        return CheckResult("V07", False, "HARNESS_TAMPERED", True, "observed harness address differs from witness declaration")
    if harness.observed_runtime_sha256 != harness.expected_runtime_sha256 or harness.observed_source_sha256 != harness.expected_source_sha256:
        return CheckResult("V07", False, "HARNESS_TAMPERED", True, "harness source/runtime hash mismatch")
    if harness.wrapper_runtime_sha256 != harness.expected_wrapper_runtime_sha256 or harness.wrapper_source_sha256 != harness.expected_wrapper_source_sha256:
        return CheckResult("V07", False, "HARNESS_TAMPERED", True, "wrapper source/runtime hash mismatch")
    if harness.observed_wrapper_depth != harness.expected_wrapper_depth:
        return CheckResult("V07", False, "HARNESS_TAMPERED", True, "wrapper/harness call depth mismatch")
    if harness.assertion_emitter.lower() != harness.harness_address.lower() or harness.assertion_event_caller.lower() != harness.wrapper_address.lower():
        return CheckResult("V07", False, "HARNESS_TAMPERED", True, "AssertionChecked origin is not the declared harness/wrapper")
    if harness.assertion_event_count != 1:
        return CheckResult("V07", False, "HARNESS_TAMPERED", True, "exactly one assertion event is required for this witness")
    if harness.economic_event_count != 1:
        return CheckResult("V07", False, "ECON_INCOMPLETE", True, "exactly one economic snapshot is required")
    if harness.control_event_count != 1:
        return CheckResult("V07", False, "HARNESS_TAMPERED", True, "exactly one mechanically observed control event is required")
    if not _norm(harness.expected_actor_addresses).issubset(_norm(harness.observed_actor_addresses)):
        return CheckResult("V07", False, "COVERAGE_INCOMPLETE", True, "declared actor coverage is incomplete")
    if not _norm(harness.expected_token_addresses).issubset(_norm(harness.observed_token_addresses)):
        return CheckResult("V07", False, "COVERAGE_INCOMPLETE", True, "declared token coverage is incomplete")
    if not economics.evidence_complete:
        return CheckResult("V07", False, "ECON_INCOMPLETE", True, "economic evidence is incomplete")
    if economics.snapshot.gas_used is None or economics.snapshot.gas_price_wei is None:
        return CheckResult("V07", False, "ECON_INCOMPLETE", True, "gas evidence is missing")
    return CheckResult("V07", True, message="CREATE2, bytecode, source, wrapper, event origin, coverage and economic-boundary evidence are verified")

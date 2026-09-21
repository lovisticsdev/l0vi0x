from __future__ import annotations

from l0vi0x.chain.trace import TraceSummary
from l0vi0x.chain.witness import assert_harness_address
from .types import CheckResult, HarnessEvidence, EconomicEvidence


def _norm_set(values: tuple[str, ...]) -> set[str]:
    return {v.lower() for v in values}


def check(*, harness: HarnessEvidence | None, trace: TraceSummary | None, witness_harness_address: str, economics: EconomicEvidence | None) -> CheckResult:
    if harness is None or trace is None:
        return CheckResult("V07", False, "HARNESS_TAMPERED", True, "harness or trace evidence missing")
    if harness.harness_address.lower() != witness_harness_address.lower():
        return CheckResult("V07", False, "HARNESS_TAMPERED", True, "observed harness address differs from witness declaration")
    if not harness.observed_runtime_sha256 or not harness.expected_runtime_sha256:
        return CheckResult("V07", False, "HARNESS_TAMPERED", True, "runtime bytecode hashes are required")
    if harness.observed_runtime_sha256 != harness.expected_runtime_sha256:
        return CheckResult("V07", False, "HARNESS_TAMPERED", True, "runtime bytecode hash mismatch")
    if (harness.observed_source_sha256 is None) != (harness.expected_source_sha256 is None):
        return CheckResult("V07", False, "HARNESS_TAMPERED", True, "harness source hash evidence is incomplete")
    if harness.observed_source_sha256 and harness.expected_source_sha256 and harness.observed_source_sha256 != harness.expected_source_sha256:
        return CheckResult("V07", False, "HARNESS_TAMPERED", True, "harness source hash mismatch")
    if not harness.wrapper_callsite_sha256 or not harness.expected_wrapper_callsite_sha256:
        return CheckResult("V07", False, "HARNESS_TAMPERED", True, "wrapper callsite hashes are required")
    if harness.wrapper_callsite_sha256 != harness.expected_wrapper_callsite_sha256:
        return CheckResult("V07", False, "HARNESS_TAMPERED", True, "wrapper callsite hash mismatch")
    if harness.observed_wrapper_depth != harness.expected_wrapper_depth:
        return CheckResult("V07", False, "HARNESS_TAMPERED", True, "wrapper call depth mismatch")
    if harness.create2_deployer and harness.create2_salt and harness.create2_init_code_hex:
        try:
            actual = assert_harness_address(deployer=harness.create2_deployer, salt=harness.create2_salt, init_code=bytes.fromhex(harness.create2_init_code_hex.removeprefix("0x")), expected=harness.harness_address)
        except ValueError as exc:
            return CheckResult("V07", False, "HARNESS_TAMPERED", True, str(exc))
        if actual.lower() != harness.harness_address.lower():
            return CheckResult("V07", False, "HARNESS_TAMPERED", True, "CREATE2 harness address mismatch")
    if harness.assertion_emitter and harness.assertion_emitter.lower() != harness.harness_address.lower():
        return CheckResult("V07", False, "HARNESS_TAMPERED", True, "AssertionChecked emitter is not the fixed harness")
    if harness.assertion_event_depth is not None and harness.assertion_event_depth != harness.expected_wrapper_depth:
        return CheckResult("V07", False, "HARNESS_TAMPERED", True, "assertion event depth does not match expected wrapper depth")
    if harness.assertion_event_caller and harness.assertion_event_caller.lower() != harness.wrapper_address.lower():
        return CheckResult("V07", False, "HARNESS_TAMPERED", True, "assertion event caller is not the declared wrapper")
    observed_actors = _norm_set(harness.observed_actor_addresses) | {x.from_address.lower() for x in trace.transfers} | {x.to_address.lower() for x in trace.transfers}
    observed_tokens = _norm_set(harness.observed_token_addresses) | {x.token.lower() for x in trace.transfers}
    if not _norm_set(harness.expected_actor_addresses).issubset(observed_actors):
        return CheckResult("V07", False, "COVERAGE_INCOMPLETE", True, "one or more declared actors were not observed")
    if not _norm_set(harness.expected_token_addresses).issubset(observed_tokens):
        return CheckResult("V07", False, "COVERAGE_INCOMPLETE", True, "one or more declared tokens were not observed")
    if harness.wrapper_event_count < 1 or harness.harness_event_count < 1:
        return CheckResult("V07", False, "COVERAGE_INCOMPLETE", True, "required harness/wrapper evidence is absent")
    if economics is None or not economics.evidence_complete or economics.snapshot.gas_used is None:
        return CheckResult("V07", False, "ECON_INCOMPLETE", True, "economic snapshots/gas evidence incomplete")
    # Token transfer consistency: trace net flow must match the declared actor snapshot delta.
    expected_tokens = _norm_set(harness.expected_token_addresses)
    for token in expected_tokens:
        trace_delta = 0
        for transfer in trace.transfers:
            if transfer.phase != "witness" or transfer.token.lower() != token:
                continue
            if transfer.to_address.lower() in _norm_set(harness.expected_actor_addresses):
                trace_delta += transfer.amount
            if transfer.from_address.lower() in _norm_set(harness.expected_actor_addresses):
                trace_delta -= transfer.amount
        before = economics.snapshot.token_before.get(token, economics.snapshot.token_before.get(token.lower()))
        after = economics.snapshot.token_after.get(token, economics.snapshot.token_after.get(token.lower()))
        if before is None or after is None or (after - before) != trace_delta:
            return CheckResult("V07", False, "ECON_INCOMPLETE", True, f"token transfer consistency mismatch for {token}", {"trace_delta": trace_delta, "snapshot_delta": None if before is None or after is None else after - before})
    return CheckResult("V07", True, message="harness integrity, coverage, and economic transfer checks pass")

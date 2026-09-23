from __future__ import annotations

from dataclasses import replace
import hashlib
from pathlib import Path

from l0vi0x.chain.trace import TraceFrame, TraceSummary
from l0vi0x.core.models import Witness, WitnessAssertion
from l0vi0x.verifier.assertion_extract import check as check_assertion
from l0vi0x.verifier.control_run import derive as derive_control_evidence
from l0vi0x.verifier.econ_check import check as check_econ
from l0vi0x.verifier.flow import route_verification_failure
from l0vi0x.verifier.harness_integrity import check as check_harness
from l0vi0x.verifier.types import ControlEvidence, EconomicEvidence, HarnessEvidence, SnapshotEvidence

ROOT = Path(__file__).resolve().parents[1]
ACTOR = "0x000000000000000000000000000000000000a11c"
TOKEN = "0x000000000000000000000000000000000000b0b0"
HARNESS = "0x0000000000000000000000000000000000001111"
WRAPPER = "0x0000000000000000000000000000000000002222"


def _witness() -> Witness:
    return Witness(
        witness_class="local_deployment",
        chain_id=31337,
        commit="fixture-commit",
        compiler={"solc": "0.8.24", "optimizer": True, "optimizer_runs": 200, "evm_version": "cancun"},
        test_file="test/Witness.t.sol",
        test_name="test_witness",
        control_test_name="test_control",
        initial_capital_wei=100,
        max_time_advance_s=1,
        max_block_advance=1,
        declared_actors=[ACTOR],
        declared_tokens=[TOKEN],
        token_decimals={TOKEN: 18},
        setup_budget={"native_wei": 100},
        assertions=[WitnessAssertion(
            id="A1", kind="balance_delta", target="balance_delta", operator="eq", expected=7,
            observed_record="AssertionChecked", actor=ACTOR, token=TOKEN,
        )],
        template_sha256="template",
        attack_body_sha256="attack",
        harness_address=HARNESS,
        harness_create2_salt="0x" + "00" * 32,
        harness_create2_deployer=WRAPPER,
        harness_init_code_sha256="init",
        harness_runtime_sha256="runtime",
        harness_source_path="test/lib/EconHarness.sol",
        harness_source_sha256="source",
        wrapper_address=WRAPPER,
        wrapper_runtime_sha256="wrapper-runtime",
        wrapper_source_path="test/Create2HarnessFactory.sol",
        wrapper_source_sha256="wrapper-source",
        expected_wrapper_depth=2,
        wrapper_callsite_sha256="wrapper-callsite",
        env_hash="env-1",
    )


def _trace(*, ok: bool = True, observed: int = 7, emitter: str = HARNESS, caller: str = WRAPPER) -> TraceSummary:
    frame = TraceFrame(
        depth=2, kind="call", to=HARNESS, caller=caller, gas_used=1000,
        logs=(
            {"event": "AssertionContext", "id": "A1", "actor": ACTOR, "token": TOKEN},
            {"event": "AssertionChecked", "id": "A1", "kind": "balance_delta", "target": "balance_delta",
             "operator": "eq", "observed": observed, "expected": 7, "ok": ok, "emitter": emitter, "caller": caller,
             "actor": ACTOR, "token": TOKEN, "depth": 2},
        ),
    )
    return TraceSummary(
        frames=(frame,), cheatcodes=(), transfers=(), assertion_events=(frame.logs[1],),
        cumulative_warp_s=0, cumulative_roll=0, initial_timestamp=1, final_timestamp=1,
        initial_block=1, final_block=1, gas_used=1000, raw_sha256=hashlib.sha256(b"trace").hexdigest(),
    )


def _control_trace(*, state_changed: bool = False, include_assertion: bool = False) -> TraceSummary:
    logs: list[dict[str, object]] = [{"event": "ControlObserved", "id": "A1", "state_changed": state_changed}]
    if include_assertion:
        logs.append({"event": "AssertionChecked", "id": "A1"})
    frame = TraceFrame(depth=1, kind="call", to=WRAPPER, caller="0x0000000000000000000000000000000000003333", gas_used=500, logs=tuple(logs))
    return TraceSummary(
        frames=(frame,), cheatcodes=(), transfers=(), assertion_events=tuple(x for x in logs if x.get("event") == "AssertionChecked"),
        cumulative_warp_s=0, cumulative_roll=0, initial_timestamp=1, final_timestamp=1, initial_block=1, final_block=1,
        gas_used=500, raw_sha256=hashlib.sha256(b"control").hexdigest(),
    )


def _control(state_changed: bool = False, assertion_count: int = 0) -> ControlEvidence:
    return ControlEvidence(
        passed=True, matching_assertion=assertion_count > 0, observed_state_changed=state_changed,
        assertion_event_count=assertion_count,
    )


def _economics(*, complete: bool = True, sensitivity: dict[str, float] | None = None, gas_price: int | None = 1) -> EconomicEvidence:
    values = dict(sensitivity or {"minus_500bps": 6.65, "base": 7.0, "plus_500bps": 7.35})
    scenarios = {
        "minus_500bps": {"bps": -500, "net_usd": values.get("minus_500bps", 6.65)},
        "base": {"bps": 0, "net_usd": values.get("base", 7.0)},
        "plus_500bps": {"bps": 500, "net_usd": values.get("plus_500bps", 7.35)},
    }
    return EconomicEvidence(
        snapshot=SnapshotEvidence(
            native_before_wei=100, native_after_wei=100, token_before={TOKEN: 0}, token_after={TOKEN: 7},
            gas_used=1000, gas_price_wei=gas_price, declared_capital_wei=100, observed_capital_wei=100,
            protocol_assets_delta_wei=-7, sensitivity=values, sensitivity_scenarios=scenarios,
        ),
        pinned_block=None, sensitivity=values, sensitivity_scenarios=scenarios,
        price_sources=("fixture",), evidence_complete=complete,
    )


def _harness(*, control_count: int = 1, assertion_count: int = 1, actor: str = ACTOR) -> HarnessEvidence:
    return HarnessEvidence(
        harness_address=HARNESS, wrapper_address=WRAPPER, expected_wrapper_depth=2, observed_wrapper_depth=2,
        observed_runtime_sha256="runtime", expected_runtime_sha256="runtime", observed_source_sha256="source", expected_source_sha256="source",
        wrapper_runtime_sha256="wrapper-runtime", expected_wrapper_runtime_sha256="wrapper-runtime",
        wrapper_source_sha256="wrapper-source", expected_wrapper_source_sha256="wrapper-source",
        create2_deployer=WRAPPER, create2_salt="0x" + "00" * 32, create2_init_code_sha256="init",
        assertion_emitter=HARNESS, assertion_event_depth=2, assertion_event_caller=WRAPPER,
        observed_actor_addresses=(actor,), observed_token_addresses=(TOKEN,), expected_actor_addresses=(ACTOR,), expected_token_addresses=(TOKEN,),
        assertion_event_count=assertion_count, economic_event_count=1, control_event_count=control_count,
    )


def test_assertion_exactly_matches_declaration() -> None:
    witness = _witness()
    result = check_assertion(witness=witness, assertion_events=_trace().assertion_events, control=_control())
    assert result.ok


def test_assertion_actor_or_token_mismatch_fails_v06() -> None:
    witness = _witness()
    bad = dict(_trace().assertion_events[0], actor="0x000000000000000000000000000000000000dead")
    result = check_assertion(witness=witness, assertion_events=(bad,), control=_control())
    assert result.code == "ASSERT_MISMATCH"


def test_control_is_derived_from_control_trace() -> None:
    witness = _witness()
    derived = derive_control_evidence(attack=_trace(), control=_control_trace(), witness=witness)
    assert derived.passed
    assert not derived.observed_state_changed
    assert derived.assertion_event_count == 0


def test_control_state_change_is_vacuuous() -> None:
    witness = _witness()
    derived = derive_control_evidence(attack=_trace(), control=_control_trace(state_changed=True), witness=witness)
    result = check_assertion(witness=witness, assertion_events=_trace().assertion_events, control=derived)
    assert result.code == "ASSERT_VACUOUS"


def test_v07_requires_exact_control_event_count() -> None:
    result = check_harness(harness=_harness(control_count=0), trace=_trace(), witness_harness_address=HARNESS, economics=_economics())
    assert result.code == "HARNESS_TAMPERED"


def test_v07_requires_actor_coverage() -> None:
    result = check_harness(harness=_harness(actor="0x000000000000000000000000000000000000dead"), trace=_trace(), witness_harness_address=HARNESS, economics=_economics())
    assert result.code == "COVERAGE_INCOMPLETE"


def test_v07_requires_economic_snapshot() -> None:
    result = check_harness(harness=replace(_harness(), economic_event_count=0), trace=_trace(), witness_harness_address=HARNESS, economics=_economics())
    assert result.code == "ECON_INCOMPLETE"


def test_v09_fails_closed_when_evidence_is_incomplete() -> None:
    result = check_econ(_economics(complete=False), production_required=False)
    assert result.code == "ECON_INCOMPLETE"


def test_v09_requires_exact_sensitivity_set() -> None:
    result = check_econ(_economics(sensitivity={"base": 7.0}), production_required=False)
    assert result.code == "SENSITIVITY_INCOMPLETE"


def test_v09_requires_actual_gas_price() -> None:
    result = check_econ(_economics(gas_price=None), production_required=False)
    assert result.code == "ECON_INCOMPLETE"


def test_v09_requires_head_replay_for_production() -> None:
    evidence = replace(_economics(), head_replay_passed=False)
    result = check_econ(evidence, production_required=True)
    assert result.code == "HEAD_REPLAY_FAIL"


def test_failure_routing_codes_match_plan() -> None:
    assert route_verification_failure("CONFIRMED", "ASSERT_MISMATCH") == "INVESTIGATING"
    assert route_verification_failure("CONFIRMED", "NONDETERMINISTIC_TRACE") == "PARKED"
    assert route_verification_failure("CONFIRMED", "KNOWN_ISSUE") == "CLOSED_DUPLICATE"


def test_m1b_foundry_image_and_lock_are_digest_pinned() -> None:
    compose = Path("docker/compose.m1b.yaml").read_text(encoding="utf-8")
    dockerfile = Path("docker/Dockerfile.sandbox").read_text(encoding="utf-8")
    lock = Path("config/tools.m1b.lock.yaml").read_text(encoding="utf-8")

    expected = "ghcr.io/foundry-rs/foundry@sha256:2e4287278639262de76db72477301d5d3212fa1b1cce710d7d148750a46ce9e7"
    assert expected in compose
    assert expected in dockerfile
    assert f"ref: {expected}" in lock


def test_economic_measure_derives_three_price_scenarios_from_raw_inputs() -> None:
    from l0vi0x.chain.econ import EconomicInputs, measure
    from l0vi0x.chain.prices import PricePoint

    token_price = PricePoint(asset=TOKEN, usd_per_unit=1.0, decimals=18, source="fixture", block=1)
    native_price = PricePoint(asset="native", usd_per_unit=2000.0, decimals=18, source="fixture", block=1)
    report = measure(EconomicInputs(
        native_before_wei=0, native_after_wei=0,
        token_before={TOKEN: 0}, token_after={TOKEN: 7},
        token_decimals={TOKEN: 18}, prices={TOKEN: token_price}, native_price=native_price,
        gas_used=0, gas_price_wei=0, declared_capital_wei=100, observed_capital_wei=100,
    ))
    assert set(report.sensitivity_scenarios) == {"minus_500bps", "base", "plus_500bps"}
    assert report.sensitivity_scenarios["minus_500bps"]["bps"] == -500
    assert report.sensitivity_scenarios["base"]["bps"] == 0
    assert report.sensitivity_scenarios["plus_500bps"]["bps"] == 500
    assert report.sensitivity["minus_500bps"] < report.sensitivity["base"] < report.sensitivity["plus_500bps"]

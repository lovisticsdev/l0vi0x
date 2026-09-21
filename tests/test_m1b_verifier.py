from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path
import tempfile
from datetime import datetime, timezone

import yaml

from l0vi0x.chain.trace import parse_trace
from l0vi0x.chain.witness import witness_hash
from l0vi0x.core.certificates import issue
from l0vi0x.core.models import (
    Capability,
    Hypothesis,
    KnownIssue,
    Scope,
    ScopeTarget,
    Span,
    Witness,
    WitnessAssertion,
)
from l0vi0x.verifier.pipeline import verify
from l0vi0x.verifier.types import (
    BuildEvidence,
    ControlEvidence,
    DuplicateEvidence,
    EconomicEvidence,
    HarnessEvidence,
    ReplayEvidence,
    SnapshotEvidence,
    VerificationContext,
)
from l0vi0x.verifier.flow import route_verification_failure

ROOT = Path(__file__).resolve().parents[1]
ACTOR = "0x000000000000000000000000000000000000a11c"
TOKEN = "0x000000000000000000000000000000000000b0b0"
HARNESS = "0x0000000000000000000000000000000000001111"
WRAPPER = "0x0000000000000000000000000000000000002222"

def _span(root: Path) -> Span:
    p = root / "fixture.sol"
    p.write_text("line one\nline two\nline three\n", encoding="utf-8")
    raw = "line two\n"
    return Span(file="fixture.sol", start=2, end=2, sha256=hashlib.sha256(raw.encode()).hexdigest())

def _witness() -> Witness:
    return Witness(
        witness_class="local_deployment",
        chain_id=31337,
        commit="fixture-commit",
        compiler={"solc": "0.8.24"},
        test_file="test/Witness.t.sol",
        test_name="test_witness",
        control_test_name="test_control",
        initial_capital_wei=100,
        max_time_advance_s=1,
        max_block_advance=1,
        declared_actors=[ACTOR],
        declared_tokens=[TOKEN],
        setup_budget={"native_wei": 100},
        assertions=[WitnessAssertion(id="A1", kind="custom", target="credit", operator="eq", expected=7, observed_record="AssertionChecked")],
        template_sha256="template",
        attack_body_sha256="attack",
        harness_address=HARNESS,
        harness_create2_salt="0x" + "00" * 32,
        expected_wrapper_depth=2,
        wrapper_callsite_sha256="wrapper-callsite",
        env_hash="env-1",
    )

def _hypothesis(span: Span) -> Hypothesis:
    now = datetime.now(timezone.utc)
    return Hypothesis(
        id="H-M1B-001", claim="credit increases without authorization", target=span,
        invariant_id="INV-1", capabilities=[Capability.PERMISSIONLESS], channel="lens",
        protocol_type="fixture", mechanism_tag="accounting", prior_p=0.5, est_impact="$7",
        est_cost="$0.01", created_at=now, updated_at=now,
        provenance={"commit": "fixture-commit"},
    )

def _scope() -> Scope:
    return Scope(
        version=1, platform="fixture", program_ref="fixture", commit="fixture-commit",
        confidentiality="public", in_scope=[ScopeTarget(id="T1", kind="file", path="fixture.sol")],
        out_of_scope=[], excluded_classes=[], dependencies=[], concurrent_programs=[], deployed=False,
        attacker_capital_wei=100, poc_required=True, severity_model_ref="fixture",
    )

def _trace(*, cheatcodes=None, actor=ACTOR, token=TOKEN, event_ok=True, emit=HARNESS, depth=2):
    frame = {
        "depth": depth, "kind": "call", "to": HARNESS, "caller": WRAPPER,
        "gas_used": 1000, "logs": [{"event":"AssertionChecked", "id":"A1", "kind":"custom", "target":"credit", "operator":"eq", "observed":7, "expected":7, "ok":event_ok, "emitter":emit}],
        "erc20_transfer": {"token":token, "from":"0x0000000000000000000000000000000000000000", "to":actor, "amount":7},
    }
    records = [frame]
    for c in cheatcodes or []:
        records.append({"depth":2,"phase":"witness","to":"0x7109709ecfa91a80626ff3989d68f67f5b1dd12d","cheatcode":c, "absolute": 1001 if c == "warp" else 11 if c == "roll" else None, "args": [1001] if c == "warp" else [11] if c == "roll" else []})
    return parse_trace({"initial_timestamp":1000,"initial_block":10,"trace":records}, cheatcode_catalog=yaml.safe_load((ROOT/"config/policy/cheatcode_categories.yaml").read_text())['categories'])

def _context(tmp: Path, *, trace=None, cert=None, key=None, env_hashes=None, records=None, control_hashes=None, actor=ACTOR, economics=None, harness=None, duplicate=None, production_required=False) -> VerificationContext:
    span = _span(tmp)
    witness = _witness()
    scope = _scope()
    hyp = _hypothesis(span)
    trace = trace or _trace()
    key = key or hashlib.sha256(b"m1b-key").digest()
    hashes = list(records or [trace.observed_records_sha256()] * 3)
    envs = list(env_hashes or [witness.env_hash] * 3)
    controls = list(control_hashes or ["control-1"] * 3)
    policy = yaml.safe_load((ROOT/"config/policy/cheatcode_policy.yaml").read_text())
    catalog = yaml.safe_load((ROOT/"config/policy/cheatcode_categories.yaml").read_text())
    from l0vi0x.verifier.cheatcode_policy import policy_hash
    p_hash = policy_hash(ROOT/"config/policy/cheatcode_policy.yaml", ROOT/"config/policy/cheatcode_categories.yaml")
    aggregate = hashlib.sha256(__import__('json').dumps(hashes, separators=(",",":")).encode()).hexdigest()
    cert = cert or issue(key, certificate_id="CERT-M1B", witness_sha256=witness_hash(witness), env_hash=witness.env_hash,
                         runs=3, observed_records_sha256=aggregate, trace_policy_sha256=p_hash, control_sha256=controls[0])
    replay = ReplayEvidence(certificate=cert, traces=(trace, trace, trace), environment_hashes=tuple(envs), control_hashes=tuple(controls), observed_record_hashes=tuple(hashes), certificate_key=key, raw_artifact_paths=("r1","r2","r3"))
    if economics is None:
        economics = EconomicEvidence(snapshot=SnapshotEvidence(native_before_wei=1_000_000, native_after_wei=1_000_000, token_before={TOKEN:0}, token_after={TOKEN:7}, gas_used=1000, gas_price_wei=1, declared_capital_wei=100, observed_capital_wei=100, slippage_bps=0, sensitivity={"base":1.0}), production_required=production_required, pinned_block=10, price_sources=("fixture-oracle",))
    if harness is None:
        harness = HarnessEvidence(
            harness_address=HARNESS, wrapper_address=WRAPPER, expected_wrapper_depth=2, observed_wrapper_depth=2,
            observed_runtime_sha256="runtime", expected_runtime_sha256="runtime",
            observed_source_sha256="source", expected_source_sha256="source",
            wrapper_callsite_sha256="wrapper-callsite", expected_wrapper_callsite_sha256="wrapper-callsite",
            assertion_emitter=HARNESS, assertion_event_depth=2, assertion_event_caller=WRAPPER,
            observed_actor_addresses=(actor,), observed_token_addresses=(TOKEN,), expected_actor_addresses=(actor,), expected_token_addresses=(TOKEN,),
            wrapper_event_count=1, harness_event_count=1,
        )
    return VerificationContext(
        root=tmp, hypothesis=hyp, scope=scope, witness=witness,
        replay=replay, build=BuildEvidence(clean=True, tool_lock_verified=True),
        control=ControlEvidence(passed=True, matching_assertion=False, observed_state_changed=False),
        harness=harness, economics=economics, duplicate=duplicate,
        current_policy_path=ROOT/"config/policy/cheatcode_policy.yaml", cheatcode_catalog_path=ROOT/"config/policy/cheatcode_categories.yaml",
        production_l7_required=production_required, pinned_impact_usd=7.0,
    )

def test_oracle_style_fixture_v01_v07_pass(tmp_path):
    ctx = _context(tmp_path)
    result = verify(ctx)
    assert result.passed
    assert all(result_for.ok for result_for in result.checks[:7])
    assert {c.check_id for c in result.checks[:7]} == {"V01","V02","V03","V04","V05","V06","V07"}
    v09 = next(c for c in result.checks if c.check_id == "V09")
    assert v09.details["severity_basis"] == "pinned_block"
    assert v09.details["pinned_block_impact_usd"] == 7.0

def test_out_of_scope_fails_v01(tmp_path):
    ctx = _context(tmp_path)
    ctx.scope.out_of_scope.append("fixture.sol")
    result = verify(ctx)
    assert result.checks[0].code == "OUT_OF_SCOPE"
    assert result.next_state == "CLOSED"

def test_known_issue_fails_v01(tmp_path):
    ctx = _context(tmp_path)
    issue = KnownIssue(id="K1", title="same", claim=ctx.hypothesis.claim, source="fixture")
    ctx = replace(ctx, known_issues=(issue,))
    result = verify(ctx)
    assert result.checks[0].code == "KNOWN_ISSUE"
    assert result.next_state == "CLOSED_DUPLICATE"

def test_span_drift_fails_v02(tmp_path):
    ctx = _context(tmp_path)
    (tmp_path/"fixture.sol").write_text("changed\n", encoding="utf-8")
    result = verify(ctx)
    assert result.checks[1].code == "SPAN_DRIFT"

def test_bad_build_fails_v03(tmp_path):
    ctx = _context(tmp_path)
    ctx = replace(ctx, build=BuildEvidence(clean=False, build_stderr="compile failed"))
    result = verify(ctx)
    assert result.checks[2].code == "BUILD_FAIL"

def test_environment_nondeterminism_is_distinct(tmp_path):
    ctx = _context(tmp_path, env_hashes=["a","a","b"])
    result = verify(ctx)
    assert result.checks[3].code == "NONDETERMINISTIC_ENV"
    assert result.next_state == "INVESTIGATING"

def test_trace_nondeterminism_parks(tmp_path):
    t = _trace()
    h1 = t.observed_records_sha256(); h2 = hashlib.sha256(b"different").hexdigest()
    ctx = _context(tmp_path, records=[h1,h2,h1])
    result = verify(ctx)
    assert result.checks[3].code == "NONDETERMINISTIC_TRACE"
    assert result.next_state == "PARKED"
    assert result.route_reason == "characterize_conditional_trigger"

def test_certificate_policy_tamper_fails_v04(tmp_path):
    ctx = _context(tmp_path)
    cert = issue(hashlib.sha256(b"m1b-key").digest(), certificate_id="CERT-M1B", witness_sha256=witness_hash(ctx.witness), env_hash=ctx.witness.env_hash, runs=3, observed_records_sha256=ctx.replay.certificate.observed_records_sha256, trace_policy_sha256="bad", control_sha256="control-1")
    ctx = replace(ctx, replay=replace(ctx.replay, certificate=cert))
    result = verify(ctx)
    assert result.checks[3].code == "CERTIFICATE_INVALID"

def test_trace_missing_cannot_authorize(tmp_path):
    ctx = _context(tmp_path)
    ctx = replace(ctx, replay=ReplayEvidence(certificate=None, traces=(), environment_hashes=(), control_hashes=(), observed_record_hashes=(), certificate_key=None))
    result = verify(ctx)
    assert result.checks[3].code == "CERTIFICATE_INVALID"

def test_missing_structured_trace_fails_v05(tmp_path):
    from l0vi0x.verifier.cheatcode_policy import check as policy_check
    result = policy_check(trace=None, witness_class="local_deployment", policy_path=ROOT/"config/policy/cheatcode_policy.yaml", catalog_path=ROOT/"config/policy/cheatcode_categories.yaml")
    assert result.code == "TRACE_MISSING"

def test_policy_unclassified_fails_v05(tmp_path):
    trace = _trace(cheatcodes=["unknown_cheatcode"])
    ctx = _context(tmp_path, trace=trace)
    result = verify(ctx)
    assert result.checks[4].code == "POLICY_VIOLATION"

def test_fork_cheatcode_mutation_fails_v05(tmp_path):
    trace = _trace(cheatcodes=["deal"])
    from l0vi0x.verifier.cheatcode_policy import check as policy_check
    result = policy_check(trace=trace, witness_class="deployed_fork", policy_path=ROOT/"config/policy/cheatcode_policy.yaml", catalog_path=ROOT/"config/policy/cheatcode_categories.yaml")
    assert result.code == "POLICY_VIOLATION"

def test_hoax_must_have_decomposed_effects(tmp_path):
    trace = _trace(cheatcodes=["hoax"])
    ctx = _context(tmp_path, trace=trace)
    result = verify(ctx)
    assert result.checks[4].code == "POLICY_VIOLATION"

def test_decomposed_hoax_effects_are_accepted_without_opaque_helper(tmp_path):
    records = [{"depth":2,"phase":"setup","to":"0x7109709ecfa91a80626ff3989d68f67f5b1dd12d","cheatcode":name,"args":[]} for name in ("deal","prank")]
    trace = parse_trace({"initial_timestamp":1000,"initial_block":10,"trace":records}, cheatcode_catalog=yaml.safe_load((ROOT/"config/policy/cheatcode_categories.yaml").read_text())['categories'])
    from l0vi0x.verifier.cheatcode_policy import check as policy_check
    result = policy_check(trace=trace, witness_class="local_deployment", policy_path=ROOT/"config/policy/cheatcode_policy.yaml", catalog_path=ROOT/"config/policy/cheatcode_categories.yaml")
    assert result.ok


def test_opaque_hoax_is_rejected_even_if_effects_are_also_present(tmp_path):
    records = [{"depth":2,"phase":"setup","to":"0x7109709ecfa91a80626ff3989d68f67f5b1dd12d","cheatcode":name,"args":[]} for name in ("hoax","deal","prank")]
    trace = parse_trace({"initial_timestamp":1000,"initial_block":10,"trace":records}, cheatcode_catalog=yaml.safe_load((ROOT/"config/policy/cheatcode_categories.yaml").read_text())['categories'])
    from l0vi0x.verifier.cheatcode_policy import check as policy_check
    result = policy_check(trace=trace, witness_class="local_deployment", policy_path=ROOT/"config/policy/cheatcode_policy.yaml", catalog_path=ROOT/"config/policy/cheatcode_categories.yaml")
    assert result.code == "POLICY_VIOLATION"

def test_assertion_mismatch_fails_v06(tmp_path):
    trace = _trace(event_ok=False)
    ctx = _context(tmp_path, trace=trace)
    result = verify(ctx)
    assert result.checks[5].code == "ASSERT_MISMATCH"

def test_control_reproducing_effect_fails_v06(tmp_path):
    ctx = _context(tmp_path)
    ctx = replace(ctx, control=ControlEvidence(passed=True, matching_assertion=True, observed_state_changed=True))
    result = verify(ctx)
    assert result.checks[5].code == "ASSERT_VACUOUS"

def test_forged_assertion_emitter_fails_v07(tmp_path):
    ctx = _context(tmp_path)
    bad = replace(ctx.harness, assertion_emitter="0x0000000000000000000000000000000000009999")
    ctx = replace(ctx, harness=bad)
    result = verify(ctx)
    assert result.checks[6].code == "HARNESS_TAMPERED"

def test_missing_actor_fails_v07(tmp_path):
    ctx = _context(tmp_path)
    declared = "0x000000000000000000000000000000000000dead"
    bad = replace(ctx.harness, expected_actor_addresses=(declared,), observed_actor_addresses=(ACTOR,))
    ctx = replace(ctx, harness=bad)
    result = verify(ctx)
    assert result.checks[6].code == "COVERAGE_INCOMPLETE"

def test_transfer_mismatch_fails_v07(tmp_path):
    ctx = _context(tmp_path)
    econ = EconomicEvidence(snapshot=SnapshotEvidence(native_before_wei=1_000_000, native_after_wei=1_000_000, token_before={TOKEN:0}, token_after={TOKEN:6}, gas_used=1000, gas_price_wei=1, declared_capital_wei=100, observed_capital_wei=100, slippage_bps=0, sensitivity={"base":1.0}), price_sources=("fixture-oracle",), pinned_block=10)
    ctx = replace(ctx, economics=econ)
    result = verify(ctx)
    assert result.checks[6].code == "ECON_INCOMPLETE"

def test_duplicate_is_soft_and_human_routed(tmp_path):
    ctx = _context(tmp_path, duplicate=DuplicateEvidence(exact_match_id="F-OLD"))
    result = verify(ctx)
    assert result.passed
    assert result.route_reason == "human_review:LIKELY_DUPLICATE"

def test_fragile_economics_is_soft(tmp_path):
    econ = EconomicEvidence(snapshot=SnapshotEvidence(native_before_wei=1_000_000, native_after_wei=1_000_000, token_before={TOKEN:0}, token_after={TOKEN:7}, gas_used=1000, gas_price_wei=1, declared_capital_wei=10, observed_capital_wei=11, slippage_bps=0, sensitivity={"base":1.0}), realism_flags=("capital_mismatch",), price_sources=("fixture-oracle",), pinned_block=10)
    ctx = _context(tmp_path, economics=econ)
    result = verify(ctx)
    assert result.passed
    assert result.route_reason == "human_review:FRAGILE"

def test_head_replay_is_hard_when_required(tmp_path):
    econ = EconomicEvidence(snapshot=SnapshotEvidence(native_before_wei=1_000_000, native_after_wei=1_000_000, token_before={TOKEN:0}, token_after={TOKEN:7}, gas_used=1000, gas_price_wei=1, declared_capital_wei=100, observed_capital_wei=100, slippage_bps=0, sensitivity={"base":1.0}, protocol_assets_delta_wei=7), price_sources=("fixture-oracle",), pinned_block=10, head_replay_passed=False)
    ctx = _context(tmp_path, economics=econ, production_required=True)
    result = verify(ctx)
    assert any(c.code == "HEAD_REPLAY_FAIL" for c in result.checks)
    assert not result.passed

def test_upstream_state_mismatch_is_hard_when_required(tmp_path):
    econ = EconomicEvidence(snapshot=SnapshotEvidence(native_before_wei=1_000_000, native_after_wei=1_000_000, token_before={TOKEN:0}, token_after={TOKEN:7}, gas_used=1000, gas_price_wei=1, declared_capital_wei=100, observed_capital_wei=100, slippage_bps=0, sensitivity={"base":1.0}, protocol_assets_delta_wei=7), price_sources=("fixture-oracle",), pinned_block=10, upstream_state_match=False)
    ctx = _context(tmp_path, economics=econ, production_required=True)
    result = verify(ctx)
    assert any(c.code == "UPSTREAM_STATE_MISMATCH" for c in result.checks)
    assert not result.passed

def test_failure_routing_codes_match_plan():
    assert route_verification_failure("CONFIRMED", "ASSERT_MISMATCH") == "INVESTIGATING"
    assert route_verification_failure("CONFIRMED", "NONDETERMINISTIC_TRACE") == "PARKED"
    assert route_verification_failure("CONFIRMED", "KNOWN_ISSUE") == "CLOSED_DUPLICATE"

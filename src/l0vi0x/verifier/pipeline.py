from __future__ import annotations

import hashlib
import json
from pathlib import Path

from l0vi0x.core.certificates import verify as verify_certificate
from l0vi0x.tools.forge import build as forge_build
from l0vi0x.tools.lock import verify_binary_lock

from .assertion_extract import check as check_assertion
from .cheatcode_policy import check as check_policy, policy_hash
from .duplicate import check as check_duplicate
from .econ_check import check as check_econ
from .eligibility import check as check_eligibility
from .harness_integrity import check as check_harness
from .span_check import check as check_span
from .types import CheckResult, ReplayEvidence, VerificationContext, VerificationResult


def _aggregate_records(replay: ReplayEvidence) -> str:
    return hashlib.sha256(json.dumps(list(replay.observed_record_hashes), separators=(",", ":")).encode()).hexdigest()


def _witness_hash(ctx: VerificationContext) -> str:
    from l0vi0x.chain.witness import witness_hash
    return witness_hash(ctx.witness)


def _v03(ctx: VerificationContext) -> CheckResult:
    if ctx.build is not None:
        if not ctx.build.clean:
            return CheckResult("V03", False, "BUILD_FAIL", True, ctx.build.build_stderr or "pinned build failed")
        if ctx.tool_lock_path:
            problems = verify_binary_lock(ctx.tool_lock_path)
            if problems:
                return CheckResult("V03", False, "BUILD_FAIL", True, "tool lock is not verified", {"problems": problems})
        elif not ctx.build.tool_lock_verified:
            return CheckResult("V03", False, "BUILD_FAIL", True, "pinned tool lock was not verified")
        return CheckResult("V03", True, message="project builds cleanly under verified toolchain")
    try:
        result = forge_build(root=ctx.root, forge_bin="forge", tool_runs_dir=ctx.root / "tool_runs")
    except Exception as exc:
        return CheckResult("V03", False, "BUILD_FAIL", True, str(exc))
    if not result.passed:
        return CheckResult("V03", False, "BUILD_FAIL", True, result.stderr or result.stdout)
    if ctx.tool_lock_path:
        problems = verify_binary_lock(ctx.tool_lock_path)
        if problems:
            return CheckResult("V03", False, "BUILD_FAIL", True, "tool lock is not verified", {"problems": problems})
    return CheckResult("V03", True, message="forge build succeeded")


def _v04(ctx: VerificationContext) -> CheckResult:
    replay = ctx.replay
    if replay is None or replay.certificate is None:
        return CheckResult("V04", False, "CERTIFICATE_INVALID", True, "replay certificate is missing")
    cert = replay.certificate
    if cert.runs < 3 or len(replay.traces) < 3 or len(replay.environment_hashes) < 3 or len(replay.observed_record_hashes) < 3:
        return CheckResult("V04", False, "CERTIFICATE_INVALID", True, "certificate does not contain >=3 fresh runs and complete evidence")
    if len(replay.raw_artifact_paths) < 3 or len(set(replay.raw_artifact_paths)) < 3:
        return CheckResult("V04", False, "CERTIFICATE_INVALID", True, "raw replay artifacts for three fresh copies are not retained")
    if len(set(replay.environment_hashes)) != 1:
        return CheckResult("V04", False, "NONDETERMINISTIC_ENV", True, "environment hashes differ across fresh copies")
    if len(set(replay.observed_record_hashes)) != 1:
        return CheckResult("V04", False, "NONDETERMINISTIC_TRACE", True, "structured observed-record hashes diverge with stable environment")
    if replay.control_hashes and len(set(replay.control_hashes)) != 1:
        return CheckResult("V04", False, "CERTIFICATE_INVALID", True, "control run hashes diverge")
    if replay.control_hashes and cert.control_sha256 != replay.control_hashes[0]:
        return CheckResult("V04", False, "CERTIFICATE_INVALID", True, "certificate is not bound to the observed control-run hash")
    if replay.certificate_key is None:
        return CheckResult("V04", False, "CERTIFICATE_INVALID", True, "certificate verification key unavailable to host verifier")
    if ctx.current_policy_path and ctx.cheatcode_catalog_path:
        expected_policy = policy_hash(ctx.current_policy_path, ctx.cheatcode_catalog_path, ctx.foundry_config_path)
        if expected_policy != cert.trace_policy_sha256:
            return CheckResult("V04", False, "CERTIFICATE_INVALID", True, "certificate policy hash does not match current trace policy")
    aggregate = _aggregate_records(replay)
    if cert.observed_records_sha256 != aggregate:
        return CheckResult("V04", False, "CERTIFICATE_INVALID", True, "certificate is not bound to observed-record hashes")
    if not verify_certificate(
        cert,
        replay.certificate_key,
        witness_sha256=_witness_hash(ctx),
        env_hash=ctx.witness.env_hash,
        observed_records_sha256=aggregate,
        trace_policy_sha256=cert.trace_policy_sha256,
        control_sha256=cert.control_sha256,
    ):
        return CheckResult("V04", False, "CERTIFICATE_INVALID", True, "certificate MAC or bound evidence does not verify")
    return CheckResult("V04", True, message="three fresh-copy replay runs are deterministic and certificate-valid")


def _failure_result(checks: list[CheckResult], code: str | None) -> VerificationResult:
    if code == "NONDETERMINISTIC_ENV":
        return VerificationResult(False, tuple(checks), next_state="INVESTIGATING", route_reason="repair:NONDETERMINISTIC_ENV")
    if code == "NONDETERMINISTIC_TRACE":
        return VerificationResult(False, tuple(checks), next_state="PARKED", route_reason="characterize_conditional_trigger")
    if code == "KNOWN_ISSUE":
        return VerificationResult(False, tuple(checks), next_state="CLOSED_DUPLICATE", route_reason="KNOWN_ISSUE")
    if code in {"OUT_OF_SCOPE", "SPAN_DRIFT"}:
        return VerificationResult(False, tuple(checks), next_state="CLOSED", route_reason=code)
    return VerificationResult(False, tuple(checks), next_state="INVESTIGATING", route_reason=f"repair:{code or 'verification_failure'}")


def verify(ctx: VerificationContext) -> VerificationResult:
    checks: list[CheckResult] = []

    # V01–V04: hard, ordered, and short-circuited.
    for current in (
        check_eligibility(hypothesis=ctx.hypothesis, scope=ctx.scope, known_issues=ctx.known_issues, witness_commit=ctx.witness.commit),
        check_span(root=ctx.root, span=ctx.hypothesis.target),
        _v03(ctx),
        _v04(ctx),
    ):
        checks.append(current)
        if current.hard and not current.ok:
            return _failure_result(checks, current.code)

    trace = ctx.replay.traces[0] if ctx.replay and ctx.replay.traces else None

    # V05: authoritative trace and sanitized-Foundry policy.
    current = check_policy(
        trace=trace,
        witness_class=ctx.witness.witness_class,
        policy_path=ctx.current_policy_path or Path("config/policy/cheatcode_policy.yaml"),
        catalog_path=ctx.cheatcode_catalog_path or Path("config/policy/cheatcode_categories.yaml"),
        foundry_config_path=ctx.foundry_config_path,
    )
    checks.append(current)
    if current.hard and not current.ok:
        return _failure_result(checks, current.code)

    # V06: declaration/observation and control-run anti-vacuity.
    current = check_assertion(
        witness=ctx.witness,
        assertion_events=trace.assertion_events if trace else (),
        control=ctx.control,
    )
    checks.append(current)
    if current.hard and not current.ok:
        return _failure_result(checks, current.code)

    # V07: bytecode/source/callsite/depth, actor/token coverage, harness event origin,
    # and transfer/snapshot consistency.
    current = check_harness(
        harness=ctx.harness,
        trace=trace,
        witness_harness_address=ctx.witness.harness_address,
        economics=ctx.economics,
    )
    checks.append(current)
    if current.hard and not current.ok:
        return _failure_result(checks, current.code)

    # V08 is intentionally soft/human-routed.
    current = check_duplicate(ctx.duplicate)
    checks.append(current)

    # V09 mixes soft realism warnings with hard production replay/state checks.
    current = check_econ(ctx.economics, production_required=ctx.production_l7_required, pinned_impact_usd=ctx.pinned_impact_usd)
    checks.append(current)
    if current.hard and not current.ok:
        return _failure_result(checks, current.code)

    soft_fail = next((c for c in checks if not c.hard and not c.ok), None)
    if soft_fail:
        return VerificationResult(True, tuple(checks), next_state="FINDING", route_reason=f"human_review:{soft_fail.code}")
    return VerificationResult(True, tuple(checks), next_state="FINDING", route_reason="all_m1b_checks_pass")

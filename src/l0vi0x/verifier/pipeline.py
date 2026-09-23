from __future__ import annotations

import json
from pathlib import Path
import yaml

from l0vi0x.core.certificates import verify as verify_certificate
from l0vi0x.tools.forge import build as forge_build
from l0vi0x.tools.lock import verify_binary_lock
from l0vi0x.chain.witness import witness_hash

from .assertion_extract import check as check_assertion
from .cheatcode_policy import check as check_policy, policy_hash
from .derived import derive_control, derive_economics, derive_harness, load_run
from .duplicate import check as check_duplicate
from .econ_check import check as check_econ
from .eligibility import check as check_eligibility
from .harness_integrity import check as check_harness
from .span_check import check as check_span
from .types import CheckResult, ReplayEvidence, VerificationContext, VerificationResult


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


def _v03(ctx: VerificationContext) -> CheckResult:
    if ctx.build is not None:
        if not ctx.build.clean:
            return CheckResult("V03", False, "BUILD_FAIL", True, ctx.build.build_stderr or "pinned build failed")
        if not ctx.build.tool_lock_verified:
            return CheckResult("V03", False, "BUILD_FAIL", True, "tool lock is not verified", {"problems": list(ctx.build.tool_lock_problems)})
        return CheckResult("V03", True, message="project builds cleanly under the verified toolchain")
    try:
        result = forge_build(root=ctx.root, forge_bin="forge", tool_runs_dir=ctx.root / "tool_runs")
    except Exception as exc:
        return CheckResult("V03", False, "BUILD_FAIL", True, str(exc))
    if not result.passed:
        return CheckResult("V03", False, "BUILD_FAIL", True, result.stderr or result.stdout)
    if ctx.tool_lock_path:
        problems = verify_binary_lock(ctx.tool_lock_path, required_names=list(ctx.build.required_tools), allow_extra=True)
        if problems:
            return CheckResult("V03", False, "BUILD_FAIL", True, "tool lock is not verified", {"problems": problems})
    return CheckResult("V03", True, message="forge build succeeded")


def _derived_runs(ctx: VerificationContext) -> list:
    replay = ctx.replay
    if replay is None:
        raise ValueError("replay evidence is missing")
    if len(replay.run_dirs) < 3:
        raise ValueError("at least three independent replay directories are required")
    trust_root = replay.root.resolve()
    runs = []
    for raw in replay.run_dirs:
        path = Path(raw).resolve()
        if not path.is_relative_to(trust_root):
            raise ValueError("replay run escapes declared replay trust root")
        runs.append(load_run(run_dir=path, witness=ctx.witness, cheatcode_catalog=_catalog(ctx)))
    return runs


def _catalog(ctx: VerificationContext) -> dict[str, str]:
    path = ctx.cheatcode_catalog_path
    if path is None:
        raise ValueError("current cheatcode catalog is required")
    raw = json.loads(json.dumps(yaml.safe_load(path.read_text(encoding="utf-8")) or {}))
    categories = raw.get("categories", raw)
    if not isinstance(categories, dict):
        raise ValueError("cheatcode catalog is malformed")
    return {str(k): str(v) for k, v in categories.items()}


def _v04(ctx: VerificationContext, derived: list) -> CheckResult:
    replay = ctx.replay
    assert replay is not None
    environments = [run.environment_hash for run in derived]
    controls = [run.control_hash for run in derived]
    records = [run.trace.observed_records_sha256() for run in derived]
    if len(set(environments)) != 1:
        return CheckResult("V04", False, "NONDETERMINISTIC_ENV", True, "environment hashes differ across fresh copies")
    if len(set(records)) != 1:
        return CheckResult("V04", False, "NONDETERMINISTIC_TRACE", True, "structured observed records differ with a stable environment")
    if len(set(controls)) != 1:
        return CheckResult("V04", False, "CONTROL_NONDETERMINISTIC", True, "control hashes differ across fresh copies")
    env_hash = environments[0]
    if env_hash != ctx.witness.env_hash:
        return CheckResult("V04", False, "ENV_DECLARATION_MISMATCH", True, "derived environment does not match witness declaration")
    aggregate = __import__("hashlib").sha256(json.dumps(records, separators=(",", ":")).encode()).hexdigest()
    control_sha = controls[0]
    expected_policy = policy_hash(ctx.current_policy_path, ctx.cheatcode_catalog_path, ctx.foundry_config_path) if ctx.current_policy_path and ctx.cheatcode_catalog_path else None
    if ctx.require_certificate:
        if replay.certificate is None or replay.certificate_key is None:
            return CheckResult("V04", False, "CERTIFICATE_INVALID", True, "final verification requires a certificate and host verification key")
        cert = replay.certificate
        if cert.runs < 3 or cert.env_hash != env_hash or cert.control_sha256 != control_sha or cert.observed_records_sha256 != aggregate:
            return CheckResult("V04", False, "CERTIFICATE_INVALID", True, "certificate binding does not match independently derived evidence")
        if expected_policy is not None and cert.trace_policy_sha256 != expected_policy:
            return CheckResult("V04", False, "CERTIFICATE_INVALID", True, "certificate policy hash does not match current policy/catalog")
        if not verify_certificate(
            cert,
            replay.certificate_key,
            witness_sha256=witness_hash(ctx.witness),
            env_hash=env_hash,
            observed_records_sha256=aggregate,
            trace_policy_sha256=cert.trace_policy_sha256,
            control_sha256=control_sha,
        ):
            return CheckResult("V04", False, "CERTIFICATE_INVALID", True, "certificate MAC does not verify against derived evidence")
    return CheckResult("V04", True, message="three fresh replay roots agree and all replay evidence is independently derived", details={"environment_hash": env_hash, "observed_records_sha256": aggregate, "control_sha256": control_sha})


def _load_prices(ctx: VerificationContext) -> dict:
    if ctx.price_evidence_path is None:
        return {}
    payload = json.loads(ctx.price_evidence_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("price evidence must be an object")
    return payload.get("prices", payload)


def verify(ctx: VerificationContext) -> VerificationResult:
    checks: list[CheckResult] = []

    for current in (
        check_eligibility(hypothesis=ctx.hypothesis, scope=ctx.scope, known_issues=ctx.known_issues, witness_commit=ctx.witness.commit),
        check_span(root=ctx.root, span=ctx.hypothesis.target),
        _v03(ctx),
    ):
        checks.append(current)
        if current.hard and not current.ok:
            return _failure_result(checks, current.code)

    try:
        derived_runs = _derived_runs(ctx)
    except Exception as exc:
        message = str(exc)
        lowered = message.lower()
        if any(marker in lowered for marker in ("trace", "structured", "json", "artifact")):
            code = "TRACE_MISSING"
        elif "environment" in lowered:
            code = "ENV_DECLARATION_MISMATCH"
        else:
            code = "CERTIFICATE_INVALID"
        current = CheckResult("V04", False, code, True, f"cannot independently derive replay evidence: {exc}")
        checks.append(current)
        return _failure_result(checks, current.code)
    current = _v04(ctx, derived_runs)
    checks.append(current)
    if current.hard and not current.ok:
        return _failure_result(checks, current.code)

    trace = derived_runs[0].trace
    sanitized_config = derived_runs[0].root / "foundry.toml"
    if not sanitized_config.is_file():
        current = CheckResult("V05", False, "POLICY_VIOLATION", True, "authoritative sanitized Foundry config is missing from the replay root")
        checks.append(current)
        return _failure_result(checks, current.code)
    current = check_policy(
        trace=trace,
        witness_class=ctx.witness.witness_class,
        policy_path=ctx.current_policy_path or Path("config/policy/cheatcode_policy.yaml"),
        catalog_path=ctx.cheatcode_catalog_path or Path("config/policy/cheatcode_categories.yaml"),
        foundry_config_path=sanitized_config,
        fork_block=ctx.witness.fork_block,
    )
    checks.append(current)
    if current.hard and not current.ok:
        return _failure_result(checks, current.code)

    control = derive_control(attack=trace, control=derived_runs[0].control_trace, witness=ctx.witness)
    current = check_assertion(witness=ctx.witness, assertion_events=trace.assertion_events, control=control)
    checks.append(current)
    if current.hard and not current.ok:
        return _failure_result(checks, current.code)

    try:
        harness = derive_harness(run=derived_runs[0], root=derived_runs[0].root, witness=ctx.witness)
    except Exception as exc:
        current = CheckResult("V07", False, "HARNESS_TAMPERED", True, f"cannot independently derive harness evidence: {exc}")
        checks.append(current)
        return _failure_result(checks, current.code)
    try:
        economics = derive_economics(run=derived_runs[0], witness=ctx.witness, price_sources=_load_prices(ctx))
    except Exception as exc:
        current = CheckResult("V09", False, "ECON_INCOMPLETE", True, f"cannot independently derive economic evidence: {exc}")
        checks.append(current)
        return _failure_result(checks, current.code)

    current = check_harness(harness=harness, trace=trace, witness_harness_address=ctx.witness.harness_address, economics=economics)
    checks.append(current)
    if current.hard and not current.ok:
        return _failure_result(checks, current.code)

    current = check_duplicate(ctx.duplicate)
    checks.append(current)

    current = check_econ(economics, production_required=ctx.production_l7_required, pinned_impact_usd=ctx.pinned_impact_usd)
    checks.append(current)
    if current.hard and not current.ok:
        return _failure_result(checks, current.code)

    soft_fail = next((c for c in checks if not c.hard and not c.ok), None)
    if soft_fail:
        return VerificationResult(True, tuple(checks), next_state="FINDING", route_reason=f"human_review:{soft_fail.code}")
    return VerificationResult(True, tuple(checks), next_state="FINDING", route_reason="all_m1b_checks_pass")
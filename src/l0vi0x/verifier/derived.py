from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Any

from l0vi0x.chain.environment import TreeObservation, check_declaration, environment_hash
from l0vi0x.chain.trace import TraceSummary, parse_trace
from l0vi0x.chain.witness import assert_harness_address, create2_address, sha256_file
from l0vi0x.core.models import Witness
from l0vi0x.verifier.types import ControlEvidence, EconomicEvidence, HarnessEvidence, SnapshotEvidence


@dataclass(frozen=True, slots=True)
class DerivedReplayRun:
    root: Path
    trace: TraceSummary
    control_trace: TraceSummary
    control_hash: str
    environment_hash: str
    environment: dict[str, Any]


def _inside(path: Path, root: Path) -> Path:
    resolved = path.resolve()
    base = root.resolve()
    if not resolved.is_relative_to(base):
        raise ValueError(f"artifact escapes trust root: {resolved}")
    return resolved


def _hash_canonical(payload: Any) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")).hexdigest()


def _control_hash_from_raw(raw: str) -> str:
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise ValueError("control artifact is not an object")

    def strip(value: Any) -> None:
        if isinstance(value, dict):
            value.pop("duration", None)
            for child in value.values(): strip(child)
        elif isinstance(value, list):
            for child in value: strip(child)
    strip(obj)
    return _hash_canonical(obj)


def _control_hash(path: Path) -> str:
    return _control_hash_from_raw(path.read_text(encoding="utf-8"))


def load_run(*, run_dir: Path, witness: Witness, cheatcode_catalog: dict[str, str]) -> DerivedReplayRun:
    repo_root = run_dir.resolve()
    artifact_dirs = sorted((repo_root / "artifacts").glob("run-*")) if (repo_root / "artifacts").exists() else []
    if len(artifact_dirs) != 1:
        raise ValueError(f"expected exactly one retained replay artifact directory under {repo_root}")
    root = artifact_dirs[0].resolve()
    trace_path = _inside(root / "trace.json", repo_root)
    control_path = _inside(root / "control.json", repo_root)
    control_trace_path = _inside(root / "control-trace.json", repo_root)
    env_path = _inside(root / "environment.json", repo_root)
    trace_sha_path = _inside(root / "trace.sha256", repo_root)
    control_sha_path = _inside(root / "control.sha256", repo_root)
    control_trace_sha_path = _inside(root / "control-trace.sha256", repo_root)
    env_sha_path = _inside(root / "environment.sha256", repo_root)
    for p in (trace_path, control_path, control_trace_path, env_path, trace_sha_path, control_sha_path, control_trace_sha_path, env_sha_path):
        if not p.is_file():
            raise ValueError(f"required replay artifact missing: {p}")
    trace_raw = trace_path.read_text(encoding="utf-8")
    control_raw = control_path.read_text(encoding="utf-8")
    control_trace_raw = control_trace_path.read_text(encoding="utf-8")
    if trace_sha_path.read_text(encoding="utf-8").strip() != hashlib.sha256(trace_raw.encode("utf-8")).hexdigest():
        raise ValueError("trace artifact hash mismatch")
    if control_sha_path.read_text(encoding="utf-8").strip() != _control_hash_from_raw(control_raw):
        raise ValueError("control artifact hash mismatch")
    if control_trace_sha_path.read_text(encoding="utf-8").strip() != hashlib.sha256(control_trace_raw.encode("utf-8")).hexdigest():
        raise ValueError("control trace artifact hash mismatch")
    trace = parse_trace(json.loads(trace_raw), cheatcode_catalog=cheatcode_catalog)
    control_trace = parse_trace(json.loads(control_trace_raw), cheatcode_catalog=cheatcode_catalog)
    env_raw = env_path.read_text(encoding="utf-8")
    env = json.loads(env_raw)
    if not isinstance(env, dict):
        raise ValueError("environment artifact is not an object")
    observed_env = str(env.get("environment_hash", ""))
    observation = TreeObservation.from_dict(dict(env["observation"]))
    check_declaration(observation, witness, root=repo_root)
    observed = environment_hash(
        observation,
        witness,
        dict(env.get("tool_versions") or {}),
        initial_timestamp=int(env["initial_timestamp"]),
        initial_block=int(env["initial_block"]),
    )
    if observed != observed_env:
        raise ValueError("environment artifact hash mismatch")
    declared_file_hash = env_sha_path.read_text(encoding="utf-8").strip()
    if declared_file_hash != observed_env:
        raise ValueError("environment hash file mismatch")
    return DerivedReplayRun(repo_root, trace, control_trace, _control_hash(control_path), observed_env, env)


def derive_control(*, attack: TraceSummary, control: TraceSummary, witness: Witness) -> ControlEvidence:
    required_ids = {a.id for a in witness.assertions if a.required}
    control_assertions = [e for e in control.assertion_events if str(e.get("id")) in required_ids]
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
    if control_assertions:
        raise ValueError("control run unexpectedly emitted the attack assertion")
    state_changed = any(bool(e.get("state_changed")) for e in control_events)
    return ControlEvidence(
        passed=True,
        matching_assertion=False,
        observed_state_changed=state_changed,
        assertion_event_count=len(control.assertion_events),
    )


def _artifact_contract(root: Path, source_path: str, field: str) -> tuple[str, dict[str, Any]]:
    src = _inside(root / source_path, root)
    source_hash = sha256_file(src)
    stem = src.stem
    candidates = sorted((root / "out").rglob(f"{stem}.json")) if (root / "out").exists() else []
    if not candidates:
        raise ValueError(f"missing Foundry artifact for {source_path}")
    matches: list[tuple[Path, dict[str, Any]]] = []
    for candidate in candidates:
        try:
            data = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        metadata = data.get("metadata")
        if isinstance(metadata, str):
            try:
                metadata = json.loads(metadata)
            except json.JSONDecodeError:
                continue
        if not isinstance(metadata, dict):
            continue
        target = metadata.get("settings", {}).get("compilationTarget", {})
        if target.get(source_path) == stem:
            matches.append((candidate, data))
    if len(matches) != 1:
        raise ValueError(f"expected exactly one compiled artifact for {source_path}, found {len(matches)}")
    return source_hash, matches[0][1]


def _runtime_hash(artifact: dict[str, Any], field: str) -> str:
    candidate = artifact.get(field, {}).get("object") if isinstance(artifact.get(field), dict) else None
    if not isinstance(candidate, str) or not candidate.startswith("0x"):
        raise ValueError(f"artifact has no {field}.object")
    return hashlib.sha256(bytes.fromhex(candidate[2:])).hexdigest()


def derive_harness(*, run: DerivedReplayRun, root: Path, witness: Witness) -> HarnessEvidence:
    assertion_events = list(run.trace.assertion_events)
    if not assertion_events:
        raise ValueError("no AssertionChecked event in replay")
    required = [a for a in witness.assertions if a.required]
    if len(assertion_events) != len(required):
        raise ValueError("unexpected AssertionChecked event count")
    assertion = assertion_events[0]
    harness = str(assertion.get("emitter", "")).lower()
    wrapper = str(assertion.get("caller", "")).lower()
    if not harness or not wrapper:
        raise ValueError("AssertionChecked lacks emitter/caller")
    if harness != witness.harness_address.lower():
        raise ValueError("observed harness address differs from witness")
    if witness.wrapper_address and wrapper != witness.wrapper_address.lower():
        raise ValueError("observed wrapper address differs from witness")
    depth = int(assertion.get("depth", -1))
    if depth != witness.expected_wrapper_depth:
        raise ValueError("AssertionChecked depth differs from witness")

    creates = [f for f in run.trace.frames if f.phase == "setup" and f.kind.lower() == "create2" and str(f.to or "").lower() == harness]
    if len(creates) != 1:
        raise ValueError("expected exactly one harness CREATE2")
    create = creates[0]
    if not create.caller or not create.data:
        raise ValueError("harness CREATE2 lacks deployer/init code")
    deployer = create.caller.lower()
    if not witness.harness_create2_deployer or deployer != witness.harness_create2_deployer.lower():
        raise ValueError("harness deployer is not the pinned deployer")
    init_hash = hashlib.sha256(bytes.fromhex(create.data[2:])).hexdigest()
    if witness.harness_init_code_sha256 and init_hash != witness.harness_init_code_sha256:
        raise ValueError("harness CREATE2 init-code hash mismatch")
    expected = assert_harness_address(deployer=deployer, salt=witness.harness_create2_salt, init_code=bytes.fromhex(create.data[2:]), expected=harness)
    if expected.lower() != harness:
        raise ValueError("CREATE2 recomputation failed")

    if not witness.harness_source_path or not witness.harness_source_sha256:
        raise ValueError("harness source path/hash must be declared")
    repo_source_root = run.root
    source_hash, artifact = _artifact_contract(repo_source_root, witness.harness_source_path, "deployedBytecode")
    if source_hash != witness.harness_source_sha256:
        raise ValueError("harness source hash mismatch")
    runtime_hash = _runtime_hash(artifact, "deployedBytecode")
    if not witness.harness_runtime_sha256 or runtime_hash != witness.harness_runtime_sha256:
        raise ValueError("harness runtime hash mismatch")

    if not witness.wrapper_address or not witness.wrapper_source_path or not witness.wrapper_source_sha256 or not witness.wrapper_runtime_sha256:
        raise ValueError("wrapper identity/source/runtime declaration is incomplete")
    wrapper_source_hash, wrapper_artifact = _artifact_contract(repo_source_root, witness.wrapper_source_path, "deployedBytecode")
    if wrapper_source_hash != witness.wrapper_source_sha256:
        raise ValueError("wrapper source hash mismatch")
    wrapper_runtime_hash = _runtime_hash(wrapper_artifact, "deployedBytecode")
    if wrapper_runtime_hash != witness.wrapper_runtime_sha256:
        raise ValueError("wrapper runtime hash mismatch")

    actors: set[str] = set()
    tokens: set[str] = set()
    for event in assertion_events:
        if event.get("actor"):
            actors.add(str(event["actor"]).lower())
    for transfer in run.trace.transfers:
        actors.add(transfer.from_address.lower()); actors.add(transfer.to_address.lower()); tokens.add(transfer.token.lower())
    for frame in run.trace.frames:
        for log in frame.logs:
            if log.get("event") == "EconomicSnapshot":
                actors.add(str(log.get("actor", "")).lower()); tokens.add(str(log.get("token", "")).lower())
    expected_actors = {a.lower() for a in witness.declared_actors}
    expected_tokens = {t.lower() for t in witness.declared_tokens}
    if not expected_actors.issubset(actors):
        raise ValueError("COVERAGE_INCOMPLETE: declared actor was not observed")
    if not expected_tokens.issubset(tokens):
        raise ValueError("COVERAGE_INCOMPLETE: declared token was not observed")

    economic_count = sum(1 for frame in run.trace.frames for log in frame.logs if log.get("event") == "EconomicSnapshot")
    control_count = sum(1 for frame in run.control_trace.frames for log in frame.logs if log.get("event") == "ControlObserved")
    if control_count != len(required):
        raise ValueError("control event count does not match required assertions")
    for assertion_spec in required:
        if assertion_spec.kind != "balance_delta" or assertion_spec.actor is None or assertion_spec.token is None:
            continue
        actor = assertion_spec.actor.lower()
        token = assertion_spec.token.lower()
        incoming = sum(t.amount for t in run.trace.transfers if t.token.lower() == token and t.to_address.lower() == actor)
        outgoing = sum(t.amount for t in run.trace.transfers if t.token.lower() == token and t.from_address.lower() == actor)
        if incoming - outgoing != int(assertion_spec.expected):
            raise ValueError("token transfer flow does not support the declared balance delta")
    return HarnessEvidence(
        harness_address=harness,
        wrapper_address=wrapper,
        expected_wrapper_depth=witness.expected_wrapper_depth,
        observed_wrapper_depth=depth,
        observed_runtime_sha256=runtime_hash,
        expected_runtime_sha256=witness.harness_runtime_sha256,
        observed_source_sha256=source_hash,
        expected_source_sha256=witness.harness_source_sha256,
        wrapper_runtime_sha256=wrapper_runtime_hash,
        expected_wrapper_runtime_sha256=witness.wrapper_runtime_sha256,
        wrapper_source_sha256=wrapper_source_hash,
        expected_wrapper_source_sha256=witness.wrapper_source_sha256,
        create2_deployer=deployer,
        create2_salt=witness.harness_create2_salt.lower(),
        create2_init_code_sha256=init_hash,
        assertion_emitter=harness,
        assertion_event_depth=depth,
        assertion_event_caller=wrapper,
        observed_actor_addresses=tuple(sorted(actors)),
        observed_token_addresses=tuple(sorted(tokens)),
        expected_actor_addresses=tuple(sorted(expected_actors)),
        expected_token_addresses=tuple(sorted(expected_tokens)),
        assertion_event_count=len(assertion_events),
        economic_event_count=economic_count,
        control_event_count=control_count,
    )


def derive_economics(*, run: DerivedReplayRun, witness: Witness, price_sources: dict[str, Any] | None = None) -> EconomicEvidence:
    from l0vi0x.chain.econ import EconomicInputs, measure
    from l0vi0x.chain.prices import PricePoint

    snapshots = [
        log for frame in run.trace.frames for log in frame.logs if log.get("event") == "EconomicSnapshot"
    ]
    if len(snapshots) != 1:
        raise ValueError("exactly one EconomicSnapshot is required")
    snap = snapshots[0]
    token = str(snap["token"]).lower()
    native_price = None
    prices: dict[str, PricePoint] = {}
    for asset, raw in (price_sources or {}).items():
        if not isinstance(raw, dict):
            raise ValueError(f"invalid price point for {asset}")
        point = PricePoint(
            asset=str(asset).lower(),
            usd_per_unit=float(raw["usd_per_unit"]),
            decimals=int(raw["decimals"]),
            source=str(raw["source"]),
            block=int(raw["block"]) if raw.get("block") is not None else witness.fork_block,
            observed_at=str(raw["observed_at"]) if raw.get("observed_at") is not None else None,
        )
        if point.asset == "native":
            native_price = point
        else:
            prices[point.asset] = point

    gas_price = int(run.environment.get("gas_price_wei", -1))
    token_decimals = getattr(witness, "token_decimals", {}) or {}
    snapshot = SnapshotEvidence(
        native_before_wei=int(snap["native_before"]),
        native_after_wei=int(snap["native_after"]),
        token_before={token: int(snap["token_before"])},
        token_after={token: int(snap["token_after"])},
        gas_used=run.trace.gas_used,
        gas_price_wei=gas_price,
        protocol_assets_delta_wei=int(snap["protocol_assets_delta"]),
        declared_capital_wei=int(snap["declared_capital"]),
        observed_capital_wei=int(snap["native_before"]),
    )
    if gas_price < 0:
        raise ValueError("actual gas price was not observed")
    inputs = EconomicInputs(
        native_before_wei=snapshot.native_before_wei,
        native_after_wei=snapshot.native_after_wei,
        token_before=snapshot.token_before,
        token_after=snapshot.token_after,
        token_decimals=token_decimals,
        prices=prices,
        native_price=native_price,
        gas_used=snapshot.gas_used or 0,
        gas_price_wei=gas_price,
        declared_capital_wei=snapshot.declared_capital_wei,
        observed_capital_wei=snapshot.observed_capital_wei,
        pinned_block=witness.fork_block,
        protocol_assets_delta_wei=snapshot.protocol_assets_delta_wei,
    )
    report = measure(inputs)
    out = SnapshotEvidence(
        native_before_wei=snapshot.native_before_wei,
        native_after_wei=snapshot.native_after_wei,
        token_before=snapshot.token_before,
        token_after=snapshot.token_after,
        gas_used=snapshot.gas_used,
        gas_price_wei=snapshot.gas_price_wei,
        protocol_assets_delta_wei=report.protocol_assets_delta_wei,
        declared_capital_wei=snapshot.declared_capital_wei,
        observed_capital_wei=snapshot.observed_capital_wei,
        sensitivity=report.sensitivity,
        sensitivity_scenarios=report.sensitivity_scenarios,
    )
    required_scenarios = {"minus_500bps", "base", "plus_500bps"}
    complete_sensitivity = set(report.sensitivity) == required_scenarios and set(report.sensitivity_scenarios) == required_scenarios
    return EconomicEvidence(
        snapshot=out,
        realism_flags=report.realism_flags,
        pinned_block=witness.fork_block,
        price_sources=report.price_sources,
        sensitivity=report.sensitivity,
        sensitivity_scenarios=report.sensitivity_scenarios,
        evidence_complete=bool(complete_sensitivity),
    )
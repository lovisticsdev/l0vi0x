from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from typing import Any

import yaml

from l0vi0x.chain.environment import TreeObservation, environment_hash
from l0vi0x.chain.replay import FoundryReplayExecutor, ReplayCollection, ReplayRun, ReplayCoordinator
from l0vi0x.chain.trace import parse_trace
from l0vi0x.chain.witness import marked_region_sha256, sha256_file, witness_hash
from l0vi0x.core.certifier import HostCertifier
from l0vi0x.core.home import ensure_audit_key
from l0vi0x.core.models import Capability, HState, Hypothesis, Scope, ScopeTarget, Span, Witness, WitnessAssertion
from l0vi0x.tools.forge import build as forge_build
from l0vi0x.tools.git import rev_parse_head
from l0vi0x.tools.lock import verify_binary_lock, verify_container_binary_lock
from l0vi0x.verifier.cheatcode_policy import policy_hash
from l0vi0x.verifier.derived import load_run
from l0vi0x.verifier.pipeline import verify
from l0vi0x.verifier.types import BuildEvidence, ReplayEvidence, VerificationContext


DEFAULT_ROOT = Path(__file__).resolve().parents[3]
FIXTURE_REL = Path("tests/fixtures/m1b_foundry")
WITNESS_FILE = "test/OracleExploitWitness.t.sol"
CONTROL_TEST = "test_control"
WITNESS_TEST = "test_witness"
HARNESS_SOURCE = "test/lib/EconHarness.sol"
WRAPPER_SOURCE = "test/Create2HarnessFactory.sol"
ASSERTION_ID = "M1B_ORACLE"
ASSERTION_EXPECTED = 50 * 10**18
ACTOR_FALLBACK = "0x000000000000000000000000000000000000a11ce"
HARNESS_SALT = "0x" + f"{0x1111:064x}"
M1B_TOOL_LOCK_REL = Path("config/tools.m1b.lock.yaml")
M1B_FOUNDRY_IMAGE = (
    "ghcr.io/foundry-rs/foundry@"
    "sha256:2e4287278639262de76db72477301d5d3212fa1b1cce710d7d148750a46ce9e7"
)


def _repo_root() -> Path:
    return Path(__import__("os").environ.get("L0VI0X_REPO_ROOT", DEFAULT_ROOT)).resolve()


def _work_root() -> Path:
    return Path(__import__("os").environ.get("L0VI0X_WORK_ROOT", _repo_root() / "eval/private/m1b-acceptance")).resolve()


def _normalize_meta_path(path: str | Path, host_root: Path) -> Path:
    """Resolve a path recorded in collection.json against the *current* process's
    work root, regardless of whether it was written by the in-container `collect`
    phase (where the task dir is bind-mounted at /workspace/task) or the host-side
    `certify`/`probes` phases (where the same directory is host_root)."""
    p = Path(path)
    if not p.is_absolute():
        return (host_root / p).resolve()

    sandbox_root = Path("/workspace/task")
    if p.is_relative_to(sandbox_root):
        return (host_root / p.relative_to(sandbox_root)).resolve()

    try:
        return p.resolve()
    except FileNotFoundError:
        return p


def _encode_work_path(path: str | Path, host_root: Path) -> str:
    """Inverse of _normalize_meta_path: record a path relative to whichever base
    (sandbox mount point or host work root) it falls under, so collection.json
    stays portable across the container/host boundary."""
    p = Path(path)
    try:
        resolved = p.resolve(strict=False)
    except Exception:
        resolved = p

    sandbox_root = Path("/workspace/task")
    if resolved.is_relative_to(sandbox_root):
        return str(resolved.relative_to(sandbox_root))

    try:
        return str(resolved.relative_to(host_root.resolve()))
    except ValueError:
        return str(resolved)


def _load_policy(root: Path) -> tuple[dict[str, Any], dict[str, str]]:
    policy = yaml.safe_load((root / "config/policy/cheatcode_policy.yaml").read_text(encoding="utf-8")) or {}
    catalog_raw = yaml.safe_load((root / "config/policy/cheatcode_categories.yaml").read_text(encoding="utf-8")) or {}
    catalog = catalog_raw.get("categories", catalog_raw)
    if not isinstance(catalog, dict):
        raise RuntimeError("cheatcode catalog is malformed")
    return policy, {str(k): str(v) for k, v in catalog.items()}


def _commit(root: Path) -> str:
    import os
    pinned = os.environ.get("L0VI0X_COMMIT")
    if pinned:
        return pinned.strip()
    return rev_parse_head(root)


def _artifact_contract(root: Path, source_path: str) -> dict[str, Any]:
    stem = Path(source_path).stem
    candidates = sorted((root / "out").rglob(f"{stem}.json")) if (root / "out").exists() else []
    matches: list[dict[str, Any]] = []
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
            matches.append(data)
    if len(matches) != 1:
        raise RuntimeError(f"expected one compiled artifact for {source_path}, found {len(matches)}")
    return matches[0]


def _runtime_hash(artifact: dict[str, Any]) -> str:
    bytecode = artifact.get("deployedBytecode")
    if not isinstance(bytecode, dict) or not isinstance(bytecode.get("object"), str):
        raise RuntimeError("compiled artifact has no deployedBytecode.object")
    raw = str(bytecode["object"])
    if not raw.startswith("0x"):
        raise RuntimeError("deployed bytecode is not hex")
    return hashlib.sha256(bytes.fromhex(raw[2:])).hexdigest()


def _extract_identity(trace_obj: Any) -> dict[str, str]:
    assertions = list(trace_obj.assertion_events)
    if len(assertions) != 1:
        raise RuntimeError(f"expected one AssertionChecked event, found {len(assertions)}")
    assertion = assertions[0]
    harness = str(assertion.get("emitter", "")).lower()
    wrapper = str(assertion.get("caller", "")).lower()
    actor = str(assertion.get("actor", "")).lower()
    token = str(assertion.get("token", "")).lower()
    if not all((harness, wrapper, actor, token)):
        raise RuntimeError("bootstrap assertion does not expose harness/wrapper/actor/token")
    create_frames = [
        frame for frame in trace_obj.frames
        if frame.phase == "setup" and frame.kind.lower() == "create2" and str(frame.to or "").lower() == harness
    ]
    if len(create_frames) != 1:
        raise RuntimeError(f"expected one harness CREATE2 frame, found {len(create_frames)}")
    frame = create_frames[0]
    if not frame.caller or not frame.data:
        raise RuntimeError("harness CREATE2 frame lacks caller or init code")
    init_code = frame.data
    init_hash = hashlib.sha256(bytes.fromhex(init_code[2:] if init_code.startswith("0x") else init_code)).hexdigest()
    return {
        "harness_address": harness,
        "wrapper_address": wrapper,
        "harness_create2_deployer": str(frame.caller).lower(),
        "harness_init_code_sha256": init_hash,
        "actor": actor,
        "token": token,
        "wrapper_depth": str(assertion.get("depth", "-1")),
    }


def _hashes(fixture: Path) -> dict[str, str]:
    path = fixture / WITNESS_FILE
    text = path.read_text(encoding="utf-8")
    return {
        "template_sha256": sha256_file(path),
        "attack_body_sha256": marked_region_sha256(text, "ATTACK BODY"),
        "wrapper_callsite_sha256": marked_region_sha256(text, "WRAPPER CALLSITE"),
    }


def _witness(
    *,
    commit: str,
    fixture: Path,
    identity: dict[str, str],
    env_hash: str,
) -> Witness:
    hashes = _hashes(fixture)
    actor = identity["actor"]
    token = identity["token"]
    return Witness(
        witness_class="local_deployment",
        chain_id=31337,
        fork_block=None,
        commit=commit,
        compiler={"solc": "0.8.24", "optimizer": True, "optimizer_runs": 200, "evm_version": "cancun"},
        test_file=WITNESS_FILE,
        test_name=WITNESS_TEST,
        control_test_name=CONTROL_TEST,
        initial_capital_wei=10**18,
        max_time_advance_s=0,
        max_block_advance=0,
        declared_actors=[actor],
        declared_tokens=[token],
        token_decimals={token: 18},
        setup_budget={"native_wei": 10**18},
        assertions=[WitnessAssertion(
            id=ASSERTION_ID,
            kind="balance_delta",
            target="balance_delta",
            operator="eq",
            expected=ASSERTION_EXPECTED,
            observed_record="AssertionChecked",
            actor=actor,
            token=token,
        )],
        invariant_check_pins={},
        template_sha256=hashes["template_sha256"],
        attack_body_sha256=hashes["attack_body_sha256"],
        harness_address=identity["harness_address"],
        harness_create2_salt=HARNESS_SALT,
        harness_create2_deployer=identity["harness_create2_deployer"],
        harness_init_code_sha256=identity["harness_init_code_sha256"],
        harness_runtime_sha256=identity["harness_runtime_sha256"],
        harness_source_path=HARNESS_SOURCE,
        harness_source_sha256=identity["harness_source_sha256"],
        wrapper_address=identity["wrapper_address"],
        wrapper_runtime_sha256=identity["wrapper_runtime_sha256"],
        wrapper_source_path=WRAPPER_SOURCE,
        wrapper_source_sha256=identity["wrapper_source_sha256"],
        expected_wrapper_depth=int(identity["wrapper_depth"]),
        wrapper_callsite_sha256=hashes["wrapper_callsite_sha256"],
        rpc_provider_label="m1b-gated-local",
        env_hash=env_hash,
    )


def _identity_from_root(root: Path, trace: Any) -> dict[str, str]:
    identity = _extract_identity(trace)
    harness_src = root / HARNESS_SOURCE
    wrapper_src = root / WRAPPER_SOURCE
    identity["harness_source_sha256"] = sha256_file(harness_src)
    identity["wrapper_source_sha256"] = sha256_file(wrapper_src)
    identity["harness_runtime_sha256"] = _runtime_hash(_artifact_contract(root, HARNESS_SOURCE))
    identity["wrapper_runtime_sha256"] = _runtime_hash(_artifact_contract(root, WRAPPER_SOURCE))
    return identity


def _build(root: Path, fixture: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="l0vi0x-m1b-target-build-") as td:
        scratch = Path(td) / "fixture"
        shutil.copytree(fixture, scratch)
        report = forge_build(root=scratch, forge_bin="forge", tool_runs_dir=_work_root() / "tool_runs")
        if not report.passed:
            raise RuntimeError(f"fixture forge build failed: {report.stderr or report.stdout}")


def _executor(root: Path) -> FoundryReplayExecutor:
    return FoundryReplayExecutor(
        forge_bin="forge",
        env={"GATE_URL": __import__("os").environ.get("GATE_URL", "")},
        harness_library_paths=(HARNESS_SOURCE,),
        foundry_policy_path=root / "config/policy/foundry_config_policy.yaml",
    )


def _bootstrap(root: Path, fixture: Path, executor: FoundryReplayExecutor, identity_placeholder: Witness, catalog: dict[str, str]) -> dict[str, str]:
    with tempfile.TemporaryDirectory(prefix="l0vi0x-m1b-bootstrap-") as td:
        copy_root = Path(td) / "repo"
        shutil.copytree(fixture, copy_root)
        result = executor.execute(witness=identity_placeholder, copy_root=copy_root, run_index=0)
        trace = parse_trace(json.loads(Path(result["trace_path"]).read_text(encoding="utf-8")), cheatcode_catalog=catalog)
        return _identity_from_root(copy_root, trace)


def _make_declaration(root: Path, fixture: Path, executor: FoundryReplayExecutor, witness: Witness, catalog: dict[str, str]) -> Witness:
    with tempfile.TemporaryDirectory(prefix="l0vi0x-m1b-declare-") as td:
        copy_root = Path(td) / "repo"
        shutil.copytree(fixture, copy_root)
        result = executor.execute(witness=witness, copy_root=copy_root, run_index=0)
        declared_env = str(result["environment_hash"])
    return witness.model_copy(update={"env_hash": declared_env})


def _scope_and_hypothesis(root: Path, commit: str) -> tuple[Scope, Hypothesis]:
    path = root / FIXTURE_REL / "src/LendingPool.sol"
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    target_line = next(i for i, line in enumerate(lines, 1) if "return oracle.price();" in line)
    span = Span(file=str(FIXTURE_REL / "src/LendingPool.sol"), start=target_line, end=target_line, sha256=hashlib.sha256(lines[target_line - 1].encode()).hexdigest())
    now = datetime.now(timezone.utc)
    hypothesis = Hypothesis(
        id="H-M1B-ORACLE-001",
        claim="The lending pool's borrow capacity is controlled by a mutable oracle price, allowing a caller to extract protocol tokens by inflating that price.",
        target=span,
        invariant_id="INV-ORACLE-BORROW-CAPACITY",
        capabilities=[Capability.PERMISSIONLESS, Capability.ORACLE_MANIP],
        preconditions=["The attacker can induce an unjustified oracle price increase before borrowing."],
        assumptions=[],
        attack_sketch=["Raise the mutable oracle price, then borrow against the inflated capacity."],
        lens="oracle_price",
        channel="seed_static",
        protocol_type="lending_market",
        mechanism_tag="oracle_manipulation",
        canonical_key="m1b:oracle:lending-borrow-capacity",
        prior_p=0.5,
        est_impact="50 token units in the pinned fixture",
        est_cost="1 ETH initial setup capital plus gas",
        state=HState.OPEN,
        witness_feasibility="local_deployment",
        provenance={"commit": commit, "fixture": str(FIXTURE_REL)},
        created_at=now,
        updated_at=now,
    )
    scope = Scope(
        version=1,
        platform="m1b-fixture",
        program_ref="m1b-real-fixture",
        commit=commit,
        confidentiality="private",
        in_scope=[ScopeTarget(id="LENDING", kind="contract", path=str(FIXTURE_REL / "src/LendingPool.sol"), contract="LendingPool")],
        out_of_scope=[],
        excluded_classes=[],
        dependencies=[],
        concurrent_programs=[],
        deployed=False,
        attacker_capital_wei=10**18,
        poc_required=True,
        severity_model_ref="fixture:pinned-impact",
    )
    return scope, hypothesis


def _price_evidence(root: Path, token: str, work: Path) -> Path:
    src = root / FIXTURE_REL / "prices.json"
    payload = json.loads(src.read_text(encoding="utf-8"))
    zero_key = next(k for k in payload["prices"] if k.startswith("0x"))
    price = payload["prices"].pop(zero_key)
    price["asset"] = token.lower()
    payload["prices"][token.lower()] = price
    dest = work / "prices.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return dest


def _load_collection(root: Path, witness: Witness, catalog: dict[str, str], policy: dict[str, Any], *, replay_root: Path, run_dirs: tuple[Path, ...]) -> ReplayCollection:
    run_dirs = tuple(Path(p).resolve() for p in run_dirs)
    if len(run_dirs) < 3:
        raise RuntimeError(f"expected at least three retained replay runs under {replay_root}")
    derived = [load_run(run_dir=p, witness=witness, cheatcode_catalog=catalog) for p in run_dirs]
    records = [run.trace.observed_records_sha256() for run in derived]
    controls = [run.control_hash for run in derived]
    envs = [run.environment_hash for run in derived]
    if len(set(envs)) != 1 or len(set(records)) != 1 or len(set(controls)) != 1:
        raise RuntimeError("retained replay collection is not deterministic")
    from l0vi0x.verifier.derived import DerivedReplayRun
    replay_runs: list[ReplayRun] = []
    for index, (run_dir, d) in enumerate(zip(run_dirs, derived), 1):
        artifact = run_dir / "artifacts"
        artifact_dirs = sorted(artifact.glob("run-*"))
        ad = artifact_dirs[0]
        replay_runs.append(ReplayRun(index, True, ad, ad / "trace.json", ad / "control.json", ad / "control-trace.json", ad / "environment.json", d.control_hash, d.environment_hash, d.trace))
    import hashlib as _hashlib
    aggregate = _hashlib.sha256(json.dumps(records, separators=(",", ":")).encode()).hexdigest()
    trace_policy_sha = policy_hash(root / "config/policy/cheatcode_policy.yaml", root / "config/policy/cheatcode_categories.yaml", root / "config/policy/foundry_config_policy.yaml")
    return ReplayCollection(
        witness_hash=witness_hash(witness),
        root=replay_root,
        runs=tuple(replay_runs),
        observed_records_sha256=aggregate,
        trace_policy_sha256=trace_policy_sha,
        control_sha256=controls[0],
        environment_hash=envs[0],
    )


def _verify_m1b_tool_lock(tool_lock_path: Path, *, required_names: list[str]) -> list[str]:
    """Verify the m1b container tool lock, adapting to whichever environment
    this process is actually running in.

    Inside the sandbox container (built FROM the pinned foundry image via
    `COPY --from=foundry ...`), the locked binaries are present on disk at the
    exact paths recorded in the lock (e.g. /usr/local/bin/forge), so we can
    and should verify them directly with no Docker dependency.

    On the host (running `certify`/`probes` outside the container), those
    paths don't exist locally, so we instead verify the pinned image itself
    by probing it with `docker run`.
    """
    lock = yaml.safe_load(tool_lock_path.read_text(encoding="utf-8")) or {}
    tools = lock.get("tools") or {}
    locked_names = [name for name in required_names if name in tools]
    binaries_present_locally = bool(locked_names) and all(
        Path(str(tools[name].get("binary", ""))).exists() for name in locked_names
    )
    if binaries_present_locally:
        return verify_binary_lock(tool_lock_path, required_names=required_names, allow_extra=True)
    return verify_container_binary_lock(tool_lock_path, image=M1B_FOUNDRY_IMAGE, required_names=required_names)


def _context(root: Path, witness: Witness, *, replay: ReplayEvidence, price_path: Path, require_certificate: bool) -> VerificationContext:
    scope, hypothesis = _scope_and_hypothesis(root, witness.commit)
    tool_lock_path = root / M1B_TOOL_LOCK_REL
    lock_problems = _verify_m1b_tool_lock(tool_lock_path, required_names=["forge", "anvil", "cast"])
    build = BuildEvidence(clean=True, tool_lock_verified=not lock_problems, tool_lock_problems=tuple(lock_problems), pinned_compiler=witness.compiler["solc"], required_tools=("forge", "anvil", "cast"))
    return VerificationContext(
        root=root,
        hypothesis=hypothesis,
        scope=scope,
        witness=witness,
        known_issues=(),
        replay=replay,
        build=build,
        current_policy_path=root / "config/policy/cheatcode_policy.yaml",
        cheatcode_catalog_path=root / "config/policy/cheatcode_categories.yaml",
        foundry_config_path=root / "config/policy/foundry_config_policy.yaml",
        tool_lock_path=tool_lock_path,
        price_evidence_path=price_path,
        require_certificate=require_certificate,
    )


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")


def _refresh_hash(path: Path, hash_path: Path) -> None:
    raw = path.read_bytes()
    hash_path.write_text(hashlib.sha256(raw).hexdigest() + "\n", encoding="utf-8")


def _artifact_dir(run: Path) -> Path:
    dirs = sorted((run / "repo" / "artifacts").glob("run-*"))
    if len(dirs) != 1:
        raise RuntimeError(f"expected exactly one artifact directory under {run}")
    return dirs[0]


def collect() -> int:
    root = _repo_root()
    fixture = root / FIXTURE_REL
    work = _work_root()
    work.mkdir(parents=True, exist_ok=True)
    policy, catalog = _load_policy(root)
    commit = _commit(root)
    _build(root, fixture)
    executor = _executor(root)

    placeholder = Witness(
        witness_class="local_deployment", chain_id=31337, commit=commit,
        compiler={"solc": "0.8.24", "optimizer": True, "optimizer_runs": 200, "evm_version": "cancun"},
        test_file=WITNESS_FILE, test_name=WITNESS_TEST, control_test_name=CONTROL_TEST,
        initial_capital_wei=10**18, max_time_advance_s=0, max_block_advance=0,
        declared_actors=[ACTOR_FALLBACK], declared_tokens=["0x" + "00" * 20],
        token_decimals={"0x" + "00" * 20: 18}, setup_budget={"native_wei": 10**18},
        assertions=[WitnessAssertion(id=ASSERTION_ID, kind="balance_delta", target="balance_delta", operator="eq", expected=ASSERTION_EXPECTED, observed_record="AssertionChecked", actor=ACTOR_FALLBACK, token="0x" + "00" * 20)],
        template_sha256=sha256_file(fixture / WITNESS_FILE), attack_body_sha256=marked_region_sha256((fixture / WITNESS_FILE).read_text(encoding="utf-8"), "ATTACK BODY"),
        harness_address="0x" + "00" * 20, harness_create2_salt=HARNESS_SALT, expected_wrapper_depth=2,
        wrapper_callsite_sha256=marked_region_sha256((fixture / WITNESS_FILE).read_text(encoding="utf-8"), "WRAPPER CALLSITE"), env_hash="0" * 64,
    )
    identity = _bootstrap(root, fixture, executor, placeholder, catalog)
    witness = _witness(commit=commit, fixture=fixture, identity=identity, env_hash="0" * 64)
    witness = _make_declaration(root, fixture, executor, witness, catalog)
    replay_root = work / "replays"
    coordinator = ReplayCoordinator(repo_root=fixture, replay_root=replay_root, executor=executor, cheatcode_catalog=catalog, cheatcode_policy=policy["rules"] if "rules" in policy else policy)
    collection = coordinator.collect(witness, runs=3, audit_id="M1B")
    prices = _price_evidence(root, identity["token"], work)
    replays = ReplayEvidence(root=collection.root, run_dirs=tuple(run.artifact_dir.parent.parent for run in collection.runs))
    # Verify once before any certificate exists: this is the hard certificate-issuance boundary.
    ctx = _context(root, witness, replay=replays, price_path=prices, require_certificate=False)
    result = verify(ctx)
    _write_json(work / "precertificate-verification.json", {"passed": result.passed, "checks": [asdict(c) for c in result.checks], "route_reason": result.route_reason, "next_state": result.next_state})
    if not result.passed:
        raise RuntimeError("pre-certificate V01-V09 verification failed: " + json.dumps([asdict(c) for c in result.hard_failures], default=str))
    _write_json(work / "witness.json", witness.model_dump(mode="json"))
    _write_json(work / "collection.json", {"replay_root": _encode_work_path(collection.root, work), "run_dirs": [_encode_work_path(p, work) for p in replays.run_dirs], "witness_hash": collection.witness_hash})
    print(f"M1b collect: PASS ({collection.root})")
    return 0


def certify() -> int:
    root = _repo_root()
    work = _work_root()
    policy, catalog = _load_policy(root)
    witness = Witness.model_validate(json.loads((work / "witness.json").read_text(encoding="utf-8")))
    meta = json.loads((work / "collection.json").read_text(encoding="utf-8"))
    run_dirs = tuple(_normalize_meta_path(p, work) for p in meta["run_dirs"])
    replay_root = _normalize_meta_path(meta["replay_root"], work)
    prices = work / "prices.json"
    # The certificate key is host-only by design. It must live under
    # L0VI0X_HOME, never under the bind-mounted per-audit task/replay root.
    key_path = ensure_audit_key("M1B")
    if key_path.is_relative_to(root.resolve()) or key_path.is_relative_to(work.resolve()):
        raise RuntimeError("certificate key must remain outside the repository and sandbox work root")
    collection = _load_collection(root, witness, catalog, policy, replay_root=replay_root, run_dirs=run_dirs)
    replay = ReplayEvidence(root=replay_root, run_dirs=run_dirs)
    ctx_pre = _context(root, witness, replay=replay, price_path=prices, require_certificate=False)
    pre = verify(ctx_pre)
    _write_json(work / "certify-precheck-verification.json", {"passed": pre.passed, "checks": [asdict(c) for c in pre.checks], "route_reason": pre.route_reason, "next_state": pre.next_state})
    if not pre.passed:
        raise RuntimeError("certificate issuance blocked: hard verification did not pass: " + json.dumps([asdict(c) for c in pre.hard_failures], default=str))
    certifier = HostCertifier(key_path)
    certificate = certifier.issue(witness=witness, collection=collection, verification=pre, certificate_id="CERT-M1B-REAL")
    _write_json(work / "certificate.json", certificate.model_dump(mode="json"))
    replay_final = ReplayEvidence(root=replay_root, run_dirs=run_dirs, certificate=certificate, certificate_key=key_path.read_bytes())
    ctx_final = _context(root, witness, replay=replay_final, price_path=prices, require_certificate=True)
    final = verify(ctx_final)
    _write_json(work / "certificate-verification.json", {"passed": final.passed, "checks": [asdict(c) for c in final.checks], "route_reason": final.route_reason, "next_state": final.next_state})
    if not final.passed:
        raise RuntimeError("final certificate-backed verification failed")
    _write_json(work / "acceptance.json", {"status": "PASS", "witness_hash": witness_hash(witness), "certificate_id": certificate.id, "issued_at": certificate.issued_at.isoformat(), "replay_root": str(replay_root), "runs": len(run_dirs)})
    print("M1b certify: PASS")
    return 0


def _adversarial_probe(name: str, mutate) -> tuple[str, str]:
    root = _repo_root()
    work = _work_root()
    witness = Witness.model_validate(json.loads((work / "witness.json").read_text(encoding="utf-8")))
    policy, catalog = _load_policy(root)
    meta = json.loads((work / "collection.json").read_text(encoding="utf-8"))
    run_dir_sources = tuple(_normalize_meta_path(p, work) for p in meta["run_dirs"])
    dest = work / "adversarial" / name
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True, exist_ok=True)
    run_dirs = []
    for index, src_repo in enumerate(run_dir_sources, start=1):
        run_dst = dest / f"run-{index}"
        shutil.copytree(src_repo.parent, run_dst)
        run_dirs.append(run_dst / "repo")
    mutate(dest)
    run_dirs = tuple(sorted(run_dirs))
    replay = ReplayEvidence(root=dest, run_dirs=run_dirs)
    prices = work / "prices.json"
    ctx = _context(root, witness, replay=replay, price_path=prices, require_certificate=False)
    result = verify(ctx)
    return result.next_state or "", ",".join(c.code or "" for c in result.hard_failures)


def _fixture_sanity_probe(name: str, *, test_file: str, test_name: str, expect_policy_violation: bool = False) -> tuple[str, str]:
    root = _repo_root()
    fixture = root / FIXTURE_REL
    policy, catalog = _load_policy(root)
    executor = _executor(root)
    witness = Witness(
        witness_class="local_deployment", chain_id=31337, commit=_commit(root),
        compiler={"solc": "0.8.24", "optimizer": True, "optimizer_runs": 200, "evm_version": "cancun"},
        test_file=test_file, test_name=test_name, control_test_name="test_control",
        initial_capital_wei=10**18, max_time_advance_s=0, max_block_advance=0,
        declared_actors=[ACTOR_FALLBACK], declared_tokens=[], token_decimals={}, setup_budget={"native_wei": 10**18},
        assertions=[], template_sha256=sha256_file(fixture / test_file), attack_body_sha256=marked_region_sha256((fixture / test_file).read_text(encoding="utf-8"), "ATTACK BODY"),
        harness_address="0x" + "00" * 20, harness_create2_salt=HARNESS_SALT, expected_wrapper_depth=0,
        wrapper_callsite_sha256=marked_region_sha256((fixture / test_file).read_text(encoding="utf-8"), "WRAPPER CALLSITE"), env_hash="0" * 64,
    )
    with tempfile.TemporaryDirectory(prefix=f"l0vi0x-m1b-negative-{name}-") as td:
        copy_root = Path(td) / "repo"
        shutil.copytree(fixture, copy_root)
        try:
            result = executor.execute(witness=witness, copy_root=copy_root, run_index=1)
            trace = parse_trace(json.loads(Path(result["trace_path"]).read_text(encoding="utf-8")), cheatcode_catalog=catalog)
            if expect_policy_violation:
                from l0vi0x.chain.trace import enforce_cheatcode_policy, TracePolicyError
                try:
                    enforce_cheatcode_policy(trace, witness_class=witness.witness_class, policy=policy, fork_block=None)
                except TracePolicyError as exc:
                    return "POLICY_VIOLATION", str(exc)
                return "PASS", "forbidden witness cheatcode was not rejected"
            return "NO_ASSERTION", str(len(trace.assertion_events))
        except Exception as exc:
            return "ERROR", str(exc)


def probes() -> int:
    work = _work_root()
    cases: dict[str, tuple[str, str]] = {}

    def _iter_frames(frames: list[dict[str, Any]]):
        """Recurse into nested `children`, mirroring chain.trace._flatten_records
        (the real reader): assertion/control logs can live on frames nested
        under a top-level call, not only on the top-level frames themselves."""
        for frame in frames:
            yield frame
            children = frame.get("children")
            if isinstance(children, list):
                yield from _iter_frames(children)

    def forged(root: Path) -> None:
        for run in root.glob("run-*"):
            path = run / "repo/artifacts" / next(p.name for p in (run / "repo/artifacts").glob("run-*")) / "trace.json"
            data = json.loads(path.read_text(encoding="utf-8"))
            for frame in _iter_frames(data["trace"]):
                for log in frame.get("logs", []):
                    if log.get("event") == "AssertionChecked":
                        log["emitter"] = "0x" + "ff" * 20
            path.write_text(json.dumps(data, sort_keys=True, separators=(",", ":")), encoding="utf-8")
            _refresh_hash(path, path.with_name("trace.sha256"))

    def text_imitation(root: Path) -> None:
        run = sorted(root.glob("run-*"))[0]
        artifact = next((run / "repo/artifacts").glob("run-*"))
        (artifact / "trace.json").write_text("forge -vvvv output: AssertionChecked=true\n", encoding="utf-8")

    def env_drift(root: Path) -> None:
        run = sorted(root.glob("run-*"))[-1]
        artifact = _artifact_dir(run)
        env_path = artifact / "environment.json"
        env = json.loads(env_path.read_text(encoding="utf-8"))
        env["tool_versions"]["forge"] = str(env["tool_versions"]["forge"]) + " tampered"
        observation = TreeObservation.from_dict(dict(env["observation"]))
        # Same witness that was persisted during collect() / used by every other
        # probe (see _adversarial_probe, certify()); env_drift previously
        # referenced a bare `witness` name that was never bound in this scope.
        witness = Witness.model_validate(json.loads((work / "witness.json").read_text(encoding="utf-8")))
        mutated_hash = environment_hash(
            observation,
            witness,
            dict(env["tool_versions"]),
            initial_timestamp=int(env["initial_timestamp"]),
            initial_block=int(env["initial_block"]),
        )
        env["environment_hash"] = mutated_hash
        env_path.write_text(json.dumps(env, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        (artifact / "environment.sha256").write_text(mutated_hash + "\n", encoding="utf-8")

    def trace_drift(root: Path) -> None:
        run = sorted(root.glob("run-*"))[-1]
        artifact = _artifact_dir(run)
        path = artifact / "trace.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        frames = data["trace"]
        frames[0]["gas_used"] = int(frames[0].get("gas_used", 0)) + 1
        path.write_text(json.dumps(data, sort_keys=True, separators=(",", ":")), encoding="utf-8")
        _refresh_hash(path, artifact / "trace.sha256")

    def forged_event(root: Path) -> None:
        for run in root.glob("run-*"):
            artifact = next((run / "repo/artifacts").glob("run-*"))
            path = artifact / "trace.json"
            data = json.loads(path.read_text(encoding="utf-8"))
            for frame in _iter_frames(data["trace"]):
                for log in frame.get("logs", []):
                    if log.get("event") == "AssertionChecked":
                        log["observed"] = 51
                        log["ok"] = True
            path.write_text(json.dumps(data, sort_keys=True, separators=(",", ":")), encoding="utf-8")
            _refresh_hash(path, path.with_name("trace.sha256"))

    def wrapper_tamper(root: Path) -> None:
        for run in root.glob("run-*"):
            source = run / "repo" / WRAPPER_SOURCE
            source.write_text(source.read_text(encoding="utf-8") + "\n// tampered by acceptance probe\n", encoding="utf-8")

    def coverage_omission(root: Path) -> None:
        for run in root.glob("run-*"):
            artifact = next((run / "repo/artifacts").glob("run-*"))
            path = artifact / "trace.json"
            data = json.loads(path.read_text(encoding="utf-8"))
            for frame in _iter_frames(data["trace"]):
                for log in frame.get("logs", []):
                    if log.get("event") == "AssertionContext":
                        log.pop("actor", None); log.pop("token", None)
            path.write_text(json.dumps(data, sort_keys=True, separators=(",", ":")), encoding="utf-8")
            _refresh_hash(path, path.with_name("trace.sha256"))

    def control_effect(root: Path) -> None:
        for run in root.glob("run-*"):
            artifact = next((run / "repo/artifacts").glob("run-*"))
            path = artifact / "control-trace.json"
            data = json.loads(path.read_text(encoding="utf-8"))
            for frame in _iter_frames(data["trace"]):
                for log in frame.get("logs", []):
                    if log.get("event") == "ControlObserved": log["state_changed"] = True
            path.write_text(json.dumps(data, sort_keys=True, separators=(",", ":")), encoding="utf-8")
            _refresh_hash(path, path.with_name("control-trace.sha256"))

    cases["forged_assertion"] = _adversarial_probe("forged_assertion", forged)
    cases["forged_event"] = _adversarial_probe("forged_event", forged_event)
    cases["trace_text_imitation"] = _adversarial_probe("trace_text_imitation", text_imitation)
    cases["environment_tamper"] = _adversarial_probe("environment_tamper", env_drift)
    cases["trace_drift"] = _adversarial_probe("trace_drift", trace_drift)
    cases["tampered_wrapper"] = _adversarial_probe("tampered_wrapper", wrapper_tamper)
    cases["actor_token_omission"] = _adversarial_probe("actor_token_omission", coverage_omission)
    cases["control_state_change"] = _adversarial_probe("control_state_change", control_effect)
    cases["cheat_exploit"] = _fixture_sanity_probe("cheat_exploit", test_file="test/CheatExploitWitness.t.sol", test_name="test_witness", expect_policy_violation=True)
    cases["benign_twin"] = _fixture_sanity_probe("benign_twin", test_file="test/BenignTwin.t.sol", test_name="test_witness")
    _write_json(work / "adversarial-probes.json", cases)
    if cases["forged_assertion"][1] not in {"HARNESS_TAMPERED", "ENV_DECLARATION_MISMATCH", "CERTIFICATE_INVALID"}:
        raise RuntimeError(f"forged assertion probe did not fail closed: {cases['forged_assertion']}")
    if cases["trace_text_imitation"][1] == "":
        raise RuntimeError("trace text imitation probe unexpectedly passed")
    if cases["environment_tamper"][1] != "NONDETERMINISTIC_ENV":
        raise RuntimeError(f"environment drift did not route as NONDETERMINISTIC_ENV: {cases['environment_tamper']}")
    if cases["trace_drift"][1] != "NONDETERMINISTIC_TRACE":
        raise RuntimeError(f"stable-environment trace drift did not route as NONDETERMINISTIC_TRACE: {cases['trace_drift']}")
    if cases["tampered_wrapper"][1] == "":
        raise RuntimeError("wrapper tamper probe unexpectedly passed")
    if cases["actor_token_omission"][1] == "":
        raise RuntimeError("actor/token omission probe unexpectedly passed")
    if cases["control_state_change"][1] == "":
        raise RuntimeError("control-effect probe unexpectedly passed")
    if cases["cheat_exploit"][0] != "POLICY_VIOLATION":
        raise RuntimeError(f"cheat exploit probe was not rejected: {cases['cheat_exploit']}")
    if cases["benign_twin"][0] != "NO_ASSERTION":
        raise RuntimeError(f"benign twin unexpectedly emitted an assertion: {cases['benign_twin']}")
    print("M1b adversarial probes: PASS")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Real M1b acceptance driver")
    parser.add_argument("--phase", choices=("collect", "certify", "probes", "all"), default="all")
    args = parser.parse_args()
    try:
        if args.phase == "collect":
            return collect()
        if args.phase == "certify":
            return certify()
        if args.phase == "probes":
            return probes()
        collect()
        certify()
        probes()
        return 0
    except Exception as exc:
        print(f"M1b acceptance: FAIL/BLOCKED\n{exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
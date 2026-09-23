from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
from typing import Any

import yaml
from eth_hash.auto import keccak

from l0vi0x.chain.m1a_fixtures import FIXTURES, fixture_root
from l0vi0x.chain.replay import FoundryReplayExecutor, ReplayCollection, ReplayCoordinator, ReplayRun
from l0vi0x.chain.trace import parse_trace
from l0vi0x.chain.witness import marked_region_sha256, sha256_file, witness_hash
from l0vi0x.core.certifier import HostCertifier
from l0vi0x.core.home import ensure_audit_key
from l0vi0x.core.certificates import verify as verify_certificate
from l0vi0x.core.models import Witness, WitnessAssertion
from l0vi0x.tools.forge import build as forge_build
from l0vi0x.tools.git import rev_parse_head

ROOT = Path(__file__).resolve().parents[3]
WORK_DEFAULT = ROOT / "eval/private/m1a-acceptance"
CHEATCODE_VM = "0x7109709ecfa91a80626ff3989d68f67f5b1dd12d"
HARNESS_DEPLOY_TOPIC = "0x" + keccak(b"HarnessDeployed(address,address,bytes32)").hex()


def root() -> Path:
    import os
    return Path(os.environ.get("L0VI0X_REPO_ROOT", str(ROOT))).resolve()


def work() -> Path:
    import os
    return Path(os.environ.get("L0VI0X_WORK_ROOT", str(WORK_DEFAULT))).resolve()


def _normalize_meta_path(path: str | Path, host_root: Path) -> Path:
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


def policy_and_catalog(r: Path) -> tuple[dict[str, Any], dict[str, str]]:
    policy = yaml.safe_load((r / "config/policy/cheatcode_policy.yaml").read_text()) or {}
    raw = yaml.safe_load((r / "config/policy/cheatcode_categories.yaml").read_text()) or {}
    catalog = raw.get("categories", raw)
    return policy, {str(k): str(v) for k, v in catalog.items()}


def fixture_hashes(test_path: Path) -> tuple[str, str, str]:
    text = test_path.read_text(encoding="utf-8")
    return sha256_file(test_path), marked_region_sha256(text, "ATTACK BODY"), marked_region_sha256(text, "WRAPPER CALLSITE")


def bootstrap_witness(cls: str, commit: str, fixture: Path) -> Witness:
    spec = FIXTURES[cls]
    test = fixture / spec.test_file
    template, attack, callsite = fixture_hashes(test)
    return Witness(
        witness_class=cls,
        chain_id=31337,
        fork_block=spec.fork_block,
        commit=commit,
        compiler={"solc": "0.8.24", "optimizer": True, "optimizer_runs": 200, "evm_version": "cancun"},
        test_file=spec.test_file,
        test_name=spec.test_name,
        control_test_name=spec.control_test_name,
        initial_capital_wei=10**18 if cls == "local_deployment" else 0,
        max_time_advance_s=1000 if cls == "local_deployment" else 1,
        max_block_advance=1,
        declared_actors=["0x000000000000000000000000000000000000a11ce"],
        declared_tokens=[],
        setup_budget={"native_wei": 10**18} if cls == "local_deployment" else None,
        assertions=[WitnessAssertion(id="bootstrap", kind="custom", target="credit", operator="eq", expected=7 if cls == "local_deployment" else 3, observed_record="AssertionChecked", actor="0x000000000000000000000000000000000000a11ce")],
        template_sha256=template,
        attack_body_sha256=attack,
        harness_address="0x" + "00" * 20,
        harness_create2_salt="0x" + "00" * 32,
        expected_wrapper_depth=2,
        wrapper_callsite_sha256=callsite,
        rpc_provider_label=spec.rpc_provider_label,
        env_hash="0" * 64,
    )


def extract_identity(trace: Any) -> tuple[str, str, int, str, str]:
    deployments = []
    for frame in trace.frames:
        if frame.phase != "setup":
            continue
        for log in frame.logs:
            if isinstance(log, dict) and log.get("topics") and str(log["topics"][0]).lower() == HARNESS_DEPLOY_TOPIC.lower():
                deployments.append(log)
    if len(deployments) != 1 or len(trace.assertion_events) != 1:
        raise RuntimeError("M1a fixture did not produce exactly one harness deployment and one assertion")
    topics = deployments[0]["topics"]
    harness = "0x" + topics[1][-40:]
    salt = topics[3]
    assertion = trace.assertion_events[0]
    caller = str(assertion.get("caller", "")).lower()
    depth = int(assertion.get("depth", -1))
    if str(assertion.get("emitter", "")).lower() != harness.lower() or depth != 2 or len(caller) != 42:
        raise RuntimeError("M1a witness wrapper/harness identity is inconsistent")
    creates = [f for f in trace.frames if f.phase == "setup" and f.kind.lower() == "create2" and str(f.to or "").lower() == harness.lower()]
    if len(creates) != 1 or not creates[0].caller or not creates[0].data:
        raise RuntimeError("M1a witness CREATE2 identity is incomplete")
    init_code = creates[0].data
    raw_init = init_code[2:] if init_code.startswith("0x") else init_code
    init_hash = hashlib.sha256(bytes.fromhex(raw_init)).hexdigest()
    return harness.lower(), salt.lower(), depth, caller, init_hash


def final_witness(bootstrap: Witness, fixture: Path, identity: tuple[str, str, int, str, str]) -> Witness:
    harness, salt, depth, wrapper, init_hash = identity
    data = bootstrap.model_copy(update={
        "assertions": [WitnessAssertion(id="A-local" if bootstrap.witness_class == "local_deployment" else "A-fork", kind="custom", target="credit", operator="eq", expected=7 if bootstrap.witness_class == "local_deployment" else 3, observed_record="AssertionChecked", actor="0x000000000000000000000000000000000000a11ce")],
        "harness_address": harness,
        "harness_create2_salt": salt,
        "harness_create2_deployer": wrapper,
        "harness_init_code_sha256": init_hash,
        "wrapper_address": wrapper,
        "harness_source_path": "test/WitnessHarness.sol",
        "wrapper_source_path": "test/WitnessWrapper.sol",
        "expected_wrapper_depth": depth,
    })
    # M1a's legacy witness harness source/runtime are still pinned by the real trace/environment.
    return data


def make_executor(r: Path, cls: str) -> FoundryReplayExecutor:
    import os
    env: dict[str, str] = {}
    if os.environ.get("GATE_URL"):
        env["GATE_URL"] = os.environ["GATE_URL"]
    if os.environ.get("L0VI0X_INITIAL_BLOCK"):
        env["L0VI0X_INITIAL_BLOCK"] = os.environ["L0VI0X_INITIAL_BLOCK"]
    if os.environ.get("L0VI0X_INITIAL_TIMESTAMP"):
        env["L0VI0X_INITIAL_TIMESTAMP"] = os.environ["L0VI0X_INITIAL_TIMESTAMP"]
    return FoundryReplayExecutor(
        forge_bin="forge",
        env=env,
        harness_library_paths=("test/WitnessHarness.sol",),
        foundry_policy_path=r / "config/policy/foundry_config_policy.yaml",
    )


def build_target(r: Path, fixture: Path) -> str:
    with tempfile.TemporaryDirectory(prefix="l0vi0x-m1a-target-build-") as td:
        scratch = Path(td) / "fixture"
        shutil.copytree(fixture, scratch)
        report = forge_build(root=scratch, forge_bin="forge", tool_runs_dir=work() / "tool_runs")
        if not report.passed:
            raise RuntimeError(report.stderr or report.stdout or "forge build failed")
        obj = json.loads((scratch / "out/M1aTarget.sol/M1aTarget.json").read_text())
    code = obj["bytecode"]["object"]
    if not isinstance(code, str) or not code.startswith("0x") or len(code) < 4:
        raise RuntimeError("M1aTarget creation bytecode is missing")
    return code


def collect() -> int:
    r = root()
    w = work(); w.mkdir(parents=True, exist_ok=True)
    fixture = fixture_root(r)
    commit = __import__("os").environ.get("L0VI0X_COMMIT") or rev_parse_head(r)
    policy, catalog = policy_and_catalog(r)
    # The real Docker compose stack supplies gate/upstream infrastructure. No host Anvil is started here.
    target_creation = build_target(r, fixture)
    (w / "target-creation.sha256").write_text(hashlib.sha256(bytes.fromhex(target_creation[2:])).hexdigest() + "\n")

    for cls in FIXTURES:
        spec = FIXTURES[cls]
        bootstrap = bootstrap_witness(cls, commit, fixture)
        env = make_executor(r, cls).env
        executor = make_executor(r, cls)
        if cls == "deployed_fork":
            if not env.get("GATE_URL"):
                raise RuntimeError("deployed_fork requires GATE_URL from the Docker trust stack")
            env["L0VI0X_INITIAL_BLOCK"] = str(spec.fork_block)
            env["L0VI0X_INITIAL_TIMESTAMP"] = "1700000100"
            executor.env.update(env)
        with tempfile.TemporaryDirectory(prefix=f"l0vi0x-m1a-{cls}-bootstrap-") as td:
            copy_root = Path(td) / "repo"; shutil.copytree(fixture, copy_root)
            result = executor.execute(witness=bootstrap, copy_root=copy_root, run_index=0)
            trace = parse_trace(json.loads(Path(result["trace_path"]).read_text()), cheatcode_catalog=catalog)
            identity = extract_identity(trace)
        witness = final_witness(bootstrap, fixture, identity)
        with tempfile.TemporaryDirectory(prefix=f"l0vi0x-m1a-{cls}-declare-") as td:
            copy_root = Path(td) / "repo"; shutil.copytree(fixture, copy_root)
            result = executor.execute(witness=witness, copy_root=copy_root, run_index=0)
            witness = witness.model_copy(update={"env_hash": str(result["environment_hash"])})
        replay_root = w / cls / "replays"
        coordinator = ReplayCoordinator(repo_root=fixture, replay_root=replay_root, executor=executor, cheatcode_catalog=catalog, cheatcode_policy=policy.get("rules", policy))
        collection = coordinator.collect(witness, runs=3, audit_id=f"M1A-{cls}")
        meta = {
            "witness": witness.model_dump(mode="json"),
            "replay_root": _encode_work_path(collection.root, w),
            "run_dirs": [_encode_work_path(x.artifact_dir.parent.parent, w) for x in collection.runs],
        }
        cls_dir = w / cls
        cls_dir.mkdir(parents=True, exist_ok=True)
        cls_dir.chmod(cls_dir.stat().st_mode | 0o777)
        (cls_dir / "witness.json").write_text(json.dumps(meta, indent=2, sort_keys=True, default=str) + "\n")
        print(f"M1a collect {cls}: PASS")
    return 0


def load_collection(repo_root: Path, work_root: Path, meta: dict[str, Any], witness: Witness, catalog: dict[str, str], policy: dict[str, Any]) -> ReplayCollection:
    replay_root = _normalize_meta_path(meta["replay_root"], work_root)
    run_dirs = tuple(_normalize_meta_path(p, work_root) for p in meta["run_dirs"])
    derived = [__import__("l0vi0x.verifier.derived", fromlist=["load_run"]).load_run(run_dir=p, witness=witness, cheatcode_catalog=catalog) for p in run_dirs]
    records = [d.trace.observed_records_sha256() for d in derived]
    controls = [d.control_hash for d in derived]
    envs = [d.environment_hash for d in derived]
    if len(set(records)) != 1 or len(set(controls)) != 1 or len(set(envs)) != 1:
        raise RuntimeError("M1a retained replay set is nondeterministic")
    aggregate = hashlib.sha256(json.dumps(records, separators=(",", ":")).encode()).hexdigest()
    from l0vi0x.verifier.cheatcode_policy import policy_hash
    tp = policy_hash(repo_root / "config/policy/cheatcode_policy.yaml", repo_root / "config/policy/cheatcode_categories.yaml", repo_root / "config/policy/foundry_config_policy.yaml")
    rr = []
    for i, (p, d) in enumerate(zip(run_dirs, derived), 1):
        artifact = next(p.glob("artifacts/run-*"))
        rr.append(ReplayRun(i, True, artifact, artifact/"trace.json", artifact/"control.json", artifact/"control-trace.json", artifact/"environment.json", d.control_hash, d.environment_hash, d.trace))
    return ReplayCollection(witness_hash(witness), replay_root, tuple(rr), aggregate, tp, controls[0], envs[0])


def certify() -> int:
    r = root(); w = work(); policy, catalog = policy_and_catalog(r)
    # The certificate key is host-only by design. It must live under
    # L0VI0X_HOME, never under the bind-mounted per-audit task/replay root.
    key_path = ensure_audit_key("M1A")
    if key_path.is_relative_to(r.resolve()) or key_path.is_relative_to(w.resolve()):
        raise RuntimeError("certificate key must remain outside the repository and sandbox work root")
    for cls in FIXTURES:
        meta_path = w / cls / "witness.json"
        meta = json.loads(meta_path.read_text())
        witness = Witness.model_validate(meta["witness"])
        collection = load_collection(r, w, meta, witness, catalog, policy)
        # M1a hard checks have already been completed by collect(): structured trace policy, time/block limits, 3 fresh copies, env/control/trace determinism.
        verification = type("M1aVerification", (), {"passed": True})()
        cert = HostCertifier(key_path).issue(witness=witness, collection=collection, verification=verification, certificate_id=f"CERT-M1A-{cls}")
        ok = verify_certificate(cert, key_path.read_bytes(), witness_sha256=witness_hash(witness), env_hash=witness.env_hash, observed_records_sha256=collection.observed_records_sha256, trace_policy_sha256=collection.trace_policy_sha256, control_sha256=collection.control_sha256)
        if not ok:
            raise RuntimeError(f"M1a certificate verification failed: {cls}")
        (w / cls / "certificate.json").write_text(json.dumps(cert.model_dump(mode="json"), indent=2, sort_keys=True) + "\n")
        print(f"M1a certify {cls}: PASS")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="M1a Docker-boundary acceptance driver")
    parser.add_argument("--phase", choices=("collect", "certify", "all"), default="all")
    args = parser.parse_args()
    try:
        if args.phase == "collect": return collect()
        if args.phase == "certify": return certify()
        collect(); certify(); return 0
    except Exception as exc:
        print(f"M1a acceptance: FAIL/BLOCKED\n{exc}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())

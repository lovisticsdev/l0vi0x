from __future__ import annotations

from pathlib import Path
import hashlib
import shutil
import subprocess
import sys
import tempfile
import yaml


try:
    from l0vi0x.chain.foundry_trace import FoundryTraceFormatError
    from l0vi0x.chain.m1a_fixtures import FIXTURES, fixture_root
    from l0vi0x.chain.replay import FoundryReplayExecutor, ReplayCoordinator
    from l0vi0x.chain.witness import compute_env_hash, witness_hash
    from l0vi0x.core.certificates import verify
    from l0vi0x.core.models import Witness, WitnessAssertion
    from l0vi0x.tools.lock import verify_binary_lock
except ImportError as exc:
    print(f"M1a acceptance: BLOCKED/FAIL\nmissing runtime dependency: {exc}", file=sys.stderr)
    raise SystemExit(2)

ROOT = Path(__file__).resolve().parents[3]


def _require_tools() -> None:
    for binary in ("forge", "anvil"):
        if shutil.which(binary) is None:
            raise RuntimeError(f"M1a acceptance requires installed {binary}; run make tools-update after installing pinned tooling")
    problems = verify_binary_lock(ROOT / "config/tools.lock.yaml")
    if problems:
        raise RuntimeError("tool lock is not verified:\n" + "\n".join(problems))


def _witness(cls: str) -> Witness:
    spec=FIXTURES[cls]; template=fixture_root(ROOT)/spec.test_file
    template_sha=hashlib.sha256(template.read_bytes()).hexdigest()
    env_hash=compute_env_hash(
        compiler={"solc":"0.8.24","optimizer":True,"optimizer_runs":200},
        sanitized_config={"ffi":False,"fs_permissions":[],"libs":[]},
        remappings="",
        commit="m1a-fixture-v1",
        witness_class=cls,
        fork_block=spec.fork_block,
        deployment_plan_hash="fixture-plan-v1" if cls=="local_deployment" else None,
        chain_id=31337,
        template_sha256=template_sha,
        attack_body_sha256=hashlib.sha256(b"fixture-attack-body-v1").hexdigest(),
        invariant_check_pins={},
        harness_library_hashes={"WitnessHarness.sol": hashlib.sha256((fixture_root(ROOT)/"test/WitnessHarness.sol").read_bytes()).hexdigest()},
        harness_address="0x0000000000000000000000000000000000000000",
        harness_create2_salt="0x"+"00"*32,
        expected_wrapper_depth=2,
        wrapper_callsite_sha256=hashlib.sha256(b"fixture-wrapper-v1").hexdigest(),
        tool_versions={"forge": "verified-in-tools.lock", "anvil": "verified-in-tools.lock"},
    )
    return Witness(
        witness_class=cls, chain_id=31337, fork_block=spec.fork_block,
        commit="m1a-fixture-v1", compiler={"solc":"0.8.24","optimizer":True},
        test_file=spec.test_file, test_name=spec.test_name, control_test_name=spec.control_test_name,
        initial_capital_wei=10**18 if cls=="local_deployment" else 0,
        max_time_advance_s=1, max_block_advance=1,
        declared_actors=["0x00000000000000000000000000000000000a11ce"], declared_tokens=[],
        setup_budget={"native_wei":10**18} if cls=="local_deployment" else None,
        assertions=[WitnessAssertion(id="A1",kind="custom",target="credit",operator="eq",expected=7,observed_record="AssertionChecked")],
        template_sha256=template_sha, attack_body_sha256=hashlib.sha256(b"fixture-attack-body-v1").hexdigest(),
        harness_address="0x0000000000000000000000000000000000000000", harness_create2_salt="0x"+"00"*32,
        expected_wrapper_depth=2, wrapper_callsite_sha256=hashlib.sha256(b"fixture-wrapper-v1").hexdigest(),
        rpc_provider_label=spec.rpc_provider_label, env_hash=env_hash,
    )


def main() -> int:
    try:
        _require_tools()
        policy=yaml.safe_load((ROOT/"config/policy/cheatcode_policy.yaml").read_text(encoding="utf-8"))["rules"]
        catalog=yaml.safe_load((ROOT/"config/policy/cheatcode_categories.yaml").read_text(encoding="utf-8"))["categories"]
        # Integration environment is intentionally required. The actual gate Anvil/upstream fixture lifecycle
        # is started by the wrapper script, keeping raw upstream URLs outside the sandbox.
        for cls in FIXTURES:
            witness=_witness(cls)
            with tempfile.TemporaryDirectory(prefix=f"l0vi0x-m1a-{cls}-") as td:
                replay_root=Path(td)/"replays"
                if cls == "deployed_fork" and not __import__("os").environ.get("GATE_URL"):
                    raise RuntimeError("deployed_fork acceptance requires GATE_URL pointing at the agent RPC gate")
                executor=FoundryReplayExecutor(forge_bin="forge", env={"GATE_URL": __import__("os").environ.get("GATE_URL", "")})
                key_path=Path(td)/"host.key"
                key_path.write_bytes(hashlib.sha256(b"m1a-host-key").digest())
                # The key stays outside each copied sandbox root; ReplayCoordinator rejects key paths under repo/replay roots.
                coordinator=ReplayCoordinator(repo_root=fixture_root(ROOT), replay_root=replay_root, executor=executor, cheatcode_catalog=catalog, cheatcode_policy=policy)
                cert=coordinator.run(witness,runs=3,audit_id="M1A",key_path=key_path,certificate_id=f"CERT-{cls}")
                if not verify(cert,key_path.read_bytes(),witness_sha256=witness_hash(witness),env_hash=witness.env_hash):
                    raise RuntimeError(f"certificate verification failed: {cls}")
        print("M1a acceptance: PASS")
        return 0
    except (RuntimeError, ValueError, FoundryTraceFormatError) as exc:
        print(f"M1a acceptance: BLOCKED/FAIL\n{exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest
import yaml

from l0vi0x.chain.foundry_config import sanitize_foundry_config
from l0vi0x.chain.replay import CallableReplayExecutor, ReplayCoordinator
from l0vi0x.chain.rpc_gate import RpcGate
from l0vi0x.chain.trace import TracePolicyError, enforce_cheatcode_policy, enforce_time_block_limits, parse_trace
from l0vi0x.chain.witness import compute_env_hash, create2_address, render_template, validate_assertion_kinds, validate_witness, witness_hash
from l0vi0x.core.models import Witness, WitnessAssertion
from l0vi0x.tools.runner import run
from l0vi0x.tools.git import rev_parse_head

ROOT = Path(__file__).resolve().parents[1]
CATALOG = (yaml.safe_load((ROOT / "config/policy/cheatcode_categories.yaml").read_text(encoding="utf-8")) or {})["categories"]
POLICY = (yaml.safe_load((ROOT / "config/policy/cheatcode_policy.yaml").read_text(encoding="utf-8")) or {})["rules"]


def make_witness(tmp_path: Path, *, witness_class: str = "local_deployment") -> Witness:
    sanitized = {"profile": {"default": {"ffi": False, "fs_permissions": []}}}
    template = ROOT / "harness/foundry_template/test/witness/LocalDeployment.t.sol.tpl"
    tmp_path.mkdir(parents=True, exist_ok=True)
    template_sha = hashlib.sha256(template.read_bytes()).hexdigest()
    body_sha = hashlib.sha256(b"vm.warp(1001);").hexdigest()
    env_hash = compute_env_hash(
        compiler={"solc": "0.8.24", "optimizer": True}, sanitized_config=sanitized, remappings="", commit="abc123",
        witness_class=witness_class, fork_block=123 if witness_class == "deployed_fork" else None,
        deployment_plan_hash="planhash" if witness_class == "local_deployment" else None, chain_id=31337,
        template_sha256=template_sha, attack_body_sha256=body_sha, invariant_check_pins={}, harness_library_hashes={"EconHarness.sol": "h"},
        harness_address="0x" + "11" * 20, harness_create2_salt="0x" + "22" * 32, expected_wrapper_depth=3,
        wrapper_callsite_sha256="w", tool_versions={"forge": "test"},
    )
    return Witness(
        witness_class=witness_class,
        chain_id=31337,
        fork_block=123 if witness_class == "deployed_fork" else None,
        commit="abc123",
        compiler={"solc": "0.8.24", "optimizer": True},
        test_file="test/witness/W.t.sol",
        test_name="test_witness",
        control_test_name="test_control",
        initial_capital_wei=100,
        max_time_advance_s=10,
        max_block_advance=3,
        declared_actors=["0x" + "aa" * 20],
        declared_tokens=["0x" + "bb" * 20],
        setup_budget={"native_wei": 100} if witness_class == "local_deployment" else None,
        assertions=[WitnessAssertion(id="A1", kind="custom", target="x", operator="violated", expected=True, observed_record="r1")],
        invariant_check_pins={}, template_sha256=template_sha, attack_body_sha256=body_sha, harness_address="0x" + "11" * 20,
        harness_create2_salt="0x" + "22" * 32, expected_wrapper_depth=3, wrapper_callsite_sha256="w",
        rpc_provider_label="fixture" if witness_class == "deployed_fork" else None, env_hash=env_hash,
    )


def test_tool_runner_records_redacted_output_and_never_uses_shell(tmp_path, monkeypatch):
    secret = "sk-live-secret-123"
    result = run(["python", "-c", f"print({secret!r})"], cwd=tmp_path, tool_runs_dir=tmp_path / "tool_runs")
    assert result.rc == 0
    record = next((tmp_path / "tool_runs").glob("*.json"))
    persisted = record.read_text(encoding="utf-8")
    assert secret not in persisted
    assert "<redacted>" in persisted

    import l0vi0x.tools.runner as runner_module
    calls = {}
    real_run = runner_module.subprocess.run

    def wrapped(*args, **kwargs):
        calls["shell"] = kwargs.get("shell")
        return real_run(*args, **kwargs)

    monkeypatch.setattr(runner_module.subprocess, "run", wrapped)
    run(["python", "-c", "print('ok')"], cwd=tmp_path)
    assert calls["shell"] is False


def test_rev_parse_head_accepts_root_positionally(tmp_path):
    import subprocess

    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", "test"], cwd=tmp_path, check=True)
    (tmp_path / "README").write_text("ok", encoding="utf-8")
    subprocess.run(["git", "add", "README"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=tmp_path, check=True)

    head = rev_parse_head(tmp_path)
    assert len(head) == 40


def test_sanitize_foundry_config_rejects_secrets_and_honors_policy(tmp_path):
    source = tmp_path / "foundry.toml"
    source.write_text('[profile.default]\nffi=true\n\n[rpc_endpoints]\nmainnet="https://secret.example"\nprivate_keys=["x"]\n', encoding="utf-8")
    dest = tmp_path / "sanitized.toml"
    result = sanitize_foundry_config(source, dest, compiler={"solc": "0.8.24"}, gate_url="http://rpc_gate:8545/agent", policy_path=ROOT / "config/policy/foundry_config_policy.yaml")
    text = dest.read_text(encoding="utf-8")
    assert "ffi = false" in text
    assert "private_keys" not in text
    assert "mainnet" not in text
    assert "l0vi0x_gate" in text
    assert "always_use_create_2_factory = true" in text
    assert result["profile"]["default"]["ffi"] is False


def test_rpc_gate_denials_are_logged_redacted(tmp_path):
    gate = RpcGate(ROOT / "config/policy/rpc_allowlist.yaml", audit_id="A-001", log_dir=tmp_path)
    denied = gate.decision("agent", "eth_sendRawTransaction", gate.agent_token)
    assert not denied.allowed and denied.status == 403
    gate.record(endpoint="agent", method="eth_sendRawTransaction", result_code=403, latency_ms=1, params={"private_key": "secret"}, allowed=False)
    line = next(tmp_path.glob("rpc-*.jsonl")).read_text(encoding="utf-8")
    assert "secret" not in line
    assert '"<redacted>"' in line
    assert gate.decision("agent", "eth_chainId", "wrong").status == 401


def test_trace_cumulative_warp_and_roll_rejects():
    payload = {"initial_timestamp": 1000, "initial_block": 10, "trace": [
        {"depth": 1, "phase": "witness", "to": "0x7109709ecfa91a80626ff3989d68f67f5b1dd12d", "cheatcode": "warp", "absolute": 1005},
        {"depth": 1, "phase": "witness", "to": "0x7109709ecfa91a80626ff3989d68f67f5b1dd12d", "cheatcode": "warp", "absolute": 1012},
        {"depth": 1, "phase": "witness", "to": "0x7109709ecfa91a80626ff3989d68f67f5b1dd12d", "cheatcode": "roll", "absolute": 12},
        {"depth": 1, "phase": "witness", "to": "0x7109709ecfa91a80626ff3989d68f67f5b1dd12d", "cheatcode": "roll", "absolute": 14},
    ]}
    summary = parse_trace(payload, cheatcode_catalog=CATALOG)
    assert summary.cumulative_warp_s == 12
    assert summary.cumulative_roll == 4
    with pytest.raises(TracePolicyError, match="cumulative warp"):
        enforce_time_block_limits(summary, max_time_advance_s=10, max_block_advance=10)
    with pytest.raises(TracePolicyError, match="cumulative roll"):
        enforce_time_block_limits(summary, max_time_advance_s=20, max_block_advance=3)


def test_deployed_fork_witness_denies_mutation_cheatcodes():
    summary = parse_trace({"trace": [{"depth": 2, "phase": "witness", "to": "0x7109709ecfa91a80626ff3989d68f67f5b1dd12d", "cheatcode": "deal", "args": ["0x" + "aa" * 20, 100]}]}, cheatcode_catalog=CATALOG)
    with pytest.raises(TracePolicyError):
        enforce_cheatcode_policy(summary, witness_class="deployed_fork", policy=POLICY)


def test_local_setup_allows_declared_setup_mutation():
    payload = {"initial_timestamp": 1000, "initial_block": 1, "trace": [
        {"depth": 1, "phase": "setup", "to": "0x7109709ecfa91a80626ff3989d68f67f5b1dd12d", "cheatcode": "deal", "args": ["0x" + "aa" * 20, 100]},
        {"depth": 1, "phase": "witness", "to": "0x7109709ecfa91a80626ff3989d68f67f5b1dd12d", "cheatcode": "warp", "absolute": 1001},
    ]}
    summary = parse_trace(payload, cheatcode_catalog=CATALOG)
    enforce_cheatcode_policy(summary, witness_class="local_deployment", policy=POLICY)


def test_render_witness_template_resolves_all_placeholders(tmp_path):
    out = tmp_path / "W.t.sol"
    digest = render_template(ROOT / "harness/foundry_template/test/witness/LocalDeployment.t.sol.tpl", out, replacements={
        "ATTACKER_ADDRESS": "0x" + "aa" * 20, "HARNESS_DEPLOYER": "0x" + "bb" * 20, "HARNESS_SALT": "0x" + "11" * 32,
        "INITIAL_CAPITAL_WEI": "100", "SETUP_BODY": "", "BEFORE_BODY": "", "ATTACK_BODY": "        attacker.attack();", "AFTER_BODY": "", "CONTROL_BODY": "        assertTrue(true);",
    })
    text = out.read_text(encoding="utf-8")
    assert "{{" not in text and "attacker.attack()" in text
    assert "HarnessCreate2Factory(HARNESS_DEPLOYER).deploy(HARNESS_SALT" in (ROOT / "harness/foundry_template/test/witness/LocalDeployment.t.sol.tpl").read_text(encoding="utf-8")
    assert len(digest) == 64


def test_witness_validation_and_create2_are_deterministic(tmp_path):
    witness = make_witness(tmp_path)
    validate_witness(witness, scope_attacker_capital_wei=100)
    assert witness_hash(witness) == witness_hash(witness.model_dump(mode="json"))
    init_code = b"EconHarness-init-code"
    a = create2_address("0x" + "11" * 20, "0x" + "22" * 32, init_code)
    assert a.startswith("0x") and len(a) == 42
    assert a == create2_address("0x" + "11" * 20, "0x" + "22" * 32, init_code)
    validate_assertion_kinds(witness.assertions, ["custom"])
    with pytest.raises(ValueError):
        validate_assertion_kinds(witness.assertions, ["invariant"])


def test_replay_collection_requires_three_fresh_runs_and_does_not_issue_certificates(tmp_path):
    witness = make_witness(tmp_path)
    base_trace = {"initial_timestamp": 1000, "initial_block": 10, "trace": [{"depth": 1, "phase": "witness", "kind": "call", "to": "0x" + "12" * 20, "gas_used": 1000}]}

    def execute(*, witness, copy_root, run_index):
        assert copy_root != ROOT
        assert not (copy_root / "certificate.key").exists()
        return {
            "passed": True,
            "trace_json": base_trace,
            "trace_path": str(copy_root / "artifacts" / f"run-{run_index}" / "trace.json"),
            "control_path": str(copy_root / "artifacts" / f"run-{run_index}" / "control.json"),
            "control_trace_path": str(copy_root / "artifacts" / f"run-{run_index}" / "control-trace.json"),
            "environment_path": str(copy_root / "artifacts" / f"run-{run_index}" / "environment.json"),
            "control_sha256": "c" * 64,
            "environment_hash": witness.env_hash,
        }

    def materializing_execute(*, witness, copy_root, run_index):
        result = execute(witness=witness, copy_root=copy_root, run_index=run_index)
        artifact = Path(result["trace_path"]).parent
        artifact.mkdir(parents=True, exist_ok=True)
        Path(result["trace_path"]).write_text(json.dumps(base_trace), encoding="utf-8")
        control = {"result": "ok"}
        Path(result["control_path"]).write_text(json.dumps(control), encoding="utf-8")
        Path(result["control_trace_path"]).write_text(json.dumps({"initial_timestamp": 1000, "initial_block": 10, "trace": []}), encoding="utf-8")
        Path(result["environment_path"]).write_text(json.dumps({"environment_hash": witness.env_hash}), encoding="utf-8")
        return result

    coord = ReplayCoordinator(repo_root=ROOT, replay_root=tmp_path / "replays", executor=CallableReplayExecutor(materializing_execute), cheatcode_catalog=CATALOG, cheatcode_policy=POLICY)
    collection = coord.collect(witness, runs=3, audit_id="A-1")
    assert len(collection.runs) == 3
    assert collection.environment_hash == witness.env_hash
    assert collection.witness_hash == witness_hash(witness)
    assert not any((run.artifact_dir / "certificate.key").exists() for run in collection.runs)


def test_replay_collection_detects_environment_and_trace_nondeterminism(tmp_path):
    witness = make_witness(tmp_path)
    trace_a = {"initial_timestamp": 1000, "initial_block": 10, "trace": []}
    trace_b = {"initial_timestamp": 1000, "initial_block": 10, "trace": [{"depth": 1, "kind": "call", "to": "0x" + "13" * 20}]}

    def materialize(trace_fn, env_fn=lambda _: witness.env_hash):
        def execute(*, witness, copy_root, run_index):
            artifact = copy_root / "artifacts" / f"run-{run_index}"
            artifact.mkdir(parents=True, exist_ok=True)
            trace = trace_fn(run_index)
            Path(artifact / "trace.json").write_text(json.dumps(trace), encoding="utf-8")
            Path(artifact / "control.json").write_text(json.dumps({"result": "ok"}), encoding="utf-8")
            Path(artifact / "control-trace.json").write_text(json.dumps({"initial_timestamp": 1000, "initial_block": 10, "trace": []}), encoding="utf-8")
            env_hash = env_fn(run_index)
            Path(artifact / "environment.json").write_text(json.dumps({"environment_hash": env_hash}), encoding="utf-8")
            return {"passed": True, "trace_path": str(artifact / "trace.json"), "control_path": str(artifact / "control.json"), "control_trace_path": str(artifact / "control-trace.json"), "environment_path": str(artifact / "environment.json"), "control_sha256": "c" * 64, "environment_hash": env_hash}
        return execute

    coord_trace = ReplayCoordinator(repo_root=ROOT, replay_root=tmp_path / "trace", executor=CallableReplayExecutor(materialize(lambda i: trace_a if i < 3 else trace_b)), cheatcode_catalog=CATALOG, cheatcode_policy=POLICY)
    with pytest.raises(ValueError, match="NONDETERMINISTIC_TRACE"):
        coord_trace.collect(witness, runs=3)

    coord_env = ReplayCoordinator(repo_root=ROOT, replay_root=tmp_path / "env", executor=CallableReplayExecutor(materialize(lambda _: trace_a, lambda i: witness.env_hash if i < 3 else "d" * 64)), cheatcode_catalog=CATALOG, cheatcode_policy=POLICY)
    with pytest.raises(ValueError, match="NONDETERMINISTIC_ENV"):
        coord_env.collect(witness, runs=3)

def test_replay_copy_excludes_generated_eval_workspace(tmp_path):
    witness = make_witness(tmp_path)

    generated = ROOT / "eval" / "private" / "m1a-acceptance"
    generated.mkdir(
        parents=True,
        exist_ok=True,
    )

    protected_file = (
        generated / "container-owned-replay"
    )
    protected_file.mkdir(
        parents=True,
        exist_ok=True,
    )
    (
        protected_file / "host-owned-artifact.json"
    ).write_text(
        '{"generated":true}\n',
        encoding="utf-8",
    )

    def execute(*, witness, copy_root, run_index):
        copied_eval = copy_root / "eval"

        assert not copied_eval.exists()

        artifact = (
            copy_root
            / "artifacts"
            / f"run-{run_index}"
        )
        artifact.mkdir(
            parents=True,
            exist_ok=True,
        )

        trace = {
            "initial_timestamp": 1000,
            "initial_block": 10,
            "trace": [],
        }

        (
            artifact / "trace.json"
        ).write_text(
            json.dumps(trace),
            encoding="utf-8",
        )

        (
            artifact / "control.json"
        ).write_text(
            json.dumps({"result": "ok"}),
            encoding="utf-8",
        )

        (
            artifact / "control-trace.json"
        ).write_text(
            json.dumps(
                {
                    "initial_timestamp": 1000,
                    "initial_block": 10,
                    "trace": [],
                }
            ),
            encoding="utf-8",
        )

        (
            artifact / "environment.json"
        ).write_text(
            json.dumps(
                {
                    "environment_hash": (
                        witness.env_hash
                    )
                }
            ),
            encoding="utf-8",
        )

        return {
            "passed": True,
            "trace_path": str(
                artifact / "trace.json"
            ),
            "control_path": str(
                artifact / "control.json"
            ),
            "control_trace_path": str(
                artifact
                / "control-trace.json"
            ),
            "environment_path": str(
                artifact
                / "environment.json"
            ),
            "control_sha256": "c" * 64,
            "environment_hash": (
                witness.env_hash
            ),
        }

    try:
        coord = ReplayCoordinator(
            repo_root=ROOT,
            replay_root=(
                tmp_path / "replays"
            ),
            executor=(
                CallableReplayExecutor(
                    execute
                )
            ),
            cheatcode_catalog=CATALOG,
            cheatcode_policy=POLICY,
        )

        collection = coord.collect(
            witness,
            runs=3,
            audit_id="M1A-EVAL-IGNORE",
        )

        assert len(collection.runs) == 3

    finally:
        shutil.rmtree(
            generated,
            ignore_errors=True,
        )
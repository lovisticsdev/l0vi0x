from __future__ import annotations

from pathlib import Path
import json
import yaml
import pytest

from l0vi0x.chain.foundry_trace import FoundryTraceFormatError, extract_structured_trace
from l0vi0x.chain.foundry_config import sanitize_foundry_config
from l0vi0x.chain.rpc_gate import RpcGate
from l0vi0x.chain.trace import parse_trace, enforce_time_block_limits, TracePolicyError
from l0vi0x.chain.witness import validate_assertion_kinds

ROOT=Path(__file__).resolve().parents[1]


def test_foundry_human_trace_imitation_is_not_accepted():
    with pytest.raises(FoundryTraceFormatError):
        extract_structured_trace({"stdout":"[123] Contract::test()\\n └─ ← ()"})


def test_foundry_structured_trace_requires_versioned_envelope():
    payload={"l0vi0x_structured_trace":{"schema":"l0vi0x.foundry.trace.v1","frames":[{"depth":1,"to":"0x12","calls":[{"depth":2,"to":"0x34","gas":9}]}]}}
    out=extract_structured_trace(payload)
    assert out["schema"] == "l0vi0x.foundry.trace.v1"
    assert out["trace"][0]["to"] == "0x12"
    assert out["trace"][0]["children"][0]["gas_used"] == 9


def test_foundry_unverified_trace_field_is_not_accepted():
    payload={"events":[{"traces":[{"depth":1,"to":"0x12"}]}]}
    with pytest.raises(FoundryTraceFormatError):
        extract_structured_trace(payload)


def test_cumulative_time_and_block_limits_are_enforced():
    payload={"initial_timestamp":1000,"initial_block":10,"trace":[
        {"depth":1,"phase":"witness","to":"0x7109709ecfa91a80626ff3989d68f67f5b1dd12d","cheatcode":"warp","absolute":1000},
        {"depth":1,"phase":"witness","to":"0x7109709ecfa91a80626ff3989d68f67f5b1dd12d","cheatcode":"warp","absolute":1001},
        {"depth":1,"phase":"witness","to":"0x7109709ecfa91a80626ff3989d68f67f5b1dd12d","cheatcode":"warp","absolute":1002},
        {"depth":1,"phase":"witness","to":"0x7109709ecfa91a80626ff3989d68f67f5b1dd12d","cheatcode":"roll","absolute":11},
        {"depth":1,"phase":"witness","to":"0x7109709ecfa91a80626ff3989d68f67f5b1dd12d","cheatcode":"roll","absolute":12},
    ]}
    summary=parse_trace(payload,cheatcode_catalog={"warp":"time_advance","roll":"block_advance"})
    assert summary.cumulative_warp_s == 2
    assert summary.cumulative_roll == 2
    with pytest.raises(TracePolicyError): enforce_time_block_limits(summary,max_time_advance_s=1,max_block_advance=2)
    with pytest.raises(TracePolicyError): enforce_time_block_limits(summary,max_time_advance_s=2,max_block_advance=1)


def test_rpc_gate_denies_upstream_admin_even_when_allowlist_is_broadened(tmp_path):
    policy=ROOT/"config/policy/rpc_allowlist.yaml"
    gate=RpcGate(policy,audit_id="A-1",log_dir=tmp_path)
    gate.policy["endpoints"]["upstream"]["allow"].append("debug_traceCall")
    decision=gate.decision("upstream","debug_traceCall",gate.upstream_token)
    assert not decision.allowed and decision.status == 403


def test_rpc_gate_redacts_secret_parameters(tmp_path):
    gate=RpcGate(ROOT/"config/policy/rpc_allowlist.yaml",audit_id="A-1",log_dir=tmp_path)
    path=gate.record(endpoint="agent",method="eth_call",result_code=403,latency_ms=1,params={"private_key":"secret","nested":{"token":"abc"}},allowed=False)
    data=path.read_text(encoding="utf-8")
    assert '"<redacted>"' in data
    assert '"secret"' not in data
    assert '"abc"' not in data


def test_foundry_config_rejects_untrusted_settings(tmp_path):
    source=tmp_path/"foundry.toml"; dest=tmp_path/"sanitized.toml"
    source.write_text('[profile.default]\nffi=true\nremappings=["evil/=evil"]\n',encoding="utf-8")
    with pytest.raises(ValueError):
        sanitize_foundry_config(source,dest,compiler={"solc":"0.8.24"},gate_url="http://rpc_gate:8545/agent")


def test_echidna_tool_uses_current_cli_name():
    tools = Path("config/tools.yaml").read_text()
    wrapper = Path("src/l0vi0x/tools/echidna.py").read_text()
    assert "echidna: {binary: echidna, timeout_s: 900}" in tools
    assert 'echidna_bin="echidna"' in wrapper
    assert "echidna-test" not in tools
    assert "echidna-test" not in wrapper


def test_solc_select_lock_probe_does_not_assume_version_flag(monkeypatch):
    import l0vi0x.tools.lock as lock

    seen = {}

    monkeypatch.setattr(lock, "_uv_tool_package_version", lambda binary, package: (seen.__setitem__("package", package) or "1.2.3"))

    def fake_command(binary, args, *, label):
        seen["binary"] = binary
        seen["args"] = args
        seen["label"] = label
        return "0.8.24 (current)"

    monkeypatch.setattr(lock, "command_text", fake_command)
    assert lock.version_text("/usr/bin/solc-select", name="solc-select") == ("1.2.3", "0.8.24 (current)")
    assert seen == {
        "package": "solc-select",
        "binary": "/usr/bin/solc-select",
        "args": ["versions"],
        "label": "solc-select versions",
    }


def test_foundry_config_renders_32_byte_fuzz_seed(tmp_path):
    source=tmp_path/"foundry.toml"; dest=tmp_path/"sanitized.toml"
    source.write_text("[profile.default]\n", encoding="utf-8")
    sanitize_foundry_config(source,dest,compiler={"solc":"0.8.24"},gate_url="http://rpc_gate:8545/agent",fuzz_seed=1)
    text=dest.read_text(encoding="utf-8")
    assert 'seed = "0x' in text
    assert 'seed = "' + ('0'*64) + '"' not in text
    assert 'seed = "0x' + ('0'*63) + '1"' in text


def test_tool_lock_empty_or_unverified_fails_closed(tmp_path):
    lock=tmp_path/"tools.lock.yaml"
    cfg=tmp_path/"tools.yaml"
    lock.write_text("version: 1\nstatus: verify-required\ntools: {}\n", encoding="utf-8")
    cfg.write_text("version: 1\ntools:\n  forge: {binary: forge}\n", encoding="utf-8")
    from l0vi0x.tools.lock import verify_binary_lock
    problems = verify_binary_lock(lock)
    assert any("not verified" in p for p in problems)
    assert any("no tool entries" in p for p in problems)
    assert any("missing required tools" in p for p in problems)

def test_assertion_checked_real_abi_shape_decodes():
    from l0vi0x.chain.cheatcode_abi import decode_abi_arguments

    data = bytes.fromhex(
        "00000000000000000000000000000000000000000000000000000000000000a0"
        "00000000000000000000000000000000000000000000000000000000000000e0"
        "0000000000000000000000000000000000000000000000000000000000000007"
        "0000000000000000000000000000000000000000000000000000000000000007"
        "0000000000000000000000000000000000000000000000000000000000000001"
        "0000000000000000000000000000000000000000000000000000000000000006"
        "637573746f6d0000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000006"
        "6372656469740000000000000000000000000000000000000000000000000000"
    )

    assert len(data) == 288

    assert decode_abi_arguments(
        ["string", "string", "int256", "int256", "bool"],
        data,
    ) == ["custom", "credit", 7, 7, True]
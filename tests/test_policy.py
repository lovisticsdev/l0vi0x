from pathlib import Path

import pytest

from l0vi0x.core.policy import CheatcodePolicy, PolicyViolation


ROOT = Path(__file__).resolve().parents[1]


def policy():
    return CheatcodePolicy(ROOT / "config/policy/cheatcode_categories.yaml", ROOT / "config/policy/cheatcode_policy.yaml")


def test_unclassified_cheatcodes_default_deny():
    with pytest.raises(PolicyViolation):
        policy().category("totallyUnknownCheatcode")


def test_deployed_fork_denies_state_minting():
    with pytest.raises(PolicyViolation):
        policy().check("deal", witness_class="deployed_fork", phase="witness")


def test_local_setup_allows_declared_setup_cheatcodes():
    policy().check("deal", witness_class="local_deployment", phase="setup")


def test_unsafe_io_is_denied_by_default():
    with pytest.raises(PolicyViolation):
        policy().check("ffi", witness_class="local_deployment", phase="witness")


def test_policy_files_are_present_and_nonempty():
    for name in [
        "rpc_allowlist.yaml",
        "cheatcode_categories.yaml",
        "cheatcode_policy.yaml",
        "foundry_config_policy.yaml",
        "sandbox.yaml",
    ]:
        path = ROOT / "config/policy" / name
        assert path.stat().st_size > 0


def test_rpc_policy_has_separate_agent_and_upstream_allowlists():
    import yaml
    data = yaml.safe_load((ROOT / "config/policy/rpc_allowlist.yaml").read_text(encoding="utf-8"))
    assert data["endpoints"]["agent"]["allow"]
    assert data["endpoints"]["upstream"]["allow"]

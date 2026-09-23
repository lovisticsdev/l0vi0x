from __future__ import annotations

from pathlib import Path
try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11 (e.g. the sandbox image's apt python3)
    import tomli as tomllib
from typing import Any

import yaml


FORBIDDEN_KEYS = {
    "private_keys", "mnemonic", "sender", "eth_rpc_url", "etherscan_api_key",
    "solc", "auto_detect_solc", "libraries", "scripts", "build_commands",
    "preprocessor", "permissions",
}
IGNORED_SECURITY_OVERRIDES = {"ffi", "fs_permissions", "rpc_endpoints"}
ALLOWED_PROFILE_KEYS = {
    "src", "test", "out", "libs", "solc_version", "evm_version", "optimizer", "optimizer_runs",
    "dynamic_test_linking", "always_use_create_2_factory", "fuzz",
}


def _validate_no_forbidden(value: Any, path: str = "foundry") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).lower()
            if normalized in FORBIDDEN_KEYS:
                raise ValueError(f"forbidden Foundry config key at {path}.{key}")
            if normalized in IGNORED_SECURITY_OVERRIDES:
                continue
            _validate_no_forbidden(child, f"{path}.{key}")
    elif isinstance(value, list):
        for i, child in enumerate(value):
            _validate_no_forbidden(child, f"{path}[{i}]")


def _quote(value: str) -> str:
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'


def _seed_hex(value: int | str) -> str:
    if isinstance(value, str):
        raw = value.strip()
        if raw.startswith("0x") and len(raw) == 66:
            int(raw, 16)
            return raw.lower()
        value = int(raw, 0)
    number = int(value)
    if number < 0 or number >= 2**256:
        raise ValueError("fuzz seed must fit in uint256")
    return f"0x{number:064x}"


def _read_policy(policy_path: str | Path | None) -> dict[str, Any]:
    if policy_path is None:
        return {
            "security": {
                "ffi": False,
                "fs_permissions": [],
                "libs": [],
                "rpc_endpoints": {"l0vi0x_gate": "gate-only"},
                "always_use_create_2_factory": True,
                "fuzz": {"runs": 256, "seed": 1},
            }
        }
    path = Path(policy_path)
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except OSError as exc:
        raise ValueError(f"cannot read Foundry security policy: {path}") from exc
    if not isinstance(payload, dict):
        raise ValueError("Foundry security policy must be a mapping")
    return payload


def _render_toml(config: dict[str, Any]) -> str:
    p = config["profile"]["default"]
    lines = ["[profile.default]"]
    for key in ("src", "test", "out", "solc_version", "evm_version", "bytecode_hash"):
        if key in p and p[key] not in (None, ""):
            lines.append(f"{key} = {_quote(str(p[key]))}")
    for key in ("block_timestamp", "block_number", "chain_id"):
        if key in p and p[key] is not None:
            lines.append(f"{key} = {int(p[key])}")
    lines.append("libs = []")
    lines.append("ffi = false")
    lines.append("fs_permissions = []")
    lines.append(f"always_use_create_2_factory = {str(bool(p['always_use_create_2_factory'])).lower()}")
    lines.append("dynamic_test_linking = false")
    lines.append(f"optimizer = {str(bool(p.get('optimizer', True))).lower()}")
    lines.append(f"optimizer_runs = {int(p.get('optimizer_runs', 200))}")
    lines.append("")
    lines.append("[profile.default.fuzz]")
    lines.append(f"runs = {int(p['fuzz']['runs'])}")
    lines.append(f'seed = "{_seed_hex(p["fuzz"]["seed"])}"')
    lines.append("")
    lines.append("[rpc_endpoints]")
    lines.append(f"l0vi0x_gate = {_quote(str(config['gate_url']))}")
    lines.append("")
    return "\n".join(lines)


def sanitize_foundry_config(
    source: str | Path,
    destination: str | Path,
    *,
    compiler: dict[str, Any],
    gate_url: str,
    policy_path: str | Path | None = None,
    fuzz_runs: int = 256,
    fuzz_seed: int = 1,
) -> dict[str, Any]:
    source_path = Path(source)
    policy = _read_policy(policy_path)
    security = policy.get("security") if isinstance(policy.get("security"), dict) else {}
    if source_path.exists() and source_path.read_text(encoding="utf-8").strip():
        try:
            raw = tomllib.loads(source_path.read_text(encoding="utf-8"))
        except tomllib.TOMLDecodeError as exc:
            raise ValueError(f"invalid foundry.toml: {exc}") from exc
        _validate_no_forbidden(raw)
        supplied = raw.get("profile", {}).get("default", {})
        unknown = set(supplied) - ALLOWED_PROFILE_KEYS - IGNORED_SECURITY_OVERRIDES
        if unknown:
            raise ValueError(f"unsupported/untrusted Foundry settings: {sorted(unknown)}")
    else:
        raw = {}
        supplied = {}
    default = {k: supplied[k] for k in ALLOWED_PROFILE_KEYS if k in supplied}
    fuzz_policy = security.get("fuzz") if isinstance(security.get("fuzz"), dict) else {}
    default.update({
        "src": "src",
        "ffi": False,
        "fs_permissions": [],
        "test": "test",
        "out": "out",
        "libs": [],
        "optimizer": bool(compiler.get("optimizer", True)),
        "optimizer_runs": int(compiler.get("optimizer_runs", 200)),
        "solc_version": compiler.get("solc", compiler.get("solc_version", "")),
        "evm_version": compiler.get("evm_version", ""),
        "dynamic_test_linking": False,
        "always_use_create_2_factory": bool(security.get("always_use_create_2_factory", True)),
        "block_timestamp": 1,
        "block_number": 1,
        "chain_id": 31337,
        "bytecode_hash": "none",
        "fuzz": {
            "runs": int(fuzz_policy.get("runs", fuzz_runs)),
            "seed": int(fuzz_policy.get("seed", fuzz_seed)),
        },
    })
    sanitized = {
        "profile": {"default": default},
        "gate_url": gate_url,
        "security": {
            "ffi": False,
            "fs_permissions": [],
            "libs": [],
            "always_use_create_2_factory": bool(default["always_use_create_2_factory"]),
        },
    }
    dest = Path(destination)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(_render_toml(sanitized), encoding="utf-8")
    return sanitized

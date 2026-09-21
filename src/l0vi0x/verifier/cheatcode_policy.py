from __future__ import annotations

import hashlib
import json
from pathlib import Path
import yaml

from l0vi0x.chain.foundry_config import sanitize_foundry_config
from l0vi0x.chain.trace import TracePolicyError, TraceSummary, enforce_cheatcode_policy
from .types import CheckResult


def policy_hash(policy_path: Path, catalog_path: Path, foundry_config_path: Path | None = None) -> str:
    # ReplayCertificate binds the trace policy vocabulary; Foundry configuration is
    # separately hashed/checked by V05 so a config edit cannot become invisible here.
    policy = yaml.safe_load(policy_path.read_text(encoding="utf-8")) or {}
    catalog = yaml.safe_load(catalog_path.read_text(encoding="utf-8")) or {}
    raw = json.dumps({"policy": policy, "catalog": catalog}, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(raw).hexdigest()


def check(*, trace: TraceSummary | None, witness_class: str, policy_path: Path, catalog_path: Path, foundry_config_path: Path | None = None, fork_block: int | None = None) -> CheckResult:
    if trace is None:
        return CheckResult("V05", False, "TRACE_MISSING", True, "authoritative structured trace is missing")
    if foundry_config_path is not None:
        try:
            text = foundry_config_path.read_text(encoding="utf-8")
        except OSError as exc:
            return CheckResult("V05", False, "POLICY_VIOLATION", True, f"sanitized Foundry config unavailable: {exc}")
        required_fragments = ("ffi = false", "fs_permissions = []", "l0vi0x_gate =")
        if any(fragment not in text for fragment in required_fragments):
            return CheckResult("V05", False, "POLICY_VIOLATION", True, "sanitized Foundry config is missing fail-closed security settings")
    try:
        policy = (yaml.safe_load(policy_path.read_text(encoding="utf-8")) or {}).get("rules", {})
        enforce_cheatcode_policy(trace, witness_class=witness_class, policy=policy, fork_block=fork_block)
    except (TracePolicyError, OSError, yaml.YAMLError) as exc:
        code = "HARNESS_TAMPERED" if "harness" in str(exc).lower() else "POLICY_VIOLATION"
        return CheckResult("V05", False, code, True, str(exc))
    # Every cheatcode call must target the canonical cheatcode address; parser-generated
    # cheatcodes are not accepted solely because a text field says "warp" or "deal".
    for cheat in trace.cheatcodes:
        if cheat.category == "UNCLASSIFIED" or not cheat.category:
            return CheckResult("V05", False, "POLICY_VIOLATION", True, "unclassified cheatcode")
        if cheat.name in {"hoax", "startHoax"}:
            return CheckResult("V05", False, "POLICY_VIOLATION", True, "opaque hoax helper is forbidden; structured trace must expose its deal+prank effects")
    return CheckResult("V05", True, message="structured trace passes authoritative cheatcode policy")

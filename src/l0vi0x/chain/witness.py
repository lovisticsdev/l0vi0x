from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

from eth_hash.auto import keccak

from l0vi0x.core.models import Witness, WitnessAssertion


def sha256_file(path: str | Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def hash_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def canonical_witness_payload(witness: Witness | dict[str, Any]) -> dict[str, Any]:
    data = witness.model_dump(mode="json") if isinstance(witness, Witness) else dict(witness)
    data.pop("env_hash", None)
    return data


def witness_hash(witness: Witness | dict[str, Any]) -> str:
    raw = json.dumps(canonical_witness_payload(witness), sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(raw).hexdigest()


def compute_env_hash(
    *,
    compiler: dict[str, Any],
    sanitized_config: dict[str, Any],
    remappings: str,
    commit: str,
    witness_class: str,
    fork_block: int | None,
    deployment_plan_hash: str | None,
    chain_id: int,
    template_sha256: str,
    attack_body_sha256: str,
    invariant_check_pins: dict[str, str],
    harness_library_hashes: dict[str, str],
    harness_address: str,
    harness_create2_salt: str,
    expected_wrapper_depth: int,
    wrapper_callsite_sha256: str,
    tool_versions: dict[str, str] | None = None,
    initial_timestamp: int | None = None,
    initial_block: int | None = None,
) -> str:
    payload = {
        "compiler": compiler,
        "sanitized_config": sanitized_config,
        "remappings": remappings,
        "commit": commit,
        "witness_class": witness_class,
        "fork_block": fork_block,
        "deployment_plan_hash": deployment_plan_hash,
        "chain_id": chain_id,
        "template_sha256": template_sha256,
        "attack_body_sha256": attack_body_sha256,
        "invariant_check_pins": invariant_check_pins,
        "harness_library_hashes": harness_library_hashes,
        "harness_address": harness_address,
        "harness_create2_salt": harness_create2_salt,
        "expected_wrapper_depth": expected_wrapper_depth,
        "wrapper_callsite_sha256": wrapper_callsite_sha256,
        "tool_versions": tool_versions or {},
        "initial_timestamp": initial_timestamp,
        "initial_block": initial_block,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def marked_region_sha256(text: str, marker: str) -> str:
    begin = f"// BEGIN {marker}"
    end = f"// END {marker}"
    start = text.find(begin)
    finish = text.find(end)
    if start < 0 or finish < 0 or finish <= start:
        raise ValueError(f"missing or invalid marked region: {marker}")
    payload_start = start + len(begin)
    return hashlib.sha256(text[payload_start:finish].encode("utf-8")).hexdigest()


def create_address(deployer: str, nonce: int) -> str:
    if nonce < 0:
        raise ValueError("nonce must be non-negative")
    if nonce >= 2**256:
        raise ValueError("nonce out of range")
    # Minimal RLP for [address, nonce]. Addresses are fixed 20-byte strings; nonces are canonically encoded.
    addr = _hex_address(deployer)
    if nonce == 0:
        enc_nonce = b"\x80"
    else:
        raw = nonce.to_bytes((nonce.bit_length() + 7) // 8, "big")
        enc_nonce = bytes([len(raw)]) + raw if len(raw) < 56 else _rlp_long_string(raw)
    payload = bytes([0x80 + len(addr)]) + addr + enc_nonce
    if len(payload) < 56:
        encoded = bytes([0xc0 + len(payload)]) + payload
    else:
        encoded = _rlp_long_list(payload)
    return "0x" + keccak(encoded)[-20:].hex()


def _rlp_long_string(raw: bytes) -> bytes:
    length = len(raw)
    lb = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0xb7 + len(lb)]) + lb + raw


def _rlp_long_list(payload: bytes) -> bytes:
    length = len(payload)
    lb = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0xf7 + len(lb)]) + lb + payload


def validate_assertion_kinds(assertions: Iterable[WitnessAssertion], allowed_kinds: Iterable[str]) -> None:
    allowed = set(allowed_kinds)
    for assertion in assertions:
        if assertion.kind not in allowed:
            raise ValueError(f"assertion kind {assertion.kind!r} is not allowed by this lens")


def validate_witness(witness: Witness, *, scope_attacker_capital_wei: int | None = None, allowed_assertion_kinds: Iterable[str] | None = None) -> None:
    if scope_attacker_capital_wei is not None and witness.initial_capital_wei > scope_attacker_capital_wei:
        raise ValueError("witness initial capital exceeds scope limit")
    if witness.max_time_advance_s < 0 or witness.max_block_advance < 0:
        raise ValueError("time/block limits must be non-negative")
    if not witness.declared_actors:
        raise ValueError("witness must declare at least one actor")
    if len(set(witness.declared_actors)) != len(witness.declared_actors):
        raise ValueError("declared actors must be unique")
    if len(set(witness.declared_tokens)) != len(witness.declared_tokens):
        raise ValueError("declared tokens must be unique")
    if allowed_assertion_kinds is not None:
        validate_assertion_kinds(witness.assertions, allowed_assertion_kinds)


def create2_address(deployer: str, salt_hex: str, init_code: bytes) -> str:
    deployer_b = _hex_address(deployer)
    salt = _hex_bytes(salt_hex, 32)
    code_hash = keccak(init_code)
    digest = keccak(b"\xff" + deployer_b + salt + code_hash)
    return "0x" + digest[-20:].hex()


def assert_harness_address(*, deployer: str, salt: str, init_code: bytes, expected: str) -> str:
    actual = create2_address(deployer, salt, init_code)
    if actual.lower() != expected.lower():
        raise ValueError(f"harness address mismatch: {actual} != {expected}")
    return actual


def render_template(template_path: str | Path, destination: str | Path, *, replacements: dict[str, str]) -> str:
    template = Path(template_path).read_text(encoding="utf-8")
    rendered = template
    for key, value in replacements.items():
        rendered = rendered.replace("{{ " + key + " }}", value).replace("{{" + key + "}}", value)
    if "{{" in rendered or "}}" in rendered:
        raise ValueError("unresolved witness template placeholders")
    dest = Path(destination)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(rendered, encoding="utf-8")
    return hashlib.sha256(rendered.encode("utf-8")).hexdigest()


def _hex_address(value: str) -> bytes:
    text = value[2:] if value.startswith("0x") else value
    if len(text) != 40:
        raise ValueError("address must be 20 bytes")
    return bytes.fromhex(text)


def _hex_bytes(value: str, size: int) -> bytes:
    text = value[2:] if value.startswith("0x") else value
    raw = bytes.fromhex(text)
    if len(raw) != size:
        raise ValueError(f"value must be {size} bytes")
    return raw

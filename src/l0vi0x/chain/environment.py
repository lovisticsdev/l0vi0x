"""Observe the replay environment from the *copied tree* instead of echoing the witness.

``Witness.env_hash`` is computed when a witness is declared. At replay time the executor rebuilds the
same digest from the fresh copy it is about to run:

* the parsed ``foundry.toml`` (compiler settings, security switches, RPC alias table),
* the template file, the ATTACK BODY region and the WRAPPER CALLSITE region,
* the harness library files and the deployment-plan sources,
* the tool versions reported by the binaries themselves.

The coordinator then compares the observed digest with the witness' declaration, so a tampered
harness library, edited test file, changed compiler pin or different Foundry build changes the digest
and the replay is refused. Comparing digests across runs alone cannot detect that: three copies that
are all wrong in the same way still agree with each other.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import tomllib
from typing import Any, Mapping, Sequence

from l0vi0x.chain.witness import compute_env_hash, marked_region_sha256, sha256_file
from l0vi0x.core.models import Witness


ATTACK_BODY_REGION = "ATTACK BODY"
WRAPPER_CALLSITE_REGION = "WRAPPER CALLSITE"

# Foundry's documented defaults; a fixture may pin others in foundry.toml.
FOUNDRY_DEFAULT_BLOCK_TIMESTAMP = 1
FOUNDRY_DEFAULT_BLOCK_NUMBER = 1


class EnvironmentMismatch(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class TreeObservation:
    compiler: dict[str, Any]
    sanitized_config: dict[str, Any]
    remappings: str
    template_sha256: str
    attack_body_sha256: str
    wrapper_callsite_sha256: str
    harness_library_hashes: dict[str, str]
    deployment_plan_hash: str | None


def read_foundry_toml(root: str | Path) -> dict[str, Any]:
    path = Path(root) / "foundry.toml"
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise EnvironmentMismatch(f"cannot read {path}: {exc}") from exc


def _default_profile(root: str | Path) -> dict[str, Any]:
    profile = read_foundry_toml(root).get("profile", {}).get("default")
    if not isinstance(profile, dict):
        raise EnvironmentMismatch("foundry.toml has no [profile.default] table")
    return profile


def observe_compiler(root: str | Path) -> dict[str, Any]:
    profile = _default_profile(root)
    missing = [k for k in ("solc_version", "optimizer", "optimizer_runs", "evm_version") if k not in profile]
    if missing:
        raise EnvironmentMismatch(f"foundry.toml must pin: {', '.join(missing)}")
    return {
        "solc": str(profile["solc_version"]),
        "optimizer": bool(profile["optimizer"]),
        "optimizer_runs": int(profile["optimizer_runs"]),
        "evm_version": str(profile["evm_version"]),
    }


def initial_block_env_from_config(root: str | Path) -> tuple[int, int]:
    """(timestamp, block number) Foundry starts a local test with, from the pinned config."""
    profile = _default_profile(root)
    timestamp = profile.get("block_timestamp", FOUNDRY_DEFAULT_BLOCK_TIMESTAMP)
    number = profile.get("block_number", FOUNDRY_DEFAULT_BLOCK_NUMBER)
    for label, value in (("block_timestamp", timestamp), ("block_number", number)):
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise EnvironmentMismatch(f"foundry.toml {label} must be a non-negative integer")
    return timestamp, number


def observe_tree(
    root: str | Path,
    *,
    test_file: str,
    witness_class: str,
    harness_library_paths: Sequence[str],
    deployment_plan_paths: Sequence[str] = (),
) -> TreeObservation:
    base = Path(root)
    raw = read_foundry_toml(base)
    text_path = base / test_file
    try:
        test_text = text_path.read_text(encoding="utf-8")
        attack_sha = marked_region_sha256(test_text, ATTACK_BODY_REGION)
        callsite_sha = marked_region_sha256(test_text, WRAPPER_CALLSITE_REGION)
        template_sha = sha256_file(text_path)
        libraries = {p: sha256_file(base / p) for p in harness_library_paths}
        plan_hash: str | None = None
        if witness_class == "local_deployment" and deployment_plan_paths:
            digest = hashlib.sha256()
            for p in deployment_plan_paths:
                digest.update(f"{p}:{sha256_file(base / p)}\n".encode())
            plan_hash = digest.hexdigest()
    except (OSError, ValueError) as exc:
        raise EnvironmentMismatch(f"cannot observe replay tree: {exc}") from exc
    remappings_path = base / "remappings.txt"
    remappings = remappings_path.read_text(encoding="utf-8") if remappings_path.exists() else ""
    return TreeObservation(
        compiler=observe_compiler(base),
        sanitized_config={"profile": raw.get("profile", {}).get("default", {}), "rpc_endpoints": raw.get("rpc_endpoints", {})},
        remappings=remappings,
        template_sha256=template_sha,
        attack_body_sha256=attack_sha,
        wrapper_callsite_sha256=callsite_sha,
        harness_library_hashes=libraries,
        deployment_plan_hash=plan_hash,
    )


def check_declaration(observation: TreeObservation, witness: Witness) -> None:
    """The tree on disk must be exactly what the witness declares."""
    if observation.template_sha256 != witness.template_sha256:
        raise EnvironmentMismatch("test file differs from the declared template hash")
    if observation.attack_body_sha256 != witness.attack_body_sha256:
        raise EnvironmentMismatch("ATTACK BODY differs from the declared attack-body hash")
    if observation.wrapper_callsite_sha256 != witness.wrapper_callsite_sha256:
        raise EnvironmentMismatch("WRAPPER CALLSITE differs from the declared call-site hash")
    for key, declared in witness.compiler.items():
        if observation.compiler.get(key) != declared:
            raise EnvironmentMismatch(f"compiler setting {key!r} differs from the declaration")


def environment_hash(observation: TreeObservation, witness: Witness, tool_versions: Mapping[str, str], *, initial_timestamp: int | None = None, initial_block: int | None = None) -> str:
    return compute_env_hash(
        compiler=observation.compiler,
        sanitized_config=observation.sanitized_config,
        remappings=observation.remappings,
        commit=witness.commit,
        witness_class=witness.witness_class,
        fork_block=witness.fork_block,
        deployment_plan_hash=observation.deployment_plan_hash,
        chain_id=witness.chain_id,
        template_sha256=observation.template_sha256,
        attack_body_sha256=observation.attack_body_sha256,
        invariant_check_pins=witness.invariant_check_pins,
        harness_library_hashes=observation.harness_library_hashes,
        harness_address=witness.harness_address.lower(),
        harness_create2_salt=witness.harness_create2_salt.lower(),
        expected_wrapper_depth=witness.expected_wrapper_depth,
        wrapper_callsite_sha256=observation.wrapper_callsite_sha256,
        tool_versions=dict(tool_versions),
        initial_timestamp=initial_timestamp,
        initial_block=initial_block,
    )

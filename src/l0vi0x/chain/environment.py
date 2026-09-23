"""Independent replay-environment observation and binding."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11 (e.g. the sandbox image's apt python3)
    import tomli as tomllib
from typing import Any, Mapping, Sequence

from l0vi0x.chain.witness import compute_env_hash, marked_region_sha256, sha256_file
from l0vi0x.core.models import Witness


ATTACK_BODY_REGION = "ATTACK BODY"
WRAPPER_CALLSITE_REGION = "WRAPPER CALLSITE"
FOUNDRY_DEFAULT_BLOCK_TIMESTAMP = 1
FOUNDRY_DEFAULT_BLOCK_NUMBER = 1
_GENERATED_DIRS = {".git", ".venv", "__pycache__", ".pytest_cache", "out", "cache", "tool_runs", "artifacts", "audits"}


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
    source_manifest_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "TreeObservation":
        required = {
            "compiler", "sanitized_config", "remappings", "template_sha256",
            "attack_body_sha256", "wrapper_callsite_sha256", "harness_library_hashes",
            "deployment_plan_hash", "source_manifest_sha256",
        }
        missing = sorted(required - set(payload))
        if missing:
            raise EnvironmentMismatch(f"environment observation missing fields: {missing}")
        return cls(
            compiler=dict(payload["compiler"]),
            sanitized_config=dict(payload["sanitized_config"]),
            remappings=str(payload["remappings"]),
            template_sha256=str(payload["template_sha256"]),
            attack_body_sha256=str(payload["attack_body_sha256"]),
            wrapper_callsite_sha256=str(payload["wrapper_callsite_sha256"]),
            harness_library_hashes={str(k): str(v) for k, v in dict(payload["harness_library_hashes"]).items()},
            deployment_plan_hash=None if payload["deployment_plan_hash"] is None else str(payload["deployment_plan_hash"]),
            source_manifest_sha256=str(payload["source_manifest_sha256"]),
        )


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
    profile = _default_profile(root)
    timestamp = profile.get("block_timestamp", FOUNDRY_DEFAULT_BLOCK_TIMESTAMP)
    number = profile.get("block_number", FOUNDRY_DEFAULT_BLOCK_NUMBER)
    for label, value in (("block_timestamp", timestamp), ("block_number", number)):
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise EnvironmentMismatch(f"foundry.toml {label} must be a non-negative integer")
    return timestamp, number


def _source_manifest(root: Path) -> str:
    rows: list[str] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root)
        if any(part in _GENERATED_DIRS for part in rel.parts):
            continue
        # Runtime logs, local secrets and ephemeral files are not source inputs.
        if rel.name in {".env", ".env.local"} or (rel.name.startswith(".env.") and rel.name != ".env.example") or "keys" in rel.parts or rel.suffix in {".pyc", ".sqlite", ".db"}:
            continue
        rows.append(f"{rel.as_posix()}:{sha256_file(path)}")
    digest = hashlib.sha256()
    for row in rows:
        digest.update((row + "\n").encode("utf-8"))
    return digest.hexdigest()


def _plan_hash(root: Path, paths: Sequence[str], witness_class: str) -> str | None:
    if witness_class != "local_deployment" or not paths:
        return None
    digest = hashlib.sha256()
    for rel in paths:
        digest.update(f"{rel}:{sha256_file(root / rel)}\n".encode("utf-8"))
    return digest.hexdigest()


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
        observation = TreeObservation(
            compiler=observe_compiler(base),
            sanitized_config={
                "profile": raw.get("profile", {}).get("default", {}),
                "rpc_endpoints": raw.get("rpc_endpoints", {}),
            },
            remappings=(base / "remappings.txt").read_text(encoding="utf-8") if (base / "remappings.txt").exists() else "",
            template_sha256=sha256_file(text_path),
            attack_body_sha256=marked_region_sha256(test_text, ATTACK_BODY_REGION),
            wrapper_callsite_sha256=marked_region_sha256(test_text, WRAPPER_CALLSITE_REGION),
            harness_library_hashes={p: sha256_file(base / p) for p in harness_library_paths},
            deployment_plan_hash=_plan_hash(base, deployment_plan_paths, witness_class),
            source_manifest_sha256=_source_manifest(base),
        )
    except (OSError, ValueError) as exc:
        raise EnvironmentMismatch(f"cannot observe replay tree: {exc}") from exc
    return observation


def check_declaration(observation: TreeObservation, witness: Witness, *, root: str | Path | None = None) -> None:
    if observation.template_sha256 != witness.template_sha256:
        raise EnvironmentMismatch("test file differs from declared template hash")
    if observation.attack_body_sha256 != witness.attack_body_sha256:
        raise EnvironmentMismatch("ATTACK BODY differs from declared attack-body hash")
    if observation.wrapper_callsite_sha256 != witness.wrapper_callsite_sha256:
        raise EnvironmentMismatch("WRAPPER CALLSITE differs from declared call-site hash")
    for key, declared in witness.compiler.items():
        if observation.compiler.get(key) != declared:
            raise EnvironmentMismatch(f"compiler setting {key!r} differs from declaration")
    if witness.harness_source_sha256 and witness.harness_source_path:
        if root is None:
            raise EnvironmentMismatch("replay root is required to validate the declared harness source")
        actual = sha256_file(Path(root) / witness.harness_source_path)
        if actual != witness.harness_source_sha256:
            raise EnvironmentMismatch("declared harness source hash does not match the replay tree")


def environment_hash(
    observation: TreeObservation,
    witness: Witness,
    tool_versions: Mapping[str, str],
    *,
    initial_timestamp: int | None = None,
    initial_block: int | None = None,
) -> str:
    payload = {
        "source_manifest_sha256": observation.source_manifest_sha256,
        "harness_source_sha256": witness.harness_source_sha256,
        "wrapper_source_sha256": witness.wrapper_source_sha256,
        "harness_init_code_sha256": witness.harness_init_code_sha256,
        "harness_runtime_sha256": witness.harness_runtime_sha256,
        "wrapper_runtime_sha256": witness.wrapper_runtime_sha256,
    }
    base = compute_env_hash(
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
        tool_versions={**dict(tool_versions), "binding": json_hash(payload)},
        initial_timestamp=initial_timestamp,
        initial_block=initial_block,
    )
    return base


def json_hash(payload: Any) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()

from __future__ import annotations

# Deterministic M1a integration-fixture constants.
# Keep these shared between the stack and the Solidity fixtures.
FIXTURE_CHAIN_ID = 31337
FIXTURE_ATTACKER = "0x000000000000000000000000000000000000a11ce"
FIXTURE_CREDIT = 3

from dataclasses import dataclass
from pathlib import Path
import hashlib


@dataclass(frozen=True, slots=True)
class FixtureSpec:
    witness_class: str
    test_file: str
    test_name: str = "test_witness"
    control_test_name: str = "test_control"
    fork_block: int | None = None
    rpc_provider_label: str | None = None


def fixture_root(repo_root: str | Path) -> Path:
    return Path(repo_root).resolve() / "fixtures" / "m1a_foundry"


def template_hash(path: str | Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


FIXTURES = {
    "local_deployment": FixtureSpec("local_deployment", "test/LocalDeploymentWitness.t.sol"),
    "deployed_fork": FixtureSpec("deployed_fork", "test/DeployedForkWitness.t.sol", fork_block=3, rpc_provider_label="m1a-fixture-upstream"),
}

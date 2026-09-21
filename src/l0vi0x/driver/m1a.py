from __future__ import annotations

from pathlib import Path
from typing import Any

from l0vi0x.chain.replay import ReplayCoordinator, ReplayExecutor
from l0vi0x.core.models import Witness


def run_replay(*, repo_root: str | Path, replay_root: str | Path, witness: Witness, executor: ReplayExecutor, catalog: dict[str, str], policy: dict[str, Any], audit_id: str, key: bytes, runs: int = 3):
    coordinator = ReplayCoordinator(repo_root=repo_root, replay_root=replay_root, executor=executor, cheatcode_catalog=catalog, cheatcode_policy=policy)
    return coordinator.run(witness, runs=runs, audit_id=audit_id, key=key)

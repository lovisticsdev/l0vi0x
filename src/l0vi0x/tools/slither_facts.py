from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class FunctionFacts:
    name: str
    signature: str
    visibility: str
    modifiers: tuple[str, ...] = ()
    state_variables_read: tuple[str, ...] = ()
    state_variables_written: tuple[str, ...] = ()
    external_calls: tuple[str, ...] = ()

@dataclass(frozen=True, slots=True)
class ContractFacts:
    name: str
    functions: tuple[FunctionFacts, ...] = ()
    raw: dict[str, Any] = field(default_factory=dict)


def analyze(*, root: str | Path, slither_bin: str = "slither", timeout_s: float = 900, tool_runs_dir: str | Path | None = None) -> Any:
    # Slither has a version-sensitive JSON schema; M1a records the raw deterministic report for M1b normalization.
    from l0vi0x.tools.runner import run
    result = run([slither_bin, str(root), "--json", "-"], cwd=root, timeout_s=timeout_s, tool_runs_dir=tool_runs_dir)
    if result.rc != 0:
        raise RuntimeError(result.stderr or result.stdout)
    return result.stdout

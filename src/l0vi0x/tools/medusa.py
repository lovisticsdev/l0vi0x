from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
import json
from l0vi0x.tools.runner import run

@dataclass(frozen=True, slots=True)
class FuzzReport:
    violations: list[dict[str, Any]]
    coverage: dict[str, Any]
    raw: dict[str, Any]


def fuzz(*, root: str | Path, config: str = "medusa.json", medusa_bin: str = "medusa", timeout_s: float = 900, tool_runs_dir: str | Path | None = None) -> FuzzReport:
    result = run([medusa_bin, "fuzz", "--config", config], cwd=root, timeout_s=timeout_s, tool_runs_dir=tool_runs_dir)
    if result.rc != 0:
        raise RuntimeError(result.stderr or result.stdout)
    try: data = json.loads(result.stdout)
    except json.JSONDecodeError: data = {}
    return FuzzReport(list(data.get("violations", [])), dict(data.get("coverage", {})), data)

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any
from l0vi0x.tools.runner import run

@dataclass(frozen=True, slots=True)
class StaticFinding:
    detector: str
    title: str
    impact: str | None
    confidence: str | None
    source: dict[str, Any]


def analyze(*, root: str | Path, aderyn_bin: str = "aderyn", timeout_s: float = 900, tool_runs_dir: str | Path | None = None) -> list[StaticFinding]:
    out = Path(root) / "aderyn.json"
    result = run([aderyn_bin, "analyze", str(root), "--output", str(out)], cwd=root, timeout_s=timeout_s, tool_runs_dir=tool_runs_dir)
    if result.rc != 0:
        raise RuntimeError(result.stderr or result.stdout)
    if not out.exists():
        return []
    data = json.loads(out.read_text(encoding="utf-8"))
    rows = data.get("detectors", data if isinstance(data, list) else [])
    return [StaticFinding(str(r.get("id", r.get("detector", "unknown"))), str(r.get("title", "")), r.get("impact"), r.get("confidence"), r) for r in rows if isinstance(r, dict)]

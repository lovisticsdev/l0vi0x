from __future__ import annotations

from pathlib import Path
from typing import Any
from l0vi0x.tools.runner import run


def set_version(version: str, *, solc_select_bin: str = "solc-select", timeout_s: float = 120, tool_runs_dir: str | Path | None = None):
    if not version or any(c not in "0123456789." for c in version):
        raise ValueError("invalid Solidity version")
    return run([solc_select_bin, "use", version], timeout_s=timeout_s, tool_runs_dir=tool_runs_dir)


def bugs_for(version: str, settings: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    # M1a exposes the deterministic lookup boundary; the versioned knowledge file is consumed by M3 analysis.
    _ = settings
    knowledge = Path(__file__).resolve().parents[3] / "knowledge" / "compiler_bugs" / "solidity_bugs_by_version.json"
    if not knowledge.exists():
        return []
    import json
    data = json.loads(knowledge.read_text(encoding="utf-8"))
    return list(data.get(version, [])) if isinstance(data, dict) else []

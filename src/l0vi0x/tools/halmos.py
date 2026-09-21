from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
from l0vi0x.tools.runner import run

@dataclass(frozen=True, slots=True)
class SymReport:
    status: str
    counterexample: dict[str, Any] | None
    stdout: str
    stderr: str


def check(*, root: str | Path, test_name: str | None = None, halmos_bin: str = "halmos", timeout_s: float = 900, tool_runs_dir: str | Path | None = None) -> SymReport:
    argv = [halmos_bin, "--root", str(root)]
    if test_name:
        argv += ["--function", test_name]
    result = run(argv, cwd=root, timeout_s=timeout_s, tool_runs_dir=tool_runs_dir)
    return SymReport("pass" if result.rc == 0 else "fail", None, result.stdout, result.stderr)

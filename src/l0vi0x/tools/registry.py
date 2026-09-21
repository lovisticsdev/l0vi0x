from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

from l0vi0x.tools.runner import ToolResult, run


@dataclass(frozen=True, slots=True)
class ToolSpec:
    name: str
    binary: str
    timeout_s: float = 900


class ToolRegistry:
    """Typed registry: callers select an operation, never a shell string."""

    def __init__(self, specs: Sequence[ToolSpec], *, audit_root: str | Path) -> None:
        self._specs = {spec.name: spec for spec in specs}
        self.audit_root = Path(audit_root)

    def spec(self, name: str) -> ToolSpec:
        try:
            return self._specs[name]
        except KeyError as exc:
            raise KeyError(f"unknown tool: {name}") from exc

    def execute(self, name: str, argv_tail: Sequence[str], *, cwd: str | Path, env: dict[str, str] | None = None) -> ToolResult:
        spec = self.spec(name)
        argv = [spec.binary, *list(argv_tail)]
        return run(argv, cwd=cwd, env=env, timeout_s=spec.timeout_s, tool_runs_dir=self.audit_root / "tool_runs")

from __future__ import annotations

from pathlib import Path
from l0vi0x.tools.runner import ToolResult, run


def call(*, rpc_url: str, to: str, signature: str, args: list[str] | None = None, cast_bin: str = "cast", timeout_s: float = 120, tool_runs_dir: str | Path | None = None) -> ToolResult:
    argv = [cast_bin, "call", to, signature, *(args or []), "--rpc-url", rpc_url]
    return run(argv, timeout_s=timeout_s, tool_runs_dir=tool_runs_dir)


def storage(*, rpc_url: str, address: str, slot: str, cast_bin: str = "cast", timeout_s: float = 120, tool_runs_dir: str | Path | None = None) -> ToolResult:
    return run([cast_bin, "storage", address, slot, "--rpc-url", rpc_url], timeout_s=timeout_s, tool_runs_dir=tool_runs_dir)


def code(*, rpc_url: str, address: str, cast_bin: str = "cast", timeout_s: float = 120, tool_runs_dir: str | Path | None = None) -> ToolResult:
    return run([cast_bin, "code", address, "--rpc-url", rpc_url], timeout_s=timeout_s, tool_runs_dir=tool_runs_dir)

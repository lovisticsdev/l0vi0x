from __future__ import annotations

from pathlib import Path

from l0vi0x.tools.runner import ToolResult, run


def rev_parse_head(root: str | Path, *, git_bin: str = "git", tool_runs_dir: str | Path | None = None) -> str:
    result = run([git_bin, "rev-parse", "HEAD"], cwd=root, timeout_s=30, tool_runs_dir=tool_runs_dir)
    if result.rc != 0 or not result.stdout.strip():
        raise RuntimeError(result.stderr.strip() or "git rev-parse HEAD failed")
    return result.stdout.strip().splitlines()[-1]

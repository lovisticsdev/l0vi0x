from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Sequence

from l0vi0x.tools.runner import ToolResult, run


@dataclass(frozen=True, slots=True)
class ForgeReport:
    command: list[str]
    passed: bool
    returncode: int
    stdout: str
    stderr: str
    json_result: Any | None
    artifact_path: str | None = None
    record_path: str | None = None


def build(*, root: str | Path, forge_bin: str = "forge", timeout_s: float = 900, tool_runs_dir: str | Path | None = None) -> ForgeReport:
    argv = [forge_bin, "build", "--root", str(root), "--color", "never"]
    result = run(argv, cwd=root, timeout_s=timeout_s, tool_runs_dir=tool_runs_dir)
    return ForgeReport(argv, result.rc == 0, result.rc, result.stdout, result.stderr, None, record_path=result.record_path)


def _parse_json_lines(text: str) -> Any | None:
    rows=[]
    for line in text.splitlines():
        line=line.strip()
        if not line.startswith(("{", "[")):
            continue
        try: rows.append(json.loads(line))
        except json.JSONDecodeError: continue
    if not rows: return None
    return rows[0] if len(rows)==1 else rows


def test(
    *,
    root: str | Path,
    test_file: str,
    test_name: str,
    forge_bin: str = "forge",
    timeout_s: float = 900,
    tool_runs_dir: str | Path | None = None,
    json_output: bool = True,
    verbosity: int = 5,
    extra_args: Sequence[str] = (),
    env: dict[str, str] | None = None,
) -> ForgeReport:
    argv = [forge_bin, "test", "--root", str(root), "--match-path", test_file, "--match-test", test_name]
    if not json_output:
        argv.extend(["--color", "never"])
    if json_output:
        argv.append("--json")
    argv.extend(["-" + "v" * max(1, verbosity)])
    argv.extend(list(extra_args))
    result = run(argv, cwd=root, env=env, timeout_s=timeout_s, tool_runs_dir=tool_runs_dir)
    parsed = _parse_json_lines(result.stdout) if json_output else None
    return ForgeReport(argv, result.rc == 0, result.rc, result.stdout, result.stderr, parsed, record_path=result.record_path)


def inspect_storage_layout(*, root: str | Path, contract: str, forge_bin: str = "forge", timeout_s: float = 900, tool_runs_dir: str | Path | None = None) -> ToolResult:
    return run([forge_bin, "inspect", contract, "storage-layout", "--json", "--root", str(root)], cwd=root, timeout_s=timeout_s, tool_runs_dir=tool_runs_dir)

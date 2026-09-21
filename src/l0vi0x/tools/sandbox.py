from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from l0vi0x.tools.runner import ToolResult, run


@dataclass(frozen=True, slots=True)
class DockerSandbox:
    compose_file: Path
    service: str = "sandbox"

    def exec(self, *, command: Sequence[str], repo_root: str | Path, env: dict[str, str] | None = None, timeout_s: float = 900, tool_runs_dir: str | Path | None = None) -> ToolResult:
        if not command:
            raise ValueError("sandbox command cannot be empty")
        repo = Path(repo_root).resolve()
        args = ["docker", "compose", "-f", str(self.compose_file), "run", "--rm", self.service, *command]
        compose_env = dict(env or {})
        compose_env["SANDBOX_TASK_DIR"] = str(repo)
        return run(args, cwd=repo, env=compose_env, timeout_s=timeout_s, tool_runs_dir=tool_runs_dir)

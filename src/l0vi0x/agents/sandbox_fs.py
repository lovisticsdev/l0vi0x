from __future__ import annotations

import os
import re
from pathlib import Path


class SandboxPathError(PermissionError):
    pass


class SandboxFS:
    """Jailed filesystem operations for agent-visible roots."""

    def __init__(self, allowed_roots: list[str | Path]):
        if not allowed_roots:
            raise ValueError("at least one allowed root is required")
        self.roots = tuple(Path(r).resolve() for r in allowed_roots)
        for root in self.roots:
            root.mkdir(parents=True, exist_ok=True)

    def _inside(self, path: str | Path, *, for_write: bool = False) -> Path:
        candidate = Path(path)
        if not candidate.is_absolute():
            raise SandboxPathError("sandbox paths must be absolute")
        # Resolve the parent and final path separately so a missing final leaf is safe to check.
        target = candidate.resolve(strict=False)
        parents = [target] + list(target.parents)
        if not any(root == p or root in p.parents for root in self.roots for p in parents):
            raise SandboxPathError(f"path escapes sandbox roots: {path}")
        # Existing symlink ancestors must also resolve inside an allowed root.
        if for_write and candidate.exists() and candidate.is_symlink():
            raise SandboxPathError("writing through a symlink is forbidden")
        return target

    def read_text(self, path: str | Path) -> str:
        target = self._inside(path)
        if not target.is_file():
            raise FileNotFoundError(target)
        return target.read_text(encoding="utf-8")

    def write_text(self, path: str | Path, content: str) -> Path:
        target = self._inside(path, for_write=True)
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_name(target.name + ".tmp")
        if tmp.exists() or tmp.is_symlink():
            tmp.unlink()
        tmp.write_text(content, encoding="utf-8")
        os.replace(tmp, target)
        return target

    def grep(self, path: str | Path, pattern: str) -> list[str]:
        text = self.read_text(path)
        rx = re.compile(pattern)
        return [line for line in text.splitlines() if rx.search(line)]

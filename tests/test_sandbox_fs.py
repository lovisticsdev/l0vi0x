import os

import pytest

from l0vi0x.agents.sandbox_fs import SandboxFS, SandboxPathError


def test_traversal_is_rejected(tmp_path):
    root = tmp_path / "task"
    root.mkdir()
    fs = SandboxFS([root])
    with pytest.raises(SandboxPathError):
        fs.read_text(str(root / ".." / "secret.txt"))


def test_symlink_escape_is_rejected(tmp_path):
    root = tmp_path / "task"
    outside = tmp_path / "outside"
    root.mkdir(); outside.mkdir()
    secret = outside / "secret.txt"
    secret.write_text("secret", encoding="utf-8")
    link = root / "link"
    link.symlink_to(secret)
    fs = SandboxFS([root])
    with pytest.raises(SandboxPathError):
        fs.read_text(link)


def test_writes_are_confined_and_atomic(tmp_path):
    root = tmp_path / "task"
    root.mkdir()
    fs = SandboxFS([root])
    target = fs.write_text(root / "result.txt", "ok")
    assert target.read_text(encoding="utf-8") == "ok"
    with pytest.raises(SandboxPathError):
        fs.write_text(root.parent / "escape.txt", "no")

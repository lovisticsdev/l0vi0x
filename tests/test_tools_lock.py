from __future__ import annotations

import subprocess
import textwrap
from pathlib import Path
from unittest.mock import patch

from l0vi0x.tools.lock import verify_container_binary_lock

IMAGE = "ghcr.io/foundry-rs/foundry@sha256:2e4287278639262de76db72477301d5d3212fa1b1cce710d7d148750a46ce9e7"

FORGE_VERSION_BLOCK = textwrap.dedent(
    """\
    forge Version: 1.8.3
    Commit SHA: cae51ad458f6abb64852b7709eb784352429825d
    Build Timestamp: 2026-09-15T10:30:32.683787271Z (1789468232)
    Build Profile: dist"""
)
FORGE_HASH = "a80861819ec50a19523b44c6e6ff8063898ab5b192a4a26ae0f473ded3779bf7"

LOCK_YAML = f"""
version: 1
status: verified

image:
  ref: {IMAGE}

tools:
  forge:
    binary: /usr/local/bin/forge
    version: |
      {FORGE_VERSION_BLOCK.replace(chr(10), chr(10) + "      ")}
    probe_output: |
      {FORGE_VERSION_BLOCK.replace(chr(10), chr(10) + "      ")}
    sha256: {FORGE_HASH}
"""


def _fake_probe(output: str):
    def _run(cmd, shell, capture_output, text, check):
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=output, stderr="")
    return _run


def test_verify_container_binary_lock_accepts_matching_multiline_version(tmp_path: Path):
    """The lock records the *entire* multi-line `--version` output (matching how
    the host-side verify_binary_lock captures it). A correct probe of the same
    binary must not be flagged as a mismatch just because the docker probe's
    output is reconstructed line-by-line rather than compared as a single line.
    """
    lock_path = tmp_path / "tools.m1b.lock.yaml"
    lock_path.write_text(LOCK_YAML, encoding="utf-8")

    good_output = "=== forge ===\n" + FORGE_VERSION_BLOCK + f"\n{FORGE_HASH}  /usr/local/bin/forge"

    with patch("subprocess.run", _fake_probe(good_output)):
        problems = verify_container_binary_lock(lock_path, image=IMAGE, required_names=["forge"])

    assert problems == []


def test_verify_container_binary_lock_flags_real_mismatch(tmp_path: Path):
    lock_path = tmp_path / "tools.m1b.lock.yaml"
    lock_path.write_text(LOCK_YAML, encoding="utf-8")

    tampered_output = (
        "=== forge ===\n"
        + FORGE_VERSION_BLOCK.replace("1.8.3", "9.9.9")
        + f"\n{FORGE_HASH}  /usr/local/bin/forge"
    )

    with patch("subprocess.run", _fake_probe(tampered_output)):
        problems = verify_container_binary_lock(lock_path, image=IMAGE, required_names=["forge"])

    assert any("forge" in p and "version mismatch" in p for p in problems)

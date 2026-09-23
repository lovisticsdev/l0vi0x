from __future__ import annotations

import os
import secrets
from pathlib import Path


def home_path(explicit: str | Path | None = None) -> Path:
    return Path(explicit or os.environ.get("L0VI0X_HOME", "~/.l0vi0x")).expanduser()


def ensure_home(explicit: str | Path | None = None) -> Path:
    root = home_path(explicit)
    root.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o700)

    keys = root / "keys"
    keys.mkdir(exist_ok=True)
    os.chmod(keys, 0o700)
    return root


def ensure_audit_key(
    audit_id: str,
    explicit_home: str | Path | None = None,
) -> Path:
    if (
        not audit_id
        or audit_id in {".", ".."}
        or "/" in audit_id
        or "\\" in audit_id
    ):
        raise ValueError(
            "audit_id must be a single path-safe identifier"
        )

    root = ensure_home(explicit_home)
    key_path = root / "keys" / f"{audit_id}.key"

    if key_path.is_symlink():
        raise RuntimeError(
            f"refusing certificate key symlink: {key_path}"
        )

    if not key_path.exists():
        key_path.write_bytes(secrets.token_bytes(32))

    os.chmod(key_path, 0o600)
    return key_path

from __future__ import annotations

from dataclasses import dataclass, asdict
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
from typing import Mapping, Sequence


DEFAULT_MAX_OUTPUT_BYTES = 8 * 1024 * 1024
SENSITIVE_ENV_MARKERS = ("KEY", "TOKEN", "SECRET", "PASSWORD", "MNEMONIC", "PRIVATE")


@dataclass(frozen=True, slots=True)
class ToolResult:
    cmd: list[str]
    rc: int
    stdout: str
    stderr: str
    secs: float
    artifact_path: str | None = None
    record_path: str | None = None


class ToolExecutionError(RuntimeError):
    pass


def _safe_name(argv: Sequence[str]) -> str:
    token = "-".join(Path(x).name for x in argv[:2]) or "tool"
    return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in token)[:80]


def _truncate(text: str, limit: int) -> str:
    raw = text.encode("utf-8", errors="replace")
    if len(raw) <= limit:
        return text
    marker = b"\n...[truncated by l0vi0x runner]...\n"
    keep = max(0, limit - len(marker))
    return (raw[:keep] + marker).decode("utf-8", errors="replace")


def _safe_env(env: Mapping[str, str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in sorted(env.items()):
        upper = str(k).upper()
        out[str(k)] = "<redacted>" if any(marker in upper for marker in SENSITIVE_ENV_MARKERS) else str(v)
    return out


def run(
    argv: Sequence[str],
    *,
    cwd: str | Path | None = None,
    env: Mapping[str, str] | None = None,
    timeout_s: float = 900,
    tool_runs_dir: str | Path | None = None,
    artifact_path: str | Path | None = None,
    input_text: str | None = None,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
) -> ToolResult:
    if not argv or any(not isinstance(x, str) or not x for x in argv):
        raise ValueError("argv must be a non-empty sequence of non-empty strings")
    if not isinstance(timeout_s, (int, float)) or timeout_s <= 0:
        raise ValueError("timeout_s must be positive")
    if max_output_bytes <= 0:
        raise ValueError("max_output_bytes must be positive")

    full_env = dict(os.environ)
    if env is not None:
        full_env.update({str(k): str(v) for k, v in env.items()})

    started = time.monotonic()
    try:
        proc = subprocess.run(
            list(argv),
            cwd=str(cwd) if cwd is not None else None,
            env=full_env,
            input=input_text,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_s,
            check=False,
            shell=False,
        )
    except FileNotFoundError as exc:
        elapsed = time.monotonic() - started
        result = ToolResult(list(argv), 127, "", str(exc), elapsed)
    except subprocess.TimeoutExpired as exc:
        elapsed = time.monotonic() - started
        result = ToolResult(
            list(argv),
            124,
            (exc.stdout or "") if isinstance(exc.stdout, str) else "",
            (exc.stderr or "") if isinstance(exc.stderr, str) else "timeout",
            elapsed,
        )
    else:
        elapsed = time.monotonic() - started
        result = ToolResult(list(argv), proc.returncode, proc.stdout, proc.stderr, elapsed)

    if artifact_path is not None:
        ap = Path(artifact_path)
        ap.parent.mkdir(parents=True, exist_ok=True)
        ap.write_text(result.stdout, encoding="utf-8")
        result = ToolResult(**{**asdict(result), "artifact_path": str(ap)})

    if tool_runs_dir is not None:
        rp = Path(tool_runs_dir)
        rp.mkdir(parents=True, exist_ok=True)
        safe_env = _safe_env(full_env)
        digest_input = {
            "argv": list(argv),
            "cwd": str(cwd) if cwd is not None else None,
            "env": safe_env,
        }
        digest = hashlib.sha256(json.dumps(digest_input, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:16]
        record = rp / f"{_safe_name(argv)}-{digest}-{int(time.time()*1000)}.json"
        record_payload = {
            **asdict(result),
            "cwd": str(cwd) if cwd is not None else None,
            "env": safe_env,
            "env_sha256": hashlib.sha256(json.dumps(sorted(full_env.items()), separators=(",", ":"), default=str).encode()).hexdigest(),
            "stdout_truncated": _truncate(result.stdout, max_output_bytes),
            "stderr_truncated": _truncate(result.stderr, max_output_bytes),
        }
        # Do not persist unlimited command output in the invocation record.
        record_payload.pop("stdout", None)
        record_payload.pop("stderr", None)
        record.write_text(json.dumps(record_payload, sort_keys=True, indent=2), encoding="utf-8")
        result = ToolResult(**{**asdict(result), "record_path": str(record)})

    return result

from __future__ import annotations

from dataclasses import dataclass, asdict
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
from typing import Mapping, Sequence

from l0vi0x.core.redaction import redact, redact_payload

DEFAULT_MAX_OUTPUT_BYTES = 8 * 1024 * 1024
SENSITIVE_ENV_MARKERS = ("KEY", "TOKEN", "SECRET", "PASSWORD", "MNEMONIC", "PRIVATE", "CREDENTIAL")


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
    # Redact before truncating. Otherwise a secret split by the byte limit could
    # evade the redaction regex and be persisted in a partial form.
    safe = redact(text)
    raw=safe.encode("utf-8",errors="replace")
    if len(raw)<=limit: return safe
    marker=b"\n...[truncated by l0vi0x runner]...\n"
    keep=max(0,limit-len(marker))
    return (raw[:keep]+marker).decode("utf-8",errors="replace")


def _redact_for_persistence(value: object) -> object:
    """Recursively redact persisted values and normalize the marker."""
    redacted = redact_payload(value)
    if isinstance(redacted, str):
        return redacted.replace("[REDACTED]", "<redacted>")
    if isinstance(redacted, list):
        return [_redact_for_persistence(item) for item in redacted]
    if isinstance(redacted, tuple):
        return tuple(_redact_for_persistence(item) for item in redacted)
    if isinstance(redacted, dict):
        return {key: _redact_for_persistence(item) for key, item in redacted.items()}
    return redacted


def _safe_env(env: Mapping[str,str]) -> dict[str,str]:
    out={}
    for k,v in sorted(env.items()):
        upper=str(k).upper()
        out[str(k)]="<redacted>" if any(marker in upper for marker in SENSITIVE_ENV_MARKERS) else str(_redact_for_persistence(str(v)))
    return out


def run(argv: Sequence[str], *, cwd: str|Path|None=None, env: Mapping[str,str]|None=None, timeout_s: float=900, tool_runs_dir: str|Path|None=None, artifact_path: str|Path|None=None, input_text: str|None=None, max_output_bytes: int=DEFAULT_MAX_OUTPUT_BYTES) -> ToolResult:
    if not argv or any(not isinstance(x,str) or not x for x in argv): raise ValueError("argv must be a non-empty sequence of non-empty strings")
    if timeout_s<=0: raise ValueError("timeout_s must be positive")
    if max_output_bytes<=0: raise ValueError("max_output_bytes must be positive")
    full_env=dict(os.environ)
    if env is not None: full_env.update({str(k):str(v) for k,v in env.items()})
    started=time.monotonic()
    try:
        proc=subprocess.run(list(argv),cwd=str(cwd) if cwd is not None else None,env=full_env,input=input_text,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout_s,check=False,shell=False)
        result=ToolResult(list(argv),proc.returncode,proc.stdout,proc.stderr,time.monotonic()-started)
    except FileNotFoundError as exc:
        result=ToolResult(list(argv),127,"",str(exc),time.monotonic()-started)
    except subprocess.TimeoutExpired as exc:
        result=ToolResult(list(argv),124,exc.stdout if isinstance(exc.stdout,str) else "",exc.stderr if isinstance(exc.stderr,str) else "timeout",time.monotonic()-started)

    if artifact_path is not None:
        ap=Path(artifact_path); ap.parent.mkdir(parents=True,exist_ok=True)
        # Artifacts are persisted logs, not transient parser buffers; never write them raw.
        ap.write_text(_truncate(result.stdout,max_output_bytes),encoding="utf-8")
        result=ToolResult(**{**asdict(result),"artifact_path":str(ap)})

    if tool_runs_dir is not None:
        rp=Path(tool_runs_dir); rp.mkdir(parents=True,exist_ok=True)
        safe_env=_safe_env(full_env)
        digest_input={"argv":redact_payload(list(argv)),"cwd":redact(str(cwd)) if cwd is not None else None,"env":safe_env}
        digest=hashlib.sha256(json.dumps(digest_input,sort_keys=True,separators=(",",":")).encode()).hexdigest()[:16]
        record=rp/f"{_safe_name(argv)}-{digest}-{int(time.time()*1000)}.json"
        actual_env_hash=hashlib.sha256(json.dumps(sorted(full_env.items()),separators=(",",":"),default=str).encode()).hexdigest()
        record_payload={
            "cmd": _redact_for_persistence(result.cmd), "rc": result.rc, "secs": result.secs,
            "cwd": _redact_for_persistence(str(cwd)) if cwd is not None else None, "env": safe_env,
            "env_sha256": actual_env_hash,
            "artifact_path": _redact_for_persistence(result.artifact_path) if result.artifact_path else None,
            "stdout_truncated": _truncate(result.stdout,max_output_bytes),
            "stderr_truncated": _truncate(result.stderr,max_output_bytes),
            "stdin_sha256": hashlib.sha256(input_text.encode("utf-8")).hexdigest() if input_text is not None else None,
        }
        record.write_text(json.dumps(record_payload,sort_keys=True,indent=2),encoding="utf-8")
        result=ToolResult(**{**asdict(result),"record_path":str(record)})
    return result

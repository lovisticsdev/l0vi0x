from __future__ import annotations

import re
from typing import Any

_SECRET_PATTERNS = [
    re.compile(r"(?i)\b(api[_-]?key|access[_-]?key|secret|password|passwd|private[_-]?key|privkey)\s*[:=]\s*['\"]?[^\s,'\"}]+"),
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(r"\bsk-ant-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bsk-proj-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgsk_[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bnvapi-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b"),
    re.compile(r"https?://[^\s/]+\.(?:alchemyapi\.io|alchemy\.com)/(?:v2|v3)/[A-Za-z0-9_-]{8,}", re.I),
    re.compile(r"https?://[^\s/]+\.infura\.io/(?:v3|v2)/[A-Za-z0-9_-]{8,}", re.I),
]
_PRIVATE_VALUE = re.compile(r"(?i)(private[_-]?key|privkey)\s*[:=]\s*['\"]?(?:0x)?[0-9a-f]{64}\b")


def redact(text: str) -> str:
    redacted = text
    for pattern in _SECRET_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)
    redacted = _PRIVATE_VALUE.sub("[REDACTED]", redacted)
    return redacted


def redact_payload(value: Any) -> Any:
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, list):
        return [redact_payload(v) for v in value]
    if isinstance(value, tuple):
        return tuple(redact_payload(v) for v in value)
    if isinstance(value, dict):
        return {k: redact_payload(v) for k, v in value.items()}
    return value

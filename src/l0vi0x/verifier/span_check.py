from __future__ import annotations

import hashlib
from pathlib import Path

from l0vi0x.core.models import Span
from .types import CheckResult


def _range_hash(path: Path, start: int, end: int) -> str:
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    if start < 1 or end > len(lines):
        raise IndexError("span line range outside file")
    return hashlib.sha256("".join(lines[start - 1 : end]).encode("utf-8")).hexdigest()


def check(*, root: Path, span: Span) -> CheckResult:
    path = (root / span.file).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError:
        return CheckResult("V02", False, "SPAN_DRIFT", True, "span escapes pinned checkout")
    if not path.is_file():
        return CheckResult("V02", False, "SPAN_DRIFT", True, "cited file does not exist")
    try:
        actual = _range_hash(path, span.start, span.end)
    except (OSError, UnicodeError, IndexError) as exc:
        return CheckResult("V02", False, "SPAN_DRIFT", True, f"cannot read cited span: {exc}")
    if actual != span.sha256:
        return CheckResult("V02", False, "SPAN_DRIFT", True, "cited span hash does not match pinned checkout", {"expected": span.sha256, "actual": actual})
    return CheckResult("V02", True, message="cited span exists and hash-matches")

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from l0vi0x.core.models import Hypothesis, KnownIssue, Scope
from .types import CheckResult


def _path_in_scope(path: str, scope: Scope) -> bool:
    norm = str(Path(path))
    for target in scope.in_scope:
        if target.path and (norm == str(Path(target.path)) or norm.startswith(str(Path(target.path)).rstrip("/") + "/")):
            return True
    return False


def check(*, hypothesis: Hypothesis, scope: Scope, known_issues: Iterable[KnownIssue], witness_commit: str | None = None) -> CheckResult:
    if hypothesis.target.file and not _path_in_scope(hypothesis.target.file, scope):
        return CheckResult("V01", False, "OUT_OF_SCOPE", True, "target span is outside scope")
    if hypothesis.target.file and any(
        hypothesis.target.file == excluded or hypothesis.target.file.startswith(excluded.rstrip("/") + "/")
        for excluded in scope.out_of_scope
    ):
        return CheckResult("V01", False, "OUT_OF_SCOPE", True, "target path is explicitly excluded")
    if hypothesis.mechanism_tag in set(scope.excluded_classes):
        return CheckResult("V01", False, "OUT_OF_SCOPE", True, "mechanism class is excluded")
    if witness_commit is not None and witness_commit != scope.commit:
        return CheckResult("V01", False, "OUT_OF_SCOPE", True, "witness commit does not match the pinned scope commit")
    for issue in known_issues:
        if issue.status in {"open", "accepted"} and (not issue.applies_to or hypothesis.target.file in issue.applies_to):
            if issue.claim.strip() == hypothesis.claim.strip():
                return CheckResult("V01", False, "KNOWN_ISSUE", True, f"matches known issue {issue.id}", {"known_issue_id": issue.id})
            if any(span.file == hypothesis.target.file and span.start <= hypothesis.target.start <= span.end for span in issue.spans):
                return CheckResult("V01", False, "KNOWN_ISSUE", True, f"target overlaps known issue {issue.id}", {"known_issue_id": issue.id})
    if hypothesis.provenance.get("commit") and hypothesis.provenance["commit"] != scope.commit:
        return CheckResult("V01", False, "OUT_OF_SCOPE", True, "hypothesis provenance commit does not match scope commit")
    return CheckResult("V01", True, message="finding is within declared scope")

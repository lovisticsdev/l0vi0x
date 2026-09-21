from __future__ import annotations

from .types import CheckResult, DuplicateEvidence


def check(evidence: DuplicateEvidence | None) -> CheckResult:
    if evidence is None:
        return CheckResult("V08", True, hard=False, message="duplicate evidence not supplied; pre-check is unavailable")
    if evidence.exact_match_id:
        return CheckResult("V08", False, "LIKELY_DUPLICATE", False, f"exact duplicate of {evidence.exact_match_id}", {"duplicate_id": evidence.exact_match_id})
    if evidence.near_match_ids:
        return CheckResult("V08", False, "LIKELY_DUPLICATE", False, "near-duplicate candidate requires human review", {"near_matches": list(evidence.near_match_ids)})
    return CheckResult("V08", True, hard=False, message="no canonical duplicate match")

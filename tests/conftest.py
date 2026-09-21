from __future__ import annotations

from datetime import datetime, timezone


def make_hypothesis_kwargs() -> dict:
    now = datetime.now(timezone.utc).isoformat()
    return {
        "id": "H-001",
        "claim": "test claim",
        "target": {"file": "a.sol", "start": 1, "end": 2, "sha256": "abc"},
        "invariant_id": "I-001",
        "capabilities": [],
        "channel": "lens",
        "protocol_type": "generic",
        "mechanism_tag": "reentrancy",
        "prior_p": 0.5,
        "est_impact": "medium",
        "est_cost": "low",
        "created_at": now,
        "updated_at": now,
    }

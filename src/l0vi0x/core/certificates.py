from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from l0vi0x.core.models import ReplayCertificate


def _canonical(fields: dict[str, Any]) -> bytes:
    return json.dumps(fields, sort_keys=True, separators=(",", ":"), default=str).encode()


def issue(key: bytes, *, certificate_id: str, witness_sha256: str, env_hash: str, runs: int,
          observed_records_sha256: str, trace_policy_sha256: str, control_sha256: str,
          cross_check_sha256: str | None = None) -> ReplayCertificate:
    if runs < 3:
        raise ValueError("replay certificates require at least three runs")
    fields = {
        "id": certificate_id,
        "witness_sha256": witness_sha256,
        "env_hash": env_hash,
        "runs": runs,
        "observed_records_sha256": observed_records_sha256,
        "trace_policy_sha256": trace_policy_sha256,
        "control_sha256": control_sha256,
        "cross_check_sha256": cross_check_sha256,
    }
    mac = hmac.new(key, _canonical(fields), hashlib.sha256).hexdigest()
    return ReplayCertificate(**fields, mac=mac, issued_at=datetime.now(timezone.utc))


def verify(cert: ReplayCertificate, key: bytes, *, witness_sha256: str, env_hash: str,
           observed_records_sha256: str | None = None, trace_policy_sha256: str | None = None,
           control_sha256: str | None = None, cross_check_sha256: str | None = None) -> bool:
    if cert.witness_sha256 != witness_sha256 or cert.env_hash != env_hash or cert.runs < 3:
        return False
    if observed_records_sha256 is not None and cert.observed_records_sha256 != observed_records_sha256:
        return False
    if trace_policy_sha256 is not None and cert.trace_policy_sha256 != trace_policy_sha256:
        return False
    if control_sha256 is not None and cert.control_sha256 != control_sha256:
        return False
    if cross_check_sha256 is not None and cert.cross_check_sha256 != cross_check_sha256:
        return False
    fields = cert.model_dump(mode="json")
    mac = fields.pop("mac")
    fields.pop("issued_at", None)
    expected = hmac.new(key, _canonical(fields), hashlib.sha256).hexdigest()
    return hmac.compare_digest(mac, expected)


def issue_from_file(key_path: str | Path, **kwargs: Any) -> ReplayCertificate:
    return issue(Path(key_path).read_bytes(), **kwargs)

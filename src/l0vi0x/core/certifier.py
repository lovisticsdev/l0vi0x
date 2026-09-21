from __future__ import annotations

from pathlib import Path
from l0vi0x.core.models import ReplayCertificate
from l0vi0x.core.certificates import issue_from_file
from l0vi0x.chain.witness import witness_hash


class HostCertifier:
    """Host-only certificate issuer. The key path must be outside target/replay roots."""
    def __init__(self, key_path: str | Path) -> None:
        self.key_path=Path(key_path).resolve()

    def issue(self, *, witness, runs:int, observed_records_sha256:str, trace_policy_sha256:str, control_sha256:str, certificate_id:str="CERT-001") -> ReplayCertificate:
        if not self.key_path.exists(): raise FileNotFoundError(self.key_path)
        return issue_from_file(self.key_path,certificate_id=certificate_id,witness_sha256=witness_hash(witness),env_hash=witness.env_hash,runs=runs,observed_records_sha256=observed_records_sha256,trace_policy_sha256=trace_policy_sha256,control_sha256=control_sha256)

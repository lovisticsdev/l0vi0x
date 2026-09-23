from __future__ import annotations

from pathlib import Path
from typing import Any

from l0vi0x.chain.replay import ReplayCollection
from l0vi0x.chain.witness import witness_hash
from l0vi0x.core.certificates import issue_from_file
from l0vi0x.core.models import ReplayCertificate, Witness


class HostCertifier:
    """Host-only issuer. Certification is impossible until the verifier has passed."""

    def __init__(self, key_path: str | Path) -> None:
        self.key_path = Path(key_path).resolve()

    def issue(self, *, witness: Witness, collection: ReplayCollection, verification: Any, certificate_id: str = "CERT-001") -> ReplayCertificate:
        if not getattr(verification, "passed", False):
            raise RuntimeError("refusing certificate issuance before all hard verification gates pass")
        if not self.key_path.exists():
            raise FileNotFoundError(self.key_path)
        if self.key_path.is_relative_to(collection.root.resolve()):
            raise ValueError("certificate key must remain outside replay trust root")
        return issue_from_file(
            self.key_path,
            certificate_id=certificate_id,
            witness_sha256=witness_hash(witness),
            env_hash=collection.environment_hash,
            runs=len(collection.runs),
            observed_records_sha256=collection.observed_records_sha256,
            trace_policy_sha256=collection.trace_policy_sha256,
            control_sha256=collection.control_sha256,
        )

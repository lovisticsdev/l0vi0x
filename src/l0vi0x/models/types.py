"""Typed LLM-layer value objects used by model access gates."""

from __future__ import annotations

import hashlib
import json
from typing import Literal

from pydantic import ConfigDict, Field, model_validator

from l0vi0x.core.models import Strict, WitnessClass


class AuthorizationContext(Strict):
    """Immutable authorization envelope required for target-touching model calls."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    audit_id: str = Field(min_length=1)
    scope_version: int = Field(ge=1)
    scope_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    target_commit: str = Field(min_length=1)
    platform: str = Field(min_length=1)
    program_ref: str = Field(min_length=1)
    confidentiality: Literal["public", "private"]
    witness_class: WitnessClass
    execution_boundary: Literal["local", "pinned_fork"]
    allowed_artifact_roots: tuple[str, ...] = Field(min_length=1)
    task_purpose: str = Field(min_length=1)
    disclosure_destination: str = Field(min_length=1)
    prohibited_actions: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _validate_boundary_and_values(self):
        if any(not value.strip() for value in self.allowed_artifact_roots):
            raise ValueError("allowed_artifact_roots must contain non-empty paths")
        if any(not value.strip() for value in self.prohibited_actions):
            raise ValueError("prohibited_actions must contain non-empty actions")
        if self.witness_class == "local_deployment" and self.execution_boundary != "local":
            raise ValueError("local_deployment requires execution_boundary=local")
        if self.witness_class == "deployed_fork" and self.execution_boundary != "pinned_fork":
            raise ValueError("deployed_fork requires execution_boundary=pinned_fork")
        return self

    def context_hash(self) -> str:
        canonical = json.dumps(
            self.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from l0vi0x.chain.trace import TraceSummary
from l0vi0x.core.models import Hypothesis, KnownIssue, Scope, Witness, ReplayCertificate


@dataclass(frozen=True, slots=True)
class CheckResult:
    check_id: str
    ok: bool
    code: str | None = None
    hard: bool = True
    message: str = ""
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ReplayEvidence:
    """Evidence root only; all hashes are derived from these artifacts by the verifier."""
    root: Path
    run_dirs: tuple[Path, ...]
    certificate: ReplayCertificate | None = None
    certificate_key: bytes | None = None


@dataclass(frozen=True, slots=True)
class BuildEvidence:
    clean: bool
    build_stdout: str = ""
    build_stderr: str = ""
    tool_lock_verified: bool = False
    tool_lock_problems: tuple[str, ...] = ()
    pinned_compiler: str | None = None
    required_tools: tuple[str, ...] = ("forge", "anvil", "cast")


@dataclass(frozen=True, slots=True)
class ControlEvidence:
    passed: bool
    matching_assertion: bool
    observed_state_changed: bool
    assertion_event_count: int
    source: str = "derived"


@dataclass(frozen=True, slots=True)
class SnapshotEvidence:
    native_before_wei: int | None = None
    native_after_wei: int | None = None
    token_before: dict[str, int] = field(default_factory=dict)
    token_after: dict[str, int] = field(default_factory=dict)
    gas_used: int | None = None
    gas_price_wei: int | None = None
    protocol_assets_delta_wei: int | None = None
    declared_capital_wei: int = 0
    observed_capital_wei: int | None = None
    slippage_bps: int | None = None
    sensitivity: dict[str, float] = field(default_factory=dict)
    sensitivity_scenarios: dict[str, dict[str, Any]] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class HarnessEvidence:
    harness_address: str
    wrapper_address: str
    expected_wrapper_depth: int
    observed_wrapper_depth: int
    observed_runtime_sha256: str
    expected_runtime_sha256: str
    observed_source_sha256: str
    expected_source_sha256: str
    wrapper_runtime_sha256: str
    expected_wrapper_runtime_sha256: str
    wrapper_source_sha256: str
    expected_wrapper_source_sha256: str
    create2_deployer: str
    create2_salt: str
    create2_init_code_sha256: str
    assertion_emitter: str
    assertion_event_depth: int
    assertion_event_caller: str
    observed_actor_addresses: tuple[str, ...]
    observed_token_addresses: tuple[str, ...]
    expected_actor_addresses: tuple[str, ...]
    expected_token_addresses: tuple[str, ...]
    assertion_event_count: int
    economic_event_count: int
    control_event_count: int


@dataclass(frozen=True, slots=True)
class EconomicEvidence:
    snapshot: SnapshotEvidence
    realism_flags: tuple[str, ...] = ()
    pinned_block: int | None = None
    head_replay_passed: bool | None = None
    upstream_state_match: bool | None = None
    production_required: bool = False
    price_sources: tuple[str, ...] = ()
    sensitivity: dict[str, float] = field(default_factory=dict)
    sensitivity_scenarios: dict[str, dict[str, Any]] = field(default_factory=dict)
    evidence_complete: bool = False


@dataclass(frozen=True, slots=True)
class DuplicateEvidence:
    exact_match_id: str | None = None
    near_match_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class VerificationContext:
    root: Path
    hypothesis: Hypothesis
    scope: Scope
    witness: Witness
    known_issues: tuple[KnownIssue, ...] = ()
    replay: ReplayEvidence | None = None
    build: BuildEvidence | None = None
    # These remain as diagnostic snapshots only. Production verification re-derives them from replay roots.
    control: ControlEvidence | None = None
    harness: HarnessEvidence | None = None
    economics: EconomicEvidence | None = None
    duplicate: DuplicateEvidence | None = None
    production_l7_required: bool = False
    current_policy_path: Path | None = None
    cheatcode_catalog_path: Path | None = None
    foundry_config_path: Path | None = None
    tool_lock_path: Path | None = None
    price_evidence_path: Path | None = None
    pinned_impact_usd: float | None = None
    severity_model_verified_at: str | None = None
    require_certificate: bool = True


@dataclass(frozen=True, slots=True)
class VerificationResult:
    passed: bool
    checks: tuple[CheckResult, ...]
    next_state: str | None = None
    route_reason: str | None = None
    severity: dict[str, Any] = field(default_factory=lambda: {"status": "not_classified"})

    @property
    def hard_failures(self) -> tuple[CheckResult, ...]:
        return tuple(c for c in self.checks if c.hard and not c.ok)

    @property
    def soft_failures(self) -> tuple[CheckResult, ...]:
        return tuple(c for c in self.checks if not c.hard and not c.ok)

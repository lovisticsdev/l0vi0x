from __future__ import annotations

from datetime import datetime
from enum import IntEnum, StrEnum
from typing import Any, Literal, TypeAlias

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class HState(StrEnum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    CONFIRMED = "CONFIRMED"
    FINDING = "FINDING"
    CLOSED = "CLOSED"
    CLOSED_DUPLICATE = "CLOSED_DUPLICATE"
    PARKED = "PARKED"
    MERGED = "MERGED"


class Level(IntEnum):
    L0 = 0
    L1 = 1
    L2 = 2
    L3 = 3
    L4 = 4
    L5 = 5
    L6 = 6
    L7 = 7
    L8 = 8


Axis: TypeAlias = Literal[
    "mechanism",
    "reachability",
    "execution",
    "economics",
    "production",
    "adjudication",
]
LadderValue: TypeAlias = Level | Literal["not_applicable"]
WitnessClass: TypeAlias = Literal["deployed_fork", "local_deployment"]


class Span(Strict):
    file: str
    start: int = Field(ge=1)
    end: int = Field(ge=1)
    sha256: str

    @model_validator(mode="after")
    def _ordered(self):
        if self.end < self.start:
            raise ValueError("span end must be >= start")
        return self


class Capability(StrEnum):
    PERMISSIONLESS = "permissionless"
    FLASH_LOAN = "flash_loan"
    DONATION = "donation"
    REENTRANCY_HOOK = "reentrancy_hook"
    MALICIOUS_TOKEN = "malicious_token_or_receiver"
    ORACLE_MANIP = "oracle_manipulation"
    ORDERING = "ordering_mev"
    CROSS_PROTOCOL = "cross_protocol_call"


class Assumption(Strict):
    id: str
    statement: str
    source: str
    spans: list[Span] = Field(default_factory=list)
    status: str = "unverified"
    evidence: list[str] = Field(default_factory=list)
    dependents: list[str] = Field(default_factory=list)


class Invariant(Strict):
    id: str
    statement: str
    expr: str | None = None
    kind: str
    origin: str
    vars: list[str] = Field(default_factory=list)
    intent_spans: list[Span] = Field(default_factory=list)
    check_contract: str | None = None
    check_sha256: str | None = None
    foundry_test: str | None = None
    z3_model: str | None = None
    status: str = "candidate"


class DisputeRecord(Strict):
    id: str
    issue_code: str
    subject_id: str
    claimant: str
    verdict: Literal["supported", "refuted", "inconclusive", "overridden"]
    defects: list[dict[str, Any]] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    override_reason: str | None = None
    reviewer: str | None = None
    created_at: datetime


class Hypothesis(Strict):
    id: str
    claim: str
    target: Span
    invariant_id: str
    capabilities: list[Capability]
    preconditions: list[str] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    attack_sketch: list[str] = Field(default_factory=list)
    lens: str | None = None
    channel: Literal["lens", "obligation", "seed_static", "seed_shadow", "chain"]
    protocol_type: str
    mechanism_tag: str
    canonical_key: str | None = None
    prior_p: float = Field(ge=0, le=1)
    est_impact: str
    est_cost: str
    state: HState = HState.OPEN
    ladder: dict[str, int | str] = Field(default_factory=dict)
    witness_feasibility: WitnessClass | Literal["unsupported", "undetermined"] = "undetermined"
    skeptic_disposition: Literal["none", "supported", "refuted_mechanical", "refuted_judgment", "inconclusive"] = "none"
    skeptic_defects: list[dict[str, Any]] = Field(default_factory=list)
    second_opinion_disposition: Literal["none", "supported", "refuted_mechanical", "refuted_judgment", "inconclusive"] = "none"
    second_opinion_defects: list[dict[str, Any]] = Field(default_factory=list)
    disputed: bool = False
    dispute: DisputeRecord | None = None
    provenance: dict[str, Any] = Field(default_factory=dict)
    parked_unblock: str | None = None
    close_reason: str | None = None
    merged_into: str | None = None
    duplicate_of: str | None = None
    reopen_count: int = Field(default=0, ge=0)
    parent_hypotheses: list[str] = Field(default_factory=list)
    composition_rationale: str | None = None
    created_at: datetime
    updated_at: datetime


class Experiment(Strict):
    id: str
    hypothesis_id: str
    task_id: str
    kind: str
    env: dict[str, Any]
    cmd: list[str]
    result: str
    artifacts: list[str]
    cost: dict[str, Any]
    attempt: int = Field(default=1, ge=1)
    failure_kind: str | None = None


class WitnessAssertion(Strict):
    id: str
    kind: Literal["invariant", "balance_delta", "solvency", "state_change", "custom"]
    target: str
    operator: Literal["eq", "neq", "gt", "gte", "lt", "lte", "holds", "violated"]
    expected: str | int | bool
    observed_record: str
    actor: str | None = None
    token: str | None = None
    required: bool = True


class Witness(Strict):
    witness_class: WitnessClass
    chain_id: int
    fork_block: int | None = None
    commit: str
    compiler: dict[str, Any]
    test_file: str
    test_name: str
    control_test_name: str
    initial_capital_wei: int = 0
    max_time_advance_s: int = 0
    max_block_advance: int = 0
    declared_actors: list[str]
    declared_tokens: list[str]
    setup_budget: dict[str, Any] | None = None
    assertions: list[WitnessAssertion]
    invariant_check_pins: dict[str, str] = Field(default_factory=dict)
    template_sha256: str
    attack_body_sha256: str
    harness_address: str
    harness_create2_salt: str
    expected_wrapper_depth: int
    wrapper_callsite_sha256: str
    rpc_provider_label: str | None = None
    cross_check_provider_label: str | None = None
    env_hash: str

    @model_validator(mode="after")
    def _class_rules(self):
        if self.witness_class == "deployed_fork" and self.fork_block is None:
            raise ValueError("deployed_fork requires fork_block")
        if self.witness_class == "local_deployment" and self.setup_budget is None:
            raise ValueError("local_deployment requires setup_budget")
        return self


class FailureRecord(Strict):
    id: str
    hypothesis_id: str
    experiment_id: str
    kind: str
    blocker: Span | None = None
    blocker_condition: str | None = None
    near_miss: float = Field(default=0.0, ge=0, le=1)
    conditions: dict[str, Any] = Field(default_factory=dict)


class ObligationCell(Strict):
    key: str
    status: Literal[
        "open",
        "verified_bounded",
        "verified_proved",
        "refuted_with_witness",
        "blocked_with_reason",
        "out_of_budget_attempted",
        "never_attempted",
    ] = "open"
    ref: str | None = None
    reason: str | None = None
    attempts: int = Field(default=0, ge=0)
    depth: int = Field(default=0, ge=0)


class EntryPoint(Strict):
    id: str
    signature: str
    access: str
    span: Span
    moves_value: bool
    reads_price_or_balance: bool
    uses_balanceof_or_totalassets: bool
    makes_external_call: bool
    token_or_receiver_callback: bool
    accepts_arbitrary_token_address: bool
    reads_spot_price: bool
    price_or_slippage_sensitive: bool
    delegatecall_or_module_or_multicall: bool


class ModuleSlice(Strict):
    id: str
    files: list[str]
    protocol_types: list[str]
    roles_detected: dict[str, list[Span]]


class Actor(Strict):
    id: str
    kind: Literal["user", "role", "contract", "keeper", "oracle", "external_protocol", "attacker", "admin"]
    capabilities: list[Capability] = Field(default_factory=list)
    spans: list[Span] = Field(default_factory=list)


class StateModel(Strict):
    id: str
    fields: list[str]
    writers: list[str] = Field(default_factory=list)
    readers: list[str] = Field(default_factory=list)


class TrustCapability(Strict):
    id: str
    actor_id: str
    capability: Capability
    allowed_actions: list[str] = Field(default_factory=list)


class ExternalDependency(Strict):
    id: str
    kind: str
    address: str | None = None
    trust_assumption: str | None = None


class LedgerModel(Strict):
    assets: list[str] = Field(default_factory=list)
    liabilities: list[str] = Field(default_factory=list)
    conservation_equations: list[str] = Field(default_factory=list)
    solvency_equations: list[str] = Field(default_factory=list)


class TransitionModel(Strict):
    id: str
    from_state: str
    to_state: str
    actor_ids: list[str] = Field(default_factory=list)
    preconditions: list[str] = Field(default_factory=list)
    effects: list[str] = Field(default_factory=list)


class EconomicModel(Strict):
    numeraire: str
    value_sources: list[str] = Field(default_factory=list)
    price_dependencies: list[str] = Field(default_factory=list)
    fee_equations: list[str] = Field(default_factory=list)


class CompositionModel(Strict):
    parent_module_ids: list[str]
    edge_kind: str
    rationale: str


class IntentImplementationGap(Strict):
    id: str
    intent: str
    implementation: str
    spans: list[Span] = Field(default_factory=list)
    status: Literal["unresolved", "resolved", "disputed"] = "unresolved"


class ProtocolModel(Strict):
    audit_id: str
    commit: str
    actors: list[Actor]
    modules: list[ModuleSlice]
    entrypoints: list[EntryPoint]
    state_schema: list[StateModel]
    trust_capabilities: list[TrustCapability]
    external_deps: list[ExternalDependency]
    ledger: LedgerModel
    transitions: list[TransitionModel]
    economics: EconomicModel
    composition: list[CompositionModel]
    intent_vs_impl: list[IntentImplementationGap]


class DependencyRef(Strict):
    id: str
    kind: str
    name: str | None = None
    address: str | None = None
    reason: str | None = None


class ScopeTarget(Strict):
    id: str
    kind: str
    path: str | None = None
    address: str | None = None
    contract: str | None = None
    rationale: str | None = None


class Scope(Strict):
    version: int = Field(ge=1)
    platform: str
    program_ref: str
    commit: str
    prior_commit: str | None = None
    confidentiality: Literal["public", "private"] = "private"
    in_scope: list[ScopeTarget]
    out_of_scope: list[str]
    excluded_classes: list[str]
    dependencies: list[DependencyRef] = Field(default_factory=list)
    concurrent_programs: list[DependencyRef] = Field(default_factory=list)
    deployed: bool
    attacker_capital_wei: int
    poc_required: bool
    severity_model_ref: str


class Finding(Strict):
    id: str
    hypothesis_id: str
    witness_class: WitnessClass
    certificate_id: str
    ladder: dict[str, int | str]
    witness_path: str
    economics_path: str
    impact_labels: dict[str, str]
    severity: dict[str, Any]
    provenance_label: str
    skeptic_families_excluded: list[str] = Field(default_factory=list)
    skeptic_disposition: Literal["none", "supported", "refuted_mechanical", "refuted_judgment", "inconclusive"] = "none"
    skeptic_defects: list[dict[str, Any]] = Field(default_factory=list)
    skeptic_second_opinion: str | None = None
    disputed: bool = False
    dispute: DisputeRecord | None = None
    human_review: str = "pending"
    submitted_at: datetime | None = None
    platform_ref: str | None = None


class TaskRecord(Strict):
    id: str
    idempotency_key: str
    phase: str
    role: str
    status: Literal["dispatched", "finished", "failed", "blocked_on_human"]
    started_at: datetime | None = None
    finished_at: datetime | None = None
    result: str | None = None


class KnownIssue(Strict):
    id: str
    title: str
    claim: str
    status: Literal["open", "accepted", "superseded"] = "open"
    spans: list[Span] = Field(default_factory=list)
    source: str
    applies_to: list[str] = Field(default_factory=list)


class CampaignPlan(Strict):
    id: str
    campaign_id: str
    phase: str
    task_ids: list[str] = Field(default_factory=list)
    candidate_hypotheses: list[str] = Field(default_factory=list)
    rationale: str
    created_at: datetime


class HumanReviewItem(Strict):
    id: str
    subject_type: str
    subject_id: str
    reason_code: str
    status: Literal["queued", "resolved"] = "queued"
    queued_at: datetime
    resolved_at: datetime | None = None
    reviewer: str | None = None
    resolution: str | None = None


class BudgetReservation(Strict):
    id: str
    task_id: str
    max_usd: float
    reserved_usd: float
    settled_usd: float = 0.0
    released_usd: float = 0.0
    status: Literal["reserved", "settled", "released"] = "reserved"


class Task(Strict):
    id: str
    idempotency_key: str
    role: str
    channel: Literal["lens", "obligation", "seed_static", "seed_shadow", "chain"] | None = None
    lens: str | None = None
    protocol_type: str | None = None
    cell_key: str | None = None
    inputs: dict[str, str]
    output_model: str
    budget: dict[str, Any]
    isolation: str = "standard"
    exclude_families: list[str] = Field(default_factory=list)


class WorkerResult(Strict):
    task_id: str
    ok: bool
    output: dict[str, Any] | None
    artifacts: list[str] = Field(default_factory=list)
    model_used: str
    usage: dict[str, Any]
    errors: list[str] = Field(default_factory=list)


class ReplayCertificate(Strict):
    id: str
    witness_sha256: str
    env_hash: str
    runs: int = Field(ge=3)
    observed_records_sha256: str
    trace_policy_sha256: str
    control_sha256: str
    cross_check_sha256: str | None = None
    mac: str
    issued_at: datetime

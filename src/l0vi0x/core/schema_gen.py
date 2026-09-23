from __future__ import annotations

import json
from pathlib import Path

from pydantic import TypeAdapter

from l0vi0x.core.models import (
    Assumption, BudgetReservation, CampaignPlan, DisputeRecord, Experiment,
    FailureRecord, Finding, HumanReviewItem, Hypothesis, Invariant,
    KnownIssue, ModelProfile, ObligationCell, ProtocolModel, ReplayCertificate,
    Scope, StackPolicy, Task, TaskRecord, Witness,
)


_SCHEMA_TYPES = [
    (Hypothesis, "hypothesis.schema.json"),
    (Assumption, "assumption.schema.json"),
    (Invariant, "invariant.schema.json"),
    (Experiment, "experiment.schema.json"),
    (Witness, "witness.schema.json"),
    (FailureRecord, "failure_record.schema.json"),
    (ObligationCell, "obligation.schema.json"),
    (Finding, "finding.schema.json"),
    (Task, "task.schema.json"),
    (TaskRecord, "task_record.schema.json"),
    (ProtocolModel, "protocol_model.schema.json"),
    (Scope, "scope.schema.json"),
    (CampaignPlan, "campaign_plan.schema.json"),
    (KnownIssue, "known_issue.schema.json"),
    (ReplayCertificate, "replay_certificate.schema.json"),
    (HumanReviewItem, "human_review.schema.json"),
    (DisputeRecord, "dispute_record.schema.json"),
    (BudgetReservation, "budget_reservation.schema.json"),
    (ModelProfile, "model_profile.schema.json"),
    (StackPolicy, "stack_policy.schema.json"),
]


def generate_schemas(output_dir: str | Path) -> list[Path]:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for model, filename in _SCHEMA_TYPES:
        schema = TypeAdapter(model).json_schema()
        target = out / filename
        target.write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        written.append(target)
    return written


def schema_payloads() -> dict[str, str]:
    payloads: dict[str, str] = {}
    for model, filename in _SCHEMA_TYPES:
        payloads[filename] = json.dumps(TypeAdapter(model).json_schema(), indent=2, sort_keys=True) + "\n"
    return payloads


def check_schema_drift(schema_dir: str | Path) -> list[str]:
    root = Path(schema_dir)
    missing_or_drifted: list[str] = []
    for filename, expected in schema_payloads().items():
        actual_path = root / filename
        if not actual_path.exists() or actual_path.read_text(encoding="utf-8") != expected:
            missing_or_drifted.append(filename)
    extras = {p.name for p in root.glob("*.schema.json")} - set(schema_payloads())
    missing_or_drifted.extend(sorted(extras))
    return sorted(set(missing_or_drifted))
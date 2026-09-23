from __future__ import annotations

from typing import Any

EVENT_KINDS = frozenset({
    "phase_started", "phase_finished", "task_dispatched", "task_finished",
    "task_blocked_on_human", "hyp_created", "hyp_transition", "hyp_reopened",
    "assumption_falsified", "experiment_run", "failure_recorded",
    "human_review_queued", "human_review_resolved", "finding_disputed",
    "budget_reserved", "budget_settled", "obligation_resolved", "replan_triggered",
    "scope_changed", "scope_rebaselined", "finding_promoted", "finding_retraction_needed",
    "finding_scope_conflict", "reopen_threshold_exceeded", "human_override",
    "budget_warning", "quota_switch", "model_unavailable", "refusal_logged",
    "skeptic_family_exhausted", "skeptic_unavailable", "skeptic_second_opinion",
    "driver_paused_for_human_review", "driver_resumed", "hyp_updated", "hyp_ladder_award",
    "entity_saved",
})


def validate_kind(kind: str) -> str:
    if kind not in EVENT_KINDS:
        raise ValueError(f"unknown event kind: {kind}")
    return kind


def emit(store: Any, kind: str, entity: str, entity_id: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    validate_kind(kind)
    return store.record_event(entity, entity_id, {"kind": kind, **(payload or {})})

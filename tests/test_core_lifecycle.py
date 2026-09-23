import pytest

from conftest import make_hypothesis_kwargs
from l0vi0x.core.interfaces import DriverToken
from l0vi0x.core.lifecycle import IllegalTransition, LEGAL_TRANSITIONS, transition
from l0vi0x.driver.run import construct_driver_token, construct_human_override_token
from l0vi0x.core.models import HState, Hypothesis
from l0vi0x.core.store import Store


def make_h(state=HState.OPEN, **extra):
    return Hypothesis(**{**make_hypothesis_kwargs(), "state": state, **extra})


def _reopen_pairs():
    return {(HState.CLOSED, HState.INVESTIGATING), (HState.CLOSED_DUPLICATE, HState.INVESTIGATING), (HState.MERGED, HState.INVESTIGATING)}


def test_driver_token_is_opaque_and_validated():
    with pytest.raises(TypeError):
        DriverToken("driver")
    tok = construct_driver_token("driver")
    assert tok.is_valid()


def test_every_transition_is_legal_but_semantically_guarded():
    cases = {
        (HState.OPEN, HState.INVESTIGATING): ["task:task-1", "scope:current"],
        (HState.OPEN, HState.PARKED): ["assumption:A-1"],
        (HState.OPEN, HState.CLOSED): ["disproof:D-1"],
        (HState.OPEN, HState.CLOSED_DUPLICATE): ["hypothesis:H-2", "duplicate_reason:exact canonical match"],
        (HState.INVESTIGATING, HState.CONFIRMED): [
            "execution_l5:R-1", "run_receipt:R-1", "witness_assertion:W-1", "build_pass:R-1",
            "ast_pass:R-1", "trace_policy_pass:R-1", "mechanism_l1:M-1", "reachability_l2:P-1", "economics_l5:E-1"
        ],
        (HState.INVESTIGATING, HState.PARKED): ["failure:F-1"],
        (HState.INVESTIGATING, HState.CLOSED): ["scope:S-1"],
        (HState.INVESTIGATING, HState.CLOSED_DUPLICATE): ["finding:F-2", "duplicate_reason:exact canonical match"],
        (HState.CONFIRMED, HState.FINDING): [
            "execution_l6:C-1", "hard_verifier_pass:V01-V13", "economics_l6:E-1", "production_l7:P-1", "adjudication:A-1"
        ],
        (HState.CONFIRMED, HState.INVESTIGATING): ["repair:logic"],
        (HState.CONFIRMED, HState.PARKED): ["certification_failure:C-1"],
        (HState.CONFIRMED, HState.CLOSED): ["disproof:D-2"],
        (HState.CONFIRMED, HState.CLOSED_DUPLICATE): ["finding:F-3", "duplicate_reason:exact canonical match"],
        (HState.PARKED, HState.INVESTIGATING): ["unblocked:A-1"],
        (HState.PARKED, HState.CLOSED): ["permanent_blocker:B-1"],
        (HState.PARKED, HState.MERGED): ["parent:H-1", "replacement:H-2", "merge_rationale:subsumed chain"],
        (HState.FINDING, HState.CLOSED): ["invalidating:D-3"],
        (HState.FINDING, HState.CLOSED_DUPLICATE): ["finding:F-4", "duplicate_reason:final duplicate"],
        (HState.FINDING, HState.MERGED): ["replacement:F-5", "preserved_evidence:W-1"],
    }
    all_non_reopen = {
        (source, target)
        for source, targets in LEGAL_TRANSITIONS.items()
        for target in targets
        if (source, target) not in _reopen_pairs()
    }
    assert set(cases) == all_non_reopen
    for source, targets in LEGAL_TRANSITIONS.items():
        for target in targets:
            if (source, target) in _reopen_pairs():
                continue
            h = make_h(source)
            transition(construct_driver_token("driver"), h, target, "cause", cases[(source, target)])
            assert h.state == target


def test_semantic_guards_reject_generic_evidence():
    generic = ["task-1"]
    for source, target in [
        (HState.OPEN, HState.PARKED),
        (HState.OPEN, HState.CLOSED),
        (HState.OPEN, HState.CLOSED_DUPLICATE),
        (HState.INVESTIGATING, HState.CONFIRMED),
        (HState.CONFIRMED, HState.FINDING),
    ]:
        with pytest.raises(IllegalTransition):
            transition(construct_driver_token("driver"), make_h(source), target, "cause", generic)


def test_reopen_requires_human_reason_new_evidence_and_second_reviewer_after_three():
    h = make_h(HState.CLOSED, reopen_count=0)
    with pytest.raises(IllegalTransition):
        transition(construct_driver_token("driver"), h, HState.INVESTIGATING, "reopen", ["human_reason:r", "new_evidence:e"])
    transition(construct_human_override_token("reviewer"), h, HState.INVESTIGATING, "reopen", ["human_reason:r", "new_evidence:e", "replacement:f"])
    assert h.reopen_count == 1

    for count, source in [(1, HState.CLOSED), (2, HState.CLOSED),]:
        h.state = source
        h.reopen_count = count
        transition(construct_human_override_token("reviewer"), h, HState.INVESTIGATING, "reopen", ["human_reason:r", "new_evidence:e", "replacement:f"])
    assert h.reopen_count == 3
    h.state = HState.CLOSED
    with pytest.raises(IllegalTransition):
        transition(construct_human_override_token("reviewer"), h, HState.INVESTIGATING, "reopen", ["human_reason:r", "new_evidence:e", "replacement:f"])
    transition(construct_human_override_token("reviewer"), h, HState.INVESTIGATING, "reopen", ["human_reason:r", "new_evidence:e", "replacement:f", "reviewer2:r2"])
    assert h.reopen_count == 4


def test_legal_transition_seed_matches_lifecycle_table():
    store = Store(":memory:")
    rows = store.conn.execute("SELECT from_state, to_state FROM legal_transitions ORDER BY from_state, to_state").fetchall()
    assert {(r[0], r[1]) for r in rows} == {(source.value, target.value) for source, targets in LEGAL_TRANSITIONS.items() for target in targets}
    store.close()


def test_store_transition_is_event_first_and_emits_reopen_threshold():
    store = Store(":memory:")
    h = make_h(HState.OPEN)
    store.create_hypothesis(h.model_dump(mode="json"))
    store.transition_hypothesis(construct_driver_token("driver"), h, HState.CLOSED, "false", ["disproof:D-1"])
    # Set the cumulative reopen count through the event-backed metadata path.
    store.save("hypothesis", h.id, {"reopen_count": 2, "cause": "restore historical count", "evidence": ["human_reason:fixture"]})
    h.reopen_count = 2
    store.transition_hypothesis(construct_human_override_token("reviewer"), h, HState.INVESTIGATING, "reopen", ["human_reason:r", "new_evidence:e", "replacement:f"])
    events = store.events
    assert [e["kind"] for e in events] == ["hyp_created", "hyp_transition", "hyp_updated", "hyp_transition", "reopen_threshold_exceeded"]
    assert store.get("hypothesis", h.id)["state"] == "INVESTIGATING"
    store.close()

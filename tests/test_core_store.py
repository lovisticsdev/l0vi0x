import sqlite3
import json

import pytest

from conftest import make_hypothesis_kwargs

from l0vi0x.core.ladder import LadderProof
from l0vi0x.driver.run import construct_driver_token, construct_human_override_token
from l0vi0x.core.models import HState, Hypothesis
from l0vi0x.core.store import Store


def make_h(state=HState.OPEN):
    return Hypothesis(**{**make_hypothesis_kwargs(), "state": state})


def test_store_has_all_plan_tables_and_blocked_on_human():
    store = Store(":memory:")
    expected = {
        "events", "hypotheses", "legal_transitions", "assumptions", "assumption_deps", "invariants",
        "experiments", "failures", "obligations", "certificates", "findings", "tasks", "llm_calls",
        "quotas", "known_issues", "campaigns", "human_reviews", "budget_reservations", "id_counters",
    }
    assert expected <= store.table_names()
    ddl = store.conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='tasks'").fetchone()[0]
    assert "blocked_on_human" in ddl
    store.close()


def test_new_hypotheses_cannot_be_inserted_as_findings():
    store = Store(":memory:")
    with pytest.raises(sqlite3.DatabaseError):
        store.submit(lambda conn: conn.execute("INSERT INTO hypotheses(id,state,body) VALUES('H-1','FINDING','{}')"))
    store.close()


def test_hypothesis_state_change_cannot_bypass_lifecycle():
    store = Store(":memory:")
    store.create_hypothesis({"id": "H-001", "claim": "x", "state": "OPEN"})
    with pytest.raises(sqlite3.DatabaseError):
        store.submit(lambda conn: conn.execute("UPDATE hypotheses SET state='FINDING' WHERE id='H-001'"))
    with pytest.raises(sqlite3.DatabaseError):
        store.submit(lambda conn: conn.execute("UPDATE hypotheses SET state='INVESTIGATING' WHERE id='H-001'"))
    store.close()


def test_existing_hypothesis_save_requires_event_metadata():
    store = Store(":memory:")
    h = make_h()
    store.create_hypothesis(h.model_dump(mode="json"))
    with pytest.raises(ValueError):
        store.save("hypothesis", h.id, {"claim": "changed"})
    before = len(store.events)
    result = store.save("hypothesis", h.id, {"claim": "changed", "cause": "human correction", "evidence": ["human_reason:correction"]})
    assert result["claim"] == "changed"
    assert len(store.events) == before + 1
    assert store.events[-1]["kind"] == "hyp_updated"
    assert store.verify_hypothesis_rebuild(h.id)
    store.close()


def test_ladder_award_is_event_first_and_rebuildable():
    store = Store(":memory:")
    h = make_h()
    store.create_hypothesis(h.model_dump(mode="json"))
    store.award_ladder(construct_driver_token("driver"), h, LadderProof("execution", 3, ["experiment"]))
    proof = LadderProof("execution", 4, ["run_receipt"])
    store.award_ladder(construct_driver_token("driver"), h, proof)
    assert h.ladder["execution"] == 4
    assert store.events[-1]["kind"] == "hyp_ladder_award"
    assert store.get("hypothesis", h.id)["ladder"]["execution"] == 4
    assert store.verify_hypothesis_rebuild(h.id)
    store.close()


def test_event_log_is_append_only_and_generic_rows_are_event_linked():
    store = Store(":memory:")
    event = store.record_event("assumption", "seed", {"kind": "entity_saved", "entity_op": "insert", "snapshot": {}})
    with pytest.raises(sqlite3.DatabaseError):
        store.submit(lambda conn: conn.execute("UPDATE events SET payload='{}' WHERE id=?", (event["id"],)))
    with pytest.raises(sqlite3.DatabaseError):
        store.submit(lambda conn: conn.execute("DELETE FROM events WHERE id=?", (event["id"],)))

    with pytest.raises(sqlite3.DatabaseError):
        store.submit(lambda conn: conn.execute("INSERT INTO assumptions(id,status,body) VALUES('A1','candidate','{}')"))
    store.save("assumption", "A1", {"status": "candidate", "note": "v1"})
    with pytest.raises(sqlite3.DatabaseError):
        store.submit(lambda conn: conn.execute("UPDATE assumptions SET body='{}' WHERE id='A1'"))
    store.save("assumption", "A1", {"status": "verified", "note": "v2"})
    with pytest.raises(sqlite3.DatabaseError):
        store.submit(lambda conn: conn.execute("UPDATE assumptions SET body='{}' WHERE id='A1'"))
    with pytest.raises(sqlite3.DatabaseError):
        store.submit(lambda conn: conn.execute("DELETE FROM assumptions WHERE id='A1'"))
    store.close()


def test_generic_event_snapshot_must_match_exact_row_state() -> None:
    store = Store(":memory:")
    store.save("assumption", "A1", {"status": "unverified", "note": "initial"})
    with pytest.raises(sqlite3.DatabaseError):
        def forged(conn):
            event = store.record_event(
                "assumption",
                "A1",
                {
                    "kind": "entity_saved",
                    "entity_op": "update",
                    "row_snapshot": {"id": "A1", "status": "verified", "body": "{\"id\":\"A1\",\"note\":\"different\"}"},
                },
                _conn=conn,
            )
            conn.execute(
                "UPDATE assumptions SET status=?, body=?, last_event_id=? WHERE id=?",
                ("unverified", json.dumps({"id": "A1", "note": "attacker-controlled"}, sort_keys=True, separators=(",", ":")), int(event["id"]), "A1"),
            )
        store.submit(forged)
    assert store.get("assumption", "A1")["note"] == "initial"
    store.close()


def test_generic_event_snapshot_accepts_exact_row_state() -> None:
    store = Store(":memory:")
    store.save("assumption", "A1", {"status": "unverified", "note": "initial"})
    store.save("assumption", "A1", {"status": "verified", "note": "updated", "cause": "test", "evidence": ["E1"]})
    assert store.get("assumption", "A1")["status"] == "verified"
    assert store.get("assumption", "A1")["note"] == "updated"
    store.close()

from l0vi0x.core.store import Store
from l0vi0x.core.tasks import TaskLedger


def test_task_begin_is_idempotent_and_persisted(tmp_path):
    db = tmp_path / "state.db"
    store = Store(db)
    ledger = TaskLedger(store)
    first = ledger.begin("key-1", "some-task")
    second = ledger.begin("key-1", "different-task")
    assert first["id"] == second["id"]
    ledger.close()

    reopened = Store(db)
    resumed = TaskLedger(reopened)
    third = resumed.begin("key-1", "third-task")
    assert third["id"] == first["id"]
    assert resumed.inflight()[0]["id"] == first["id"]
    resumed.finish(first["id"], {"ok": True})
    assert reopened.get("task", first["id"])["status"] == "finished"
    resumed.close()


def test_task_blocked_on_human_is_persisted(tmp_path):
    store = Store(tmp_path / "state.db")
    ledger = TaskLedger(store)
    task = ledger.begin("key-2", "some-task")
    blocked = ledger.block_human(task["id"], "review needed")
    assert blocked["status"] == "blocked_on_human"
    assert store.events[-1]["kind"] == "task_blocked_on_human"
    ledger.close()


def test_concurrent_begin_same_idempotency_key_does_not_duplicate(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    store = Store(tmp_path / "state.db")
    ledger = TaskLedger(store)
    with ThreadPoolExecutor(max_workers=8) as pool:
        rows = list(pool.map(lambda i: ledger.begin("same-key", f"task-{i}"), range(16)))
    assert {row["id"] for row in rows} == {rows[0]["id"]}
    assert len(store.query_tasks()) == 1
    ledger.close()

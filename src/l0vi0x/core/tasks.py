from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from l0vi0x.core.store import Store


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class TaskLedger:
    def __init__(self, store: Store | None = None):
        self.store = store or Store()
        self._owns_store = store is None

    def begin(self, key: str, kind: str, *, phase: str = "default", role: str = "worker") -> dict[str, Any]:
        key = key.strip()
        if not key:
            raise ValueError("idempotency key must be non-empty")
        existing = self.store.find_task_by_key(key)
        if existing is not None:
            return existing
        task_id = self.store.next_id("T")
        try:
            return self.store.dispatch_task(task_id=task_id, idempotency_key=key, kind=kind, phase=phase, role=role, started_at=_now())
        except Exception:
            existing = self.store.find_task_by_key(key)
            if existing is not None:
                return existing
            raise

    def finish(self, task_id: str, result: Any) -> dict[str, Any]:
        return self.store.finish_task(task_id, result, _now())

    def fail(self, task_id: str, result: Any = None) -> dict[str, Any]:
        task = self.store.get("task", task_id)
        self.store.save("task", task_id, {**task, "status": "failed", "finished_at": _now(), "result": result})
        return self.store.get("task", task_id)

    def block_human(self, task_id: str, reason: str | None = None) -> dict[str, Any]:
        return self.store.block_task(task_id, reason, _now())

    def inflight(self) -> list[dict[str, Any]]:
        return self.store.query_tasks(status="dispatched")

    def close(self) -> None:
        if self._owns_store:
            self.store.close()

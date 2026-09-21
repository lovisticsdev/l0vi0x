from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, TypeVar

from l0vi0x.core.events import EVENT_KINDS, validate_kind
from l0vi0x.core.lifecycle import LEGAL_TRANSITIONS, validate_transition
from l0vi0x.core.ladder import Ladder, LadderProof
from l0vi0x.core.models import HState, Hypothesis
from l0vi0x.core.redaction import redact_payload

T = TypeVar("T")

_DDL = """
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY, ts TEXT NOT NULL, kind TEXT NOT NULL,
  entity TEXT NOT NULL, entity_id TEXT NOT NULL, payload TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS hypotheses(
  id TEXT PRIMARY KEY, state TEXT NOT NULL CHECK(state IN
   ('OPEN','INVESTIGATING','CONFIRMED','FINDING','CLOSED','CLOSED_DUPLICATE','PARKED','MERGED')),
  lens TEXT, protocol_type TEXT, prior_p REAL, body TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS hyp_canon ON hypotheses(json_extract(body, '$.canonical_key'));

CREATE TABLE IF NOT EXISTS legal_transitions(from_state TEXT NOT NULL, to_state TEXT NOT NULL,
  PRIMARY KEY(from_state, to_state));

CREATE TABLE IF NOT EXISTS assumptions(id TEXT PRIMARY KEY, status TEXT NOT NULL, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS assumption_deps(hyp_id TEXT, assumption_id TEXT, PRIMARY KEY(hyp_id, assumption_id));
CREATE TABLE IF NOT EXISTS invariants(id TEXT PRIMARY KEY, status TEXT NOT NULL, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS experiments(id TEXT PRIMARY KEY, hyp_id TEXT, task_id TEXT, kind TEXT, result TEXT, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS failures(id TEXT PRIMARY KEY, hyp_id TEXT, kind TEXT, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS obligations(key TEXT PRIMARY KEY, status TEXT NOT NULL CHECK(status IN
 ('open','verified_bounded','verified_proved','refuted_with_witness','blocked_with_reason','out_of_budget_attempted','never_attempted')),
 ref TEXT, reason TEXT, attempts INT NOT NULL DEFAULT 0, depth INT NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS certificates(
  id TEXT PRIMARY KEY, witness_sha256 TEXT NOT NULL, env_hash TEXT NOT NULL, runs INT NOT NULL,
  observed_records_sha256 TEXT NOT NULL, trace_policy_sha256 TEXT NOT NULL, control_sha256 TEXT NOT NULL,
  cross_check_sha256 TEXT, mac TEXT NOT NULL, issued_at TEXT NOT NULL, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS findings(
  id TEXT PRIMARY KEY, hyp_id TEXT, human_review TEXT, certificate_id TEXT, body TEXT NOT NULL,
  FOREIGN KEY(certificate_id) REFERENCES certificates(id));
CREATE TABLE IF NOT EXISTS tasks(
  id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE, phase TEXT, role TEXT,
  status TEXT NOT NULL CHECK(status IN ('dispatched','finished','failed','blocked_on_human')),
  started_at TEXT, finished_at TEXT, result TEXT);
CREATE TABLE IF NOT EXISTS llm_calls(
  id INTEGER PRIMARY KEY, ts TEXT, role TEXT, phase TEXT, hyp_id TEXT,
  provider TEXT, model TEXT, tokens_in INT, tokens_out INT, tokens_cached INT, cache_write_tokens INT,
  latency_ms INT, usd REAL, billing TEXT, stack TEXT, reservation_id TEXT, status TEXT, error TEXT);
CREATE TABLE IF NOT EXISTS quotas(
  provider TEXT, model TEXT, window_start TEXT, requests INT, tokens INT,
  PRIMARY KEY(provider, model, window_start));
CREATE TABLE IF NOT EXISTS known_issues(id TEXT PRIMARY KEY, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS campaigns(id TEXT PRIMARY KEY, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS human_reviews(
  id TEXT PRIMARY KEY, subject_type TEXT NOT NULL, subject_id TEXT NOT NULL, reason_code TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('queued','resolved')), queued_at TEXT NOT NULL, resolved_at TEXT, reviewer TEXT, resolution TEXT);
CREATE TABLE IF NOT EXISTS budget_reservations(
  id TEXT PRIMARY KEY, task_id TEXT NOT NULL, max_usd REAL NOT NULL, reserved_usd REAL NOT NULL,
  settled_usd REAL NOT NULL DEFAULT 0, released_usd REAL NOT NULL DEFAULT 0,
  status TEXT NOT NULL CHECK(status IN ('reserved','settled','released')));
CREATE TABLE IF NOT EXISTS id_counters(prefix TEXT PRIMARY KEY, value INTEGER NOT NULL);

CREATE TRIGGER IF NOT EXISTS hyp_state_insert_guard
BEFORE INSERT ON hypotheses
WHEN NEW.state <> 'OPEN'
BEGIN
  SELECT RAISE(ABORT, 'new hypotheses must start in OPEN');
END;

CREATE TRIGGER IF NOT EXISTS hyp_state_guard
BEFORE UPDATE OF state ON hypotheses
WHEN OLD.state <> NEW.state AND (
  NOT EXISTS (
    SELECT 1 FROM legal_transitions WHERE from_state = OLD.state AND to_state = NEW.state
  )
  OR NOT EXISTS (
    SELECT 1
    FROM events e
    WHERE e.entity = 'hypothesis'
      AND e.entity_id = OLD.id
      AND e.id = (
        SELECT MAX(id) FROM events WHERE entity = 'hypothesis' AND entity_id = OLD.id
      )
      AND e.kind = 'hyp_transition'
      AND json_extract(e.payload, '$.from') = OLD.state
      AND json_extract(e.payload, '$.to') = NEW.state
  )
)
BEGIN SELECT RAISE(ABORT, 'hypothesis state changes must be legal and event-first'); END;
"""


def _transition_seed() -> list[tuple[str, str]]:
    return sorted((src.value, dst.value) for src, dsts in LEGAL_TRANSITIONS.items() for dst in dsts)


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class Store:
    """SQLite state store with one serialized writer path and independent reader connections."""

    def __init__(self, db_path: str | Path = ":memory:"):
        raw = str(db_path)
        self._memory = raw == ":memory:"
        if self._memory:
            self._uri = f"file:l0vi0x_store_{uuid.uuid4().hex}?mode=memory&cache=shared"
            self._writer = sqlite3.connect(self._uri, uri=True, check_same_thread=False)
        else:
            path = Path(raw).expanduser().resolve()
            path.parent.mkdir(parents=True, exist_ok=True)
            self.db_path = str(path)
            self._writer = sqlite3.connect(str(path), check_same_thread=False)
            self._uri = f"file:{path.as_posix()}"
        self._lock = threading.RLock()
        self._writer.execute("PRAGMA journal_mode=WAL")
        self._writer.execute("PRAGMA foreign_keys=ON")
        self._writer.execute("PRAGMA busy_timeout=5000")
        self._writer.execute("PRAGMA synchronous=NORMAL")
        self._ensure_schema()

    @property
    def conn(self) -> sqlite3.Connection:
        """Compatibility reader connection. It must not be used for writes."""
        conn = self._reader()
        return conn

    def _reader(self) -> sqlite3.Connection:
        if self._memory:
            conn = sqlite3.connect(self._uri, uri=True, check_same_thread=False)
        else:
            conn = sqlite3.connect(f"{self._uri}?mode=ro", uri=True, check_same_thread=False)
        conn.execute("PRAGMA query_only=ON")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.row_factory = sqlite3.Row
        return conn

    def _ensure_schema(self) -> None:
        with self._lock:
            self._writer.executescript(_DDL)
            rows = self._writer.execute("SELECT COUNT(*) FROM legal_transitions").fetchone()[0]
            if rows == 0:
                self._writer.executemany("INSERT INTO legal_transitions(from_state,to_state) VALUES (?,?)", _transition_seed())
            elif rows != len(_transition_seed()):
                raise RuntimeError("legal_transitions table has unexpected row count")
            db_seed = set(self._writer.execute("SELECT from_state,to_state FROM legal_transitions").fetchall())
            if db_seed != set(_transition_seed()):
                raise RuntimeError("legal_transitions seed drifted from lifecycle authority")
            self._writer.commit()

    def submit(self, txn: Callable[[sqlite3.Connection], T]) -> T:
        """Run a prepared write transaction through the sole writer connection."""
        with self._lock:
            self._writer.execute("BEGIN IMMEDIATE")
            try:
                result = txn(self._writer)
                self._writer.commit()
                return result
            except BaseException:
                self._writer.rollback()
                raise

    def close(self) -> None:
        with self._lock:
            self._writer.close()

    def next_id(self, prefix: str) -> str:
        prefix = prefix.strip().upper()
        if not prefix or len(prefix) > 8 or not prefix.isalnum():
            raise ValueError("invalid ID prefix")

        def txn(conn: sqlite3.Connection) -> str:
            row = conn.execute("SELECT value FROM id_counters WHERE prefix=?", (prefix,)).fetchone()
            next_value = int(row[0]) if row else 1
            conn.execute(
                "INSERT INTO id_counters(prefix,value) VALUES(?,?) ON CONFLICT(prefix) DO UPDATE SET value=excluded.value",
                (prefix, next_value + 1),
            )
            return f"{prefix}-{next_value:03d}"

        return self.submit(txn)

    def record_event(self, entity: str, entity_id: str, payload: dict[str, Any], *, _conn: sqlite3.Connection | None = None) -> dict[str, Any]:
        payload = redact_payload(payload)
        kind = str(payload.get("kind", "event"))
        if kind not in EVENT_KINDS:
            raise ValueError(f"unknown event kind: {kind}")
        row = {
            "ts": _iso_now(),
            "kind": kind,
            "entity": entity,
            "entity_id": entity_id,
            "payload": json.dumps(payload, sort_keys=True, separators=(",", ":")),
        }

        def txn(conn: sqlite3.Connection) -> dict[str, Any]:
            cur = conn.execute(
                "INSERT INTO events(ts,kind,entity,entity_id,payload) VALUES(?,?,?,?,?)",
                (row["ts"], row["kind"], row["entity"], row["entity_id"], row["payload"]),
            )
            return {"id": cur.lastrowid, **row}

        if _conn is not None:
            return txn(_conn)
        return self.submit(txn)

    def create_hypothesis(self, payload: dict[str, Any], *, entity_id: str | None = None) -> dict[str, Any]:
        data = redact_payload(payload)
        hid = entity_id or str(data.get("id") or self.next_id("H"))
        data["id"] = hid
        data.setdefault("state", HState.OPEN.value)
        if data["state"] != HState.OPEN.value:
            raise ValueError("new hypotheses must start in OPEN")
        body = json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)

        def txn(conn: sqlite3.Connection) -> None:
            conn.execute(
                "INSERT INTO hypotheses(id,state,lens,protocol_type,prior_p,body) VALUES(?,?,?,?,?,?)",
                (hid, HState.OPEN.value, data.get("lens"), data.get("protocol_type"), data.get("prior_p"), body),
            )
            self.record_event(
                "hypothesis", hid,
                {"kind": "hyp_created", "state": "OPEN", "snapshot": data},
                _conn=conn,
            )

        self.submit(txn)
        return data

    def save(self, entity: str, entity_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        entity = entity.strip().lower()
        if entity in {"hypothesis", "hypotheses"}:
            existing = self._fetch_optional("hypotheses", entity_id)
            if existing is None:
                return self.create_hypothesis(payload, entity_id=entity_id)
            if payload.get("state", existing["state"]) != existing["state"]:
                raise ValueError("hypothesis state changes must use Store.transition_hypothesis")
            if not payload:
                return json.loads(existing["body"])
            payload = dict(payload)
            if "cause" not in payload or "evidence" not in payload:
                raise ValueError("existing hypothesis updates require cause and evidence so the change is event-backed")
            cause = str(payload.pop("cause"))
            evidence = list(payload.pop("evidence"))
            data = redact_payload({**json.loads(existing["body"]), **payload, "id": entity_id, "state": existing["state"]})
            body = json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)
            def txn(conn: sqlite3.Connection) -> None:
                self.record_event("hypothesis", entity_id, {"kind": "hyp_updated", "cause": cause, "evidence": evidence, "snapshot": data}, _conn=conn)
                conn.execute(
                    "UPDATE hypotheses SET lens=?,protocol_type=?,prior_p=?,body=? WHERE id=?",
                    (data.get("lens"), data.get("protocol_type"), data.get("prior_p"), body, entity_id),
                )
            self.submit(txn)
            return data

        data = redact_payload(payload)
        body = json.dumps({**data, "id": entity_id}, sort_keys=True, separators=(",", ":"), default=str)
        self._save_generic(entity, entity_id, data, body)
        return json.loads(body)

    def _save_generic(self, entity: str, entity_id: str, data: dict[str, Any], body: str) -> None:
        def txn(conn: sqlite3.Connection) -> None:
            if entity in {"assumption", "assumptions"}:
                conn.execute("INSERT INTO assumptions(id,status,body) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET status=excluded.status,body=excluded.body", (entity_id, data.get("status", "unverified"), body))
            elif entity in {"invariant", "invariants"}:
                conn.execute("INSERT INTO invariants(id,status,body) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET status=excluded.status,body=excluded.body", (entity_id, data.get("status", "candidate"), body))
            elif entity in {"experiment", "experiments"}:
                conn.execute("INSERT INTO experiments(id,hyp_id,task_id,kind,result,body) VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET hyp_id=excluded.hyp_id,task_id=excluded.task_id,kind=excluded.kind,result=excluded.result,body=excluded.body", (entity_id, data.get("hypothesis_id"), data.get("task_id"), data.get("kind"), data.get("result"), body))
            elif entity in {"failure", "failures", "failure_record"}:
                conn.execute("INSERT INTO failures(id,hyp_id,kind,body) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET hyp_id=excluded.hyp_id,kind=excluded.kind,body=excluded.body", (entity_id, data.get("hypothesis_id"), data.get("kind"), body))
            elif entity in {"obligation", "obligations"}:
                conn.execute("INSERT INTO obligations(key,status,ref,reason,attempts,depth) VALUES(?,?,?,?,?,?) ON CONFLICT(key) DO UPDATE SET status=excluded.status,ref=excluded.ref,reason=excluded.reason,attempts=excluded.attempts,depth=excluded.depth", (entity_id, data.get("status", "open"), data.get("ref"), data.get("reason"), data.get("attempts", 0), data.get("depth", 0)))
            elif entity in {"certificate", "certificates", "replay_certificate"}:
                conn.execute("INSERT INTO certificates(id,witness_sha256,env_hash,runs,observed_records_sha256,trace_policy_sha256,control_sha256,cross_check_sha256,mac,issued_at,body) VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET body=excluded.body", (entity_id, data["witness_sha256"], data["env_hash"], data["runs"], data["observed_records_sha256"], data["trace_policy_sha256"], data["control_sha256"], data.get("cross_check_sha256"), data["mac"], data["issued_at"], body))
            elif entity in {"finding", "findings"}:
                conn.execute("INSERT INTO findings(id,hyp_id,human_review,certificate_id,body) VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET hyp_id=excluded.hyp_id,human_review=excluded.human_review,certificate_id=excluded.certificate_id,body=excluded.body", (entity_id, data.get("hypothesis_id"), data.get("human_review", "pending"), data.get("certificate_id"), body))
            elif entity in {"task", "tasks"}:
                conn.execute("INSERT INTO tasks(id,idempotency_key,phase,role,status,started_at,finished_at,result) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET phase=excluded.phase,role=excluded.role,status=excluded.status,started_at=excluded.started_at,finished_at=excluded.finished_at,result=excluded.result", (entity_id, data["idempotency_key"], data.get("phase"), data.get("role"), data.get("status", "dispatched"), data.get("started_at"), data.get("finished_at"), json.dumps(data.get("result"), sort_keys=True, default=str) if data.get("result") is not None else None))
            elif entity in {"known_issue", "known_issues"}:
                conn.execute("INSERT INTO known_issues(id,body) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET body=excluded.body", (entity_id, body))
            elif entity in {"campaign", "campaigns"}:
                conn.execute("INSERT INTO campaigns(id,body) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET body=excluded.body", (entity_id, body))
            elif entity in {"human_review", "human_reviews"}:
                conn.execute("INSERT INTO human_reviews(id,subject_type,subject_id,reason_code,status,queued_at,resolved_at,reviewer,resolution) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET status=excluded.status,resolved_at=excluded.resolved_at,reviewer=excluded.reviewer,resolution=excluded.resolution", (entity_id, data["subject_type"], data["subject_id"], data["reason_code"], data.get("status", "queued"), data["queued_at"], data.get("resolved_at"), data.get("reviewer"), data.get("resolution")))
            elif entity in {"budget_reservation", "budget_reservations"}:
                conn.execute("INSERT INTO budget_reservations(id,task_id,max_usd,reserved_usd,settled_usd,released_usd,status) VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET task_id=excluded.task_id,max_usd=excluded.max_usd,reserved_usd=excluded.reserved_usd,settled_usd=excluded.settled_usd,released_usd=excluded.released_usd,status=excluded.status", (entity_id, data["task_id"], data["max_usd"], data["reserved_usd"], data.get("settled_usd", 0), data.get("released_usd", 0), data.get("status", "reserved")))
            else:
                raise ValueError(f"unsupported entity: {entity}")
        self.submit(txn)

    def _fetch_optional(self, table: str, entity_id: str) -> dict[str, Any] | None:
        with self._lock:
            conn = self._reader()
            try:
                row = conn.execute(f"SELECT * FROM {table} WHERE id = ?", (entity_id,)).fetchone()
                return dict(row) if row is not None else None
            finally:
                conn.close()

    def transition_hypothesis(self, token: Any, hypothesis: Hypothesis, new_state: HState, cause: str, evidence: list[str]) -> Hypothesis:
        validate_transition(token, hypothesis, new_state, cause, evidence)
        old_state = hypothesis.state
        payload = hypothesis.model_dump(mode="json")
        payload["state"] = new_state.value
        if old_state in {HState.CLOSED, HState.CLOSED_DUPLICATE, HState.MERGED} and new_state == HState.INVESTIGATING:
            payload["reopen_count"] = int(payload.get("reopen_count", 0)) + 1
        payload["updated_at"] = _iso_now()
        event_payload = {"kind": "hyp_transition", "from": old_state.value, "to": new_state.value, "cause": cause, "evidence": list(evidence)}
        body = json.dumps(redact_payload(payload), sort_keys=True, separators=(",", ":"), default=str)

        def txn(conn: sqlite3.Connection) -> None:
            row = conn.execute("SELECT state FROM hypotheses WHERE id=?", (hypothesis.id,)).fetchone()
            if row is None:
                raise KeyError(hypothesis.id)
            if row[0] != old_state.value:
                raise RuntimeError("stale hypothesis state; reload before transition")
            event_payload["snapshot"] = payload
            self.record_event("hypothesis", hypothesis.id, event_payload, _conn=conn)
            conn.execute("UPDATE hypotheses SET state=?,lens=?,protocol_type=?,prior_p=?,body=? WHERE id=?", (new_state.value, payload.get("lens"), payload.get("protocol_type"), payload.get("prior_p"), body, hypothesis.id))
            if old_state in {HState.CLOSED, HState.CLOSED_DUPLICATE, HState.MERGED} and new_state == HState.INVESTIGATING and payload["reopen_count"] == 3:
                self.record_event("hypothesis", hypothesis.id, {"kind": "reopen_threshold_exceeded", "reopen_count": 3}, _conn=conn)

        self.submit(txn)
        hypothesis.state = new_state
        hypothesis.updated_at = datetime.fromisoformat(payload["updated_at"].replace("Z", "+00:00"))
        hypothesis.reopen_count = int(payload.get("reopen_count", hypothesis.reopen_count))
        return hypothesis

    def award_ladder(self, token: Any, hypothesis: Hypothesis, proof: LadderProof) -> Hypothesis:
        candidate = hypothesis.model_copy(deep=True)
        if not Ladder.award(token, candidate, proof.axis, proof.level, proof):
            raise ValueError("invalid ladder proof")
        payload = candidate.model_dump(mode="json")
        body = json.dumps(redact_payload(payload), sort_keys=True, separators=(",", ":"), default=str)
        def txn(conn: sqlite3.Connection) -> None:
            row = conn.execute("SELECT body,state FROM hypotheses WHERE id=?", (hypothesis.id,)).fetchone()
            if row is None:
                raise KeyError(hypothesis.id)
            current = json.loads(row[0])
            if current.get("state") != payload.get("state"):
                raise RuntimeError("stale hypothesis state; reload before ladder award")
            self.record_event(
                "hypothesis", hypothesis.id,
                {"kind": "hyp_ladder_award", "axis": proof.axis, "level": proof.level, "evidence": list(proof.evidence), "snapshot": payload},
                _conn=conn,
            )
            conn.execute("UPDATE hypotheses SET body=? WHERE id=?", (body, hypothesis.id))
        self.submit(txn)
        hypothesis.ladder = candidate.ladder
        hypothesis.updated_at = candidate.updated_at
        return hypothesis

    def rebuild_hypothesis_from_events(self, hypothesis_id: str) -> dict[str, Any]:
        with self._lock:
            conn = self._reader()
            try:
                rows = conn.execute(
                    "SELECT kind,payload FROM events WHERE entity='hypothesis' AND entity_id=? ORDER BY id",
                    (hypothesis_id,),
                ).fetchall()
                snapshot: dict[str, Any] | None = None
                for row in rows:
                    payload = json.loads(row[1])
                    if payload.get("snapshot") is not None:
                        snapshot = payload["snapshot"]
                if snapshot is None:
                    raise KeyError(hypothesis_id)
                return snapshot
            finally:
                conn.close()

    def verify_hypothesis_rebuild(self, hypothesis_id: str) -> bool:
        rebuilt = self.rebuild_hypothesis_from_events(hypothesis_id)
        current = self.get("hypothesis", hypothesis_id)
        return rebuilt == current

    def find_task_by_key(self, key: str) -> dict[str, Any] | None:
        with self._lock:
            conn = self._reader()
            try:
                row = conn.execute("SELECT id,idempotency_key,phase,role,status,started_at,finished_at,result FROM tasks WHERE idempotency_key=?", (key,)).fetchone()
                if row is None:
                    return None
                data = dict(row)
                if data.get("result") is not None:
                    try:
                        data["result"] = json.loads(data["result"])
                    except json.JSONDecodeError:
                        pass
                data["key"] = data["idempotency_key"]
                return data
            finally:
                conn.close()

    def query_tasks(self, *, status: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            conn = self._reader()
            try:
                if status is None:
                    rows = conn.execute("SELECT id,idempotency_key,phase,role,status,started_at,finished_at,result FROM tasks ORDER BY id").fetchall()
                else:
                    rows = conn.execute("SELECT id,idempotency_key,phase,role,status,started_at,finished_at,result FROM tasks WHERE status=? ORDER BY id", (status,)).fetchall()
                out = []
                for row in rows:
                    item = dict(row)
                    if item.get("result") is not None:
                        try:
                            item["result"] = json.loads(item["result"])
                        except json.JSONDecodeError:
                            pass
                    item["key"] = item["idempotency_key"]
                    out.append(item)
                return out
            finally:
                conn.close()

    def dispatch_task(self, *, task_id: str, idempotency_key: str, kind: str, phase: str, role: str, started_at: str) -> dict[str, Any]:
        def txn(conn: sqlite3.Connection) -> None:
            conn.execute("INSERT INTO tasks(id,idempotency_key,phase,role,status,started_at) VALUES(?,?,?,?,?,?)", (task_id, idempotency_key, phase, role, "dispatched", started_at))
            self.record_event("task", task_id, {"kind": "task_dispatched", "idempotency_key": idempotency_key, "task_kind": kind}, _conn=conn)
        self.submit(txn)
        return self.get("task", task_id)

    def finish_task(self, task_id: str, result: Any, finished_at: str) -> dict[str, Any]:
        def txn(conn: sqlite3.Connection) -> None:
            conn.execute("UPDATE tasks SET status='finished',finished_at=?,result=? WHERE id=?", (finished_at, json.dumps(redact_payload(result), sort_keys=True, default=str), task_id))
            if conn.execute("SELECT changes()").fetchone()[0] != 1:
                raise KeyError(task_id)
            self.record_event("task", task_id, {"kind": "task_finished"}, _conn=conn)
        self.submit(txn)
        return self.get("task", task_id)

    def block_task(self, task_id: str, reason: str | None, finished_at: str) -> dict[str, Any]:
        def txn(conn: sqlite3.Connection) -> None:
            conn.execute("UPDATE tasks SET status='blocked_on_human',finished_at=?,result=? WHERE id=?", (finished_at, json.dumps({"reason": redact_payload(reason or "")}), task_id))
            if conn.execute("SELECT changes()").fetchone()[0] != 1:
                raise KeyError(task_id)
            self.record_event("task", task_id, {"kind": "task_blocked_on_human", "reason": reason or ""}, _conn=conn)
        self.submit(txn)
        return self.get("task", task_id)

    def get(self, entity: str, entity_id: str) -> dict[str, Any]:
        entity = entity.strip().lower()
        table = {"hypothesis": "hypotheses", "assumption": "assumptions", "invariant": "invariants", "experiment": "experiments", "failure": "failures", "obligation": "obligations", "certificate": "certificates", "finding": "findings", "task": "tasks", "known_issue": "known_issues", "campaign": "campaigns", "human_review": "human_reviews", "budget_reservation": "budget_reservations"}.get(entity, entity)
        with self._lock:
            conn = self._reader()
            try:
                key_col = "key" if table == "obligations" else "id"
                row = conn.execute(f"SELECT * FROM {table} WHERE {key_col} = ?", (entity_id,)).fetchone()
                if row is None:
                    raise KeyError(entity_id)
                data = dict(row)
                if "body" in data and data["body"]:
                    body = json.loads(data["body"])
                    if table == "hypotheses":
                        body["state"] = data["state"]
                        body["lens"] = data["lens"]
                        body["protocol_type"] = data["protocol_type"]
                        body["prior_p"] = data["prior_p"]
                        return body
                    return body
                if table == "tasks" and data.get("result") is not None:
                    try:
                        data["result"] = json.loads(data["result"])
                    except json.JSONDecodeError:
                        pass
                if table == "obligations":
                    return {k: data[k] for k in ("key", "status", "ref", "reason", "attempts", "depth")}
                return data
            finally:
                conn.close()

    @property
    def events(self) -> list[dict[str, Any]]:
        with self._lock:
            conn = self._reader()
            try:
                rows = conn.execute("SELECT id,ts,kind,entity,entity_id,payload FROM events ORDER BY id").fetchall()
                return [{"id": r[0], "ts": r[1], "kind": r[2], "entity": r[3], "entity_id": r[4], "payload": json.loads(r[5])} for r in rows]
            finally:
                conn.close()

    def table_names(self) -> set[str]:
        with self._lock:
            conn = self._reader()
            try:
                return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            finally:
                conn.close()

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

_MUTABLE_TABLE_KEYS = {
    "assumptions": "id",
    "invariants": "id",
    "experiments": "id",
    "failures": "id",
    "obligations": "key",
    "certificates": "id",
    "findings": "id",
    "tasks": "id",
    "known_issues": "id",
    "campaigns": "id",
    "human_reviews": "id",
    "budget_reservations": "id",
}

_DDL = r"""
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY, ts TEXT NOT NULL, kind TEXT NOT NULL,
  entity TEXT NOT NULL, entity_id TEXT NOT NULL, payload TEXT NOT NULL);

CREATE TRIGGER IF NOT EXISTS events_append_only_update
BEFORE UPDATE ON events
BEGIN SELECT RAISE(ABORT, 'events is append-only'); END;

CREATE TRIGGER IF NOT EXISTS events_append_only_delete
BEFORE DELETE ON events
BEGIN SELECT RAISE(ABORT, 'events is append-only'); END;

CREATE TABLE IF NOT EXISTS hypotheses(
  id TEXT PRIMARY KEY, state TEXT NOT NULL CHECK(state IN
   ('OPEN','INVESTIGATING','CONFIRMED','FINDING','CLOSED','CLOSED_DUPLICATE','PARKED','MERGED')),
  lens TEXT, protocol_type TEXT, prior_p REAL, body TEXT NOT NULL, last_event_id INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS hyp_canon ON hypotheses(json_extract(body, '$.canonical_key'));

CREATE TABLE IF NOT EXISTS legal_transitions(from_state TEXT NOT NULL, to_state TEXT NOT NULL,
  PRIMARY KEY(from_state, to_state));

CREATE TABLE IF NOT EXISTS assumptions(id TEXT PRIMARY KEY, status TEXT NOT NULL, body TEXT NOT NULL, last_event_id INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS assumption_deps(hyp_id TEXT, assumption_id TEXT, PRIMARY KEY(hyp_id, assumption_id));
CREATE TABLE IF NOT EXISTS invariants(id TEXT PRIMARY KEY, status TEXT NOT NULL, body TEXT NOT NULL, last_event_id INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS experiments(id TEXT PRIMARY KEY, hyp_id TEXT, task_id TEXT, kind TEXT, result TEXT, body TEXT NOT NULL, last_event_id INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS failures(id TEXT PRIMARY KEY, hyp_id TEXT, kind TEXT, body TEXT NOT NULL, last_event_id INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS obligations(key TEXT PRIMARY KEY, status TEXT NOT NULL CHECK(status IN
 ('open','verified_bounded','verified_proved','refuted_with_witness','blocked_with_reason','out_of_budget_attempted','never_attempted')),
 ref TEXT, reason TEXT, attempts INT NOT NULL DEFAULT 0, depth INT NOT NULL DEFAULT 0, last_event_id INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS certificates(
  id TEXT PRIMARY KEY, witness_sha256 TEXT NOT NULL, env_hash TEXT NOT NULL, runs INT NOT NULL,
  observed_records_sha256 TEXT NOT NULL, trace_policy_sha256 TEXT NOT NULL, control_sha256 TEXT NOT NULL,
  cross_check_sha256 TEXT, mac TEXT NOT NULL, issued_at TEXT NOT NULL, body TEXT NOT NULL, last_event_id INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS findings(
  id TEXT PRIMARY KEY, hyp_id TEXT, human_review TEXT, certificate_id TEXT, body TEXT NOT NULL,
  last_event_id INTEGER NOT NULL DEFAULT 0,
  FOREIGN KEY(certificate_id) REFERENCES certificates(id));
CREATE TABLE IF NOT EXISTS tasks(
  id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE, phase TEXT, role TEXT,
  status TEXT NOT NULL CHECK(status IN ('dispatched','finished','failed','blocked_on_human')),
  started_at TEXT, finished_at TEXT, result TEXT, last_event_id INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS llm_calls(
  id INTEGER PRIMARY KEY, ts TEXT, role TEXT, phase TEXT, hyp_id TEXT,
  provider TEXT, model TEXT, tokens_in INT, tokens_out INT, tokens_cached INT, cache_write_tokens INT,
  latency_ms INT, usd REAL, billing TEXT, stack TEXT, reservation_id TEXT, status TEXT, error TEXT);
CREATE TABLE IF NOT EXISTS quotas(
  provider TEXT, model TEXT, window_start TEXT, requests INT, tokens INT,
  PRIMARY KEY(provider, model, window_start));
CREATE TABLE IF NOT EXISTS known_issues(id TEXT PRIMARY KEY, body TEXT NOT NULL, last_event_id INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS campaigns(id TEXT PRIMARY KEY, body TEXT NOT NULL, last_event_id INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS human_reviews(
  id TEXT PRIMARY KEY, subject_type TEXT NOT NULL, subject_id TEXT NOT NULL, reason_code TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('queued','resolved')), queued_at TEXT NOT NULL, resolved_at TEXT, reviewer TEXT, resolution TEXT,
  last_event_id INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS budget_reservations(
  id TEXT PRIMARY KEY, task_id TEXT NOT NULL, max_usd REAL NOT NULL, reserved_usd REAL NOT NULL,
  settled_usd REAL NOT NULL DEFAULT 0, released_usd REAL NOT NULL DEFAULT 0,
  status TEXT NOT NULL CHECK(status IN ('reserved','settled','released')), last_event_id INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS id_counters(prefix TEXT PRIMARY KEY, value INTEGER NOT NULL);

CREATE TRIGGER IF NOT EXISTS hyp_state_insert_guard
BEFORE INSERT ON hypotheses
WHEN NEW.state <> 'OPEN'
BEGIN SELECT RAISE(ABORT, 'new hypotheses must start in OPEN'); END;

CREATE TRIGGER IF NOT EXISTS hyp_insert_event_guard
BEFORE INSERT ON hypotheses
WHEN NOT EXISTS (SELECT 1 FROM events e WHERE e.entity='hypothesis' AND e.entity_id=NEW.id AND e.id=NEW.last_event_id AND e.kind='hyp_created' AND NEW.id IS json_extract(e.payload,'$.row_snapshot.id') AND NEW.state IS json_extract(e.payload,'$.row_snapshot.state') AND NEW.lens IS json_extract(e.payload,'$.row_snapshot.lens') AND NEW.protocol_type IS json_extract(e.payload,'$.row_snapshot.protocol_type') AND NEW.prior_p IS json_extract(e.payload,'$.row_snapshot.prior_p') AND NEW.body IS json_extract(e.payload,'$.row_snapshot.body'))
BEGIN SELECT RAISE(ABORT, 'hypothesis inserts must be event-first and match the exact event snapshot'); END;

CREATE TRIGGER IF NOT EXISTS hyp_update_event_guard
BEFORE UPDATE ON hypotheses
WHEN NEW.last_event_id <= OLD.last_event_id
  OR NOT EXISTS (SELECT 1 FROM events e WHERE e.entity='hypothesis' AND e.entity_id=OLD.id AND e.id=NEW.last_event_id AND e.kind IN ('hyp_updated','hyp_transition','hyp_ladder_award') AND NEW.id IS json_extract(e.payload,'$.row_snapshot.id') AND NEW.state IS json_extract(e.payload,'$.row_snapshot.state') AND NEW.lens IS json_extract(e.payload,'$.row_snapshot.lens') AND NEW.protocol_type IS json_extract(e.payload,'$.row_snapshot.protocol_type') AND NEW.prior_p IS json_extract(e.payload,'$.row_snapshot.prior_p') AND NEW.body IS json_extract(e.payload,'$.row_snapshot.body'))
BEGIN SELECT RAISE(ABORT, 'hypothesis updates must be event-first and match the exact event snapshot'); END;

CREATE TRIGGER IF NOT EXISTS hyp_state_guard
BEFORE UPDATE OF state ON hypotheses
WHEN OLD.state <> NEW.state AND (
  NOT EXISTS (SELECT 1 FROM legal_transitions WHERE from_state = OLD.state AND to_state = NEW.state)
  OR NOT EXISTS (SELECT 1 FROM events e WHERE e.entity = 'hypothesis' AND e.entity_id = OLD.id
      AND e.id = NEW.last_event_id
      AND e.kind = 'hyp_transition'
      AND json_extract(e.payload, '$.from') = OLD.state
      AND json_extract(e.payload, '$.to') = NEW.state)
)
BEGIN SELECT RAISE(ABORT, 'hypothesis state changes must be legal and event-first'); END;

-- All generic entities are append-to-event then mutate. Direct UPDATE is impossible without a
-- preceding entity event with the matching operation marker. Direct DELETE is never supported.
"""

_ROW_COLUMNS = {
    "assumptions": ("id", "status", "body"),
    "invariants": ("id", "status", "body"),
    "experiments": ("id", "hyp_id", "task_id", "kind", "result", "body"),
    "failures": ("id", "hyp_id", "kind", "body"),
    "obligations": ("key", "status", "ref", "reason", "attempts", "depth"),
    "certificates": ("id", "witness_sha256", "env_hash", "runs", "observed_records_sha256", "trace_policy_sha256", "control_sha256", "cross_check_sha256", "mac", "issued_at", "body"),
    "findings": ("id", "hyp_id", "human_review", "certificate_id", "body"),
    "tasks": ("id", "idempotency_key", "phase", "role", "status", "started_at", "finished_at", "result"),
    "known_issues": ("id", "body"),
    "campaigns": ("id", "body"),
    "human_reviews": ("id", "subject_type", "subject_id", "reason_code", "status", "queued_at", "resolved_at", "reviewer", "resolution"),
    "budget_reservations": ("id", "task_id", "max_usd", "reserved_usd", "settled_usd", "released_usd", "status"),
}

def _json_snapshot_match(table: str, alias: str) -> str:
    cols = _ROW_COLUMNS[table]
    parts = [f"{alias}.{column} IS json_extract(e.payload, '$.row_snapshot.{column}')" for column in cols]
    return " AND ".join(parts)

for table, key in _MUTABLE_TABLE_KEYS.items():
    canonical = table[:-1] if table.endswith("s") else table
    insert_match = _json_snapshot_match(table, "NEW")
    update_match = _json_snapshot_match(table, "NEW")
    _DDL += f"""
CREATE TRIGGER IF NOT EXISTS {table}_delete_guard
BEFORE DELETE ON {table}
BEGIN SELECT RAISE(ABORT, '{table} rows are not directly deletable'); END;

CREATE TRIGGER IF NOT EXISTS {table}_insert_event_guard
BEFORE INSERT ON {table}
WHEN NOT EXISTS (SELECT 1 FROM events e WHERE e.entity='{canonical}' AND e.entity_id=CAST(NEW.{key} AS TEXT) AND e.id=NEW.last_event_id AND json_extract(e.payload,'$.entity_op')='insert' AND {insert_match})
BEGIN SELECT RAISE(ABORT, '{table} inserts must be event-first and match the exact event snapshot'); END;

CREATE TRIGGER IF NOT EXISTS {table}_update_event_guard
BEFORE UPDATE ON {table}
WHEN NEW.last_event_id <= OLD.last_event_id
  OR NOT EXISTS (SELECT 1 FROM events e WHERE e.entity='{canonical}' AND e.entity_id=CAST(OLD.{key} AS TEXT) AND e.id=NEW.last_event_id AND json_extract(e.payload,'$.entity_op')='update' AND {update_match})
BEGIN SELECT RAISE(ABORT, '{table} updates must be event-first and match the exact event snapshot'); END;
"""



def _transition_seed() -> list[tuple[str, str]]:
    return sorted((src.value, dst.value) for src, dsts in LEGAL_TRANSITIONS.items() for dst in dsts)


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _hypothesis_row_snapshot(*, payload: dict[str, Any], body: str) -> dict[str, Any]:
    return {
        "id": payload["id"],
        "state": payload["state"],
        "lens": payload.get("lens"),
        "protocol_type": payload.get("protocol_type"),
        "prior_p": payload.get("prior_p"),
        "body": body,
    }


class Store:
    """SQLite state store with one serialized writer and event-first mutation invariants."""

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
        return self._reader()

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
            self._ensure_event_link_columns()
            self._recreate_event_link_triggers()
            seed = _transition_seed()
            rows = self._writer.execute("SELECT COUNT(*) FROM legal_transitions").fetchone()[0]
            if rows == 0:
                self._writer.executemany("INSERT INTO legal_transitions(from_state,to_state) VALUES (?,?)", seed)
            elif rows != len(seed):
                raise RuntimeError("legal_transitions table has unexpected row count")
            db_seed = set(self._writer.execute("SELECT from_state,to_state FROM legal_transitions").fetchall())
            if db_seed != set(seed):
                raise RuntimeError("legal_transitions seed drifted from lifecycle authority")
            self._writer.commit()

    def _ensure_event_link_columns(self) -> None:
        for table in ["hypotheses", *sorted(_MUTABLE_TABLE_KEYS)]:
            cols = {row[1] for row in self._writer.execute(f"PRAGMA table_info({table})").fetchall()}
            if "last_event_id" not in cols:
                self._writer.execute(f"ALTER TABLE {table} ADD COLUMN last_event_id INTEGER NOT NULL DEFAULT 0")

    def _recreate_event_link_triggers(self) -> None:
        names = ["hyp_insert_event_guard", "hyp_update_event_guard", "hyp_state_guard"]
        names += [f"{table}_{suffix}" for table in _MUTABLE_TABLE_KEYS for suffix in ("insert_event_guard", "update_event_guard", "delete_guard")]
        for name in names:
            self._writer.execute(f"DROP TRIGGER IF EXISTS {name}")
        self._writer.executescript(_DDL[_DDL.index("CREATE TRIGGER IF NOT EXISTS hyp_state_insert_guard"):])

    def submit(self, txn: Callable[[sqlite3.Connection], T]) -> T:
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
        kind = validate_kind(str(payload.get("kind", "event")))
        if kind == "entity_saved" and payload.get("entity_op") not in {"insert", "update"}:
            raise ValueError("entity_saved events require entity_op=insert|update")
        row = {
            "ts": _iso_now(),
            "kind": kind,
            "entity": str(entity),
            "entity_id": str(entity_id),
            "payload": json.dumps(payload, sort_keys=True, separators=(",", ":")),
        }

        def txn(conn: sqlite3.Connection) -> dict[str, Any]:
            cur = conn.execute(
                "INSERT INTO events(ts,kind,entity,entity_id,payload) VALUES(?,?,?,?,?)",
                (row["ts"], row["kind"], row["entity"], row["entity_id"], row["payload"]),
            )
            return {"id": cur.lastrowid, **row}

        return txn(_conn) if _conn is not None else self.submit(txn)

    def create_hypothesis(self, payload: dict[str, Any], *, entity_id: str | None = None) -> dict[str, Any]:
        data = redact_payload(payload)
        hid = entity_id or str(data.get("id") or self.next_id("H"))
        data["id"] = hid
        data.setdefault("state", HState.OPEN.value)
        if data["state"] != HState.OPEN.value:
            raise ValueError("new hypotheses must start in OPEN")
        body = json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)

        def txn(conn: sqlite3.Connection) -> None:
            event = self.record_event("hypothesis", hid, {"kind": "hyp_created", "entity_op": "insert", "state": "OPEN", "snapshot": data, "row_snapshot": _hypothesis_row_snapshot(payload=data, body=body)}, _conn=conn)
            conn.execute(
                "INSERT INTO hypotheses(id,state,lens,protocol_type,prior_p,body,last_event_id) VALUES(?,?,?,?,?,?,?)",
                (hid, HState.OPEN.value, data.get("lens"), data.get("protocol_type"), data.get("prior_p"), body, event["id"]),
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
                event = self.record_event("hypothesis", entity_id, {"kind": "hyp_updated", "entity_op": "update", "cause": cause, "evidence": evidence, "snapshot": data, "row_snapshot": _hypothesis_row_snapshot(payload=data, body=body)}, _conn=conn)
                conn.execute("UPDATE hypotheses SET lens=?,protocol_type=?,prior_p=?,body=?,last_event_id=? WHERE id=?", (data.get("lens"), data.get("protocol_type"), data.get("prior_p"), body, int(event["id"]), entity_id))

            self.submit(txn)
            return data

        data = redact_payload(payload)
        body = json.dumps({**data, "id": entity_id}, sort_keys=True, separators=(",", ":"), default=str)
        self._save_generic(entity, entity_id, data, body)
        return json.loads(body)

    def _save_generic(self, entity: str, entity_id: str, data: dict[str, Any], body: str) -> None:
        aliases = {
            "assumption": "assumptions", "assumptions": "assumptions",
            "invariant": "invariants", "invariants": "invariants",
            "experiment": "experiments", "experiments": "experiments",
            "failure": "failures", "failures": "failures", "failure_record": "failures",
            "obligation": "obligations", "obligations": "obligations",
            "certificate": "certificates", "certificates": "certificates", "replay_certificate": "certificates",
            "finding": "findings", "findings": "findings",
            "task": "tasks", "tasks": "tasks",
            "known_issue": "known_issues", "known_issues": "known_issues",
            "campaign": "campaigns", "campaigns": "campaigns",
            "human_review": "human_reviews", "human_reviews": "human_reviews",
            "budget_reservation": "budget_reservations", "budget_reservations": "budget_reservations",
        }
        table = aliases.get(entity)
        if table is None:
            raise ValueError(f"unsupported entity: {entity}")
        key_col = _MUTABLE_TABLE_KEYS[table]
        canonical_entity = table[:-1] if table.endswith("s") else table

        def exists(conn: sqlite3.Connection) -> bool:
            return conn.execute(f"SELECT 1 FROM {table} WHERE {key_col}=?", (entity_id,)).fetchone() is not None

        def txn(conn: sqlite3.Connection) -> None:
            op = "update" if exists(conn) else "insert"

            # Build the exact SQL row first. The event's row_snapshot is derived from
            # these values, not from the caller's pre-default payload.
            row_snapshot: dict[str, Any]
            if table in {"assumptions", "invariants"}:
                status = data.get("status", "unverified" if table == "assumptions" else "candidate")
                row_snapshot = {"id": entity_id, "status": status, "body": body}
            elif table == "experiments":
                result_json = json.dumps(data.get("result"), sort_keys=True, default=str) if data.get("result") is not None else None
                row_snapshot = {"id": entity_id, "hyp_id": data.get("hypothesis_id"), "task_id": data.get("task_id"), "kind": data.get("kind"), "result": result_json, "body": body}
            elif table == "failures":
                row_snapshot = {"id": entity_id, "hyp_id": data.get("hypothesis_id"), "kind": data.get("kind"), "body": body}
            elif table == "obligations":
                row_snapshot = {"key": entity_id, "status": data.get("status", "open"), "ref": data.get("ref"), "reason": data.get("reason"), "attempts": data.get("attempts", 0), "depth": data.get("depth", 0)}
            elif table == "certificates":
                row_snapshot = {"id": entity_id, "witness_sha256": data["witness_sha256"], "env_hash": data["env_hash"], "runs": data["runs"], "observed_records_sha256": data["observed_records_sha256"], "trace_policy_sha256": data["trace_policy_sha256"], "control_sha256": data["control_sha256"], "cross_check_sha256": data.get("cross_check_sha256"), "mac": data["mac"], "issued_at": data["issued_at"], "body": body}
            elif table == "findings":
                row_snapshot = {"id": entity_id, "hyp_id": data.get("hypothesis_id"), "human_review": data.get("human_review", "pending"), "certificate_id": data.get("certificate_id"), "body": body}
            elif table == "tasks":
                result_json = json.dumps(data.get("result"), sort_keys=True, default=str) if data.get("result") is not None else None
                row_snapshot = {"id": entity_id, "idempotency_key": data["idempotency_key"], "phase": data.get("phase"), "role": data.get("role"), "status": data.get("status", "dispatched"), "started_at": data.get("started_at"), "finished_at": data.get("finished_at"), "result": result_json}
            elif table in {"known_issues", "campaigns"}:
                row_snapshot = {"id": entity_id, "body": body}
            elif table == "human_reviews":
                row_snapshot = {"id": entity_id, "subject_type": data["subject_type"], "subject_id": data["subject_id"], "reason_code": data["reason_code"], "status": data.get("status", "queued"), "queued_at": data["queued_at"], "resolved_at": data.get("resolved_at"), "reviewer": data.get("reviewer"), "resolution": data.get("resolution")}
            elif table == "budget_reservations":
                row_snapshot = {"id": entity_id, "task_id": data["task_id"], "max_usd": data["max_usd"], "reserved_usd": data["reserved_usd"], "settled_usd": data.get("settled_usd", 0), "released_usd": data.get("released_usd", 0), "status": data.get("status", "reserved")}
            else:
                raise AssertionError(f"unhandled mutable table: {table}")

            event = self.record_event(
                canonical_entity,
                entity_id,
                {"kind": "entity_saved", "entity_op": op, "table": table, "snapshot": {**data, key_col: entity_id}, "row_snapshot": row_snapshot},
                _conn=conn,
            )
            event_id = int(event["id"])

            if table == "assumptions":
                status = row_snapshot["status"]
                if op == "insert":
                    conn.execute("INSERT INTO assumptions(id,status,body,last_event_id) VALUES(?,?,?,?)", (entity_id, status, body, event_id))
                else:
                    conn.execute("UPDATE assumptions SET status=?,body=?,last_event_id=? WHERE id=?", (status, body, event_id, entity_id))
            elif table == "invariants":
                status = row_snapshot["status"]
                if op == "insert":
                    conn.execute("INSERT INTO invariants(id,status,body,last_event_id) VALUES(?,?,?,?)", (entity_id, status, body, event_id))
                else:
                    conn.execute("UPDATE invariants SET status=?,body=?,last_event_id=? WHERE id=?", (status, body, event_id, entity_id))
            elif table == "experiments":
                values = (entity_id, row_snapshot["hyp_id"], row_snapshot["task_id"], row_snapshot["kind"], row_snapshot["result"], body)
                if op == "insert":
                    conn.execute("INSERT INTO experiments(id,hyp_id,task_id,kind,result,body,last_event_id) VALUES(?,?,?,?,?,?,?)", (*values, event_id))
                else:
                    conn.execute("UPDATE experiments SET hyp_id=?,task_id=?,kind=?,result=?,body=?,last_event_id=? WHERE id=?", (*values[1:], event_id, entity_id))
            elif table == "failures":
                values = (row_snapshot["hyp_id"], row_snapshot["kind"], body)
                if op == "insert":
                    conn.execute("INSERT INTO failures(id,hyp_id,kind,body,last_event_id) VALUES(?,?,?,?,?)", (entity_id, *values, event_id))
                else:
                    conn.execute("UPDATE failures SET hyp_id=?,kind=?,body=?,last_event_id=? WHERE id=?", (*values, event_id, entity_id))
            elif table == "obligations":
                values = (row_snapshot["status"], row_snapshot["ref"], row_snapshot["reason"], row_snapshot["attempts"], row_snapshot["depth"])
                if op == "insert":
                    conn.execute("INSERT INTO obligations(key,status,ref,reason,attempts,depth,last_event_id) VALUES(?,?,?,?,?,?,?)", (entity_id, *values, event_id))
                else:
                    conn.execute("UPDATE obligations SET status=?,ref=?,reason=?,attempts=?,depth=?,last_event_id=? WHERE key=?", (*values, event_id, entity_id))
            elif table == "certificates":
                values = tuple(row_snapshot[k] for k in ("witness_sha256", "env_hash", "runs", "observed_records_sha256", "trace_policy_sha256", "control_sha256", "cross_check_sha256", "mac", "issued_at")) + (body,)
                if op == "insert":
                    conn.execute("INSERT INTO certificates(id,witness_sha256,env_hash,runs,observed_records_sha256,trace_policy_sha256,control_sha256,cross_check_sha256,mac,issued_at,body,last_event_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", (entity_id, *values, event_id))
                else:
                    conn.execute("UPDATE certificates SET witness_sha256=?,env_hash=?,runs=?,observed_records_sha256=?,trace_policy_sha256=?,control_sha256=?,cross_check_sha256=?,mac=?,issued_at=?,body=?,last_event_id=? WHERE id=?", (*values, event_id, entity_id))
            elif table == "findings":
                values = (row_snapshot["hyp_id"], row_snapshot["human_review"], row_snapshot["certificate_id"], body)
                if op == "insert":
                    conn.execute("INSERT INTO findings(id,hyp_id,human_review,certificate_id,body,last_event_id) VALUES(?,?,?,?,?,?)", (entity_id, *values, event_id))
                else:
                    conn.execute("UPDATE findings SET hyp_id=?,human_review=?,certificate_id=?,body=?,last_event_id=? WHERE id=?", (*values, event_id, entity_id))
            elif table == "tasks":
                values = tuple(row_snapshot[k] for k in ("idempotency_key", "phase", "role", "status", "started_at", "finished_at", "result"))
                if op == "insert":
                    conn.execute("INSERT INTO tasks(id,idempotency_key,phase,role,status,started_at,finished_at,result,last_event_id) VALUES(?,?,?,?,?,?,?,?,?)", (entity_id, *values, event_id))
                else:
                    conn.execute("UPDATE tasks SET idempotency_key=?,phase=?,role=?,status=?,started_at=?,finished_at=?,result=?,last_event_id=? WHERE id=?", (*values, event_id, entity_id))
            elif table == "known_issues":
                if op == "insert":
                    conn.execute("INSERT INTO known_issues(id,body,last_event_id) VALUES(?,?,?)", (entity_id, body, event_id))
                else:
                    conn.execute("UPDATE known_issues SET body=?,last_event_id=? WHERE id=?", (body, event_id, entity_id))
            elif table == "campaigns":
                if op == "insert":
                    conn.execute("INSERT INTO campaigns(id,body,last_event_id) VALUES(?,?,?)", (entity_id, body, event_id))
                else:
                    conn.execute("UPDATE campaigns SET body=?,last_event_id=? WHERE id=?", (body, event_id, entity_id))
            elif table == "human_reviews":
                values = tuple(row_snapshot[k] for k in ("subject_type", "subject_id", "reason_code", "status", "queued_at", "resolved_at", "reviewer", "resolution"))
                if op == "insert":
                    conn.execute("INSERT INTO human_reviews(id,subject_type,subject_id,reason_code,status,queued_at,resolved_at,reviewer,resolution,last_event_id) VALUES(?,?,?,?,?,?,?,?,?,?)", (entity_id, *values, event_id))
                else:
                    conn.execute("UPDATE human_reviews SET subject_type=?,subject_id=?,reason_code=?,status=?,queued_at=?,resolved_at=?,reviewer=?,resolution=?,last_event_id=? WHERE id=?", (*values, event_id, entity_id))
            elif table == "budget_reservations":
                values = tuple(row_snapshot[k] for k in ("task_id", "max_usd", "reserved_usd", "settled_usd", "released_usd", "status"))
                if op == "insert":
                    conn.execute("INSERT INTO budget_reservations(id,task_id,max_usd,reserved_usd,settled_usd,released_usd,status,last_event_id) VALUES(?,?,?,?,?,?,?,?)", (entity_id, *values, event_id))
                else:
                    conn.execute("UPDATE budget_reservations SET task_id=?,max_usd=?,reserved_usd=?,settled_usd=?,released_usd=?,status=?,last_event_id=? WHERE id=?", (*values, event_id, entity_id))

        self.submit(txn)

    def _fetch_optional(self, table: str, entity_id: str) -> dict[str, Any] | None:
        with self._lock:
            conn = self._reader()
            try:
                key_col = "key" if table == "obligations" else "id"
                row = conn.execute(f"SELECT * FROM {table} WHERE {key_col} = ?", (entity_id,)).fetchone()
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
        event_payload = {"kind": "hyp_transition", "entity_op": "update", "from": old_state.value, "to": new_state.value, "cause": cause, "evidence": list(evidence)}
        body = json.dumps(redact_payload(payload), sort_keys=True, separators=(",", ":"), default=str)

        def txn(conn: sqlite3.Connection) -> None:
            row = conn.execute("SELECT state FROM hypotheses WHERE id=?", (hypothesis.id,)).fetchone()
            if row is None:
                raise KeyError(hypothesis.id)
            if row[0] != old_state.value:
                raise RuntimeError("stale hypothesis state; reload before transition")
            event_payload["snapshot"] = payload
            event_payload["row_snapshot"] = _hypothesis_row_snapshot(payload=payload, body=body)
            event = self.record_event("hypothesis", hypothesis.id, event_payload, _conn=conn)
            conn.execute("UPDATE hypotheses SET state=?,lens=?,protocol_type=?,prior_p=?,body=?,last_event_id=? WHERE id=?", (new_state.value, payload.get("lens"), payload.get("protocol_type"), payload.get("prior_p"), body, event["id"], hypothesis.id))
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
            event = self.record_event("hypothesis", hypothesis.id, {"kind": "hyp_ladder_award", "entity_op": "update", "axis": proof.axis, "level": proof.level, "evidence": list(proof.evidence), "snapshot": payload, "row_snapshot": _hypothesis_row_snapshot(payload=payload, body=body)}, _conn=conn)
            conn.execute("UPDATE hypotheses SET body=?,last_event_id=? WHERE id=?", (body, event["id"], hypothesis.id))

        self.submit(txn)
        hypothesis.ladder = candidate.ladder
        hypothesis.updated_at = candidate.updated_at
        return hypothesis

    def rebuild_hypothesis_from_events(self, hypothesis_id: str) -> dict[str, Any]:
        with self._lock:
            conn = self._reader()
            try:
                rows = conn.execute("SELECT kind,payload FROM events WHERE entity='hypothesis' AND entity_id=? ORDER BY id", (hypothesis_id,)).fetchall()
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
        return self.rebuild_hypothesis_from_events(hypothesis_id) == self.get("hypothesis", hypothesis_id)

    def find_task_by_key(self, key: str) -> dict[str, Any] | None:
        with self._lock:
            conn = self._reader()
            try:
                row = conn.execute("SELECT id,idempotency_key,phase,role,status,started_at,finished_at,result FROM tasks WHERE idempotency_key=?", (key,)).fetchone()
                if row is None: return None
                data = dict(row)
                if data.get("result") is not None:
                    try: data["result"] = json.loads(data["result"])
                    except json.JSONDecodeError: pass
                data["key"] = data["idempotency_key"]
                return data
            finally:
                conn.close()

    def query_tasks(self, *, status: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            conn = self._reader()
            try:
                rows = conn.execute("SELECT id,idempotency_key,phase,role,status,started_at,finished_at,result FROM tasks" + (" WHERE status=?" if status else "") + " ORDER BY id", ((status,) if status else ())).fetchall()
                out=[]
                for row in rows:
                    item=dict(row)
                    if item.get("result") is not None:
                        try: item["result"] = json.loads(item["result"])
                        except json.JSONDecodeError: pass
                    item["key"] = item["idempotency_key"]
                    out.append(item)
                return out
            finally: conn.close()

    def dispatch_task(self, *, task_id: str, idempotency_key: str, kind: str, phase: str, role: str, started_at: str) -> dict[str, Any]:
        def txn(conn: sqlite3.Connection) -> None:
            row_snapshot = {"id": task_id, "idempotency_key": idempotency_key, "phase": phase, "role": role, "status": "dispatched", "started_at": started_at, "finished_at": None, "result": None}
            event = self.record_event("task", task_id, {"kind": "task_dispatched", "entity_op": "insert", "idempotency_key": idempotency_key, "task_kind": kind, "row_snapshot": row_snapshot}, _conn=conn)
            conn.execute("INSERT INTO tasks(id,idempotency_key,phase,role,status,started_at,last_event_id) VALUES(?,?,?,?,?,?,?)", (task_id, idempotency_key, phase, role, "dispatched", started_at, event["id"]))
        self.submit(txn)
        return self.get("task", task_id)

    def finish_task(self, task_id: str, result: Any, finished_at: str) -> dict[str, Any]:
        def txn(conn: sqlite3.Connection) -> None:
            row = conn.execute("SELECT idempotency_key,phase,role,status,started_at FROM tasks WHERE id=?", (task_id,)).fetchone()
            if row is None: raise KeyError(task_id)
            safe_result = redact_payload(result)
            result_json = json.dumps(safe_result, sort_keys=True, default=str)
            payload = {"kind": "task_finished", "entity_op": "update", "snapshot": {"id": task_id, "idempotency_key": row[0], "phase": row[1], "role": row[2], "status": "finished", "started_at": row[4], "finished_at": finished_at, "result": safe_result}, "row_snapshot": {"id": task_id, "idempotency_key": row[0], "phase": row[1], "role": row[2], "status": "finished", "started_at": row[4], "finished_at": finished_at, "result": result_json}}
            event = self.record_event("task", task_id, payload, _conn=conn)
            conn.execute("UPDATE tasks SET status='finished',finished_at=?,result=?,last_event_id=? WHERE id=?", (finished_at, result_json, event["id"], task_id))
        self.submit(txn)
        return self.get("task", task_id)

    def block_task(self, task_id: str, reason: str | None, finished_at: str) -> dict[str, Any]:
        def txn(conn: sqlite3.Connection) -> None:
            row = conn.execute("SELECT idempotency_key,phase,role,started_at FROM tasks WHERE id=?", (task_id,)).fetchone()
            if row is None: raise KeyError(task_id)
            reason_safe = redact_payload(reason or "")
            result_json = json.dumps({"reason": reason_safe}, sort_keys=True)
            event = self.record_event("task", task_id, {"kind": "task_blocked_on_human", "entity_op": "update", "reason": reason_safe, "snapshot": {"id": task_id, "idempotency_key": row[0], "phase": row[1], "role": row[2], "status": "blocked_on_human", "started_at": row[3], "finished_at": finished_at, "result": {"reason": reason_safe}}, "row_snapshot": {"id": task_id, "idempotency_key": row[0], "phase": row[1], "role": row[2], "status": "blocked_on_human", "started_at": row[3], "finished_at": finished_at, "result": result_json}}, _conn=conn)
            conn.execute("UPDATE tasks SET status='blocked_on_human',finished_at=?,result=?,last_event_id=? WHERE id=?", (finished_at, result_json, event["id"], task_id))
        self.submit(txn)
        return self.get("task", task_id)

    def get(self, entity: str, entity_id: str) -> dict[str, Any]:
        entity = entity.strip().lower()
        table = {"hypothesis": "hypotheses", "assumption": "assumptions", "invariant": "invariants", "experiment": "experiments", "failure": "failures", "obligation": "obligations", "certificate": "certificates", "finding": "findings", "task": "tasks", "known_issue": "known_issues", "campaign": "campaigns", "human_review": "human_reviews", "budget_reservation": "budget_reservations"}.get(entity, entity)
        with self._lock:
            conn = self._reader()
            try:
                key_col = "key" if table == "obligations" else "id"
                row = conn.execute(f"SELECT * FROM {table} WHERE {key_col}=?", (entity_id,)).fetchone()
                if row is None: raise KeyError(entity_id)
                data=dict(row)
                if "body" in data and data["body"]:
                    body=json.loads(data["body"])
                    if table == "hypotheses":
                        body.update(state=data["state"], lens=data["lens"], protocol_type=data["protocol_type"], prior_p=data["prior_p"])
                    return body
                if table == "tasks" and data.get("result") is not None:
                    try: data["result"]=json.loads(data["result"])
                    except json.JSONDecodeError: pass
                if table == "obligations": return {k:data[k] for k in ("key","status","ref","reason","attempts","depth")}
                return data
            finally: conn.close()

    @property
    def events(self) -> list[dict[str, Any]]:
        with self._lock:
            conn=self._reader()
            try:
                rows=conn.execute("SELECT id,ts,kind,entity,entity_id,payload FROM events ORDER BY id").fetchall()
                return [{"id":r[0],"ts":r[1],"kind":r[2],"entity":r[3],"entity_id":r[4],"payload":json.loads(r[5])} for r in rows]
            finally: conn.close()

    def table_names(self) -> set[str]:
        with self._lock:
            conn=self._reader()
            try: return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
            finally: conn.close()

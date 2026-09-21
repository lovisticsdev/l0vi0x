from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from typing import Any, Iterable


CHEATCODE_ADDRESS = "0x7109709ecfa91a80626ff3989d68f67f5b1dd12d".lower()


class TracePolicyError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class TraceFrame:
    depth: int
    kind: str
    to: str | None = None
    selector: str | None = None
    phase: str = "witness"
    caller: str | None = None
    data: str | None = None
    gas_used: int | None = None
    logs: tuple[dict[str, Any], ...] = ()


@dataclass(frozen=True, slots=True)
class CheatcodeCall:
    name: str
    category: str
    depth: int
    phase: str
    args: tuple[Any, ...] = ()
    selector: str | None = None


@dataclass(frozen=True, slots=True)
class TraceTransfer:
    token: str
    from_address: str
    to_address: str
    amount: int
    depth: int
    phase: str = "witness"


@dataclass(frozen=True, slots=True)
class TraceSummary:
    frames: tuple[TraceFrame, ...]
    cheatcodes: tuple[CheatcodeCall, ...]
    transfers: tuple[TraceTransfer, ...]
    assertion_events: tuple[dict[str, Any], ...]
    cumulative_warp_s: int
    cumulative_roll: int
    initial_timestamp: int | None
    final_timestamp: int | None
    initial_block: int | None
    final_block: int | None
    gas_used: int
    raw_sha256: str

    def observed_records_sha256(self) -> str:
        payload = {
            "frames": [
                {
                    "depth": f.depth, "kind": f.kind, "to": f.to, "selector": f.selector,
                    "phase": f.phase, "caller": f.caller, "data": f.data, "gas_used": f.gas_used,
                    "logs": list(f.logs),
                } for f in self.frames
            ],
            "cheatcodes": [{"name": c.name, "category": c.category, "depth": c.depth, "phase": c.phase, "args": list(c.args), "selector": c.selector} for c in self.cheatcodes],
            "transfers": [{"token": t.token, "from_address": t.from_address, "to_address": t.to_address, "amount": t.amount, "depth": t.depth, "phase": t.phase} for t in self.transfers],
            "assertion_events": list(self.assertion_events),
            "cumulative_warp_s": self.cumulative_warp_s,
            "cumulative_roll": self.cumulative_roll,
            "gas_used": self.gas_used,
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def parse_trace(payload: str | bytes | dict[str, Any] | list[Any], *, cheatcode_catalog: dict[str, str] | None = None) -> TraceSummary:
    if isinstance(payload, (bytes, bytearray)):
        raw_bytes = bytes(payload)
        text = raw_bytes.decode("utf-8")
        obj = json.loads(text)
    elif isinstance(payload, str):
        text = payload
        obj = json.loads(payload)
        raw_bytes = payload.encode()
    else:
        obj = payload
        raw_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()

    records = obj.get("trace", obj) if isinstance(obj, dict) else obj
    if not isinstance(records, list):
        raise TracePolicyError("structured trace must contain a list of frames")

    frames: list[TraceFrame] = []
    cheats: list[CheatcodeCall] = []
    transfers: list[TraceTransfer] = []
    assertions: list[dict[str, Any]] = []
    prev_ts = _first_int(obj.get("initial_timestamp")) if isinstance(obj, dict) else None
    prev_block = _first_int(obj.get("initial_block")) if isinstance(obj, dict) else None
    initial_ts = prev_ts
    initial_block = prev_block
    warp_sum = 0
    roll_sum = 0
    gas_used = 0

    catalog = {k.lower(): v for k, v in (cheatcode_catalog or {}).items()}
    for item in _flatten_records(records):
        if not isinstance(item, dict):
            raise TracePolicyError("trace frame must be an object")
        depth = int(item.get("depth", 0))
        phase = str(item.get("phase", "witness"))
        to = str(item.get("to")).lower() if item.get("to") is not None else None
        selector = str(item.get("selector")).lower() if item.get("selector") is not None else None
        kind = str(item.get("kind", "call"))
        frame = TraceFrame(depth, kind, to, selector, phase, item.get("caller"), item.get("data"), _first_int(item.get("gas_used")), tuple(item.get("logs", ())))
        frames.append(frame)
        if frame.gas_used:
            gas_used += frame.gas_used
        name = item.get("cheatcode")
        if to == CHEATCODE_ADDRESS or name:
            if not name:
                name = _selector_to_name(selector)
            key = str(name)
            category = catalog.get(key.lower(), "")
            if not category:
                cheats.append(CheatcodeCall(key, "UNCLASSIFIED", depth, phase, tuple(item.get("args", ())), selector))
            else:
                cheats.append(CheatcodeCall(key, category, depth, phase, tuple(item.get("args", ())), selector))
            if key.lower() in {"warp", "roll"}:
                new_value = _first_int(item.get("absolute", item.get("args", [None])[0]))
                if new_value is None:
                    raise TracePolicyError(f"{key} missing absolute value")
                if key.lower() == "warp":
                    if prev_ts is not None and new_value < prev_ts:
                        raise TracePolicyError("backward warp is forbidden")
                    if prev_ts is not None:
                        warp_sum += new_value - prev_ts
                    prev_ts = new_value
                else:
                    if prev_block is not None and new_value < prev_block:
                        raise TracePolicyError("backward roll is forbidden")
                    if prev_block is not None:
                        roll_sum += new_value - prev_block
                    prev_block = new_value
        transfer = item.get("erc20_transfer")
        if transfer:
            transfers.append(TraceTransfer(str(transfer["token"]).lower(), str(transfer["from"]).lower(), str(transfer["to"]).lower(), int(transfer["amount"]), depth, phase))
        for log in item.get("logs", []):
            if isinstance(log, dict) and log.get("event") == "AssertionChecked":
                assertions.append(dict(log, depth=depth, caller=item.get("caller"), emitter=to))

    return TraceSummary(tuple(frames), tuple(cheats), tuple(transfers), tuple(assertions), warp_sum, roll_sum, initial_ts, prev_ts, initial_block, prev_block, gas_used, hashlib.sha256(raw_bytes).hexdigest())


def enforce_time_block_limits(summary: TraceSummary, *, max_time_advance_s: int, max_block_advance: int) -> None:
    if summary.cumulative_warp_s > max_time_advance_s:
        raise TracePolicyError(f"cumulative warp advance {summary.cumulative_warp_s} exceeds {max_time_advance_s}")
    if summary.cumulative_roll > max_block_advance:
        raise TracePolicyError(f"cumulative roll advance {summary.cumulative_roll} exceeds {max_block_advance}")


def enforce_cheatcode_policy(summary: TraceSummary, *, witness_class: str, policy: dict[str, Any]) -> None:
    allowed_by_phase = policy.get(witness_class, {})
    for call in summary.cheatcodes:
        phase_policy = allowed_by_phase.get("setup" if call.phase == "setup" else "witness", allowed_by_phase.get("default", {}))
        allowed = set(phase_policy.get("allow_categories", []))
        if call.category == "UNCLASSIFIED" or call.category not in allowed:
            raise TracePolicyError(f"cheatcode denied: {call.name} ({call.category}) in {call.phase}")
        if call.name in {"ffi", "readFile", "writeFile", "setEnv"}:
            raise TracePolicyError(f"external I/O cheatcode denied: {call.name}")
        if witness_class == "deployed_fork" and call.name in {"deal", "etch", "store", "load", "prank", "startPrank", "hoax", "startHoax"} and call.phase == "witness":
            raise TracePolicyError(f"fork witness mutation/impersonation denied: {call.name}")


def _selector_to_name(selector: str | None) -> str:
    known = {"0x0": "unknown"}
    return known.get(selector or "", "unknown")


def _flatten_records(records: list[Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    def visit(item: Any) -> None:
        if not isinstance(item, dict):
            out.append(item)
            return
        current = dict(item)
        children = current.pop("children", current.pop("calls", None))
        out.append(current)
        if isinstance(children, list):
            for child in children:
                visit(child)
    for record in records:
        visit(record)
    return out


def _first_int(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None

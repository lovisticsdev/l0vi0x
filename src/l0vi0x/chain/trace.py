from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any

from l0vi0x.chain.cheatcode_abi import CHEATCODE_ADDRESS as ABI_CHEATCODE_ADDRESS, name_for_selector

CHEATCODE_ADDRESS = ABI_CHEATCODE_ADDRESS.lower()


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
    success: bool = True
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
                    "depth": f.depth,
                    "kind": f.kind,
                    "to": f.to,
                    "selector": f.selector,
                    "phase": f.phase,
                    "caller": f.caller,
                    "data": f.data,
                    "gas_used": f.gas_used,
                    "success": f.success,
                    "logs": list(f.logs),
                }
                for f in self.frames
            ],
            "cheatcodes": [
                {
                    "name": c.name,
                    "category": c.category,
                    "depth": c.depth,
                    "phase": c.phase,
                    "args": list(c.args),
                    "selector": c.selector,
                }
                for c in self.cheatcodes
            ],
            "transfers": [
                {
                    "token": t.token,
                    "from_address": t.from_address,
                    "to_address": t.to_address,
                    "amount": t.amount,
                    "depth": t.depth,
                    "phase": t.phase,
                }
                for t in self.transfers
            ],
            "assertion_events": list(self.assertion_events),
            "cumulative_warp_s": self.cumulative_warp_s,
            "cumulative_roll": self.cumulative_roll,
            "gas_used": self.gas_used,
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def parse_trace(
    payload: str | bytes | dict[str, Any] | list[Any],
    *,
    cheatcode_catalog: dict[str, str] | None = None,
) -> TraceSummary:
    if isinstance(payload, (bytes, bytearray)):
        raw_bytes = bytes(payload)
        try:
            obj = json.loads(raw_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise TracePolicyError("trace is not valid UTF-8 JSON") from exc
    elif isinstance(payload, str):
        raw_bytes = payload.encode("utf-8")
        try:
            obj = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise TracePolicyError("trace is not valid JSON") from exc
    else:
        obj = payload
        raw_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()

    if isinstance(obj, dict) and "trace" in obj:
        records = obj["trace"]
    else:
        records = obj
    if not isinstance(records, list):
        raise TracePolicyError("structured trace must contain a list of frames")

    prev_ts = _first_int(obj.get("initial_timestamp")) if isinstance(obj, dict) else None
    prev_block = _first_int(obj.get("initial_block")) if isinstance(obj, dict) else None
    initial_ts = prev_ts
    initial_block = prev_block
    warp_sum = 0
    roll_sum = 0
    gas_used = 0

    catalog = {str(k).lower(): str(v) for k, v in (cheatcode_catalog or {}).items()}
    frames: list[TraceFrame] = []
    cheats: list[CheatcodeCall] = []
    transfers: list[TraceTransfer] = []
    assertions: list[dict[str, Any]] = []

    for item in _flatten_records(records):
        if not isinstance(item, dict):
            raise TracePolicyError("trace frame must be an object")
        try:
            depth = int(item.get("depth", 0))
        except (TypeError, ValueError) as exc:
            raise TracePolicyError("trace frame depth is invalid") from exc
        if depth < 0:
            raise TracePolicyError("trace frame depth must be non-negative")
        phase = str(item.get("phase", "witness"))
        if phase not in {"setup", "witness"}:
            raise TracePolicyError(f"unsupported trace phase: {phase}")
        to = str(item["to"]).lower() if item.get("to") is not None else None
        selector = str(item["selector"]).lower() if item.get("selector") is not None else None
        kind = str(item.get("kind", "call"))
        gas = _first_int(item.get("gas_used"))
        success = item.get("success", True)
        if not isinstance(success, bool):
            raise TracePolicyError("trace frame success must be boolean")
        frame = TraceFrame(
            depth=depth,
            kind=kind,
            to=to,
            selector=selector,
            phase=phase,
            caller=item.get("caller"),
            data=item.get("data"),
            gas_used=gas,
            success=success,
            logs=tuple(item.get("logs", ())) if isinstance(item.get("logs", ()), list) else (),
        )
        frames.append(frame)
        # Only the depth-0 witness transaction owns its gas; summing nested frames would double count.
        if frame.gas_used is not None and frame.phase == "witness" and frame.depth == 0:
            gas_used += frame.gas_used

        # The trace, not a free-form "cheatcode" field, determines that a cheatcode occurred.
        if to == CHEATCODE_ADDRESS:
            name = str(item.get("cheatcode") or name_for_selector(selector))
            category = catalog.get(name.lower(), "")
            args = tuple(item.get("args", ())) if isinstance(item.get("args", ()), (list, tuple)) else ()
            cheats.append(CheatcodeCall(name, category or "UNCLASSIFIED", depth, phase, args, selector))
            if name.lower() in {"warp", "roll"}:
                new_value = _first_int(item.get("absolute", args[0] if args else None))
                if new_value is None:
                    raise TracePolicyError(f"{name} missing absolute value")
                if name.lower() == "warp":
                    if prev_ts is None:
                        raise TracePolicyError("initial timestamp is required before warp accounting")
                    if new_value < prev_ts:
                        raise TracePolicyError("backward warp is forbidden")
                    warp_sum += new_value - prev_ts
                    prev_ts = new_value
                else:
                    if prev_block is None:
                        raise TracePolicyError("initial block is required before roll accounting")
                    if new_value < prev_block:
                        raise TracePolicyError("backward roll is forbidden")
                    roll_sum += new_value - prev_block
                    prev_block = new_value

        transfer = item.get("erc20_transfer")
        if transfer:
            transfers.append(_transfer_from_mapping(transfer, depth=depth, phase=phase))
        for transfer in item.get("erc20_transfers", []):
            if isinstance(transfer, dict):
                transfers.append(_transfer_from_mapping(transfer, depth=depth, phase=phase))

        contexts = {str(log.get("id")): log for log in item.get("logs", []) if isinstance(log, dict) and log.get("event") == "AssertionContext"}
        for log in item.get("logs", []):
            if not isinstance(log, dict) or log.get("reverted") or item.get("success") is False:
                continue
            if log.get("event") == "AssertionChecked":
                enriched = dict(log, depth=depth, caller=log.get("caller", item.get("caller")), emitter=log.get("emitter", to))
                context = contexts.get(str(enriched.get("id")))
                if context:
                    enriched["actor"] = context.get("actor")
                    enriched["token"] = context.get("token")
                assertions.append(enriched)

    return TraceSummary(
        tuple(frames),
        tuple(cheats),
        tuple(transfers),
        tuple(assertions),
        warp_sum,
        roll_sum,
        initial_ts,
        prev_ts,
        initial_block,
        prev_block,
        gas_used,
        hashlib.sha256(raw_bytes).hexdigest(),
    )


def _transfer_from_mapping(transfer: dict[str, Any], *, depth: int, phase: str) -> TraceTransfer:
    try:
        return TraceTransfer(
            str(transfer["token"]).lower(),
            str(transfer["from"]).lower(),
            str(transfer["to"]).lower(),
            int(transfer["amount"]),
            depth,
            phase,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise TracePolicyError("malformed ERC-20 transfer record") from exc


def enforce_time_block_limits(summary: TraceSummary, *, max_time_advance_s: int, max_block_advance: int) -> None:
    if max_time_advance_s < 0 or max_block_advance < 0:
        raise TracePolicyError("time/block limits must be non-negative")
    if summary.cumulative_warp_s > max_time_advance_s:
        raise TracePolicyError(f"cumulative warp advance {summary.cumulative_warp_s} exceeds {max_time_advance_s}")
    if summary.cumulative_roll > max_block_advance:
        raise TracePolicyError(f"cumulative roll advance {summary.cumulative_roll} exceeds {max_block_advance}")


def enforce_cheatcode_policy(
    summary: TraceSummary,
    *,
    witness_class: str,
    policy: dict[str, Any],
    fork_block: int | None = None,
) -> None:
    root = policy.get("rules", policy)
    allowed_by_phase = root.get(witness_class, {}) if isinstance(root, dict) else {}
    for call in summary.cheatcodes:
        phase_policy = allowed_by_phase.get(call.phase, allowed_by_phase.get("default", {}))
        allowed = set(phase_policy.get("allow_categories", [])) if isinstance(phase_policy, dict) else set()
        if call.category == "UNCLASSIFIED" or call.category not in allowed:
            raise TracePolicyError(f"cheatcode denied: {call.name} ({call.category}) in {call.phase}")
        if call.name in {"ffi", "readFile", "writeFile", "setEnv", "envString", "envOrFile"}:
            raise TracePolicyError(f"external I/O cheatcode denied: {call.name}")
        if call.name in {"createFork", "selectFork"}:
            raise TracePolicyError(f"cheatcode denied: {call.name}; only createSelectFork is permitted")
        if call.name == "createSelectFork":
            if witness_class != "deployed_fork" or call.phase != "setup":
                raise TracePolicyError("createSelectFork is allowed only during deployed_fork setup")
            if len(call.args) not in (2, 3):
                raise TracePolicyError("createSelectFork must use an alias and a block")
            alias = call.args[0]
            if alias != "l0vi0x_gate":
                raise TracePolicyError("createSelectFork must use the l0vi0x_gate alias")
            if isinstance(alias, str) and "://" in alias:
                raise TracePolicyError("raw RPC URLs are forbidden in createSelectFork")
            if len(call.args) != 2:
                raise TracePolicyError("createSelectFork must use the pinned numeric block form")
            if fork_block is None:
                raise TracePolicyError("createSelectFork requires a declared pinned fork block")
            requested_block = _first_int(call.args[1])
            if requested_block is None or requested_block != int(fork_block):
                raise TracePolicyError("createSelectFork must select the pinned fork block")
        if witness_class == "deployed_fork" and call.phase == "witness" and call.name in {
            "deal", "etch", "store", "load", "prank", "startPrank", "hoax", "startHoax", "setNonce", "mockCall", "mockCallRevert"
        }:
            raise TracePolicyError(f"fork witness mutation/impersonation denied: {call.name}")


def _flatten_records(records: list[Any]) -> list[Any]:
    out: list[Any] = []

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

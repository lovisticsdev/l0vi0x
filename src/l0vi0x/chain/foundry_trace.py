"""Foundry trace adapter for ``forge test --json -vvv`` (verified against Foundry 1.8.3).

Two layers, deliberately separate:

``adapt_forge_test_json``
    The *Foundry-version-specific* part. It converts the call-trace arenas that ``forge test --json``
    emits (``test_results[<test>].traces`` = ``[[kind, {"arena": [...]}], ...]``) into the canonical
    ``l0vi0x.foundry.trace.v1`` envelope. Anything it does not understand raises
    ``FoundryTraceFormatError``; it never guesses.

``extract_structured_trace``
    The strict, version-agnostic validator/normalizer for that envelope. Human-readable ``-vvvv``
    text and recursively discovered ``trace`` fields are never evidence.

Trust boundary
--------------
Only tool-produced JSON is read. The adapter requires that

* exactly one suite for the declared test file and exactly one ``Unit`` test with the declared name
  is present, and it passed;
* every arena node is reachable from the arena root through ``ordering`` (an unreachable node could
  hide a cheatcode call);
* every log Foundry reports at test level appears, in order, among the arena logs.

Frame ``depth`` is Foundry's own call depth (the test function itself is depth 0). ``phase`` is
``setup`` for the ``Deployment`` and ``Setup`` arenas (constructor and ``setUp``) and ``witness`` for
the ``Execution`` arena.
"""
from __future__ import annotations

import posixpath
from typing import Any

from eth_hash.auto import keccak

from l0vi0x.chain.cheatcode_abi import (
    CHEATCODE_ADDRESS,
    CheatcodeDecodeError,
    decode_abi_arguments,
    decode_cheatcode,
)


CANONICAL_TRACE_SCHEMA = "l0vi0x.foundry.trace.v1"
ASSERTION_EVENT_SIGNATURE = "AssertionChecked(bytes32,string,string,int256,int256,bool)"
ASSERTION_TOPIC0 = "0x" + keccak(ASSERTION_EVENT_SIGNATURE.encode("ascii")).hex()
TRANSFER_TOPIC0 = "0x" + keccak(b"Transfer(address,address,uint256)").hex()

_PHASES = {"Deployment": "setup", "Setup": "setup", "Execution": "witness"}
_ARENA_ORDER = ("Deployment", "Setup", "Execution")
_CALL_KINDS = {"call", "staticcall", "delegatecall", "callcode"}


class FoundryTraceFormatError(ValueError):
    pass


# --------------------------------------------------------------------------------------------
# Adapter: forge test --json  ->  canonical envelope
# --------------------------------------------------------------------------------------------

def adapt_forge_test_json(
    payload: Any,
    *,
    test_file: str,
    test_name: str,
    initial_timestamp: int,
    initial_block: int,
) -> dict[str, Any]:
    """Return ``{"l0vi0x_structured_trace": {...}}`` for exactly one passing unit test."""
    if not isinstance(payload, dict):
        raise FoundryTraceFormatError("Forge JSON is not an object")
    for label, value in (("initial_timestamp", initial_timestamp), ("initial_block", initial_block)):
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise FoundryTraceFormatError(f"{label} must be a non-negative integer supplied by the host")

    suite_key = _select_suite(payload, test_file)
    result = _select_test(payload[suite_key], test_name)
    if result.get("status") != "Success":
        raise FoundryTraceFormatError(f"test {test_name} did not succeed: {result.get('status')!r}")
    kind = result.get("kind")
    if not isinstance(kind, dict) or "Unit" not in kind:
        raise FoundryTraceFormatError("only unit tests can be witnesses or controls")

    arenas = _select_arenas(result.get("traces"))
    frames: list[dict[str, Any]] = []
    derived_logs: list[tuple[str, tuple[str, ...], str]] = []
    for arena_kind in _ARENA_ORDER:
        if arena_kind in arenas:
            frames.append(_convert_arena(arenas[arena_kind], _PHASES[arena_kind], derived_logs))

    _check_logs_against_forge(result.get("logs"), derived_logs)

    return {
        "l0vi0x_structured_trace": {
            "schema": CANONICAL_TRACE_SCHEMA,
            "source": {"tool": "forge", "suite": suite_key, "test": f"{test_name}()"},
            "initial_timestamp": initial_timestamp,
            "initial_block": initial_block,
            "frames": frames,
        }
    }


def _select_suite(payload: dict[str, Any], test_file: str) -> str:
    wanted = posixpath.normpath(test_file.replace("\\", "/"))
    matches = []
    for key, suite in payload.items():
        path = str(key).rpartition(":")[0]
        if posixpath.normpath(path.replace("\\", "/")) == wanted and isinstance(suite, dict):
            matches.append(key)
    if len(matches) != 1:
        raise FoundryTraceFormatError(f"expected exactly one suite for {test_file}, found {len(matches)}")
    return matches[0]


def _select_test(suite: dict[str, Any], test_name: str) -> dict[str, Any]:
    results = suite.get("test_results")
    if not isinstance(results, dict) or len(results) != 1:
        raise FoundryTraceFormatError("Forge output must contain exactly one test result")
    name, result = next(iter(results.items()))
    if name != f"{test_name}()" or not isinstance(result, dict):
        raise FoundryTraceFormatError(f"unexpected test in Forge output: {name!r}; expected {test_name}()")
    return result


def _select_arenas(traces: Any) -> dict[str, list[dict[str, Any]]]:
    if not isinstance(traces, list) or not traces:
        raise FoundryTraceFormatError("Forge output contains no call traces (run with --json -vvv)")
    arenas: dict[str, list[dict[str, Any]]] = {}
    for entry in traces:
        if not (isinstance(entry, list) and len(entry) == 2 and isinstance(entry[0], str) and isinstance(entry[1], dict)):
            raise FoundryTraceFormatError("unexpected trace entry shape")
        arena_kind, body = entry
        if arena_kind not in _PHASES:
            raise FoundryTraceFormatError(f"unknown trace arena kind: {arena_kind!r}")
        if arena_kind in arenas:
            raise FoundryTraceFormatError(f"duplicate {arena_kind} trace arena")
        nodes = body.get("arena")
        if not isinstance(nodes, list) or not nodes or not all(isinstance(n, dict) for n in nodes):
            raise FoundryTraceFormatError(f"{arena_kind} arena has no nodes")
        arenas[arena_kind] = nodes
    if "Execution" not in arenas:
        raise FoundryTraceFormatError("Forge output has no Execution trace")
    return arenas


def _hex(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise FoundryTraceFormatError(f"{label} is not 0x-prefixed hex")
    try:
        bytes.fromhex(value[2:])
    except ValueError as exc:
        raise FoundryTraceFormatError(f"{label} is not valid hex") from exc
    return value.lower()


def _address(value: Any, label: str) -> str:
    text = _hex(value, label)
    if len(text) != 42:
        raise FoundryTraceFormatError(f"{label} is not a 20-byte address")
    return text


def _int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise FoundryTraceFormatError(f"{label} is not a non-negative integer")
    return value


def _convert_arena(nodes: list[dict[str, Any]], phase: str, derived_logs: list[tuple[str, tuple[str, ...], str]]) -> dict[str, Any]:
    by_idx: dict[int, dict[str, Any]] = {}
    for node in nodes:
        idx = node.get("idx")
        if isinstance(idx, bool) or not isinstance(idx, int) or idx in by_idx:
            raise FoundryTraceFormatError("arena node index is missing or duplicated")
        by_idx[idx] = node
    roots = [n for n in nodes if n.get("parent") is None]
    if len(roots) != 1:
        raise FoundryTraceFormatError("arena must have exactly one root node")

    visited: set[int] = set()

    def open_node(node: dict[str, Any], parent_reverted: bool) -> tuple[dict[str, Any], bool]:
        idx = node["idx"]
        if idx in visited:
            raise FoundryTraceFormatError("arena node is reachable twice")
        visited.add(idx)
        trace = node.get("trace")
        if not isinstance(trace, dict):
            raise FoundryTraceFormatError("arena node has no trace")
        kind = str(trace.get("kind", "")).lower()
        if not kind:
            raise FoundryTraceFormatError("arena node has no call kind")
        to = _address(trace.get("address"), "frame address")
        data = _hex(trace.get("data", "0x"), "frame data")
        success = trace.get("success")
        if not isinstance(success, bool):
            raise FoundryTraceFormatError("frame success flag is missing")
        frame: dict[str, Any] = {
            "depth": _int(trace.get("depth"), "frame depth"),
            "kind": kind,
            "to": to,
            "caller": _address(trace.get("caller"), "frame caller"),
            "phase": phase,
            "data": data,
            "selector": data[:10] if kind in _CALL_KINDS and len(data) >= 10 else None,
            "gas_used": _int(trace.get("gas_used", 0), "frame gas"),
            "success": success,
            "logs": [],
            "children": [],
        }
        if to == CHEATCODE_ADDRESS and kind in _CALL_KINDS:
            try:
                decoded = decode_cheatcode(data)
            except CheatcodeDecodeError as exc:
                raise FoundryTraceFormatError(f"cannot decode cheatcode call: {exc}") from exc
            frame["cheatcode"] = decoded.name
            frame["args"] = list(decoded.args) if decoded.args is not None else []
            if decoded.name in ("warp", "roll"):
                if not decoded.args:
                    raise FoundryTraceFormatError(f"{decoded.name} has no decoded value")
                frame["absolute"] = decoded.args[0]
        return frame, parent_reverted or not success

    root = roots[0]
    root_frame, root_reverted = open_node(root, False)
    # Each stack entry: [node, frame, reverted, ordering iterator, consumed calls, consumed logs]
    stack: list[list[Any]] = [[root, root_frame, root_reverted, iter(_ordering(root)), set(), set()]]
    while stack:
        node, frame, reverted, steps, calls, logs = stack[-1]
        step = next(steps, None)
        if step is None:
            _require_consumed(node, calls, logs)
            stack.pop()
            continue
        if "Step" in step:
            continue
        if "Call" in step:
            position = step["Call"]
            children = node.get("children")
            if not isinstance(children, list) or not isinstance(position, int) or not 0 <= position < len(children) or position in calls:
                raise FoundryTraceFormatError("arena ordering references an invalid child")
            calls.add(position)
            child = by_idx.get(children[position])
            if child is None or child.get("parent") != node["idx"]:
                raise FoundryTraceFormatError("arena child does not point back to its parent")
            child_frame, child_reverted = open_node(child, reverted)
            frame["children"].append(child_frame)
            stack.append([child, child_frame, child_reverted, iter(_ordering(child)), set(), set()])
            continue
        if "Log" in step:
            position = step["Log"]
            node_logs = node.get("logs")
            if not isinstance(node_logs, list) or not isinstance(position, int) or not 0 <= position < len(node_logs) or position in logs:
                raise FoundryTraceFormatError("arena ordering references an invalid log")
            logs.add(position)
            record, transfer = _convert_log(node_logs[position], reverted)
            frame["logs"].append(record)
            if transfer is not None:
                frame.setdefault("erc20_transfers", []).append(transfer)
            derived_logs.append((record["address"], tuple(record["topics"]), record["data"]))
            continue
        raise FoundryTraceFormatError(f"unknown arena ordering entry: {sorted(step)}")

    if len(visited) != len(nodes):
        raise FoundryTraceFormatError("arena contains nodes that are unreachable from its root")
    return root_frame


def _ordering(node: dict[str, Any]) -> list[dict[str, Any]]:
    ordering = node.get("ordering")
    if not isinstance(ordering, list) or not all(isinstance(x, dict) for x in ordering):
        raise FoundryTraceFormatError("arena node lacks call/log ordering")
    return ordering


def _require_consumed(node: dict[str, Any], calls: set[int], logs: set[int]) -> None:
    if len(calls) != len(node.get("children") or []) or len(logs) != len(node.get("logs") or []):
        raise FoundryTraceFormatError("arena node has calls or logs missing from its ordering")


def _convert_log(entry: Any, reverted: bool) -> tuple[dict[str, Any], dict[str, Any] | None]:
    if not isinstance(entry, dict) or not isinstance(entry.get("raw_log"), dict):
        raise FoundryTraceFormatError("arena log has no raw_log")
    raw = entry["raw_log"]
    topics = raw.get("topics")
    if not isinstance(topics, list) or not all(isinstance(t, str) for t in topics) or len(topics) > 4:
        raise FoundryTraceFormatError("log topics are malformed")
    record: dict[str, Any] = {
        "address": _address(entry.get("address"), "log emitter"),
        "topics": [_hex(t, "log topic") for t in topics],
        "data": _hex(raw.get("data", "0x"), "log data"),
        "reverted": reverted,
    }
    transfer = None
    if record["topics"] and record["topics"][0] == ASSERTION_TOPIC0:
        record["event"] = "AssertionChecked"
        record.update(_decode_assertion(record["topics"], record["data"]))
    elif not reverted and record["topics"] and record["topics"][0] == TRANSFER_TOPIC0:
        transfer = _decode_transfer(record)
    return record, transfer


def _bytes32_label(word_hex: str) -> str:
    raw = bytes.fromhex(word_hex[2:])
    stripped = raw.rstrip(b"\x00")
    if stripped and all(0x20 <= b <= 0x7E for b in stripped):
        return stripped.decode("ascii")
    return word_hex


def _decode_assertion(topics: list[str], data_hex: str) -> dict[str, Any]:
    if len(topics) != 2 or len(topics[1]) != 66:
        raise FoundryTraceFormatError("AssertionChecked must have exactly one indexed argument")
    try:
        kind, target, operator, observed, expected, ok = decode_abi_arguments(
            ["string", "string", "string", "int256", "int256", "bool"], bytes.fromhex(data_hex[2:])
        )
    except CheatcodeDecodeError as exc:
        raise FoundryTraceFormatError(f"malformed AssertionChecked event: {exc}") from exc
    return {
        "id": _bytes32_label(topics[1]),
        "kind": kind,
        "target": target,
        "operator": operator,
        "observed": observed,
        "expected": expected,
        "ok": ok,
    }


def _decode_transfer(record: dict[str, Any]) -> dict[str, Any] | None:
    topics = record["topics"]
    data = record["data"]
    # ERC-20 Transfer has two indexed addresses and a 32-byte amount. ERC-721 (indexed tokenId) does not match.
    if len(topics) != 3 or len(data) != 66:
        return None
    if any(t[2:26] != "0" * 24 for t in topics[1:]):
        return None
    return {
        "token": record["address"],
        "from": "0x" + topics[1][26:],
        "to": "0x" + topics[2][26:],
        "amount": int(data, 16),
    }


def _check_logs_against_forge(forge_logs: Any, derived: list[tuple[str, tuple[str, ...], str]]) -> None:
    if forge_logs is None:
        return
    if not isinstance(forge_logs, list):
        raise FoundryTraceFormatError("Forge log list is malformed")
    normalized: list[tuple[str, tuple[str, ...], str]] = []
    for entry in forge_logs:
        try:
            normalized.append((
                _address(entry["address"], "forge log emitter"),
                tuple(_hex(t, "forge log topic") for t in entry["topics"]),
                _hex(entry["data"], "forge log data"),
            ))
        except (KeyError, TypeError) as exc:
            raise FoundryTraceFormatError("Forge log entry is malformed") from exc
    if normalized != derived:
        raise FoundryTraceFormatError("Forge-reported logs do not exactly match call-trace arena logs")


# --------------------------------------------------------------------------------------------
# Strict envelope extraction (unchanged contract)
# --------------------------------------------------------------------------------------------

def extract_structured_trace(payload: Any, *, expected_schema: str | None = None) -> dict[str, Any]:
    """Accept only an explicitly versioned structured trace envelope.

    ``forge --json`` is not treated as a general-purpose execution-trace schema. The installed Foundry
    version must first be verified and its adapter must emit this canonical envelope. Human-readable
    ``-vvvv`` output and recursively discovered fields named ``trace``/``traces`` are never evidence.
    """
    expected = expected_schema or CANONICAL_TRACE_SCHEMA
    if not isinstance(payload, dict):
        raise FoundryTraceFormatError("Forge JSON is not an object")
    envelope = payload.get("l0vi0x_structured_trace")
    if not isinstance(envelope, dict):
        raise FoundryTraceFormatError(
            "verified Foundry adapter did not provide the canonical structured-trace envelope"
        )
    if envelope.get("schema") != expected:
        raise FoundryTraceFormatError(
            f"unexpected structured trace schema: {envelope.get('schema')!r}; expected {expected!r}"
        )
    frames = envelope.get("frames")
    if not isinstance(frames, list) or not frames or not all(isinstance(x, dict) for x in frames):
        raise FoundryTraceFormatError("canonical structured-trace envelope has no valid frame list")
    try:
        out: dict[str, Any] = {"trace": [_normalize_frame(x, phase="witness") for x in frames], "schema": expected}
    except RecursionError as exc:
        raise FoundryTraceFormatError("structured trace nesting is too deep") from exc
    for key in ("initial_timestamp", "initial_block"):
        if key in envelope:
            value = envelope[key]
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise FoundryTraceFormatError(f"{key} must be a non-negative integer")
            out[key] = value
    return out


def _normalize_frame(item: dict[str, Any], *, phase: str) -> dict[str, Any]:
    frame = {
        "depth": int(item.get("depth", 0)),
        "kind": str(item.get("kind", item.get("type", "call"))),
        "to": item.get("to") or item.get("address"),
        "selector": item.get("selector") or item.get("function"),
        "phase": str(item.get("phase", phase)),
        "caller": item.get("caller") or item.get("from"),
        "data": item.get("data"),
        "gas_used": item.get("gas_used", item.get("gas")),
        "logs": item.get("logs", []),
    }
    if "cheatcode" in item:
        frame["cheatcode"] = item["cheatcode"]
        if "args" in item:
            frame["args"] = item["args"]
        if "absolute" in item:
            frame["absolute"] = item["absolute"]
    if "erc20_transfer" in item:
        frame["erc20_transfer"] = item["erc20_transfer"]
    if "erc20_transfers" in item:
        frame["erc20_transfers"] = item["erc20_transfers"]
    children = item.get("children", item.get("calls"))
    if isinstance(children, list):
        frame["children"] = [
            _normalize_frame(child, phase=phase)
            for child in children
            if isinstance(child, dict)
        ]
    return frame

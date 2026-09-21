from __future__ import annotations

from typing import Any


CANONICAL_TRACE_SCHEMA = "l0vi0x.foundry.trace.v1"


class FoundryTraceFormatError(ValueError):
    pass


def extract_structured_trace(payload: Any, *, expected_schema: str | None = None) -> dict[str, Any]:
    """Accept only an explicitly versioned structured trace envelope.

    ``forge --json`` is not treated as a general-purpose execution-trace schema. The
    installed Foundry version must first be verified and its adapter must emit this
    canonical envelope. Human-readable ``-vvvv`` output and recursively discovered
    fields named ``trace``/``traces`` are never evidence.
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
    return {"trace": [_normalize_frame(x, phase="witness") for x in frames], "schema": expected}


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
    children = item.get("children", item.get("calls"))
    if isinstance(children, list):
        frame["children"] = [
            _normalize_frame(child, phase=phase)
            for child in children
            if isinstance(child, dict)
        ]
    return frame

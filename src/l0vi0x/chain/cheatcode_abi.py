"""Cheatcode selector table and a deliberately small ABI decoder.

Foundry exposes every cheatcode as an ordinary CALL to one fixed address. A structured trace
therefore has to recover the cheatcode *name* and *arguments* from raw calldata. Selectors are
derived from the signatures below with Keccak-256 at import time, so no selector is typed by hand.

Fail-closed rules:

* A call to the cheatcode address whose selector is not in this table is reported as
  ``unknown_0x<selector>``. That name is absent from ``cheatcode_categories.yaml`` and is therefore
  UNCLASSIFIED and denied by policy.
* A selector that *is* known but whose calldata cannot be decoded raises ``CheatcodeDecodeError``.
  The adapter turns that into a rejected trace instead of guessing arguments.

Only the categories in ``cheatcode_categories.yaml`` can ever be allowed. Names listed here that are
not in the catalog exist purely so denial messages are readable.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from eth_hash.auto import keccak

CHEATCODE_ADDRESS = "0x7109709ecfa91a80626ff3989d68f67f5b1dd12d"


class CheatcodeDecodeError(ValueError):
    pass


_PRANK_FORMS = ("(address)", "(address,address)", "(address,bool)", "(address,address,bool)")

_SIGNATURES: dict[str, tuple[str, ...]] = {
    # Cheatcodes present in config/policy/cheatcode_categories.yaml.
    "warp": ("warp(uint256)",),
    "roll": ("roll(uint256)",),
    "deal": ("deal(address,uint256)",),
    "prank": tuple("prank" + form for form in _PRANK_FORMS),
    "startPrank": tuple("startPrank" + form for form in _PRANK_FORMS),
    "stopPrank": ("stopPrank()",),
    "etch": ("etch(address,bytes)",),
    "store": ("store(address,bytes32,bytes32)",),
    "load": ("load(address,bytes32)",),
    "label": ("label(address,string)",),
    "expectRevert": ("expectRevert()", "expectRevert(bytes4)", "expectRevert(bytes)"),
    "expectEmit": ("expectEmit()", "expectEmit(address)", "expectEmit(bool,bool,bool,bool)", "expectEmit(bool,bool,bool,bool,address)"),
    "assume": ("assume(bool)",),
    "ffi": ("ffi(string[])",),
    "readFile": ("readFile(string)",),
    "writeFile": ("writeFile(string,string)",),
    "setEnv": ("setEnv(string,string)",),
    "createSelectFork": ("createSelectFork(string)", "createSelectFork(string,uint256)", "createSelectFork(string,bytes32)"),
    # Classified by decoding for diagnostics, but intentionally absent from the policy catalog.
    "deployCode": ("deployCode(bytes)", "deployCode(bytes,uint256)", "deployCode(string)", "deployCode(string,uint256)"),
    # Not in the catalog on purpose: named only so a denial says what was attempted.
    "createFork": ("createFork(string)", "createFork(string,uint256)", "createFork(string,bytes32)"),
    "selectFork": ("selectFork(uint256)",),
    "envString": ("envString(string)", "envString(string,string)"),
    "skip": ("skip(uint256)", "skip(bool)", "skip(bool,string)"),
    "rewind": ("rewind(uint256)",),
    "chainId": ("chainId(uint256)",),
    "coinbase": ("coinbase(address)",),
    "prevrandao": ("prevrandao(bytes32)", "prevrandao(uint256)"),
    "fee": ("fee(uint256)",),
    "txGasPrice": ("txGasPrice(uint256)",),
    "mockCall": ("mockCall(address,bytes,bytes)",),
    "setNonce": ("setNonce(address,uint64)",),
    "sign": ("sign(uint256,bytes32)",),
    "makePersistent": ("makePersistent(address)",),
}


def _selector(signature: str) -> str:
    return "0x" + keccak(signature.encode("ascii"))[:4].hex()


def _build_table() -> dict[str, tuple[str, str]]:
    table: dict[str, tuple[str, str]] = {}
    for name, signatures in _SIGNATURES.items():
        for signature in signatures:
            selector = _selector(signature)
            if selector in table:  # pragma: no cover - guards future edits to the table
                raise RuntimeError(f"cheatcode selector collision: {signature}")
            table[selector] = (name, signature)
    return table


SELECTOR_TABLE: dict[str, tuple[str, str]] = _build_table()


@dataclass(frozen=True, slots=True)
class DecodedCheatcode:
    name: str
    selector: str
    signature: str | None
    args: tuple[Any, ...] | None


def name_for_selector(selector: str | None) -> str:
    if not selector:
        return "unknown"
    entry = SELECTOR_TABLE.get(selector.lower())
    return entry[0] if entry else f"unknown_{selector.lower()}"


def _split_types(argument_list: str) -> list[str]:
    return [t for t in argument_list.split(",") if t]


def _word(data: bytes, offset: int) -> bytes:
    if offset < 0 or offset + 32 > len(data):
        raise CheatcodeDecodeError("calldata is truncated")
    return data[offset : offset + 32]


def _to_int(word: bytes, *, signed: bool = False) -> int:
    return int.from_bytes(word, "big", signed=signed)


def _decode_static(kind: str, word: bytes) -> Any:
    if kind == "address":
        if any(word[:12]):
            raise CheatcodeDecodeError("address argument has non-zero high bytes")
        return "0x" + word[12:].hex()
    if kind == "bool":
        value = _to_int(word)
        if value not in (0, 1):
            raise CheatcodeDecodeError("bool argument is not 0 or 1")
        return bool(value)
    if kind.startswith("uint"):
        bits = int(kind[4:] or 256)
        value = _to_int(word)
        if value >> bits:
            raise CheatcodeDecodeError(f"{kind} argument overflows its width")
        return value
    if kind.startswith("int"):
        bits = int(kind[3:] or 256)
        value = _to_int(word, signed=True)
        if not (-(1 << (bits - 1)) <= value < (1 << (bits - 1))):
            raise CheatcodeDecodeError(f"{kind} argument overflows its width")
        return value
    if kind.startswith("bytes") and kind != "bytes":
        size = int(kind[5:])
        if not 1 <= size <= 32 or any(word[size:]):
            raise CheatcodeDecodeError(f"{kind} argument has non-zero padding")
        return "0x" + word[:size].hex()
    raise CheatcodeDecodeError(f"unsupported static type {kind}")


def _decode_dynamic(kind: str, data: bytes, head_word: bytes) -> Any:
    offset = _to_int(head_word)
    length = _to_int(_word(data, offset))
    start = offset + 32
    if start + length > len(data):
        raise CheatcodeDecodeError("dynamic argument is truncated")
    raw = data[start : start + length]
    return raw.decode("utf-8", errors="replace") if kind == "string" else "0x" + raw.hex()


def decode_abi_arguments(types: list[str], body: bytes) -> list[Any]:
    """Decode ``body`` (calldata without selector, or log data) as the given ABI head/tail layout."""
    args: list[Any] = []
    for index, kind in enumerate(types):
        head = _word(body, 32 * index)
        if kind in ("string", "bytes"):
            args.append(_decode_dynamic(kind, body, head))
        elif kind.endswith("[]"):
            args.append(None)  # arrays are never policy-relevant; their presence is still recorded.
        else:
            args.append(_decode_static(kind, head))
    return args


def decode_cheatcode(calldata_hex: str | None) -> DecodedCheatcode:
    """Decode calldata sent to the cheatcode address."""
    text = (calldata_hex or "0x").lower()
    if not text.startswith("0x"):
        raise CheatcodeDecodeError("calldata must be 0x-prefixed hex")
    try:
        raw = bytes.fromhex(text[2:])
    except ValueError as exc:
        raise CheatcodeDecodeError("calldata is not valid hex") from exc
    if len(raw) < 4:
        return DecodedCheatcode("unknown", "0x", None, None)
    selector = "0x" + raw[:4].hex()
    entry = SELECTOR_TABLE.get(selector)
    if entry is None:
        return DecodedCheatcode(f"unknown_{selector}", selector, None, None)
    name, signature = entry
    types = _split_types(signature[signature.index("(") + 1 : -1])
    return DecodedCheatcode(name, selector, signature, tuple(decode_abi_arguments(types, raw[4:])))

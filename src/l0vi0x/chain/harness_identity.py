"""Bind a witness' declared harness identity to what the replay actually deployed.

A witness declares ``harness_address``, ``harness_create2_salt`` and ``expected_wrapper_depth``.
Declaring them is not enough: the trace must show that

1. exactly one CREATE2 frame in the setup phase created that address,
2. the address equals ``keccak(0xff ++ deployer ++ salt ++ keccak(init_code))`` recomputed here from
   the *observed* deployer and init code and the *declared* salt,
3. the harness' recorded WRAPPER (the last constructor argument in the init code) is a real address, and
4. every ``AssertionChecked`` event was emitted by that harness, at the declared depth, by that wrapper.

This is the deterministic slice of V07 that needs nothing but the structured trace. Bytecode/source
hash comparison and coverage/economics evidence remain the verifier's job.
"""
from __future__ import annotations

from dataclasses import dataclass

from l0vi0x.chain.trace import TraceSummary
from l0vi0x.chain.witness import create2_address
from l0vi0x.core.models import Witness


class HarnessIdentityError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class HarnessObservation:
    harness_address: str
    deployer: str
    wrapper: str
    assertion_event_count: int


def verify_harness_identity(trace: TraceSummary, witness: Witness) -> HarnessObservation:
    harness = witness.harness_address.lower()
    deployments = [f for f in trace.frames if f.kind == "create2" and f.phase == "setup" and (f.to or "").lower() == harness]
    if len(deployments) != 1:
        raise HarnessIdentityError(f"expected exactly one setup CREATE2 of the declared harness {harness}, saw {len(deployments)}")
    frame = deployments[0]
    if not frame.caller or not frame.data or not frame.data.startswith("0x"):
        raise HarnessIdentityError("harness CREATE2 frame lacks deployer or init code")
    try:
        init_code = bytes.fromhex(frame.data[2:])
        recomputed = create2_address(frame.caller, witness.harness_create2_salt, init_code)
    except ValueError as exc:
        raise HarnessIdentityError(f"cannot recompute harness CREATE2 address: {exc}") from exc
    if recomputed.lower() != harness:
        raise HarnessIdentityError(f"declared harness address {harness} does not match CREATE2 derivation {recomputed}")
    if len(init_code) < 32 or any(init_code[-32:][:12]):
        raise HarnessIdentityError("harness init code does not end in a wrapper address argument")
    wrapper = "0x" + init_code[-20:].hex()
    for event in trace.assertion_events:
        if str(event.get("emitter", "")).lower() != harness:
            raise HarnessIdentityError("AssertionChecked was not emitted by the fixed harness")
        if event.get("depth") != witness.expected_wrapper_depth:
            raise HarnessIdentityError(
                f"AssertionChecked depth {event.get('depth')} != declared wrapper depth {witness.expected_wrapper_depth}"
            )
        if str(event.get("caller", "")).lower() != wrapper:
            raise HarnessIdentityError("AssertionChecked caller is not the harness' recorded wrapper")
    return HarnessObservation(harness, frame.caller.lower(), wrapper, len(trace.assertion_events))

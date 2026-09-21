from __future__ import annotations

from dataclasses import dataclass, field
from l0vi0x.core.certificates import verify as verify_certificate
from l0vi0x.core.interfaces import DriverToken
from l0vi0x.core.models import HState, Hypothesis, Level, ReplayCertificate


class LadderError(ValueError):
    pass


@dataclass(frozen=True)
class LadderProof:
    axis: str
    level: int | str
    evidence: list[str] = field(default_factory=list)
    certificate: ReplayCertificate | None = None
    key: bytes | None = None
    witness_sha256: str | None = None
    env_hash: str | None = None
    observed_records_sha256: str | None = None
    trace_policy_sha256: str | None = None
    control_sha256: str | None = None
    cross_check_sha256: str | None = None
    production_cross_check: bool = False  # retained for backwards-compatible callers; certificate hash is authoritative


class Ladder:
    AXES = {"mechanism", "reachability", "execution", "economics", "production", "adjudication"}
    LEVELS = {
        "mechanism": {0, 1},
        "reachability": {0, 2, 4},
        "execution": {3, 4, 5, 6},
        "economics": {0, 5, 6, 7},
        "production": {7},
        "adjudication": {8},
    }
    REQUIRED = {
        "mechanism": {0: [], 1: ["span", "invariant"]},
        "reachability": {0: [], 2: ["entrypoint_path"], 4: ["run_receipt"]},
        "execution": {3: ["experiment"], 4: ["run_receipt"], 5: ["run_receipt", "witness_assertion"], 6: ["certificate"]},
        "economics": {0: [], 5: ["econ_harness"], 6: ["econ_harness", "certificate"], 7: ["economics_realism", "certificate"]},
        "production": {7: ["production_replay", "certificate"]},
        "adjudication": {8: ["adjudication", "human_approval"]},
    }

    @classmethod
    def required_artifacts(cls, axis: str, level: int | str) -> list[str]:
        if axis not in cls.AXES:
            raise LadderError(f"unknown axis: {axis}")
        if level == "not_applicable":
            return []
        level = int(level)
        if level not in cls.LEVELS[axis]:
            raise LadderError(f"unsupported level {level} for axis {axis}")
        return list(cls.REQUIRED[axis].get(level, []))

    @classmethod
    def _validate(
        cls,
        token: DriverToken,
        hypothesis: Hypothesis | None,
        axis: str,
        level: int | str,
        proof: LadderProof | None,
    ) -> tuple[bool, list[str]]:
        if not isinstance(token, DriverToken) or not token.is_valid():
            raise LadderError("only a valid driver token may award ladder levels")
        if axis not in cls.AXES:
            raise LadderError(f"unknown axis: {axis}")
        if level != "not_applicable":
            try:
                level = int(level)
            except (TypeError, ValueError) as exc:
                raise LadderError("level must be an integer or 'not_applicable'") from exc
            if level not in cls.LEVELS[axis]:
                raise LadderError(f"unsupported level {level} for axis {axis}")
        if proof is None or proof.axis != axis or proof.level != level:
            return False, []
        required = cls.required_artifacts(axis, level)
        if not set(required).issubset(set(proof.evidence)):
            return False, required

        if isinstance(level, int) and level >= 6:
            if proof.certificate is None or proof.key is None:
                return False, required
            for value, name in ((proof.witness_sha256, "witness_sha256"), (proof.env_hash, "env_hash"),
                                (proof.observed_records_sha256, "observed_records_sha256"),
                                (proof.trace_policy_sha256, "trace_policy_sha256"), (proof.control_sha256, "control_sha256")):
                if not value:
                    return False, required
            if not verify_certificate(
                proof.certificate, proof.key,
                witness_sha256=proof.witness_sha256, env_hash=proof.env_hash,
                observed_records_sha256=proof.observed_records_sha256,
                trace_policy_sha256=proof.trace_policy_sha256, control_sha256=proof.control_sha256,
                cross_check_sha256=proof.cross_check_sha256 if level == 7 else None,
            ):
                return False, required
            if level == 7 and not proof.cross_check_sha256:
                return False, required

        if axis == "production" and level == 7 and not proof.certificate:
            return False, required
        if axis == "adjudication" and level == 8:
            if hypothesis is not None and hypothesis.state not in {HState.FINDING, HState.CLOSED}:
                return False, required
        return True, required

    @classmethod
    def validate_award(
        cls, token: DriverToken, hypothesis: Hypothesis | None, axis: str, level: int | str, proof: LadderProof | None = None
    ) -> bool:
        ok, _ = cls._validate(token, hypothesis, axis, level, proof)
        if not ok:
            return False
        if hypothesis is None:
            return True
        current = hypothesis.ladder.get(axis)
        if level == "not_applicable":
            if current is not None and current != "not_applicable":
                raise LadderError(f"cannot mark {axis} not_applicable after a level was awarded")
            return True
        current_level = 0 if current is None else int(current)
        if current == "not_applicable":
            raise LadderError(f"{axis} is already marked not_applicable")
        if int(level) < current_level:
            raise LadderError(f"ladder is monotonic: {axis} cannot move from L{current_level} to L{int(level)}")
        return True

    @classmethod
    def award(
        cls, token: DriverToken, hypothesis: Hypothesis | None, axis: str, level: int | str, proof: LadderProof | None = None,
    ) -> bool:
        ok = cls.validate_award(token, hypothesis, axis, level, proof)
        if not ok:
            return False
        if hypothesis is not None:
            hypothesis.ladder[axis] = level if level == "not_applicable" else int(level)
        return True

import hashlib

import pytest

from conftest import make_hypothesis_kwargs
from l0vi0x.core.certificates import issue

from l0vi0x.core.ladder import Ladder, LadderError, LadderProof
from l0vi0x.driver.run import construct_driver_token, construct_human_override_token
from l0vi0x.core.models import HState, Hypothesis


def make_h(state=HState.INVESTIGATING):
    return Hypothesis(**{**make_hypothesis_kwargs(), "state": state})


def cert(key, cross=None):
    return issue(
        key, certificate_id="C-001",
        witness_sha256=hashlib.sha256(b"witness").hexdigest(), env_hash="env", runs=3,
        observed_records_sha256="records", trace_policy_sha256="trace", control_sha256="control",
        cross_check_sha256=cross,
    )


def test_plan_axes_and_levels_are_exact():
    assert Ladder.LEVELS == {
        "mechanism": {0, 1}, "reachability": {0, 2, 4}, "execution": {3, 4, 5, 6},
        "economics": {0, 5, 6, 7}, "production": {7}, "adjudication": {8},
    }
    assert Ladder.required_artifacts("production", 7) == ["production_replay", "certificate"]


def test_ladder_requires_axis_prerequisites_and_is_monotonic():
    tok = construct_driver_token("driver")
    assert Ladder.award(tok, None, "execution", 5, LadderProof("execution", 5, ["run_receipt"])) is False
    h = make_h()
    with pytest.raises(LadderError, match="axis prerequisites"):
        Ladder.award(tok, h, "execution", 4, LadderProof("execution", 4, ["run_receipt"]))
    assert Ladder.award(tok, h, "execution", 3, LadderProof("execution", 3, ["experiment"])) is True
    assert Ladder.award(tok, h, "execution", 4, LadderProof("execution", 4, ["run_receipt"])) is True
    assert h.ladder["execution"] == 4
    with pytest.raises(LadderError):
        Ladder.award(tok, h, "execution", 3, LadderProof("execution", 3, ["experiment"]))
    assert Ladder.award(tok, h, "execution", 4, LadderProof("execution", 4, ["run_receipt"])) is True


def test_l6_requires_full_certificate_binding_and_lower_execution_levels():
    key = b"k" * 32
    c = cert(key)
    h = make_h()
    tok = construct_driver_token("driver")
    assert Ladder.award(tok, h, "execution", 3, LadderProof("execution", 3, ["experiment"])) is True
    assert Ladder.award(tok, h, "execution", 4, LadderProof("execution", 4, ["run_receipt"])) is True
    assert Ladder.award(tok, h, "execution", 5, LadderProof("execution", 5, ["run_receipt", "witness_assertion"])) is True
    proof = LadderProof("execution", 6, ["certificate"], c, key, c.witness_sha256, "env", "records", "trace", "control")
    assert Ladder.award(tok, h, "execution", 6, proof) is True
    tampered = LadderProof("execution", 6, ["certificate"], c, key, c.witness_sha256, "env", "wrong-records", "trace", "control")
    assert Ladder.award(tok, make_h(), "execution", 6, tampered) is False


def test_l7_requires_cross_check_certificate_and_lower_axes():
    key = b"k" * 32
    c = cert(key, cross="cross")
    h = make_h()
    tok = construct_driver_token("driver")
    assert Ladder.award(tok, h, "execution", 3, LadderProof("execution", 3, ["experiment"])) is True
    assert Ladder.award(tok, h, "execution", 4, LadderProof("execution", 4, ["run_receipt"])) is True
    assert Ladder.award(tok, h, "execution", 5, LadderProof("execution", 5, ["run_receipt", "witness_assertion"])) is True
    assert Ladder.award(tok, h, "execution", 6, LadderProof("execution", 6, ["certificate"], cert(key), key, c.witness_sha256, "env", "records", "trace", "control")) is True
    assert Ladder.award(tok, h, "economics", 5, LadderProof("economics", 5, ["econ_harness"])) is True
    assert Ladder.award(tok, h, "economics", 6, LadderProof("economics", 6, ["econ_harness", "certificate"], c, key, c.witness_sha256, "env", "records", "trace", "control")) is True
    proof = LadderProof("production", 7, ["production_replay", "certificate"], c, key, c.witness_sha256, "env", "records", "trace", "control", "cross")
    assert Ladder.award(tok, h, "production", 7, proof) is True
    no_cross = LadderProof("production", 7, ["production_replay", "certificate"], cert(key), key, hashlib.sha256(b"witness").hexdigest(), "env", "records", "trace", "control")
    assert Ladder.award(construct_driver_token("driver"), make_h(), "production", 7, no_cross) is False


def test_not_applicable_and_driver_enforcement():
    h = make_h()
    tok = construct_driver_token("driver")
    assert Ladder.award(tok, h, "production", "not_applicable", LadderProof("production", "not_applicable", [])) is True
    assert h.ladder["production"] == "not_applicable"
    assert Ladder.award(tok, h, "production", 7, LadderProof("production", 7, ["production_replay", "certificate"])) is False
    with pytest.raises(LadderError):
        Ladder.award("driver", h, "execution", 4, LadderProof("execution", 4, ["run_receipt"]))

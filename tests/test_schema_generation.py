from pathlib import Path

from pydantic import ValidationError
import pytest

from l0vi0x.core.models import Hypothesis, ReplayCertificate, Scope, TaskRecord
from l0vi0x.core.schema_gen import check_schema_drift, generate_schemas


def test_all_plan_schemas_exist_and_are_generated_from_models(tmp_path):
    root = Path(__file__).resolve().parents[1]
    schema_dir = tmp_path / "schemas"
    written = generate_schemas(schema_dir)
    assert len(written) == 18
    assert check_schema_drift(schema_dir) == []
    assert check_schema_drift(root / "schemas") == []



def test_committed_schema_check_fails_when_a_schema_is_missing(tmp_path):
    generated = tmp_path / "schemas"
    generate_schemas(generated)
    missing = generated / "assumption.schema.json"
    missing.unlink()
    drift = check_schema_drift(generated)
    assert drift == ["assumption.schema.json"]

def test_hypothesis_plan_required_fields_do_not_silently_default():
    with pytest.raises(ValidationError):
        Hypothesis(
            id="H-1",
            claim="x",
            target={"file": "a.sol", "start": 1, "end": 1, "sha256": "x"},
            invariant_id="I-1",
            capabilities=[],
            created_at="2026-01-01T00:00:00Z",
            updated_at="2026-01-01T00:00:00Z",
        )


def test_core_models_validate():
    task = TaskRecord(id="T-1", idempotency_key="k", phase="plan", role="hunter", status="dispatched")
    cert = ReplayCertificate(id="C-1", witness_sha256="a", env_hash="b", runs=3, observed_records_sha256="c", trace_policy_sha256="d", control_sha256="e", mac="f", issued_at="2026-01-01T00:00:00Z")
    scope = Scope(version=1, platform="test", program_ref="p", commit="abc", in_scope=[], out_of_scope=[], excluded_classes=[], deployed=False, attacker_capital_wei=0, poc_required=True, severity_model_ref="s")
    assert task.id == "T-1" and cert.runs == 3 and scope.version == 1

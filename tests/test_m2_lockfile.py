from __future__ import annotations

from datetime import datetime, timezone

import pytest

from l0vi0x.core.models import ModelProfile
from l0vi0x.models.adapters.fake import FakeAdapter
from l0vi0x.models.doctor import probe_model
from l0vi0x.models.lockfile import (
    build_lock,
    check_lockfile_drift,
    load_profiles,
    profiles_from_probe_results,
    write_lockfile,
)

TERMS = "2026-01-01"
PRICING = "2026-01-01"
FIXED_NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _profile(**overrides) -> ModelProfile:
    fields = dict(
        provider="fake",
        model_id="fake-large-1",
        family="fake-large",
        roles=["worker", "skeptic"],
        context_window=128_000,
        capabilities={"structured_output": True, "tool_use": False},
        pricing_tier="free",
        terms_version=TERMS,
        terms_observed_at=FIXED_NOW,
        pricing_version=PRICING,
        pricing_observed_at=FIXED_NOW,
    )
    fields.update(overrides)
    return ModelProfile(**fields)


# --- write / read round trip --------------------------------------------


def test_write_lockfile_and_load_profiles_round_trips(tmp_path):
    profile = _profile()
    lock_path = tmp_path / "models.lock.yaml"
    lock = write_lockfile(lock_path, [profile], generated_at=FIXED_NOW)

    assert lock["version"] == 1
    assert lock["status"] == "verified"
    assert "fake/fake-large-1" in lock["models"]

    loaded = load_profiles(lock_path)
    assert set(loaded) == {"fake/fake-large-1"}
    assert loaded["fake/fake-large-1"] == profile


def test_build_lock_rejects_duplicate_provider_model_id():
    with pytest.raises(ValueError, match="duplicate"):
        build_lock([_profile(), _profile()], generated_at=FIXED_NOW)


def test_load_profiles_on_missing_file_returns_empty():
    assert load_profiles("/nonexistent/models.lock.yaml") == {}


# --- determinism: the M2.3 stop condition --------------------------------


@pytest.mark.asyncio
async def test_two_doctor_runs_against_fake_produce_byte_identical_lockfile(tmp_path):
    """The literal stop condition: running doctor against `fake` twice,
    with nothing about the underlying config changed, must produce a
    stable, byte-identical lockfile -- no nondeterminism (dict ordering,
    wall-clock stamps, run-specific IDs) leaking into the artifact."""

    def make_adapters():
        return [FakeAdapter(provider="fake", model_id="fake-large-1", family="fake-large"),
                FakeAdapter(provider="fake", model_id="fake-small-1", family="fake-small")]

    async def run_once(path):
        results = [await probe_model(a, terms_version=TERMS, pricing_version=PRICING, now=FIXED_NOW) for a in make_adapters()]
        profiles = profiles_from_probe_results(results)
        write_lockfile(path, profiles, generated_at=FIXED_NOW)
        return path.read_bytes()

    first = await run_once(tmp_path / "run1.lock.yaml")
    second = await run_once(tmp_path / "run2.lock.yaml")
    assert first == second


@pytest.mark.asyncio
async def test_lockfile_changes_when_underlying_config_changes(tmp_path):
    """The other half of the same claim: it's *stable*, not *frozen* --
    an actual capability/config change must show up in the bytes."""
    a1 = FakeAdapter(provider="fake", model_id="fake-large-1", family="fake-large")
    r1 = await probe_model(a1, terms_version=TERMS, pricing_version=PRICING, now=FIXED_NOW)
    path1 = tmp_path / "a.lock.yaml"
    write_lockfile(path1, profiles_from_probe_results([r1]), generated_at=FIXED_NOW)

    a2 = FakeAdapter(provider="fake", model_id="fake-large-1", family="fake-large", context_window=8_000)
    r2 = await probe_model(a2, terms_version=TERMS, pricing_version=PRICING, now=FIXED_NOW)
    path2 = tmp_path / "b.lock.yaml"
    write_lockfile(path2, profiles_from_probe_results([r2]), generated_at=FIXED_NOW)

    assert path1.read_bytes() != path2.read_bytes()


# --- profiles_from_probe_results ------------------------------------------


@pytest.mark.asyncio
async def test_profiles_from_probe_results_skips_failed_probes():
    ok_adapter = FakeAdapter(provider="fake", model_id="fake-ok")
    failed_adapter = FakeAdapter(provider="fake", model_id="fake-down", fail_mode="timeout")
    results = [
        await probe_model(ok_adapter, terms_version=TERMS, pricing_version=PRICING, now=FIXED_NOW),
        await probe_model(failed_adapter, terms_version=TERMS, pricing_version=PRICING, now=FIXED_NOW),
    ]
    profiles = profiles_from_probe_results(results)
    assert [p.model_id for p in profiles] == ["fake-ok"]


# --- drift detection -------------------------------------------------------


def test_check_lockfile_drift_clean_when_nothing_changed(tmp_path):
    profile = _profile()
    path = tmp_path / "models.lock.yaml"
    write_lockfile(path, [profile], generated_at=FIXED_NOW)
    assert check_lockfile_drift(path, [profile]) == []


def test_check_lockfile_drift_ignores_observed_at_timestamp_changes(tmp_path):
    """A fresh probe always has a new terms_observed_at/pricing_observed_at
    by construction; that alone must never be reported as drift, or every
    real doctor run would falsely flag every model."""
    path = tmp_path / "models.lock.yaml"
    write_lockfile(path, [_profile()], generated_at=FIXED_NOW)

    later = datetime(2026, 6, 1, tzinfo=timezone.utc)
    refreshed = _profile(terms_observed_at=later, pricing_observed_at=later)
    assert check_lockfile_drift(path, [refreshed]) == []


def test_check_lockfile_drift_detects_capability_change(tmp_path):
    path = tmp_path / "models.lock.yaml"
    write_lockfile(path, [_profile()], generated_at=FIXED_NOW)

    changed = _profile(capabilities={"structured_output": False, "tool_use": False})
    problems = check_lockfile_drift(path, [changed])
    assert any("capabilities changed" in p for p in problems)


def test_check_lockfile_drift_detects_missing_and_new_models(tmp_path):
    path = tmp_path / "models.lock.yaml"
    write_lockfile(path, [_profile(model_id="fake-a")], generated_at=FIXED_NOW)

    problems = check_lockfile_drift(path, [_profile(model_id="fake-b")])
    assert any("fake-a" in p and "not in current" in p for p in problems)
    assert any("fake-b" in p and "not locked" in p for p in problems)

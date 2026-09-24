"""M2.3 -- models.lock.yaml generation.

"Native probes write models.lock.yaml" is a literal acceptance clause,
and the intent is the same as `config/tools.lock.yaml` already serves
for Foundry/forge (`l0vi0x.tools.lock.update_lock` /
`verify_binary_lock`, exercised by `make tools-verify`): the lockfile is
the auditable artifact, not a cache. This module mirrors that pattern
deliberately -- same `{version, status, generated_at, <entries>}` top-
level shape, same `yaml.safe_dump(..., sort_keys=False)` write style,
same "return a list of problem strings, empty means clean" convention
for the drift checker -- rather than inventing a second lockfile idiom
alongside the one this codebase already has.

One real difference from `tools.lock.yaml`: `build_lock()` here takes
no wall-clock access at all (`generated_at` is a required parameter,
not stamped internally). `update_lock()` can get away with stamping its
own timestamp because nothing downstream diffs `tools.lock.yaml`
byte-for-byte; `models.lock.yaml` does need to be reproducible given
identical probe output (M2.3's own stop condition), so the impure part
(what time is it right now) stays at the caller -- `doctor --profile
free` (M2.12) passes real wall-clock time; a determinism test passes a
fixed one twice.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

from l0vi0x.core.models import ModelProfile

if TYPE_CHECKING:
    from l0vi0x.models.doctor import ProbeResult

LOCK_VERSION = 1

# Fields compared for drift. Deliberately excludes terms_observed_at and
# pricing_observed_at: those are observation timestamps that differ on
# every real probe by construction (like tools.lock.yaml's own
# `generated_at`, which verify_binary_lock never compares either) and
# are not themselves a capability/config change worth flagging.
_DRIFT_FIELDS = (
    "family",
    "roles",
    "context_window",
    "capabilities",
    "pricing_tier",
    "terms_version",
    "pricing_version",
    "deprecated",
)


def _model_key(profile: ModelProfile) -> str:
    return f"{profile.provider}/{profile.model_id}"


def profiles_from_probe_results(results: list["ProbeResult"]) -> list[ModelProfile]:
    """Doctor's battery includes models that failed to probe at all
    (`profile is None`, see doctor.py) -- those have nothing to lock, so
    this is the one place that boundary is enforced: a lockfile only
    ever contains models doctor actually got a profile for."""
    return [r.profile for r in results if r.profile is not None]


def build_lock(profiles: list[ModelProfile], *, generated_at: datetime) -> dict[str, Any]:
    """Pure function from probe output to the lock's dict shape -- no I/O.
    Raises ValueError on a duplicate (provider, model_id) pair rather than
    silently letting the later one clobber the earlier one in the dict."""
    ordered = sorted(profiles, key=_model_key)
    keys = [_model_key(p) for p in ordered]
    duplicates = sorted({k for k in keys if keys.count(k) > 1})
    if duplicates:
        raise ValueError(f"duplicate provider/model_id in profiles: {', '.join(duplicates)}")
    return {
        "version": LOCK_VERSION,
        "status": "verified",
        "generated_at": generated_at.isoformat().replace("+00:00", "Z"),
        "models": {_model_key(p): p.model_dump(mode="json") for p in ordered},
    }


def write_lockfile(path: str | Path, profiles: list[ModelProfile], *, generated_at: datetime) -> dict[str, Any]:
    lock = build_lock(profiles, generated_at=generated_at)
    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(yaml.safe_dump(lock, sort_keys=False), encoding="utf-8")
    return lock


def read_lock(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    if not p.exists():
        return {}
    return yaml.safe_load(p.read_text(encoding="utf-8")) or {}


def load_profiles(path: str | Path) -> dict[str, ModelProfile]:
    lock = read_lock(path)
    models = lock.get("models") or {}
    return {key: ModelProfile.model_validate(entry) for key, entry in models.items()}


def check_lockfile_drift(path: str | Path, current_profiles: list[ModelProfile]) -> list[str]:
    """verify_binary_lock-style checker: given a lockfile and current probe
    results, report drift as a list of problem strings -- empty means
    clean, mirroring `l0vi0x.tools.lock.verify_binary_lock`'s own return
    convention so callers (and `make`-style targets) can treat the two
    identically."""
    locked = load_profiles(path)
    current = {_model_key(p): p for p in current_profiles}

    problems: list[str] = []
    for key in sorted(set(locked) - set(current)):
        problems.append(f"{key}: present in lock but not in current probe results")
    for key in sorted(set(current) - set(locked)):
        problems.append(f"{key}: present in current probe results but not locked")

    for key in sorted(set(locked) & set(current)):
        old, new = locked[key], current[key]
        for field_name in _DRIFT_FIELDS:
            old_val, new_val = getattr(old, field_name), getattr(new, field_name)
            if old_val != new_val:
                problems.append(f"{key}: {field_name} changed ({old_val!r} -> {new_val!r})")
    return problems

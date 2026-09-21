from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


class PolicyViolation(ValueError):
    pass


class CheatcodePolicy:
    def __init__(self, categories_file: str | Path, policy_file: str | Path):
        self.categories = yaml.safe_load(Path(categories_file).read_text(encoding="utf-8")) or {}
        self.policy = yaml.safe_load(Path(policy_file).read_text(encoding="utf-8")) or {}
        self._categories = self.categories.get("categories", {})
        self._rules = self.policy.get("rules", {})

    def category(self, cheatcode: str) -> str:
        category = self._categories.get(cheatcode)
        if category is None:
            raise PolicyViolation(f"unclassified cheatcode is forbidden: {cheatcode}")
        return str(category)

    def allowed(self, cheatcode: str, *, witness_class: str, phase: str) -> bool:
        category = self.category(cheatcode)
        witness_rules = self._rules.get(witness_class, {})
        phase_rules = witness_rules.get(phase, witness_rules.get("default", {}))
        allowed_categories = set(phase_rules.get("allow_categories", []))
        return category in allowed_categories

    def check(self, cheatcode: str, *, witness_class: str, phase: str) -> None:
        if not self.allowed(cheatcode, witness_class=witness_class, phase=phase):
            raise PolicyViolation(f"cheatcode denied: {cheatcode} ({witness_class}/{phase})")

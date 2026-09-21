from __future__ import annotations


class Budget:
    def __init__(self, phase_caps: dict[str, float] | None = None, reserve: float = 0.0):
        self.phase_caps = dict(phase_caps or {})
        self.reserve = float(reserve)
        self._used = {name: 0.0 for name in self.phase_caps}

    def charge(self, phase: str, amount: float) -> bool:
        cap = self.phase_caps.get(phase, float("inf"))
        new_total = self._used.get(phase, 0.0) + float(amount)
        if new_total <= cap:
            self._used[phase] = new_total
            return True
        return False

    def remaining(self, phase: str) -> float:
        cap = self.phase_caps.get(phase, float("inf"))
        return max(0.0, cap - self._used.get(phase, 0.0))

    def reserve_remaining(self) -> float:
        return self.reserve

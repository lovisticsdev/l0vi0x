from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from l0vi0x.core.store import Store


@dataclass
class AuditCounter:
    prefix: str
    start: int = 1

    def __post_init__(self) -> None:
        if not self.prefix or not self.prefix.isalnum():
            raise ValueError("prefix must be non-empty and alphanumeric")
        if self.start < 1:
            raise ValueError("start must be >= 1")
        self.value = self.start

    def next(self) -> str:
        current = self.value
        self.value += 1
        return f"{self.prefix}-{current:03d}"


def next_id(prefix: str, counter: AuditCounter | None = None, store: "Store | None" = None) -> str:
    if store is not None:
        return store.next_id(prefix)
    if counter is None:
        raise ValueError("next_id requires an AuditCounter or DB-backed Store")
    return counter.next()

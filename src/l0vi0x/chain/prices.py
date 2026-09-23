from __future__ import annotations

from dataclasses import dataclass
from math import isfinite
from typing import Mapping


@dataclass(frozen=True, slots=True)
class PricePoint:
    asset: str
    usd_per_unit: float
    decimals: int
    source: str
    block: int | None = None
    observed_at: str | None = None

    def __post_init__(self) -> None:
        if self.decimals < 0 or self.decimals > 255:
            raise ValueError("asset decimals must be in [0,255]")
        if self.usd_per_unit < 0 or not isfinite(self.usd_per_unit):
            raise ValueError("price must be finite and non-negative")
        if not self.source.strip():
            raise ValueError("price source is required")


def usd_value(amount: int, price: PricePoint) -> float:
    if amount < 0:
        raise ValueError("amount must be non-negative")
    return (int(amount) / 10 ** price.decimals) * price.usd_per_unit


def signed_usd_delta(delta: int, price: PricePoint) -> float:
    sign = -1.0 if delta < 0 else 1.0
    return sign * usd_value(abs(int(delta)), price)


def sensitivity_values(base_value: float, *, bps: tuple[int, ...] = (-500, 0, 500)) -> dict[str, float]:
    if not isfinite(base_value):
        raise ValueError("base value must be finite")
    result = {}
    for delta_bps in bps:
        multiplier = 1.0 + delta_bps / 10_000.0
        label = "base" if delta_bps == 0 else (f"minus_{abs(delta_bps)}bps" if delta_bps < 0 else f"plus_{delta_bps}bps")
        result[label] = base_value * multiplier
    return result


def validate_price_set(prices: Mapping[str, PricePoint], required_assets: Mapping[str, int]) -> None:
    missing = sorted(asset.lower() for asset in required_assets if asset.lower() not in {k.lower() for k in prices})
    if missing:
        raise ValueError("missing prices: " + ", ".join(missing))

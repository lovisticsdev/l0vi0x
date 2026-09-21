from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping


@dataclass(frozen=True, slots=True)
class EconomicInputs:
    native_before_wei: int
    native_after_wei: int
    token_before: Mapping[str, int] = field(default_factory=dict)
    token_after: Mapping[str, int] = field(default_factory=dict)
    token_prices_usd: Mapping[str, float] = field(default_factory=dict)
    native_price_usd: float | None = None
    gas_used: int = 0
    gas_price_wei: int = 0
    declared_capital_wei: int = 0
    observed_capital_wei: int | None = None
    pinned_block: int | None = None


@dataclass(frozen=True, slots=True)
class EconomicReport:
    native_delta_wei: int
    token_deltas: dict[str, int]
    attacker_net_usd: float | None
    gas_cost_native_wei: int
    gas_cost_usd: float | None
    capital_required_wei: int
    realism_flags: tuple[str, ...]
    price_sources: tuple[str, ...] = ()


def measure(inputs: EconomicInputs) -> EconomicReport:
    if inputs.gas_used < 0 or inputs.gas_price_wei < 0:
        raise ValueError("gas measurements must be non-negative")
    if inputs.declared_capital_wei < 0:
        raise ValueError("declared capital must be non-negative")
    native_delta = inputs.native_after_wei - inputs.native_before_wei
    token_keys = set(inputs.token_before) | set(inputs.token_after)
    deltas = {k.lower(): int(inputs.token_after.get(k, 0) - inputs.token_before.get(k, 0)) for k in token_keys}
    capital_required = inputs.observed_capital_wei if inputs.observed_capital_wei is not None else inputs.declared_capital_wei
    flags: list[str] = []
    if capital_required > inputs.declared_capital_wei:
        flags.append("declared_capital_understates_observed_capital")
    gas_cost_wei = inputs.gas_used * inputs.gas_price_wei
    native_price = inputs.native_price_usd
    gas_usd = gas_cost_wei * native_price / 10**18 if native_price is not None else None
    net_usd: float | None = None
    if native_price is not None:
        net_usd = native_delta * native_price / 10**18
        for token, delta in deltas.items():
            price = inputs.token_prices_usd.get(token, inputs.token_prices_usd.get(token.lower()))
            if price is None:
                flags.append(f"price_unavailable:{token}")
            else:
                net_usd += delta * price / 1e18
    else:
        flags.append("native_price_unavailable")
    return EconomicReport(
        native_delta_wei=native_delta,
        token_deltas=deltas,
        attacker_net_usd=net_usd,
        gas_cost_native_wei=gas_cost_wei,
        gas_cost_usd=gas_usd,
        capital_required_wei=capital_required,
        realism_flags=tuple(flags),
        price_sources=tuple(sorted(inputs.token_prices_usd)),
    )

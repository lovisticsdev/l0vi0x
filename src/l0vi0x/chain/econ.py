from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Mapping

from l0vi0x.chain.prices import PricePoint, signed_usd_delta


@dataclass(frozen=True, slots=True)
class EconomicInputs:
    native_before_wei: int
    native_after_wei: int
    token_before: Mapping[str, int] = field(default_factory=dict)
    token_after: Mapping[str, int] = field(default_factory=dict)
    token_decimals: Mapping[str, int] = field(default_factory=dict)
    prices: Mapping[str, PricePoint] = field(default_factory=dict)
    gas_used: int = 0
    gas_price_wei: int = 0
    declared_capital_wei: int = 0
    observed_capital_wei: int | None = None
    native_price: PricePoint | None = None
    pinned_block: int | None = None
    protocol_assets_delta_wei: int | None = None


@dataclass(frozen=True, slots=True)
class EconomicReport:
    native_delta_wei: int
    token_deltas: dict[str, int]
    attacker_gross_usd: float | None
    gas_cost_native_wei: int
    gas_cost_usd: float | None
    attacker_net_usd: float | None
    capital_required_wei: int
    protocol_assets_delta_wei: int | None
    sensitivity: dict[str, float]
    sensitivity_scenarios: dict[str, dict[str, object]]
    realism_flags: tuple[str, ...]
    price_sources: tuple[str, ...] = ()


def _measure_base(inputs: EconomicInputs) -> EconomicReport:
    if inputs.gas_used < 0 or inputs.gas_price_wei < 0:
        raise ValueError("gas measurements must be non-negative")
    if inputs.declared_capital_wei < 0:
        raise ValueError("declared capital must be non-negative")
    native_delta = int(inputs.native_after_wei) - int(inputs.native_before_wei)
    token_keys = set(inputs.token_before) | set(inputs.token_after)
    deltas = {k.lower(): int(inputs.token_after.get(k, 0) - inputs.token_before.get(k, 0)) for k in token_keys}
    capital_required = int(inputs.observed_capital_wei if inputs.observed_capital_wei is not None else inputs.declared_capital_wei)
    flags: list[str] = []
    if capital_required > inputs.declared_capital_wei:
        flags.append("declared_capital_understates_observed_capital")
    gas_cost_wei = int(inputs.gas_used) * int(inputs.gas_price_wei)
    gas_usd = signed_usd_delta(gas_cost_wei, inputs.native_price) if inputs.native_price else None
    gross_usd: float | None = None
    if inputs.native_price is not None:
        gross_usd = signed_usd_delta(native_delta, inputs.native_price)
    elif native_delta != 0:
        flags.append("native_price_unavailable")
    price_sources: set[str] = set()
    for asset, delta in deltas.items():
        price = next((p for key, p in inputs.prices.items() if key.lower() == asset), None)
        declared_decimals = inputs.token_decimals.get(asset)
        if price is not None and declared_decimals is not None and int(price.decimals) != int(declared_decimals):
            raise ValueError(f"price decimals for {asset} do not match declared token decimals")
        if price is None:
            if delta:
                flags.append(f"price_unavailable:{asset}")
            continue
        gross_usd = (gross_usd or 0.0) + signed_usd_delta(delta, price)
        price_sources.add(price.source)
    if inputs.native_price is not None:
        price_sources.add(inputs.native_price.source)
    net_usd = None if gross_usd is None else gross_usd - (gas_usd or 0.0)
    return EconomicReport(
        native_delta_wei=native_delta,
        token_deltas=deltas,
        attacker_gross_usd=gross_usd,
        gas_cost_native_wei=gas_cost_wei,
        gas_cost_usd=gas_usd,
        attacker_net_usd=net_usd,
        capital_required_wei=capital_required,
        protocol_assets_delta_wei=inputs.protocol_assets_delta_wei,
        sensitivity={},
        sensitivity_scenarios={},
        realism_flags=tuple(flags),
        price_sources=tuple(sorted(price_sources)),
    )


def measure(inputs: EconomicInputs, *, sensitivity_bps: tuple[int, ...] = (-500, 0, 500)) -> EconomicReport:
    """Measure base economics and independently recompute price-valuation scenarios.

    The scenarios are derived from the retained raw balance/gas observations and
    perturbed price inputs. They do not scale a previously computed net result.
    """
    if tuple(sorted(set(sensitivity_bps))) != (-500, 0, 500):
        raise ValueError("M1b economics requires exactly -500, 0, +500 bps sensitivity scenarios")
    base = _measure_base(inputs)
    sensitivity: dict[str, float] = {}
    scenarios: dict[str, dict[str, object]] = {}
    if base.attacker_net_usd is not None:
        labels = {-500: "minus_500bps", 0: "base", 500: "plus_500bps"}
        for bps in sensitivity_bps:
            factor = 1.0 + (bps / 10_000.0)
            native_price = None if inputs.native_price is None else replace(inputs.native_price, usd_per_unit=inputs.native_price.usd_per_unit * factor)
            prices = {
                key: replace(price, usd_per_unit=price.usd_per_unit * factor)
                for key, price in inputs.prices.items()
            }
            scenario_inputs = replace(inputs, native_price=native_price, prices=prices)
            scenario = _measure_base(scenario_inputs)
            if scenario.attacker_net_usd is None:
                raise ValueError(f"sensitivity scenario {bps} bps lacks a reproducible USD result")
            label = labels[bps]
            sensitivity[label] = float(scenario.attacker_net_usd)
            scenarios[label] = {
                "bps": bps,
                "price_multiplier": factor,
                "net_usd": float(scenario.attacker_net_usd),
                "native_price_usd_per_unit": None if native_price is None else float(native_price.usd_per_unit),
                "token_prices_usd_per_unit": {k.lower(): float(v.usd_per_unit) for k, v in prices.items()},
            }
    return replace(base, sensitivity=sensitivity, sensitivity_scenarios=scenarios)

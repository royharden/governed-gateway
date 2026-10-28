"""Forecasts and conservative liability quotes are different quantities."""
from __future__ import annotations

from gateway.schemas import digest, money_from_micros, usd_micros
from gateway.schemas.operator import AcquisitionQuote, QuoteRequest


def quote_acquisition(request: QuoteRequest) -> AcquisitionQuote:
    reasons = {reason for item in request.components for reason in item.incomplete_reasons}
    expected_values = []
    maximum_values = []
    per_tranche = {item.tranche_id: [] for item in request.tranches}
    # Inputs are already rounded upward to canonical micro-USD; integer products/sums are exact.
    for item in request.components:
        expected = (None if item.expected_cost_per_execution_usd is None else
                    usd_micros(item.expected_cost_per_execution_usd) * item.execution_count)
        maximum = (None if item.maximum_liability_per_execution_usd is None else
                   usd_micros(item.maximum_liability_per_execution_usd) * item.execution_count)
        if expected is None:
            reasons.add("missing_price")
        if maximum is None:
            reasons.add("missing_bound")
        expected_values.append(expected)
        maximum_values.append(maximum)
        per_tranche[item.tranche_id].append(maximum)

    def complete_units(values):
        return None if any(value is None for value in values) else sum(values)

    expected_units = complete_units(expected_values)
    maximum_units = complete_units(maximum_values)
    ceiling_units = complete_units([None if item.ceiling_usd is None else usd_micros(item.ceiling_usd)
                                   for item in request.tranches])
    if ceiling_units is None:
        reasons.add("insufficient_budget")
    for tranche in request.tranches:
        exposure = complete_units(per_tranche[tranche.tranche_id])
        if exposure is not None and tranche.ceiling_usd is not None and exposure > usd_micros(tranche.ceiling_usd):
            reasons.add("insufficient_budget")
    expected_total = None if expected_units is None else money_from_micros(expected_units)
    maximum_total = None if maximum_units is None else money_from_micros(maximum_units)
    ceilings = None if ceiling_units is None else money_from_micros(ceiling_units)

    # Counts are separate from prices: a cheap or empty plan cannot masquerade as acceptance coverage.
    by_category = {}
    for item in request.components:
        by_category[item.category] = by_category.get(item.category, 0) + item.execution_count
    if request.planned_task_count < 120 or by_category.get("heldout_generation", 0) < request.planned_task_count * 2:
        reasons.add("missing_observation")
    if by_category.get("smoke", 0) < 20:
        reasons.add("missing_observation")
    route_counts = {}
    smoke_counts = {}
    for item in request.components:
        if item.category == "heldout_generation":
            route_counts[item.target_id] = route_counts.get(item.target_id, 0) + item.execution_count
        elif item.category == "smoke":
            smoke_counts[item.target_id] = smoke_counts.get(item.target_id, 0) + item.execution_count
    if (len(route_counts) != 2 or any(count < request.planned_task_count for count in route_counts.values())
            or set(smoke_counts) != set(route_counts)
            or any(count < 10 for count in smoke_counts.values())):
        reasons.add("missing_observation")
    # External mode is disabled in this construction. A quote is never spending permission.
    if request.mode != "simulation":
        reasons.add("external_disabled")
    return AcquisitionQuote(
        quote_id=request.quote_id, request_sha256=digest(request), mode=request.mode,
        components=request.components, tranches=request.tranches,
        expected_total_usd=expected_total, maximum_reserved_total_usd=maximum_total,
        aggregate_authorized_ceiling_usd=ceilings,
        unknown_liability_sensitivity_usd=maximum_total,
        complete=not reasons, incomplete_reasons=tuple(sorted(reasons)), created_utc=request.observed_utc)

"""Pure body-free S3 projections. No alternate ledger or boundary schemas."""
from decimal import Decimal, localcontext
from collections.abc import Mapping, Sequence
from gateway.schemas import (
    AccountingTotals, ErrorCode, IncidentSnapshot, LedgerJoin, SettlementReceipt,
)
from gateway.shared.s3.callledger.models import canonical_digest
from .errors import AccountingError


def amount(value: str | Decimal) -> Decimal:
    try:
        result = Decimal(value)
        if not result.is_finite() or result < 0:
            raise ValueError
        # Shared micro-USD records cannot represent finer actual costs faithfully.
        # Reject instead of silently clamping or rounding an actual charge.
        if result.as_tuple().exponent < -6:
            if result != result.quantize(Decimal("0.000001")):
                raise ValueError
            result = result.quantize(Decimal("0.000001"))
        return result
    except (ValueError, ArithmeticError):
        raise AccountingError(ErrorCode.INVALID_EVIDENCE) from None


def settlement_projection(*, authority_id: str, row: Mapping,
                          already_settled: bool) -> SettlementReceipt:
    if row["state"] not in ("known", "unknown") or not row["settlement_sha"]:
        raise AccountingError(ErrorCode.INVALID_TRANSITION)
    with localcontext() as context:
        context.prec = 150
        reserved = amount(row["reservation"])
        known = amount(row["cost"]) if row["state"] == "known" else None
        return SettlementReceipt(
            authority_id=authority_id, operation_id=row["operation_id"],
            child_id=row["child_id"], attempt_id=row["id"],
            settlement_sha256=row["settlement_sha"], state=row["state"],
            reserved_usd=reserved, known_usage_cost_usd=known,
            terminal_unknown_usd=reserved if known is None else Decimal(0),
            released_usd=max(reserved-known, Decimal(0)) if known is not None else Decimal(0),
            excess_usd=max(known-reserved, Decimal(0)) if known is not None else Decimal(0),
            already_settled=already_settled,
        )


def totals_projection(*, authority_id: str, cap_usd: Decimal,
                      children: Sequence[Mapping], attempts: Sequence[Mapping],
                      incident: IncidentSnapshot, ledger_halted: bool) -> AccountingTotals:
    if incident.authority_id != authority_id:
        raise AccountingError(ErrorCode.AUTHORITY_MISMATCH)
    with localcontext() as context:
        context.prec = 150
        reserved = future = active = released = known = unknown = excess = Decimal(0)
        by_child = {}
        for attempt in attempts:
            key = (attempt["operation_id"], attempt["child_id"])
            if key in by_child:
                # M8 adopts only one attempt per separately funded child.
                raise AccountingError(ErrorCode.INVALID_EVIDENCE)
            by_child[key] = attempt
        for child in children:
            bound = amount(child["reserved_usd_per_attempt"])
            if child["max_attempts"] != 1 or child["remaining"] not in (0, 1):
                raise AccountingError(ErrorCode.INVALID_EVIDENCE)
            reserved += bound
            row = by_child.pop((child["operation_id"], child["child_id"]), None)
            if row is None:
                if child["remaining"] == 1 and child["state"] == "pending":
                    future += bound
                elif child["remaining"] == 0 and child["state"] in ("skipped", "cancelled_before_dispatch"):
                    released += bound
                else:
                    raise AccountingError(ErrorCode.INVALID_EVIDENCE)
            else:
                if child["remaining"] != 0 or amount(row["reservation"]) != bound:
                    raise AccountingError(ErrorCode.INVALID_EVIDENCE)
                if row["state"] == "active":
                    active += bound
                elif row["state"] == "unknown":
                    unknown += bound
                elif row["state"] == "known":
                    cost = amount(row["cost"])
                    known += cost
                    released += max(bound-cost, Decimal(0))
                    excess += max(cost-bound, Decimal(0))
                else:
                    raise AccountingError(ErrorCode.INVALID_EVIDENCE)
        if by_child:
            raise AccountingError(ErrorCode.INVALID_EVIDENCE)
        # D is the governance journal's sum of per-attempt uncovered maxima,
        # never max(sum(late)-sum(U), 0), which hides an individual excess.
        uncovered = incident.uncovered_excess_usd
        return AccountingTotals(
            authority_id=authority_id, cap_usd=cap_usd, reserved_usd=reserved,
            future_usd=future, active_usd=active, released_usd=released,
            known_usd=known, unknown_usd=unknown, excess_usd=excess,
            uncovered_excess_usd=uncovered,
            exposure_usd=known+future+active+unknown+uncovered,
            halted=ledger_halted or incident.halted or excess > 0 or uncovered > 0 or incident.conflict,
            conflict=incident.conflict,
        )
"""Real SQLite transactions/reopen. No controller conformance is inferred."""
from decimal import Decimal

import pytest

from gateway.shared.s3.callledger import LedgerError
from ledger_support import configuration, inputs, open_ledger, settle


def test_whole_attempt_graph_funded_atomically(artifact_dir):
    config = configuration(cap="0.10")
    context, plan, request = inputs(config, children=2)
    ledger = open_ledger(artifact_dir / "m8-ledger.sqlite3", config)
    try:
        with pytest.raises(LedgerError, match="budget_rejected"):
            ledger.admit_operation(plan, context=context, limits=config.limits, mode="simulation")
        total = ledger.totals()
        assert Decimal(total["total_exposure_usd"]) == 0
        assert total["dispatched_attempts"] == 0
    finally:
        ledger.close()


@pytest.mark.parametrize("outcome", ["known", "unknown", "above-bound"])
def test_claim_settlement_reopen_and_no_second_claim(artifact_dir, outcome):
    config = configuration()
    context, plan, request = inputs(config)
    database = artifact_dir / "m8-ledger.sqlite3"
    ledger = open_ledger(database, config, (request,))
    allocation = ledger.admit_operation(plan, context=context, limits=config.limits, mode="simulation")
    attempt = ledger.begin_attempt(allocation, context=context, request=request)
    before = ledger.totals()
    assert before["dispatched_attempts"] == 1
    assert Decimal(before["future_holds_usd"]) == 0
    assert Decimal(before["active_holds_usd"]) > 0
    with pytest.raises(LedgerError, match="attempt_limit"):
        ledger.begin_attempt(allocation, context=context, request=request)
    if outcome == "unknown":
        first = ledger.mark_unknown(attempt)
        assert ledger.mark_unknown(attempt) == first
    else:
        output = 100_000 if outcome == "above-bound" else 4
        first = settle(ledger, attempt, context, output_tokens=output)
        assert settle(ledger, attempt, context, output_tokens=output) == first
        with pytest.raises(LedgerError, match="settlement_conflict"):
            settle(ledger, attempt, context, output_tokens=output+1)
    total = ledger.totals()
    ledger.close()
    reopened = open_ledger(database, config, (request,))
    try:
        assert reopened.totals() == total
        if outcome == "unknown":
            assert Decimal(total["unknown_liability_usd"]) == plan.declared_worst_case_usd
        elif outcome == "above-bound":
            assert total["halted"]
            assert Decimal(total["known_spend_usd"]) == Decimal("0.200008")
        else:
            assert Decimal(total["known_spend_usd"]) == Decimal("0.000016")
        with pytest.raises(LedgerError):
            reopened.begin_attempt(allocation, context=context, request=request)
    finally:
        reopened.close()


def test_authority_cannot_reset_cap_on_reopen(artifact_dir):
    config = configuration()
    path = artifact_dir / "m8-ledger.sqlite3"
    ledger = open_ledger(path, config)
    ledger.close()
    from dataclasses import replace
    altered = replace(config, authority=config.authority.model_copy(update={"cap_usd": "2"}))
    with pytest.raises(LedgerError):
        ledger = open_ledger(path, altered)


def test_synthetic_evidence_cannot_fund_external_mode(artifact_dir):
    config = configuration()
    context, plan, request = inputs(config)
    ledger = open_ledger(artifact_dir / "m8-ledger.sqlite3", config)
    try:
        with pytest.raises(LedgerError, match="synthetic_not_live_proof"):
            ledger.admit_operation(plan, context=context, limits=config.limits, mode="external")
        assert ledger.totals()["dispatched_attempts"] == 0
    finally:
        ledger.close()


def test_non_decreasing_coarse_wall_clock_does_not_false_rollback(artifact_dir):
    """Regression: an unchanged coarse wall tick is not clock rollback.

    An advancing monotonic clock must tighten elapsed time without causing the
    ledger to reject a subsequent admission just because wall resolution lags.
    """
    from datetime import datetime, timedelta
    config = configuration()
    wall = datetime.fromisoformat(config.authority.run_deadline_utc.replace("Z", "+00:00")) - timedelta(hours=2)
    ticks = iter([0.0, 0.001, 0.002, 0.003, 0.004, 0.005, 0.006])
    ledger = open_ledger(artifact_dir / "m8-coarse-clock.sqlite3", config, clock=lambda: wall, monotonic=lambda: next(ticks))
    try:
        context, plan, request = inputs(config, operation="first")
        ledger.admit_operation(plan, context=context, limits=config.limits, mode="simulation")
        context, plan, request = inputs(config, operation="second")
        ledger.admit_operation(plan, context=context, limits=config.limits, mode="simulation")
    finally:
        ledger.close()

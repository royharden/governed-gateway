"""DEC-057 hand examples and mutation controls; projections, not ledger conformance."""
from dataclasses import replace
from decimal import Decimal, localcontext

import pytest

from gateway.accounting.mapping import totals_projection
from gateway.schemas import IncidentSnapshot
from integer_oracle import State, expected, micros


@pytest.mark.parametrize("phase,charge,late,exposure", [
    ("known", 60000, None, 60000), ("known", 100000, None, 100000),
    ("known", 150000, None, 150000), ("unknown", None, None, 100000),
    ("unknown", None, 60000, 100000), ("unknown", None, 100000, 100000),
    ("unknown", None, 150000, 150000), ("future", None, None, 100000),
    ("active", None, None, 100000), ("cancelled", None, None, 0)])
def test_hand_calculated_oracle_controls(phase, charge, late, exposure):
    state = expected(100000, phase, charge, late)
    state.verify()
    assert state.exposure == exposure
    with pytest.raises(AssertionError):
        replace(state, released=state.released + 1).verify()


@pytest.mark.parametrize("phase,charge,late", [
    ("future", None, None), ("active", None, None), ("cancelled", None, None),
    ("known", "0.06", None), ("known", "0.10", None), ("known", "0.15", None),
    ("unknown", None, None), ("unknown", None, "0.06"), ("unknown", None, "0.10"), ("unknown", None, "0.15")])
def test_production_projection_matches_integer_oracle(phase, charge, late):
    oracle = expected(100000, phase, None if charge is None else micros(charge), None if late is None else micros(late))
    child = {"operation_id": "operation", "child_id": "child", "reserved_usd_per_attempt": "0.1", "max_attempts": 1,
             "remaining": 1 if phase == "future" else 0, "state": "cancelled_before_dispatch" if phase == "cancelled" else "pending"}
    attempts = [] if phase in ("future", "cancelled") else [{"operation_id": "operation", "child_id": "child", "reservation": "0.1", "state": phase, "cost": charge}]
    incident = IncidentSnapshot(authority_id="authority", terminal_unknown_usd=Decimal("0.1") if phase == "unknown" else Decimal(0),
        maximum_credible_usd=None if late is None else Decimal(late), uncovered_excess_usd=Decimal(oracle.uncovered) / 1_000_000,
        conflict=False, halted=bool(oracle.uncovered), evidence_sha256="a" * 64)
    with localcontext() as ctx:
        ctx.prec = 6
        total = totals_projection(authority_id="authority", cap_usd=Decimal("1"), children=[child], attempts=attempts, incident=incident, ledger_halted=False)
    for name in ("reserved", "future", "active", "released", "known", "unknown", "excess"):
        assert micros(getattr(total, name + "_usd")) == getattr(oracle, name)
    assert micros(total.exposure_usd) == oracle.exposure
    assert total.halted == bool(oracle.excess or oracle.uncovered)
    oracle.verify()

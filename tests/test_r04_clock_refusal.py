"""Cross-boundary refusal controls; no journey, acquisition or provider transport."""
from datetime import timedelta
import json
import sqlite3
from unittest.mock import Mock

import pytest

from gateway.bootstrap import build_mock_context
from gateway.schemas import AttemptChild, ErrorCode, GatewayError, OperationPermit, PermitState, PolicyError


@pytest.mark.parametrize("entry", ["fund", "claim", "totals"])
def test_clock_refusal_propagates_without_accounting_effects(loaded_simulation, monkeypatch, entry):
    # what_bug_this_catches: a swallowed clock error can fund/claim after refusal;
    # an ordinary transaction rollback can erase the durable policy halt.
    spec, *_ = loaded_simulation
    context = build_mock_context(spec, initialize=True)
    path = spec.runtime_root / "policy.sqlite3"
    try:
        before = context.clock._last
        assert before is not None
        previous, ticks = before
        # Inject a local supplier; no OS/VM clock is readjusted or sampled.
        monkeypatch.setattr(context.clock, "_utc_now", lambda: previous - timedelta(microseconds=7))
        monkeypatch.setattr(context.clock, "_monotonic_ns", lambda: ticks + 1)
        water = context.clock._high_water
        cas = Mock(wraps=water.compare_and_advance)
        monkeypatch.setattr(water, "compare_and_advance", cas)
        admit = Mock(side_effect=AssertionError("post-refusal funding"))
        claim = Mock(side_effect=AssertionError("post-refusal claim"))
        monkeypatch.setattr(context.ledger._ledger, "admit_operation", admit)
        monkeypatch.setattr(context.ledger._ledger, "begin_attempt", claim)
        permit = OperationPermit(
            permit_id="refusal-permit", operation_id="refusal-operation", authority_id=spec.authority_id,
            caller_id="synthetic-client", request_sha256="a" * 64, policy_generation=0,
            state=PermitState.PERMITTED, purpose="serve", policy_bundle_sha256="b" * 64,
            chosen_target_ids=("B0",), attempt_children=(AttemptChild(
                child_id="refusal-child", target_id="B0", purpose="serve", conditional=False,
                provider="openai", model="mock-openai-v1", maximum_liability_usd="0.000001",
                request_evidence_sha256="c" * 64),), adapter_capability_sha256="d" * 64,
            price_sha256="e" * 64, bound_sha256="f" * 64, serialized_envelope_sha256="1" * 64,
            created_utc=previous, expires_utc=previous + timedelta(seconds=30),
            evaluation_authorization_sha256=None)
        # The permit is structurally valid, never approved or admitted. The clock
        # gate must refuse before its later evidence/authorization checks.
        with context.guard.hold(spec.authority_id):
            with pytest.raises(GatewayError) as first:
                if entry == "fund":
                    context.ledger.fund_plan(permit)
                elif entry == "claim":
                    context.ledger.begin_attempt(operation_id="absent", child_id="absent", permit_sha256="2" * 64)
                else:
                    context.ledger.totals(authority_id=spec.authority_id)
            assert first.value.code == ErrorCode.CLOCK_ROLLBACK
            # A later policy transaction sees closed-highwater CLOCK_UNTRUSTED.
            # Different codes are retained rather than pretending recovery.
            with pytest.raises(PolicyError) as second:
                context.ledger.totals(authority_id=spec.authority_id)
            assert second.value.code == ErrorCode.CLOCK_UNTRUSTED
        assert context.clock._last == before
        assert context.clock._failure == ErrorCode.CLOCK_ROLLBACK
        assert water._closed and water._connection is None
        cas.assert_not_called()
        admit.assert_not_called()
        claim.assert_not_called()
        with sqlite3.connect(path) as db:
            row = db.execute("SELECT incident_halt,halt_reasons_json,max_observed_utc,generation FROM authority_state").fetchone()
            assert row[0] == 1 and row[3] == 0
            reasons = set(json.loads(row[1]))
            assert "clock_untrusted" in reasons
            if entry == "totals":
                assert "clock_rollback" in reasons
            assert row[2] == previous.isoformat(timespec="microseconds").replace("+00:00", "Z")
            assert db.execute("SELECT COUNT(*) FROM permits").fetchone()[0] == 0
        with sqlite3.connect(spec.runtime_root / "accounting.sqlite3") as db:
            assert db.execute("SELECT COUNT(*) FROM operations").fetchone()[0] == 0
            assert db.execute("SELECT COUNT(*) FROM attempts").fetchone()[0] == 0
    finally:
        context.close()

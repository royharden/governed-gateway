"""M8 consumer-to-S3 conformance with a gate double and controlled clocks.

The real monetary store and OS lock execute; this does not certify governance,
clock fidelity, or the controller's transport path.
"""
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from functools import partial

import pytest

from gateway.accounting.adapter import LedgerAdapter
from gateway.accounting.errors import AccountingError
from gateway.adapters.openai import OpenAIAdapter
from gateway.controller.authority_lock import AuthorityLock
from gateway.schemas import (AttemptChild, BudgetAuthority, ErrorCode, GatewayRequest, IncidentSnapshot,
    OperationPermit, PermitState, UnknownReason, WireMessage, digest, request_digest)
from ledger_support import configuration


class GateDouble:
    """Explicit test-only authorization seam, never independent policy evidence."""
    def __init__(self, authority_id):
        self.authority_id = authority_id
        self.allow = True
        self.permits = {}

    def validate_funding(self, permit, *, now):
        if not self.allow:
            raise AccountingError(ErrorCode.HALTED)
        self.permits[permit.operation_id] = permit

    def validate_dispatch(self, *, operation_id, child_id, permit_sha256, now):
        permit = self.permits[operation_id]
        assert digest(permit) == permit_sha256
        assert child_id in {child.child_id for child in permit.attempt_children}

    def incident_snapshot(self, *, authority_id):
        return IncidentSnapshot(authority_id=authority_id, terminal_unknown_usd=Decimal(0), maximum_credible_usd=None,
            uncovered_excess_usd=Decimal(0), conflict=False, halted=False, evidence_sha256="a"*64)


def test_consumer_funding_claim_unknown_reopen(artifact_dir, monkeypatch):
    from gateway.accounting import adapter as consumer
    from gateway.shared.s3.callledger import Ledger
    # Supported ledger injection isolates wrapper conformance from known clock defect.
    monkeypatch.setattr(consumer, "Ledger", partial(Ledger, monotonic=lambda: 0.0))
    config = configuration(authority_id="m8-consumer")
    now = datetime.now(timezone.utc)
    guard = AuthorityLock(artifact_dir)
    gate = GateDouble("m8-consumer")
    authority = BudgetAuthority(authority_id="m8-consumer", cap_usd=Decimal("1"), config_sha256=config.config_sha256)
    profile = next(p for p in config.profiles if p.provider == "openai")
    adapter = OpenAIAdapter(profile)
    messages = (WireMessage(role="user", content="synthetic-consumer"),)
    request = GatewayRequest(authority_id="m8-consumer", caller_id="client", idempotency_key="request", route_alias="default",
        messages=messages, max_completion_tokens=128, request_sha256=request_digest(route_alias="default", messages=messages, max_completion_tokens=128),
        deadline_utc=now+timedelta(seconds=60))
    envelope = adapter.serialize(request)
    def opened():
        return LedgerAdapter(authority=authority, database_path=artifact_dir / "m8-consumer.sqlite3", guard=guard,
            gate=gate, clock=lambda: now, configuration=config)
    with guard.hold("m8-consumer"):
        ledger = opened()
        try:
            evidence = ledger.register_envelope(envelope)
            reserved = ledger.reserve_for(envelope)
            permit = OperationPermit(permit_id="permit", operation_id="operation", authority_id="m8-consumer", caller_id="client",
                request_sha256=request.request_sha256, policy_generation=1, state=PermitState.PERMITTED, purpose="serve",
                policy_bundle_sha256="b"*64, chosen_target_ids=("B0",),
                attempt_children=(AttemptChild(child_id="child", target_id="B0", purpose="serve", conditional=False,
                    provider="openai", model=profile.exact_model, maximum_liability_usd=reserved, request_evidence_sha256=evidence),),
                adapter_capability_sha256=profile.capability_sha256, price_sha256=profile.price_sha256,
                bound_sha256=profile.bound_sha256, serialized_envelope_sha256=envelope.serialized_envelope_sha256,
                created_utc=now, expires_utc=now+timedelta(seconds=60), evaluation_authorization_sha256=None)
            gate.allow = False
            with pytest.raises(AccountingError):
                ledger.fund_plan(permit)
            assert ledger.totals(authority_id="m8-consumer").exposure_usd == 0
            gate.allow = True
            funded = ledger.fund_plan(permit)
            assert funded.plan_reserved_usd == reserved
            assert ledger.fund_plan(permit).already_funded
            ticket = ledger.begin_attempt(operation_id="operation", child_id="child", permit_sha256=digest(permit))
            assert ticket.reserved_usd == reserved
            with pytest.raises(AccountingError):
                ledger.begin_attempt(operation_id="operation", child_id="child", permit_sha256=digest(permit))
            settlement = ledger.mark_unknown(operation_id="operation", child_id="child", attempt_id=ticket.attempt_id,
                reason=UnknownReason.MISSING_USAGE)
            assert settlement.terminal_unknown_usd == reserved and settlement.released_usd == 0
            before = ledger.totals(authority_id="m8-consumer")
        finally:
            ledger.close()
        reopened = opened()
        try:
            assert reopened.totals(authority_id="m8-consumer") == before
            with pytest.raises(AccountingError):
                reopened.begin_attempt(operation_id="operation", child_id="child", permit_sha256=digest(permit))
        finally:
            reopened.close()

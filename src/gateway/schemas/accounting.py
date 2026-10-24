"""Body-free finite-authority accounting boundary records; no ledger implementation."""
from __future__ import annotations

from enum import Enum
from typing import Annotated, Literal
from pydantic import Field, model_validator
from .core import Hash, Identifier, Money, NonnegativeInt, Provider, Record, UTC, usd_micros


class BudgetAuthority(Record):
    authority_id: Identifier
    cap_usd: Money
    currency: Literal["USD"] = "USD"
    precision: Literal[6] = 6
    config_sha256: Hash


class FundingReceipt(Record):
    authority_id: Identifier
    operation_id: Identifier
    permit_sha256: Hash
    funded_children: Annotated[tuple[Identifier, ...], Field(min_length=1, max_length=2)]
    plan_reserved_usd: Money
    already_funded: bool


class DispatchTicket(Record):
    authority_id: Identifier
    operation_id: Identifier
    child_id: Identifier
    attempt_id: Identifier
    permit_sha256: Hash
    envelope_sha256: Hash
    reserved_usd: Money


class SettlementReceipt(Record):
    authority_id: Identifier
    operation_id: Identifier
    child_id: Identifier
    attempt_id: Identifier
    settlement_sha256: Hash
    state: Literal["known", "unknown"]
    reserved_usd: Money
    known_usage_cost_usd: Money | None
    terminal_unknown_usd: Money
    released_usd: Money
    excess_usd: Money
    already_settled: bool
    @model_validator(mode="after")
    def conservation(self):
        cost = None if self.known_usage_cost_usd is None else usd_micros(self.known_usage_cost_usd)
        reserved = usd_micros(self.reserved_usd)
        if self.state == "known":
            if cost is None or self.terminal_unknown_usd != 0 or usd_micros(self.released_usd) != max(reserved - cost, 0) or usd_micros(self.excess_usd) != max(cost - reserved, 0):
                raise ValueError("invalid_settlement")
        elif cost is not None or self.terminal_unknown_usd != self.reserved_usd or self.released_usd != 0 or self.excess_usd != 0:
            raise ValueError("invalid_settlement")
        return self


class UnknownReason(str, Enum):
    MISSING_USAGE = "missing_usage"
    MALFORMED_USAGE = "malformed_usage"
    UNSUPPORTED_COMPONENT = "unsupported_component"
    TIMEOUT = "timeout"
    CANCELLED_AFTER_DISPATCH = "cancelled_after_dispatch"
    CONNECTION_LOST = "connection_lost"
    OWNER_TERMINATED = "owner_terminated"
    AMBIGUOUS_DISPATCH = "ambiguous_dispatch"
    RESULT_NOT_STAGED = "result_not_staged"


class RecoveryEvidence(Record):
    authority_id: Identifier
    operation_id: Identifier
    child_id: Identifier | None
    attempt_id: Identifier | None
    observed_utc: UTC
    expires_utc: UTC
    cancelled: bool
    owner_pid: Annotated[int, Field(gt=0)] | None
    owner_process_instance_id: Identifier | None
    owner_exit_evidence_sha256: Hash | None
    staged_settlement_sha256: Hash | None
    @model_validator(mode="after")
    def owner_evidence(self):
        if self.owner_exit_evidence_sha256 is not None and (self.owner_pid is None or self.owner_process_instance_id is None):
            raise ValueError("invalid_owner_evidence")
        return self


class UnstartedProof(Record):
    authority_id: Identifier
    operation_id: Identifier
    child_id: Identifier
    allocation_id: Identifier
    undispatched: Literal[True] = True
    reason: Literal["skipped", "cancelled_before_dispatch"]
    proof_sha256: Hash
    recovery_evidence: RecoveryEvidence


class ChildClosureReceipt(Record):
    authority_id: Identifier
    operation_id: Identifier
    child_id: Identifier
    closure_sha256: Hash
    released_usd: Money
    already_closed: bool


class RecoveryAction(Record):
    operation_id: Identifier
    child_id: Identifier | None
    action: Literal["closed_unstarted", "marked_unknown", "settled_staged", "retained", "blocked"]
    evidence_sha256: Hash | None


class RecoveryReport(Record):
    authority_id: Identifier
    actions: Annotated[tuple[RecoveryAction, ...], Field(max_length=4096)]
    retained: Annotated[tuple[Identifier, ...], Field(max_length=4096)]
    blocked: Annotated[tuple[Identifier, ...], Field(max_length=4096)]


class IncidentSnapshot(Record):
    authority_id: Identifier
    terminal_unknown_usd: Money
    maximum_credible_usd: Money | None
    uncovered_excess_usd: Money
    conflict: bool
    halted: bool
    evidence_sha256: Hash


class AccountingTotals(Record):
    authority_id: Identifier
    cap_usd: Money
    reserved_usd: Money
    future_usd: Money
    active_usd: Money
    released_usd: Money
    known_usd: Money
    unknown_usd: Money
    excess_usd: Money
    uncovered_excess_usd: Money
    exposure_usd: Money
    halted: bool
    conflict: bool
    @model_validator(mode="after")
    def conserved(self):
        if usd_micros(self.reserved_usd) + usd_micros(self.excess_usd) != sum(usd_micros(v) for v in (self.future_usd, self.active_usd, self.released_usd, self.known_usd, self.unknown_usd)):
            raise ValueError("reservation_conservation")
        if usd_micros(self.exposure_usd) != sum(usd_micros(v) for v in (self.known_usd, self.future_usd, self.active_usd, self.unknown_usd, self.uncovered_excess_usd)):
            raise ValueError("exposure_mismatch")
        return self


class AccountingIncident(Record):
    authority_id: Identifier
    operation_id: Identifier
    child_id: Identifier
    attempt_id: Identifier
    provider: Provider
    source_sha256: Hash
    observed_cost_usd: Money | None
    reserved_usd: Money
    terminal_unknown_usd: Money
    authenticated: bool
    conflict: bool
    reason_code: Literal["bound_breach", "late_evidence", "evidence_conflict", "unauthenticated_evidence", "settlement_conflict"]
    recorded_utc: UTC


class IncidentReceipt(Record):
    authority_id: Identifier
    incident_sha256: Hash
    uncovered_excess_usd: Money
    halted: bool
    conflict: bool
    duplicate: bool

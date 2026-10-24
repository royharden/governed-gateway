"""Typed journey/replay projections. They carry evidence references, never prove custody."""
from __future__ import annotations

from enum import Enum
from typing import Annotated, Literal
from pydantic import Field, model_validator
from .core import ErrorCode, Hash, Identifier, NonnegativeInt, PositiveInt, Record, UTC
from .requests import (AttemptReceipt, ChatCompletionRequest, GatewayResult, LedgerJoin,
                       OperationPermit)
from .governance import PolicyBundle
from .accounting import SettlementReceipt

# Exact wire model, one implementation and no added accepted fields.
ChatCompletionInput = ChatCompletionRequest


class CallerContext(Record):
    authority_id: Identifier
    caller_id: Identifier


class OperationState(str, Enum):
    PERMITTED = "permitted"
    FUNDED = "funded"
    ATTEMPT_STARTED = "attempt_started"
    STAGED = "staged"
    KNOWN_SETTLED = "known_settled"
    UNKNOWN_SETTLED = "unknown_settled"
    TERMINAL = "terminal"
    ABANDONED = "abandoned"
    RESULT_EXPIRED = "result_expired"


class GatewayReply(Record):
    http_status: Literal[200, 202, 400, 401, 403, 409, 410, 429, 502, 503, 504]
    code: ErrorCode | None
    state: OperationState | None
    result: GatewayResult | None
    operation_id: Identifier | None
    @model_validator(mode="after")
    def reply(self):
        if self.http_status == 200 and self.result is None:
            raise ValueError("missing_result")
        if self.http_status == 202 and (self.operation_id is None or self.result is not None):
            raise ValueError("invalid_pending_reply")
        if self.http_status >= 400 and (self.code is None or self.result is not None):
            raise ValueError("invalid_error_reply")
        return self


class RoutingSnapshot(Record):
    authority_id: Identifier
    generation: PositiveInt
    policy_bundle_sha256: Hash
    approval_sha256: Hash
    bundle: PolicyBundle
    eligible_target_ids: Annotated[tuple[Identifier, ...], Field(min_length=1, max_length=2)]
    evidence_context_sha256: Hash
    expires_utc: UTC
    @model_validator(mode="after")
    def routing(self):
        from .core import digest
        if digest(self.bundle) != self.policy_bundle_sha256:
            raise ValueError("policy_digest_mismatch")
        if any(target not in {t.target_id for t in self.bundle.targets} for target in self.eligible_target_ids):
            raise ValueError("invalid_target")
        return self


class ReplayBinding(Record):
    authority_id: Identifier
    caller_id: Identifier
    operation_id: Identifier
    request_sha256: Hash
    policy_bundle_sha256: Hash


class EncryptedResult(Record):
    key_id: Identifier
    nonce_b64: Annotated[str, Field(min_length=16, max_length=16, pattern=r"^[A-Za-z0-9+/]{16}$", repr=False)]
    ciphertext_b64: Annotated[str, Field(min_length=24, max_length=2097152, pattern=r"^[A-Za-z0-9+/]+={0,2}$", repr=False)]
    aad_sha256: Hash
    result_sha256: Hash


class StagedResult(Record):
    authority_id: Identifier
    operation_id: Identifier
    permit_sha256: Hash
    binding: ReplayBinding
    encrypted_result: EncryptedResult
    receipt: AttemptReceipt
    staged_utc: UTC
    @model_validator(mode="after")
    def stage_identity(self):
        if self.binding.authority_id != self.authority_id or self.binding.operation_id != self.operation_id or self.receipt.operation_id != self.operation_id or self.receipt.permit_sha256 != self.permit_sha256:
            raise ValueError("staged_identity_mismatch")
        if self.binding.request_sha256 != self.receipt.request_sha256 or self.binding.policy_bundle_sha256 != self.receipt.policy_bundle_sha256:
            raise ValueError("staged_digest_mismatch")
        return self


class OperationSnapshot(Record):
    authority_id: Identifier
    caller_id: Identifier
    operation_id: Identifier
    key_digest: Hash
    request_sha256: Hash
    permit: OperationPermit
    state: OperationState
    cancelled: bool
    staged_result: StagedResult | None
    settlement: SettlementReceipt | None
    join: LedgerJoin | None
    result_expires_utc: UTC | None
    result_purged: bool
    @model_validator(mode="after")
    def operation_identity(self):
        p = self.permit
        if (p.authority_id, p.caller_id, p.operation_id, p.request_sha256) != (self.authority_id, self.caller_id, self.operation_id, self.request_sha256):
            raise ValueError("operation_identity_mismatch")
        for child in (self.staged_result, self.settlement, self.join):
            if child is not None and (child.authority_id != self.authority_id or child.operation_id != self.operation_id):
                raise ValueError("operation_identity_mismatch")
        if self.result_purged and self.staged_result is not None:
            raise ValueError("purged_result_present")
        return self


class PermitDecision(Record):
    created: bool
    operation: OperationSnapshot
    permit: OperationPermit | None
    @model_validator(mode="after")
    def decision(self):
        if self.created and (self.permit is None or self.permit != self.operation.permit):
            raise ValueError("missing_permit")
        if not self.created and self.permit is not None:
            raise ValueError("duplicate_dispatch_permit")
        return self


class ProcessInstance(Record):
    pid: PositiveInt
    process_start_id: Identifier
    started_utc: UTC


class OwnerExitEvidence(Record):
    process: ProcessInstance
    observed_utc: UTC
    exit_code: int
    owned_process_evidence_sha256: Hash
    exit_evidence_sha256: Hash
    @model_validator(mode="after")
    def exit_time(self):
        if self.observed_utc < self.process.started_utc:
            raise ValueError("invalid_exit_time")
        return self


class RecoverySummary(Record):
    authority_id: Identifier
    examined_count: NonnegativeInt
    closed_operation_ids: Annotated[tuple[Identifier, ...], Field(max_length=4096)]
    retained_operation_ids: Annotated[tuple[Identifier, ...], Field(max_length=4096)]
    blocked_operation_ids: Annotated[tuple[Identifier, ...], Field(max_length=4096)]
    incident_sha256s: Annotated[tuple[Hash, ...], Field(max_length=4096)]
    next_cursor: Identifier | None


class LedgerAttemptSnapshot(Record):
    child_id: Identifier
    attempt_id: Identifier | None
    state: Literal["future", "active", "known", "unknown", "closed_unstarted"]
    owner: ProcessInstance | None
    settlement_sha256: Hash | None
    deadline_utc: UTC


class LedgerOperationSnapshot(Record):
    authority_id: Identifier
    operation_id: Identifier
    permit_sha256: Hash
    ledger_context_sha256: Hash
    join: LedgerJoin
    attempts: Annotated[tuple[LedgerAttemptSnapshot, ...], Field(min_length=1, max_length=2)]
    breach: bool
    conflict: bool
    @model_validator(mode="after")
    def ledger_identity(self):
        if (self.join.authority_id, self.join.operation_id, self.join.permit_sha256, self.join.ledger_context_sha256) != (self.authority_id, self.operation_id, self.permit_sha256, self.ledger_context_sha256):
            raise ValueError("ledger_identity_mismatch")
        if {a.child_id for a in self.attempts} != set(self.join.child_ids):
            raise ValueError("ledger_child_mismatch")
        return self


class LedgerRecoveryPage(Record):
    items: Annotated[tuple[LedgerOperationSnapshot, ...], Field(max_length=1024)]
    next_cursor: Identifier | None


class PolicyRecoveryPage(Record):
    authority_id: Identifier
    items: Annotated[tuple[OperationSnapshot, ...], Field(max_length=1024)]
    next_cursor: Identifier | None
    @model_validator(mode="after")
    def scoped(self):
        if any(item.authority_id != self.authority_id for item in self.items):
            raise ValueError("authority_mismatch")
        return self

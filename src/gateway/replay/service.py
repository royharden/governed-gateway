"""Read original ciphertext only after terminal committed accounting matches."""
from datetime import datetime

from gateway.schemas import (
    CallerContext, ErrorCode, GatewayError, GatewayReply, OperationSnapshot,
    OperationState, ReplayBinding, digest,
)
from gateway.api.errors import error_reply
from .cipher import ReplayCipher


class ReplayService:
    def __init__(self, cipher: ReplayCipher):
        self.cipher = cipher

    def reply(self, snapshot: OperationSnapshot, caller: CallerContext,
              request_sha256: str, *, now: datetime, replayed: bool = True) -> GatewayReply:
        if (caller.authority_id, caller.caller_id) != (snapshot.authority_id, snapshot.caller_id):
            raise GatewayError(ErrorCode.FORBIDDEN)
        if snapshot.request_sha256 != request_sha256:
            return error_reply(ErrorCode.IDEMPOTENCY_CONFLICT)
        operation = snapshot.operation_id
        if snapshot.settlement is not None and snapshot.settlement.state == "unknown":
            return error_reply(ErrorCode.UNRESOLVED_LIABILITY, operation_id=operation)
        if snapshot.state == OperationState.UNKNOWN_SETTLED:
            return error_reply(ErrorCode.UNRESOLVED_LIABILITY, operation_id=operation)
        if snapshot.result_purged or snapshot.state == OperationState.RESULT_EXPIRED:
            return error_reply(ErrorCode.RESULT_EXPIRED, operation_id=operation)
        if snapshot.state == OperationState.ABANDONED:
            return error_reply(ErrorCode.CANCELLED if snapshot.cancelled else ErrorCode.DEADLINE_EXCEEDED,
                               operation_id=operation)
        if snapshot.cancelled and snapshot.state != OperationState.TERMINAL:
            return error_reply(ErrorCode.CANCELLED, operation_id=operation)
        if snapshot.state != OperationState.TERMINAL:
            return GatewayReply(http_status=202, code=None, state=snapshot.state,
                                result=None, operation_id=operation)
        if snapshot.result_expires_utc is None:
            return error_reply(ErrorCode.UNRESOLVED_LIABILITY, operation_id=operation)
        if now >= snapshot.result_expires_utc:
            return error_reply(ErrorCode.RESULT_EXPIRED, operation_id=operation)
        staged, settled, join = snapshot.staged_result, snapshot.settlement, snapshot.join
        if staged is None or settled is None or join is None:
            raise GatewayError(ErrorCode.INVALID_JOIN)
        permit_hash = digest(snapshot.permit)
        if (staged.permit_sha256 != permit_hash or join.permit_sha256 != permit_hash
            or join.settlement_sha256 != settled.settlement_sha256
            or staged.receipt.attempt_id != settled.attempt_id
            or staged.receipt.child_id != settled.child_id
            or staged.receipt.request_sha256 != snapshot.request_sha256
            or join.request_sha256 != snapshot.request_sha256
            or join.policy_bundle_sha256 != snapshot.permit.policy_bundle_sha256
            or join.price_sha256 != snapshot.permit.price_sha256
            or join.bound_sha256 != snapshot.permit.bound_sha256
            or join.serialized_envelope_sha256 != snapshot.permit.serialized_envelope_sha256
            or set(join.child_ids) != {child.child_id for child in snapshot.permit.attempt_children}
            or settled.known_usage_cost_usd != staged.receipt.known_usage_cost_usd):
            raise GatewayError(ErrorCode.INVALID_JOIN)
        binding = ReplayBinding(authority_id=caller.authority_id, caller_id=caller.caller_id,
            operation_id=operation, request_sha256=request_sha256,
            policy_bundle_sha256=snapshot.permit.policy_bundle_sha256)
        if staged.binding != binding:
            raise GatewayError(ErrorCode.INVALID_JOIN)
        result = self.cipher.decrypt(staged.encrypted_result, binding)
        if (result.cost.status != "known" or result.cost.amount_usd != settled.known_usage_cost_usd
            or settled.attempt_id not in result.attempt_ids):
            raise GatewayError(ErrorCode.INVALID_JOIN)
        if result.error is not None:
            return error_reply(result.error.code, operation_id=operation)
        return GatewayReply(http_status=200, code=None, state=OperationState.TERMINAL,
            # Staging precedes settlement/terminal commit. Its internal expiry
            # candidate never controls retention. The policy terminal projection
            # fixes expiry once; first delivery and all duplicates use that value.
            result=result.model_copy(update={"replayed": replayed,
                "result_expires_utc": snapshot.result_expires_utc}), operation_id=operation)

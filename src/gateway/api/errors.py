"""Closed HTTP mapping; never serialize a validation or upstream exception."""
from gateway.schemas import ErrorCode, GatewayReply


def error_reply(code: ErrorCode, *, operation_id: str | None = None) -> GatewayReply:
    groups = {
        400: {ErrorCode.INVALID_REQUEST, ErrorCode.UNSUPPORTED_REQUEST, ErrorCode.UNSUPPORTED_PROFILE},
        401: {ErrorCode.UNAUTHENTICATED},
        403: {ErrorCode.FORBIDDEN, ErrorCode.INVALID_AUTHORIZATION},
        409: {ErrorCode.IDEMPOTENCY_CONFLICT, ErrorCode.GENERATION_CONFLICT,
              ErrorCode.UNRESOLVED_LIABILITY, ErrorCode.RECORD_CONFLICT,
              ErrorCode.ALREADY_CLAIMED, ErrorCode.ATTEMPT_CONSUMED},
        410: {ErrorCode.RESULT_EXPIRED},
        429: {ErrorCode.BUDGET_REJECTED, ErrorCode.BUDGET_EXCEEDED},
        502: {ErrorCode.UPSTREAM_ERROR},
        504: {ErrorCode.DEADLINE_EXCEEDED},
    }
    status = next((status for status, codes in groups.items() if code in codes), 503)
    return GatewayReply(http_status=status, code=code, state=None, result=None,
                        operation_id=operation_id)

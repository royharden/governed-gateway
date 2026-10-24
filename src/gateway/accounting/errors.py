"""Closed accounting errors; no SQL, source values or upstream exception text."""
from gateway.schemas import ErrorCode, GatewayError


class AccountingError(GatewayError):
    pass


def upstream_error(code: str) -> AccountingError:
    mapped = {
        "budget_rejected": ErrorCode.BUDGET_EXCEEDED,
        "authority_conflict": ErrorCode.AUTHORITY_MISMATCH,
        "authority_mismatch": ErrorCode.AUTHORITY_MISMATCH,
        "halted": ErrorCode.HALTED,
        "deadline": ErrorCode.PERMIT_EXPIRED,
        "clock_rollback": ErrorCode.CLOCK_ROLLBACK,
        "attempt_limit": ErrorCode.ALREADY_CLAIMED,
        "active_attempt": ErrorCode.ALREADY_CLAIMED,
        "settlement_conflict": ErrorCode.SETTLEMENT_CONFLICT,
        "storage": ErrorCode.STORAGE_UNAVAILABLE,
        "schema_version": ErrorCode.SCHEMA_MISMATCH,
        "operation_conflict": ErrorCode.PERMIT_MISMATCH,
        "context_mismatch": ErrorCode.PERMIT_MISMATCH,
        "allocation_mismatch": ErrorCode.PERMIT_MISMATCH,
    }
    return AccountingError(mapped.get(code, ErrorCode.INVALID_EVIDENCE))
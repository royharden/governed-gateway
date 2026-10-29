"""Shared strict primitives. No I/O, key material, or import-time authority."""
from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from enum import Enum
import hashlib
import json
import re
from collections.abc import Mapping
from typing import Annotated, Any, Literal

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, ValidationInfo, field_validator


class Record(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra="forbid", hide_input_in_errors=True)
    schema_version: Literal[1] = 1

    @field_validator(
        "schema_version", "n", "max_attempts", "precision",
        "stream", "undispatched", "synthetic", "bootstrap_resamples",
        mode="before", check_fields=False,
    )
    @classmethod
    def exact_literals(cls, value: Any, info: ValidationInfo) -> Any:
        # A model-level before validator materializes JSON arrays as Python
        # lists before strict tuple decoding. Validate only these scalar fields
        # so JSON retains its native strict decoding, including nested records.
        expected = bool if info.field_name in {"stream", "undispatched", "synthetic"} else int
        if type(value) is not expected:
            raise ValueError("invalid_literal")
        return value


Identifier = Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@/-]*$")]
Hash = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
SafeLabel = Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9 ._:@/+-]*$")]
Signature = Annotated[str, Field(min_length=1, max_length=512, pattern=r"^[A-Za-z0-9+/=_-]+$")]
PositiveInt = Annotated[int, Field(gt=0)]
NonnegativeInt = Annotated[int, Field(ge=0)]
Provider = Literal["mock", "openai", "anthropic"]
Mode = Literal["simulation", "recorded", "live"]


def _money(value: Any) -> Decimal:
    if not isinstance(value, (str, Decimal)):
        raise ValueError("invalid_money")
    if isinstance(value, str) and not re.fullmatch(r"(?:0|[1-9][0-9]*)(?:\.[0-9]{1,6})?", value):
        raise ValueError("invalid_money")
    try:
        amount = Decimal(value)
        if not amount.is_finite() or amount < 0 or amount.as_tuple().exponent < -6:
            raise ValueError("invalid_money")
    except InvalidOperation:
        raise ValueError("invalid_money") from None
    return amount


Money = Annotated[Decimal, BeforeValidator(_money)]


def _coefficient(value: Decimal) -> int:
    coefficient = 0
    for digit in value.as_tuple().digits:
        coefficient = coefficient * 10 + digit
    return coefficient


def _signed_decimal(value: Any) -> Decimal:
    if not isinstance(value, (str, Decimal)):
        raise ValueError("invalid_signed_decimal")
    if isinstance(value, str) and not re.fullmatch(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]{1,6})?", value):
        raise ValueError("invalid_signed_decimal")
    try:
        number = Decimal(value)
    except InvalidOperation:
        raise ValueError("invalid_signed_decimal") from None
    if not number.is_finite() or number.as_tuple().exponent < -6:
        raise ValueError("invalid_signed_decimal")
    return number


# Dimensionless metrics and signed deltas use six fractional places, no USD meaning.
SignedDecimal = Annotated[Decimal, BeforeValidator(_signed_decimal)]


def decimal_micros(value: Decimal) -> int:
    """Exact six-place scaled integer; independent of Decimal context and magnitude."""
    number = _signed_decimal(value)
    components = number.as_tuple()
    scaled = _coefficient(number) * (10 ** (components.exponent + 6))
    return -scaled if components.sign else scaled


def usd_micros(value: Decimal) -> int:
    return decimal_micros(_money(value))


def money_from_micros(value: int) -> Decimal:
    if type(value) is not int or value < 0:
        raise ValueError("invalid_money")
    # Decimal(int) is exact; rebuilding its coefficient with exponent -6 does no arithmetic.
    return Decimal((0, Decimal(value).as_tuple().digits, -6))


def reserve_up(value: Decimal) -> Decimal:
    """Ceiling to micro-USD using coefficient integers, independent of ambient context."""
    if not isinstance(value, Decimal) or not value.is_finite() or value < 0:
        raise ValueError("invalid_money")
    components = value.as_tuple()
    coefficient = _coefficient(value)
    exponent = components.exponent + 6
    if exponent >= 0:
        units = coefficient * (10 ** exponent)
    else:
        divisor = 10 ** (-exponent)
        units = (coefficient + divisor - 1) // divisor
    return money_from_micros(units)


def _utc(value: Any) -> datetime:
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError("invalid_utc") from None
    if not isinstance(value, datetime) or value.utcoffset() is None or value.utcoffset().total_seconds() != 0:
        raise ValueError("invalid_utc")
    return value.astimezone(timezone.utc)


UTC = Annotated[datetime, BeforeValidator(_utc)]


class ErrorCode(str, Enum):
    INVALID_REQUEST = "invalid_request"
    UNSUPPORTED_REQUEST = "unsupported_request"
    UNAUTHENTICATED = "unauthenticated"
    FORBIDDEN = "forbidden"
    IDEMPOTENCY_CONFLICT = "idempotency_conflict"
    GENERATION_CONFLICT = "generation_conflict"
    RECORD_CONFLICT = "record_conflict"
    RESULT_EXPIRED = "result_expired"
    BUDGET_REJECTED = "budget_rejected"
    UPSTREAM_ERROR = "upstream_error"
    HALTED = "halted"
    NO_APPROVED_POLICY = "no_approved_policy"
    STALE_EVIDENCE = "stale_evidence"
    DEADLINE_EXCEEDED = "deadline_exceeded"
    UNRESOLVED_LIABILITY = "unresolved_liability"
    EXTERNAL_DISABLED = "external_disabled"
    INVALID_SIGNATURE = "invalid_signature"
    INVALID_AUTHORIZATION = "invalid_authorization"
    INVALID_APPROVAL = "invalid_approval"
    INELIGIBLE_POLICY = "ineligible_policy"
    INVALID_PERMIT = "invalid_permit"
    INVALID_JOIN = "invalid_join"
    INVALID_TRANSITION = "invalid_transition"
    STORE_UNAVAILABLE = "store_unavailable"
    SCHEMA_MISMATCH = "schema_mismatch"
    CONFIG_MISMATCH = "config_mismatch"
    UNSAFE_RUNTIME_PATH = "unsafe_runtime_path"
    CLOCK_UNTRUSTED = "clock_untrusted"
    CLOCK_ROLLBACK = "clock_rollback"
    LOCK_UNAVAILABLE = "lock_unavailable"
    EVIDENCE_CONFLICT = "evidence_conflict"
    BOUND_BREACH = "bound_breach"
    CANCELLED = "cancelled"
    ATTEMPT_CONSUMED = "attempt_consumed"
    MISSING_EVIDENCE = "missing_evidence"
    BUDGET_EXCEEDED = "budget_exceeded"
    AUTHORITY_MISMATCH = "authority_mismatch"
    PERMIT_MISMATCH = "permit_mismatch"
    PERMIT_EXPIRED = "permit_expired"
    ALREADY_CLAIMED = "already_claimed"
    SETTLEMENT_CONFLICT = "settlement_conflict"
    INVALID_EVIDENCE = "invalid_evidence"
    STORAGE_UNAVAILABLE = "storage_unavailable"
    UNSUPPORTED_PROFILE = "unsupported_profile"
    DEPENDENCY_UNAVAILABLE = "dependency_unavailable"
    INTERNAL_ERROR = "internal_error"


class GatewayError(Exception):
    """Only closed codes cross package boundaries; never store exception/payload text."""
    def __init__(self, code: ErrorCode | str) -> None:
        self.code = ErrorCode(code)
        super().__init__(self.code.value)

    @property
    def safe_message(self) -> str:
        return self.code.value.replace("_", " ")


class PolicyError(GatewayError):
    pass


def _canonical(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return _canonical(value.model_dump(mode="python", exclude_none=False))
    if isinstance(value, Enum):
        return _canonical(value.value)
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise ValueError("nonfinite_decimal")
        if value == 0:
            return "0"
        encoded = format(value, "f")
        return encoded.rstrip("0").rstrip(".") if "." in encoded else encoded
    if isinstance(value, datetime):
        return _utc(value).isoformat(timespec="microseconds").replace("+00:00", "Z")
    if value is None or type(value) in (str, int, bool):
        return value
    if isinstance(value, Mapping):
        if any(type(key) is not str for key in value):
            raise ValueError("invalid_canonical_key")
        return {key: _canonical(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_canonical(item) for item in value]
    raise ValueError("unsupported_canonical_type")


def canonical_bytes(value: Any) -> bytes:
    """Explicit nulls, exact text, sorted keys, normalized Decimal strings; no floats."""
    return json.dumps(_canonical(value), ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()

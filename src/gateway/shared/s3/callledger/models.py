"""Versioned accounting declarations, not an executing or durable budget ledger."""

import hashlib
import json
from datetime import datetime
from decimal import Decimal
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator, model_validator

Identifier = Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")]
Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Money = Annotated[str, Field(pattern=r"^(0|[1-9][0-9]*)(\.[0-9]+)?$", max_length=64)]
Count = Annotated[int, Field(ge=0)]
PositiveCount = Annotated[int, Field(gt=0)]
Seconds = Annotated[float, Field(gt=0, allow_inf_nan=False)]
UsageField = Literal[
    "input_tokens",
    "output_tokens",
    "cache_read_input_tokens",
    "cache_write_input_tokens",
    "reasoning_output_tokens",
]
ErrorCode = Literal[
    "auth",
    "missing_key",
    "unsupported_capability",
    "invalid_output",
    "price_unknown",
    "budget_rejected",
    "attempt_limit",
    "deadline",
    "cache_miss",
    "unknown_dispatch",
    "cancelled",
]
Status = Literal[
    "ok",
    "refused",
    "invalid_output",
    "provider_error",
    "unknown",
    "budget_rejected",
    "unsupported",
    "cache_miss",
    "deadline_exceeded",
    "cancelled",
]


class WireModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        allow_inf_nan=False,
        hide_input_in_errors=True,
    )

    @field_validator("run_deadline_utc", "expires_at", check_fields=False)
    @classmethod
    def utc_deadline(cls, value: str | None) -> str | None:
        if value is None:
            return None
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
            raise ValueError("deadline must be a valid UTC timestamp")
        return value

    @model_validator(mode="before")
    @classmethod
    def reject_boolean_version(cls, value):
        if isinstance(value, dict) and isinstance(value.get("schema_version"), bool):
            raise ValueError("schema_version must be the integer 1")
        return value


def decode_wire_json(payload: str, *, max_bytes: int = 1_000_000) -> JsonValue:
    """Reject duplicate JSON keys and nonfinite literals before model validation."""
    if len(payload.encode("utf-8")) > max_bytes:
        raise ValueError("wire document exceeds byte limit")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def constant(_):
        raise ValueError("nonfinite JSON literal")

    return json.loads(payload, object_pairs_hook=pairs, parse_constant=constant)


def canonical_digest(value: JsonValue) -> str:
    encoded = json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class NormalizedUsage(WireModel):
    input_tokens: Count | None = None
    output_tokens: Count | None = None
    cache_read_input_tokens: Count | None = None
    cache_write_input_tokens: Count | None = None
    reasoning_output_tokens: Count | None = None

    @model_validator(mode="after")
    def partitions(self) -> Self:
        if self.input_tokens is not None:
            cache = (self.cache_read_input_tokens or 0) + (self.cache_write_input_tokens or 0)
            if cache > self.input_tokens:
                raise ValueError("cache partitions exceed inclusive input")
        if (
            self.output_tokens is not None
            and self.reasoning_output_tokens is not None
            and self.reasoning_output_tokens > self.output_tokens
        ):
            raise ValueError("reasoning subset exceeds inclusive output")
        return self


class BillingPolicy(WireModel):
    schema_version: Literal[1]
    policy_sha256: Digest
    required_usage_fields: list[UsageField]
    fee_context_known: bool

    @model_validator(mode="after")
    def unique_fields(self) -> Self:
        if len(set(self.required_usage_fields)) != len(self.required_usage_fields):
            raise ValueError("duplicate billed component")
        return self

    def usage_complete(self, usage: NormalizedUsage) -> bool:
        return self.fee_context_known and all(
            getattr(usage, field) is not None for field in self.required_usage_fields
        )


class CostObservation(WireModel):
    """Validate completeness of a declared cost; does not calculate or verify pricing."""

    schema_version: Literal[1]
    usage: NormalizedUsage
    billing_policy: BillingPolicy
    status: Literal["known", "unknown"]
    computed_cost_usd: Money | None
    unresolved_liability_usd: Money

    @model_validator(mode="after")
    def completeness(self) -> Self:
        if self.status == "known":
            if self.computed_cost_usd is None or not self.billing_policy.usage_complete(self.usage):
                raise ValueError("known cost requires every billed usage component and fee context")
            if Decimal(self.unresolved_liability_usd) != 0:
                raise ValueError("known settled cost cannot retain the same unresolved liability")
        elif self.computed_cost_usd is not None:
            raise ValueError("unknown total cost cannot be filled with a subtotal")
        return self


class BudgetAuthority(WireModel):
    schema_version: Literal[1]
    authority_id: Identifier
    scope_sha256: Digest
    cap_usd: Money
    max_outbound_attempts: Count
    run_deadline_utc: Annotated[str, Field(pattern=r"^\d{4}-\d\d-\d\dT.*Z$")]
    expires_at: Annotated[str, Field(pattern=r"^\d{4}-\d\d-\d\dT.*Z$")] | None = None


class CallContext(WireModel):
    schema_version: Literal[1]
    authority_id: Identifier
    run_id: Identifier
    operation_id: Identifier
    child_id: Identifier
    task_id: Identifier
    span_id: Identifier
    parent_span_id: Identifier | None = None
    consumer_namespace: Identifier
    purpose: Identifier
    source_generation: Identifier | None = None
    consumer_context_sha256: Digest
    policy_sha256: Digest
    template_sha256: Digest
    config_sha256: Digest

    def semantic_context(self) -> dict:
        return {
            key: getattr(self, key)
            for key in (
                "consumer_namespace",
                "purpose",
                "source_generation",
                "consumer_context_sha256",
                "policy_sha256",
                "template_sha256",
                "config_sha256",
            )
        }


class Limits(WireModel):
    schema_version: Literal[1]
    max_attempts_total: Annotated[int, Field(ge=1, le=3)]
    max_content_repairs: Annotated[int, Field(ge=0, le=1)]
    operation_deadline_s: Seconds
    attempt_timeout_s: Seconds
    run_deadline_utc: Annotated[str, Field(pattern=r"^\d{4}-\d\d-\d\dT.*Z$")]
    max_outbound_attempts: Count
    max_concurrent_operations: PositiveCount
    max_total_input_tokens: PositiveCount | None = None
    max_state_plus_longest_question_tokens: PositiveCount | None = None
    max_request_bytes: PositiveCount
    max_response_bytes: PositiveCount
    max_questions: PositiveCount
    max_choice_options: Annotated[int, Field(ge=1, le=255)]
    max_total_output_tokens: PositiveCount | None = None

    @model_validator(mode="after")
    def repair_capacity(self) -> Self:
        if self.max_content_repairs >= self.max_attempts_total:
            raise ValueError("content repair must fit inside total attempt allowance")
        return self


class ChildBound(WireModel):
    child_id: Identifier
    purpose: Identifier
    provider_config_sha256: Digest
    model: Annotated[str, Field(min_length=1, max_length=128)]
    bound_evidence_sha256: Digest
    max_attempts: Annotated[int, Field(ge=0, le=3)]
    max_repairs: Annotated[int, Field(ge=0, le=1)]
    input_token_maximum: Count
    output_token_maximum: Count | None
    fee_maximum_usd: Money
    reserved_usd_per_attempt: Money
    request_shape_limit_sha256: Digest
    conditional: bool

    @model_validator(mode="after")
    def repairs(self) -> Self:
        if self.max_attempts == 0:
            if self.max_repairs != 0 or Decimal(self.reserved_usd_per_attempt) != 0:
                raise ValueError("zero outbound quota is only a zero-cost no-dispatch child")
        elif self.max_repairs >= self.max_attempts:
            raise ValueError("repair does not fit funded attempts")
        if Decimal(self.reserved_usd_per_attempt) < Decimal(self.fee_maximum_usd):
            raise ValueError("reservation does not cover declared fee maximum")
        return self


class OperationPlan(WireModel):
    schema_version: Literal[1]
    operation_id: Identifier
    authority_id: Identifier
    context_sha256: Digest
    children: Annotated[list[ChildBound], Field(min_length=1, max_length=256)]

    @model_validator(mode="after")
    def child_identity(self) -> Self:
        if len({child.child_id for child in self.children}) != len(self.children):
            raise ValueError("duplicate operation child")
        return self

    @property
    def declared_worst_case_usd(self) -> Decimal:
        return sum(
            (Decimal(c.reserved_usd_per_attempt) * c.max_attempts for c in self.children),
            Decimal(0),
        )

    @property
    def plan_sha256(self) -> str:
        return canonical_digest(self.model_dump(mode="json"))


class Allocation(WireModel):
    schema_version: Literal[1]
    allocation_id: Identifier
    authority_id: Identifier
    operation_id: Identifier
    plan_sha256: Digest


class FundingDeclaration(WireModel):
    """Schema check for claimed admission, not a durable reservation transaction."""

    schema_version: Literal[1]
    authority: BudgetAuthority
    plan: OperationPlan
    allocation: Allocation
    known_spend_usd: Money
    other_held_exposure_usd: Money
    already_dispatched_attempts: Count

    @model_validator(mode="after")
    def funded(self) -> Self:
        if not (
            self.authority.authority_id == self.plan.authority_id == self.allocation.authority_id
        ):
            raise ValueError("funding authority mismatch")
        if self.plan.operation_id != self.allocation.operation_id:
            raise ValueError("funding operation mismatch")
        if self.plan.plan_sha256 != self.allocation.plan_sha256:
            raise ValueError("allocation plan digest mismatch")
        exposure = (
            Decimal(self.known_spend_usd)
            + Decimal(self.other_held_exposure_usd)
            + self.plan.declared_worst_case_usd
        )
        if exposure > Decimal(self.authority.cap_usd):
            raise ValueError("complete declared operation exceeds cap")
        attempts = sum(c.max_attempts for c in self.plan.children)
        if self.already_dispatched_attempts + attempts > self.authority.max_outbound_attempts:
            raise ValueError("complete declared operation exceeds attempt quota")
        return self


class MetadataUsage(WireModel):
    """An allowlisted numeric usage subtree; no HTTP/body/error payload fields."""

    input_tokens: Count | None = None
    output_tokens: Count | None = None
    prompt_tokens: Count | None = None
    completion_tokens: Count | None = None
    total_tokens: Count | None = None
    cache_read_input_tokens: Count | None = None
    cache_creation_input_tokens: Count | None = None
    details: NormalizedUsage | None = None


class MetadataRecord(WireModel):
    schema_version: Literal[1]
    context: CallContext
    request_identity_sha256: Digest
    usage: MetadataUsage | None
    usage_projection_sha256: Digest
    usage_redacted_fields: bool
    status: Status
    duration_ms: Annotated[float, Field(ge=0, allow_inf_nan=False)]
    error_code: ErrorCode | None = None


class NonModelSpan(WireModel):
    schema_version: Literal[1]
    kind: Literal["non_model"]
    context: CallContext
    duration_ms: Annotated[float, Field(ge=0, allow_inf_nan=False)]
    status: Literal["ok", "failed", "cancelled"]
    input_tokens: None = None
    output_tokens: None = None
    resource_cost_usd: Money | None = None

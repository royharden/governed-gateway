"""Validated wire and body-free provider/accounting request records."""
from __future__ import annotations

from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .core import (ErrorCode, Hash, Identifier, Money, NonnegativeInt, Provider,
                   Record, SafeLabel, UTC, canonical_bytes, digest)


class WireMessage(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra="forbid", hide_input_in_errors=True)
    role: Literal["system", "user", "assistant"]
    content: Annotated[str, Field(min_length=1, max_length=65536, repr=False)]

    @model_validator(mode="before")
    @classmethod
    def reject_version(cls, value):
        if isinstance(value, dict) and "schema_version" in value:
            raise ValueError("unsupported_request")
        return value


def _messages(messages: tuple[WireMessage, ...]) -> None:
    rest = messages[1:] if messages[0].role == "system" else messages
    if not rest or any(message.role != ("user" if i % 2 == 0 else "assistant")
                       for i, message in enumerate(rest)) or rest[-1].role != "user":
        raise ValueError("invalid_message_order")


class ChatCompletionRequest(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra="forbid", hide_input_in_errors=True)
    model: Identifier
    messages: Annotated[tuple[WireMessage, ...], Field(min_length=1, max_length=32)]
    max_completion_tokens: Annotated[int, Field(gt=0, le=1024)]
    stream: Literal[False] = False
    n: Literal[1] = 1

    @model_validator(mode="before")
    @classmethod
    def exact_wire(cls, value):
        if isinstance(value, dict):
            if "schema_version" in value or ("stream" in value and value["stream"] is not False) or ("n" in value and (type(value["n"]) is not int or value["n"] != 1)):
                raise ValueError("unsupported_request")
            if len(canonical_bytes(value)) > 65536:
                raise ValueError("request_too_large")
        return value

    @model_validator(mode="after")
    def check_wire(self):
        _messages(self.messages)
        return self


class RequestFeatures(Record):
    route_alias: Identifier
    input_utf8_bytes: Annotated[int, Field(ge=1, le=65536)]
    message_count: Annotated[int, Field(ge=1, le=32)]
    has_system: bool
    max_completion_tokens: Annotated[int, Field(gt=0, le=1024)]
    length_bucket: Literal["small", "medium", "large"]
    input_token_bound: NonnegativeInt | None


def request_features(request: GatewayRequest, *, input_token_bound: int | None = None) -> RequestFeatures:
    size = sum(len(message.content.encode("utf-8")) for message in request.messages)
    return RequestFeatures(route_alias=request.route_alias, input_utf8_bytes=size,
                           message_count=len(request.messages), has_system=request.messages[0].role == "system",
                           max_completion_tokens=request.max_completion_tokens,
                           length_bucket="small" if size <= 1024 else "medium" if size <= 8192 else "large",
                           input_token_bound=input_token_bound)


def request_digest(*, route_alias: str, messages: tuple[WireMessage, ...],
                   max_completion_tokens: int) -> str:
    return digest({"schema_version": 1, "model": route_alias,
                   "messages": tuple({"role": m.role, "content": m.content} for m in messages),
                   "max_completion_tokens": max_completion_tokens, "stream": False, "n": 1})


class GatewayRequest(Record):
    authority_id: Identifier
    caller_id: Identifier
    idempotency_key: Identifier
    request_sha256: Hash
    route_alias: Identifier
    messages: Annotated[tuple[WireMessage, ...], Field(min_length=1, max_length=32)]
    max_completion_tokens: Annotated[int, Field(gt=0, le=1024)]
    stream: Literal[False] = False
    n: Literal[1] = 1
    deadline_utc: UTC

    @model_validator(mode="after")
    def validate_request(self):
        _messages(self.messages)
        wire = {"model": self.route_alias, "messages": tuple({"role": m.role, "content": m.content} for m in self.messages),
                "max_completion_tokens": self.max_completion_tokens, "stream": False, "n": 1}
        if len(canonical_bytes(wire)) > 65536:
            raise ValueError("request_too_large")
        if self.request_sha256 != request_digest(route_alias=self.route_alias, messages=self.messages,
                                                 max_completion_tokens=self.max_completion_tokens):
            raise ValueError("request_digest_mismatch")
        return self


class AttemptChild(Record):
    child_id: Identifier
    target_id: Identifier
    purpose: Literal["serve", "eval", "count", "retry"]
    conditional: bool
    max_attempts: Literal[1] = 1
    provider: Provider
    model: Identifier
    maximum_liability_usd: Money
    request_evidence_sha256: Hash


class PermitState(str, Enum):
    PERMITTED = "permitted"
    FUNDED = "funded"
    ABANDONED = "abandoned"
    TERMINAL = "terminal"


class PermitPlan(Record):
    operation_id: Identifier
    policy_bundle_sha256: Hash
    chosen_target_ids: Annotated[tuple[Identifier, ...], Field(min_length=1, max_length=2)]
    attempt_children: Annotated[tuple[AttemptChild, ...], Field(min_length=1, max_length=2)]
    adapter_capability_sha256: Hash
    price_sha256: Hash
    bound_sha256: Hash
    serialized_envelope_sha256: Hash
    created_utc: UTC
    expires_utc: UTC
    evaluation_authorization_sha256: Hash | None
    purpose: Literal["serve", "eval", "count"]

    @model_validator(mode="after")
    def validate_plan(self):
        if not 0 < (self.expires_utc - self.created_utc).total_seconds() <= 60:
            raise ValueError("invalid_deadline")
        if len({c.child_id for c in self.attempt_children}) != len(self.attempt_children):
            raise ValueError("duplicate_child")
        if self.attempt_children[0].conditional or (len(self.attempt_children) == 2 and not self.attempt_children[1].conditional):
            raise ValueError("invalid_attempt_graph")
        if len(set(self.chosen_target_ids)) != len(self.chosen_target_ids) or set(self.chosen_target_ids) != {c.target_id for c in self.attempt_children}:
            raise ValueError("invalid_target")
        if self.attempt_children[0].purpose != self.purpose or (len(self.attempt_children) == 2 and self.attempt_children[1].purpose != "retry"):
            raise ValueError("invalid_attempt_graph")
        if any(c.target_id not in self.chosen_target_ids for c in self.attempt_children):
            raise ValueError("invalid_target")
        if (self.purpose == "eval") != (self.evaluation_authorization_sha256 is not None):
            raise ValueError("invalid_authorization")
        return self


class OperationPermit(PermitPlan):
    permit_id: Identifier
    authority_id: Identifier
    caller_id: Identifier
    request_sha256: Hash
    policy_generation: NonnegativeInt
    state: PermitState


class LedgerJoin(Record):
    authority_id: Identifier
    operation_id: Identifier
    permit_sha256: Hash
    policy_bundle_sha256: Hash
    request_sha256: Hash
    serialized_envelope_sha256: Hash
    bound_sha256: Hash
    price_sha256: Hash
    allocation_id: Identifier
    child_ids: Annotated[tuple[Identifier, ...], Field(min_length=1, max_length=2)]
    ledger_context_sha256: Hash
    settlement_sha256: Hash | None


class Usage(Record):
    input_tokens: NonnegativeInt | None
    output_tokens: NonnegativeInt | None
    cache_read_tokens: NonnegativeInt | None
    cache_write_tokens: NonnegativeInt | None
    reasoning_tokens: NonnegativeInt | None


class AttemptReceipt(Record):
    operation_id: Identifier
    child_id: Identifier
    attempt_id: Identifier
    provider: Provider
    model: Identifier
    provider_request_id: Identifier | None
    policy_bundle_sha256: Hash
    request_sha256: Hash
    dispatch_sha256: Hash
    permit_sha256: Hash
    price_sha256: Hash
    bound_sha256: Hash
    serialized_envelope_sha256: Hash
    state: Literal["active", "known", "unknown"]
    started_utc: UTC
    completed_utc: UTC | None
    status: Literal["ok", "refused", "truncated", "provider_error", "cancelled", "timeout"]
    usage: Usage
    cost_status: Literal["known", "unknown"]
    known_usage_cost_usd: Money | None
    reserved_usd: Money
    error_code: ErrorCode | None
    settlement_sha256: Hash | None

    @model_validator(mode="after")
    def valid_receipt(self):
        if (self.cost_status == "known") != (self.known_usage_cost_usd is not None):
            raise ValueError("invalid_cost_status")
        if self.state == "unknown" and self.cost_status != "unknown":
            raise ValueError("invalid_cost_status")
        if (self.state == "active") != (self.completed_utc is None):
            raise ValueError("invalid_timestamps")
        if self.state == "known" and self.cost_status != "known":
            raise ValueError("invalid_cost_status")
        if self.completed_utc is not None and self.completed_utc < self.started_utc:
            raise ValueError("invalid_timestamps")
        return self


class ResultChoice(Record):
    text: Annotated[str, Field(max_length=1048576, repr=False)] | None
    refusal: Annotated[str, Field(max_length=65536, repr=False)] | None
    finish_reason: Literal["stop", "length", "refusal", "error"]
    native_finish_reason: SafeLabel | None

    @model_validator(mode="after")
    def choice(self):
        if self.finish_reason == "refusal" and (self.refusal is None or self.text is not None):
            raise ValueError("invalid_refusal")
        if self.finish_reason in ("stop", "length") and self.text is None:
            raise ValueError("missing_result_text")
        return self


class ResultCost(Record):
    status: Literal["known", "unknown"]
    amount_usd: Money | None
    price_sha256: Hash

    @model_validator(mode="after")
    def valid_cost(self):
        if (self.status == "known") != (self.amount_usd is not None):
            raise ValueError("invalid_cost_status")
        return self


class SafeError(Record):
    code: ErrorCode
    safe_message: Annotated[str, Field(min_length=1, max_length=128)]

    @model_validator(mode="before")
    @classmethod
    def fixed_message(cls, value):
        if isinstance(value, dict) and "code" in value:
            try:
                code = ErrorCode(value["code"])
            except (ValueError, TypeError):
                raise ValueError("invalid_error_code") from None
            expected = code.value.replace("_", " ")
            if "safe_message" in value and value["safe_message"] != expected:
                raise ValueError("invalid_safe_message")
            value = {**value, "safe_message": expected}
        return value


class GatewayResult(Record):
    operation_id: Identifier
    provider: Provider
    model: Identifier
    policy_bundle_sha256: Hash
    choice: ResultChoice
    usage: Usage
    cost: ResultCost
    attempt_ids: Annotated[tuple[Identifier, ...], Field(min_length=1, max_length=2)]
    replayed: bool
    result_expires_utc: UTC
    error: SafeError | None

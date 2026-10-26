"""In-memory provider boundary. Payloads must never enter operational evidence."""
from __future__ import annotations

import json
from typing import Annotated, Literal
from pydantic import Field, model_validator
from .core import Hash, Identifier, NonnegativeInt, Provider as Provider, Record, SafeLabel, UTC, canonical_bytes, digest

BillableComponent = Literal["input_tokens", "output_tokens", "cache_read_tokens", "cache_write_tokens", "reasoning_tokens"]


class CapabilityProfile(Record):
    provider: Literal["openai", "anthropic"]
    exact_model: Identifier
    api_version: SafeLabel
    mode: Literal["simulation", "external"]
    capability_sha256: Hash
    adapter_sha256: Hash
    price_sha256: Hash
    bound_sha256: Hash
    max_input_bytes: Annotated[int, Field(gt=0, le=65536)]
    max_messages: Annotated[int, Field(gt=0, le=32)]
    max_output_tokens: Annotated[int, Field(gt=0, le=1024)]
    expires_utc: UTC
    supported_billable_components: Annotated[tuple[BillableComponent, ...], Field(min_length=1, max_length=5)]
    @model_validator(mode="after")
    def profile(self):
        if len(set(self.supported_billable_components)) != len(self.supported_billable_components):
            raise ValueError("duplicate_component")
        if self.mode == "simulation" and not self.exact_model.startswith("mock-"):
            raise ValueError("invalid_simulation_profile")
        return self


def _reject_constant(value: str):
    raise ValueError("invalid_payload_json")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_payload_key")
        result[key] = value
    return result


class ProviderEnvelope(Record):
    provider: Literal["openai", "anthropic"]
    model: Identifier
    api_version: SafeLabel
    request_sha256: Hash
    capability_sha256: Hash
    adapter_sha256: Hash
    price_sha256: Hash
    bound_sha256: Hash
    payload_json: Annotated[str, Field(min_length=2, max_length=131072, repr=False)]
    serialized_envelope_sha256: Hash
    @model_validator(mode="after")
    def envelope(self):
        try:
            payload = json.loads(self.payload_json, parse_constant=_reject_constant, object_pairs_hook=_unique_object)
            if not isinstance(payload, dict) or canonical_bytes(payload).decode("utf-8") != self.payload_json:
                raise ValueError("invalid_payload_json")
        except (ValueError, TypeError, UnicodeError):
            raise ValueError("invalid_payload_json") from None
        if envelope_digest(self) != self.serialized_envelope_sha256:
            raise ValueError("envelope_digest_mismatch")
        return self


def envelope_digest(envelope: ProviderEnvelope) -> str:
    return digest(envelope.model_dump(mode="python", exclude={"serialized_envelope_sha256"}, exclude_none=False))


class ProviderUsage(Record):
    input_tokens: NonnegativeInt | None
    output_tokens: NonnegativeInt | None
    complete: bool
    unknown_components: Annotated[tuple[Literal["input_tokens", "output_tokens", "cache_read_tokens", "cache_write_tokens", "reasoning_tokens", "unknown_component"], ...], Field(max_length=6)]
    @model_validator(mode="after")
    def complete_usage(self):
        if self.complete and (self.input_tokens is None or self.output_tokens is None or self.unknown_components):
            raise ValueError("incomplete_usage")
        if len(set(self.unknown_components)) != len(self.unknown_components):
            raise ValueError("duplicate_component")
        return self


class ProviderResult(Record):
    provider: Literal["openai", "anthropic"]
    model: Identifier
    status: Literal["ok", "refused", "truncated", "provider_error", "cancelled", "timeout"]
    text: Annotated[str, Field(max_length=1048576, repr=False)] | None
    refusal: Annotated[str, Field(max_length=65536, repr=False)] | None
    finish_reason: Literal["stop", "length", "refusal", "error"]
    native_finish_reason: Literal["stop", "length", "content_filter", "refusal", "end_turn", "max_tokens", "error", "cancelled", "timeout", "unknown"] | None
    provider_request_id: Identifier | None
    usage: ProviderUsage
    error_code: Literal["external_disabled", "invalid_profile", "invalid_envelope", "deadline_exceeded", "cancelled", "provider_error", "malformed_response", "unsupported_response", "timeout", "disconnected", "rate_limited", "service_unavailable", "pre_send_failure", "unknown_finish_reason"] | None
    dispatch_state: Literal["not_sent", "response_received", "ambiguous"]
    retry_evidence: Literal["none", "pre_send_certain", "no_charge_429", "no_charge_503"]
    @model_validator(mode="after")
    def outcome(self):
        expected = {"ok": "stop", "refused": "refusal", "truncated": "length", "provider_error": "error", "cancelled": "error", "timeout": "error"}
        if self.finish_reason != expected[self.status]:
            raise ValueError("invalid_finish_reason")
        if self.dispatch_state == "ambiguous" and self.retry_evidence != "none":
            raise ValueError("ambiguous_retry")
        if self.retry_evidence == "pre_send_certain" and self.dispatch_state != "not_sent":
            raise ValueError("invalid_retry_evidence")
        return self

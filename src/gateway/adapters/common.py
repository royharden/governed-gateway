"""Shared adapter mechanics. No network, key access, retry or accounting effect."""

import json
from datetime import datetime, timezone

from gateway.schemas import (
    CapabilityProfile, DispatchTicket, GatewayRequest, ProviderEnvelope, ProviderResult,
    ProviderUsage, canonical_bytes, envelope_digest,
)

from .errors import AdapterError
from .ports import CancellationToken

SCENARIOS = frozenset({
    "success", "refusal", "truncation", "missing_usage", "partial_usage",
    "malformed_usage", "unknown_usage", "rate_limit", "unavailable",
    "pre_send_failure", "timeout", "disconnect", "cancelled", "malformed_response",
})


def canonical_payload(value: object) -> str:
    return canonical_bytes(value).decode("utf-8")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def valid_utc(value: datetime) -> bool:
    return isinstance(value, datetime) and value.tzinfo is not None and value.utcoffset() is not None and value.utcoffset().total_seconds() == 0


def unknown_usage() -> ProviderUsage:
    return ProviderUsage(input_tokens=None, output_tokens=None, complete=False,
                         unknown_components=())


def error_result(envelope: ProviderEnvelope, code: str, *,
                 status: str = "provider_error", dispatch_state: str = "response_received",
                 retry_evidence: str = "none", usage: ProviderUsage | None = None) -> ProviderResult:
    # Callers pass literals from this package, never provider error strings.
    return ProviderResult(
        schema_version=1, provider=envelope.provider, model=envelope.model,
        status=status, text=None, refusal=None, finish_reason="error",
        native_finish_reason=None, provider_request_id=None,
        usage=usage if usage is not None else unknown_usage(), error_code=code,
        dispatch_state=dispatch_state, retry_evidence=retry_evidence,
    )


class _CompletedGeneration:
    """The mock result already exists; awaiting it performs no handoff or work."""

    __slots__ = ("_result",)

    def __init__(self, result: ProviderResult) -> None:
        self._result = result

    async def result(self) -> ProviderResult:
        return self._result

    def cancel(self) -> None:
        # Synchronous mock computation is already terminal. Do not rewrite its
        # usage/dispatch state or pretend cancellation proves a free attempt.
        return None


class BaseAdapter:
    provider: str

    def __init__(self, profile: CapabilityProfile, *, mode: str = "mock",
                 scenario: str = "success") -> None:
        if mode not in {"mock", "external"}:
            raise AdapterError("invalid_configuration", "mode")
        if scenario not in SCENARIOS:
            raise AdapterError("invalid_configuration", "scenario")
        if not isinstance(profile, CapabilityProfile) or profile.provider != self.provider:
            raise AdapterError("invalid_profile", "profile")
        if mode == "mock" and (profile.mode != "simulation" or not profile.exact_model.startswith("mock-")):
            raise AdapterError("invalid_profile", "model")
        self._profile = profile
        self._mode = mode
        self._scenario = scenario

    def capability_profile(self) -> CapabilityProfile:
        return self._profile

    def _check_profile(self) -> None:
        if self._mode != "mock":
            raise AdapterError("external_disabled", "mode")
        if not valid_utc(self._profile.expires_utc) or self._profile.expires_utc <= utc_now():
            raise AdapterError("stale_profile", "profile")
        if set(self._profile.supported_billable_components) != {"input_tokens", "output_tokens"}:
            raise AdapterError("invalid_profile", "profile")

    def _check_request(self, request: GatewayRequest) -> None:
        self._check_profile()
        if not isinstance(request, GatewayRequest):
            raise AdapterError("unsupported_request", "request")
        if not request.messages or len(request.messages) > min(32, self._profile.max_messages):
            raise AdapterError("unsupported_request", "messages")
        if type(request.max_completion_tokens) is not int or not 0 < request.max_completion_tokens <= min(1024, self._profile.max_output_tokens):
            raise AdapterError("unsupported_request", "max_completion_tokens")
        if request.stream is not False or type(request.n) is not int or request.n != 1:
            raise AdapterError("unsupported_request", "request")
        messages = list(request.messages)
        if messages[0].role == "system":
            messages = messages[1:]
        if not messages or messages[-1].role != "user":
            raise AdapterError("unsupported_request", "messages")
        for index, message in enumerate(messages):
            if message.role != ("user" if index % 2 == 0 else "assistant"):
                raise AdapterError("unsupported_request", "messages")
        for message in request.messages:
            if not isinstance(message.content, str) or not message.content:
                raise AdapterError("unsupported_request", "messages")

    def _envelope(self, request: GatewayRequest, payload: dict[str, object]) -> ProviderEnvelope:
        payload_json = canonical_payload(payload)
        if len(payload_json.encode("utf-8")) > min(65536, self._profile.max_input_bytes):
            raise AdapterError("unsupported_request", "messages")
        fields = dict(
            schema_version=1, provider=self.provider, model=self._profile.exact_model,
            api_version=self._profile.api_version, request_sha256=request.request_sha256,
            capability_sha256=self._profile.capability_sha256,
            adapter_sha256=self._profile.adapter_sha256, price_sha256=self._profile.price_sha256,
            bound_sha256=self._profile.bound_sha256, payload_json=payload_json,
        )
        # Only a private unsigned projection uses model_construct. Its sole use
        # is the shared own-digest helper (which requires an envelope instance).
        # Never return that projection or use it as authority/dispatch evidence.
        unsigned = ProviderEnvelope.model_construct(**fields, serialized_envelope_sha256="0" * 64)
        return ProviderEnvelope(**fields, serialized_envelope_sha256=envelope_digest(unsigned))

    def _check_envelope(self, envelope: ProviderEnvelope) -> None:
        if not isinstance(envelope, ProviderEnvelope):
            raise AdapterError("invalid_envelope", "envelope")
        expected = {
            "provider": self.provider, "model": self._profile.exact_model,
            "api_version": self._profile.api_version,
            "capability_sha256": self._profile.capability_sha256,
            "adapter_sha256": self._profile.adapter_sha256,
            "price_sha256": self._profile.price_sha256, "bound_sha256": self._profile.bound_sha256,
        }
        if any(getattr(envelope, field) != value for field, value in expected.items()):
            raise AdapterError("invalid_envelope", "envelope")
        if envelope.serialized_envelope_sha256 != envelope_digest(envelope):
            raise AdapterError("invalid_envelope", "envelope")
        try:
            payload = json.loads(envelope.payload_json)
            canonical = canonical_payload(payload)
        except (ValueError, TypeError, RecursionError):
            raise AdapterError("invalid_envelope", "envelope") from None
        if canonical != envelope.payload_json or not isinstance(payload, dict):
            raise AdapterError("invalid_envelope", "envelope")

    def _generate_mock_now(self, envelope: ProviderEnvelope, *, deadline: datetime,
                           cancel_token: CancellationToken) -> ProviderResult:
        # Deliberately before any mock handoff; no external fallback or transport exists.
        if self._mode != "mock":
            return error_result(envelope, "external_disabled", dispatch_state="not_sent")
        self._check_profile()
        self._check_envelope(envelope)
        if not valid_utc(deadline):
            raise AdapterError("invalid_deadline", "deadline")
        if deadline <= utc_now():
            return error_result(envelope, "deadline_exceeded", status="timeout", dispatch_state="not_sent")
        if cancel_token.is_cancelled():
            return error_result(envelope, "cancelled", status="cancelled", dispatch_state="not_sent")
        # Mock handoff AND deterministic response computation finish here,
        # synchronously under the caller's authority lock. Never sleeps/retries.
        from .mock import generate_mock
        return generate_mock(envelope, self._scenario)

    def begin_generate(self, envelope: ProviderEnvelope, *, ticket: DispatchTicket,
                       deadline: datetime, cancel_token: CancellationToken) -> _CompletedGeneration:
        """Called under DL4's lock after its unique committed ledger claim.

        Ticket type/digest checks establish binding only, never ledger provenance
        or single-use authority. The controller must obtain the successful new
        begin_attempt return itself; neither a copied record nor this adapter
        grants permission to send. No live transport exists in this phase.
        """
        if not isinstance(ticket, DispatchTicket) or not isinstance(envelope, ProviderEnvelope):
            raise AdapterError("invalid_envelope", "envelope")
        if ticket.envelope_sha256 != envelope.serialized_envelope_sha256:
            raise AdapterError("invalid_envelope", "envelope")
        return _CompletedGeneration(self._generate_mock_now(
            envelope, deadline=deadline, cancel_token=cancel_token,
        ))

    async def generate(self, envelope: ProviderEnvelope, *, deadline: datetime,
                       cancel_token: CancellationToken) -> ProviderResult:
        """Compatibility mock API; does not establish a lock-time handoff.

        JOURNEY must use begin_generate instead. This entrypoint can never send
        externally, and is retained for the approved async development port.
        """
        return self._generate_mock_now(envelope, deadline=deadline, cancel_token=cancel_token)

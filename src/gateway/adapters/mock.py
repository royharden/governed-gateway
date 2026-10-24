"""Deterministic in-memory synthetic outcomes; never claims live API behavior."""

from gateway.schemas import ProviderEnvelope, ProviderResult, ProviderUsage

from .common import error_result
from .normalization import normalize_anthropic, normalize_openai


def generate_mock(envelope: ProviderEnvelope, scenario: str) -> ProviderResult:
    """One synthetic attempt. Call only after the controller's funded claim gate."""
    if scenario == "pre_send_failure":
        # This allowlisted synthetic branch deterministically performs no send.
        # Explicit fixture knowledge is not a default for absent provider usage
        # and is not live no-charge evidence or permission to retry/refund.
        return error_result(
            envelope, "pre_send_failure", status="provider_error",
            dispatch_state="not_sent", retry_evidence="pre_send_certain",
            usage=ProviderUsage(input_tokens=0, output_tokens=0, complete=True,
                                unknown_components=()),
        )
    if scenario in {"cancelled", "timeout", "disconnect", "rate_limit", "unavailable"}:
        outcomes = {
            "cancelled": ("cancelled", "cancelled", "not_sent", "none"),
            "timeout": ("timeout", "timeout", "ambiguous", "none"),
            "disconnect": ("disconnected", "provider_error", "ambiguous", "none"),
            # These are labelled synthetic observations; never live no-charge proof.
            "rate_limit": ("rate_limited", "provider_error", "response_received", "no_charge_429"),
            "unavailable": ("service_unavailable", "provider_error", "response_received", "no_charge_503"),
        }
        code, status, state, evidence = outcomes[scenario]
        return error_result(envelope, code, status=status, dispatch_state=state, retry_evidence=evidence)
    if envelope.provider == "openai":
        response: dict[str, object] = {
            "id": "mock-openai-response", "model": envelope.model,
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "Synthetic response.", "refusal": None}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 8, "completion_tokens": 4, "total_tokens": 12},
        }
        if scenario == "refusal":
            response["choices"] = [{"index": 0, "message": {"role": "assistant", "content": None, "refusal": "Synthetic refusal."}, "finish_reason": "stop"}]
        elif scenario == "truncation":
            response["choices"] = [{"index": 0, "message": {"role": "assistant", "content": "Synthetic partial", "refusal": None}, "finish_reason": "length"}]
        input_key, output_key = "prompt_tokens", "completion_tokens"
        normalize = normalize_openai
    elif envelope.provider == "anthropic":
        response = {
            "id": "mock-anthropic-response", "type": "message", "role": "assistant", "model": envelope.model,
            "content": [{"type": "text", "text": "Synthetic response."}], "stop_reason": "end_turn",
            "usage": {"input_tokens": 8, "output_tokens": 4},
        }
        if scenario == "refusal":
            response["content"] = [{"type": "text", "text": "Synthetic refusal."}]
            response["stop_reason"] = "refusal"
        elif scenario == "truncation":
            response["content"] = [{"type": "text", "text": "Synthetic partial"}]
            response["stop_reason"] = "max_tokens"
        input_key, output_key = "input_tokens", "output_tokens"
        normalize = normalize_anthropic
    else:
        return error_result(envelope, "invalid_profile", dispatch_state="not_sent")
    if scenario == "missing_usage":
        response.pop("usage")
    elif scenario == "partial_usage":
        response["usage"] = {input_key: 8}
    elif scenario == "malformed_usage":
        response["usage"] = {input_key: True, output_key: "4"}
    elif scenario == "unknown_usage":
        response["usage"] = {input_key: 8, output_key: 4, "synthetic_unrecognized_billable": 2}
    elif scenario == "malformed_response":
        response = {"error": {"message": "Synthetic body must never surface in safe errors."}}
    return normalize(response, envelope=envelope)

"""Public, authored wire vectors. No real transports or provider price claims."""
from datetime import datetime, timedelta, timezone
import json

import pytest

from gateway.adapters.anthropic import AnthropicAdapter
from gateway.adapters.openai import OpenAIAdapter
from gateway.adapters.normalization import normalize_anthropic, normalize_openai
from gateway.schemas import CapabilityProfile, GatewayRequest, WireMessage, request_digest

TEXTS = ["plain", "\u754c", "\U0001f600", "e\u0301", "\n\t", "!@#$%^&*()", " a ", "a\r\nb", "0", "\u05e9\u05dc\u05d5\u05dd",
         "\u0645\u0631\u062d\u0628\u0627", "\u0939\u093f\u0928\u094d\u0926\u0940", "\u00e9", "\\\"", "<>/", "x" * 1024, "\u200d", "\U0001f1fa\U0001f1f8", "null", "false"]


def adapter_and_envelope(provider, text="synthetic"):
    now = datetime.now(timezone.utc)
    profile = CapabilityProfile(provider=provider, exact_model="mock-" + provider + "-v1", api_version="mock-v1", mode="simulation",
        capability_sha256="a"*64, adapter_sha256="b"*64, price_sha256="c"*64, bound_sha256="d"*64,
        max_input_bytes=65536, max_messages=32, max_output_tokens=1024, expires_utc=now + timedelta(hours=1),
        supported_billable_components=("input_tokens", "output_tokens"))
    adapter = (OpenAIAdapter if provider == "openai" else AnthropicAdapter)(profile)
    messages = (WireMessage(role="system", content="synthetic system"), WireMessage(role="user", content=text))
    request = GatewayRequest(authority_id="authority", caller_id="caller", idempotency_key="key", route_alias="default", messages=messages,
        max_completion_tokens=128, request_sha256=request_digest(route_alias="default", messages=messages, max_completion_tokens=128),
        deadline_utc=now + timedelta(seconds=60))
    return adapter, adapter.serialize(request)


def response(provider, text="synthetic"):
    if provider == "openai":
        return {"id": "synthetic-response", "model": "mock-openai-v1", "choices": [{"index": 0, "message": {"role": "assistant", "content": text}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 8, "completion_tokens": 4, "total_tokens": 12}}
    return {"id": "synthetic-response", "model": "mock-anthropic-v1", "type": "message", "role": "assistant", "content": [{"type": "text", "text": text}],
            "stop_reason": "end_turn", "usage": {"input_tokens": 8, "output_tokens": 4}}


def normalize(provider, body, envelope):
    return (normalize_openai if provider == "openai" else normalize_anthropic)(body, envelope=envelope)


@pytest.mark.parametrize("provider", ["openai", "anthropic"])
@pytest.mark.parametrize("text", TEXTS, ids=[f"wire-{i:02d}" for i in range(20)])
def test_twenty_exact_normalization_vectors_per_profile(provider, text):
    _, envelope = adapter_and_envelope(provider, text)
    payload = json.loads(envelope.payload_json)
    assert payload["messages"][-1]["content"] == text
    if provider == "anthropic":
        assert payload["system"] == "synthetic system"
        assert payload["max_tokens"] == 128
    else:
        assert payload["messages"][0]["role"] == "system"
        assert payload["max_completion_tokens"] == 128
    result = normalize(provider, response(provider, text), envelope)
    assert result.text == text and result.status == "ok"
    assert result.usage.complete and result.usage.input_tokens == 8 and result.usage.output_tokens == 4


@pytest.mark.parametrize("provider", ["openai", "anthropic"])
@pytest.mark.parametrize("case", ["missing", "partial", "negative", "bool", "extra", "wrong-model", "truncation", "refusal"])
def test_billing_and_finish_semantics(provider, case):
    _, envelope = adapter_and_envelope(provider)
    body = response(provider)
    output_key = "completion_tokens" if provider == "openai" else "output_tokens"
    if case == "missing":
        body.pop("usage")
    elif case == "partial":
        body["usage"].pop(output_key)
    elif case == "negative":
        body["usage"][output_key] = -1
    elif case == "bool":
        body["usage"][output_key] = True
    elif case == "extra":
        body["usage"]["unrecognized_billed_tokens"] = 5
    elif case == "wrong-model":
        body["model"] = "unapproved"
    elif provider == "openai":
        body["choices"][0]["finish_reason"] = "length" if case == "truncation" else "content_filter"
    else:
        body["stop_reason"] = "max_tokens" if case == "truncation" else "refusal"
    result = normalize(provider, body, envelope)
    if case in ("missing", "partial", "negative", "bool", "extra"):
        assert not result.usage.complete
    elif case == "wrong-model":
        assert result.status == "provider_error"
    else:
        assert result.status == ("truncated" if case == "truncation" else "refused")


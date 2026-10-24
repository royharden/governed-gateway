"""Pure translation of synthetic provider bodies; no I/O or monetary settlement."""

import re

from gateway.schemas import ProviderEnvelope, ProviderResult, ProviderUsage

from .common import error_result, unknown_usage

_OPAQUE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_MAX_RESPONSE_BYTES = 262144


def _token(value: object) -> int | None:
    return value if type(value) is int and 0 <= value <= 2**63 - 1 else None


def _usage(response: dict[str, object], provider: str) -> ProviderUsage:
    usage = response.get("usage")
    if not isinstance(usage, dict):
        return unknown_usage()
    if provider == "openai":
        input_key, output_key = "prompt_tokens", "completion_tokens"
        allowed = {input_key, output_key, "total_tokens"}
    else:
        input_key, output_key = "input_tokens", "output_tokens"
        allowed = {input_key, output_key}
    input_tokens, output_tokens = _token(usage.get(input_key)), _token(usage.get(output_key))
    extra = bool(set(usage) - allowed)
    complete = input_tokens is not None and output_tokens is not None and not extra
    if provider == "openai" and "total_tokens" in usage:
        total = _token(usage["total_tokens"])
        if total is None or input_tokens is None or output_tokens is None or total != input_tokens + output_tokens:
            complete = False
    return ProviderUsage(input_tokens=input_tokens, output_tokens=output_tokens,
                         complete=complete,
                         unknown_components=("unknown_component",) if extra else ())


def _id(value: object) -> str | None:
    return value if isinstance(value, str) and _OPAQUE.fullmatch(value) else None


def _text(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return len(value.encode("utf-8")) <= _MAX_RESPONSE_BYTES
    except UnicodeError:
        return False


def _result(envelope: ProviderEnvelope, *, text: str | None, refusal: str | None,
            finish: str, native: str, request_id: object, usage: ProviderUsage) -> ProviderResult:
    return ProviderResult(
        schema_version=1, provider=envelope.provider, model=envelope.model,
        status={"stop": "ok", "length": "truncated", "refusal": "refused"}[finish],
        text=text, refusal=refusal, finish_reason=finish, native_finish_reason=native,
        provider_request_id=_id(request_id), usage=usage, error_code=None,
        dispatch_state="response_received", retry_evidence="none",
    )


def normalize_openai(response: object, *, envelope: ProviderEnvelope) -> ProviderResult:
    if not isinstance(response, dict):
        return error_result(envelope, "malformed_response")
    usage = _usage(response, "openai")
    if envelope.provider != "openai" or response.get("model") != envelope.model:
        return error_result(envelope, "invalid_profile", usage=usage)
    choices = response.get("choices")
    if not isinstance(choices, list) or len(choices) != 1 or not isinstance(choices[0], dict):
        return error_result(envelope, "malformed_response", usage=usage)
    choice = choices[0]
    if type(choice.get("index")) is not int or choice["index"] != 0:
        return error_result(envelope, "malformed_response", usage=usage)
    message = choice.get("message")
    if not isinstance(message, dict) or message.get("role") != "assistant":
        return error_result(envelope, "malformed_response", usage=usage)
    if set(message) - {"role", "content", "refusal"}:
        return error_result(envelope, "unsupported_response", usage=usage)
    text, refusal = message.get("content"), message.get("refusal")
    if (text is not None and not _text(text)) or (refusal is not None and (not _text(refusal) or len(refusal) > 65536)):
        return error_result(envelope, "malformed_response", usage=usage)
    native = choice.get("finish_reason")
    if not isinstance(native, str) or native not in {"stop", "length", "content_filter"}:
        return error_result(envelope, "unknown_finish_reason", usage=usage)
    if refusal or native == "content_filter":
        finish = "refusal"
        # Explicit normalized content, not an error or diagnostic field.
        refusal = refusal or "Provider declined this request."
        text = None
    else:
        finish = native
        if text is None:
            return error_result(envelope, "malformed_response", usage=usage)
    return _result(envelope, text=text, refusal=refusal, finish=finish, native=native,
                   request_id=response.get("id"), usage=usage)


def normalize_anthropic(response: object, *, envelope: ProviderEnvelope) -> ProviderResult:
    if not isinstance(response, dict):
        return error_result(envelope, "malformed_response")
    usage = _usage(response, "anthropic")
    if envelope.provider != "anthropic" or response.get("model") != envelope.model:
        return error_result(envelope, "invalid_profile", usage=usage)
    if response.get("type") != "message" or response.get("role") != "assistant":
        return error_result(envelope, "malformed_response", usage=usage)
    native = response.get("stop_reason")
    finishes = {"end_turn": "stop", "max_tokens": "length", "refusal": "refusal"}
    if not isinstance(native, str) or native not in finishes:
        return error_result(envelope, "unknown_finish_reason", usage=usage)
    content = response.get("content")
    if not isinstance(content, list) or len(content) > 32:
        return error_result(envelope, "malformed_response", usage=usage)
    pieces: list[str] = []
    for block in content:
        if not isinstance(block, dict) or set(block) != {"type", "text"} or block.get("type") != "text":
            return error_result(envelope, "unsupported_response", usage=usage)
        if not _text(block["text"]):
            return error_result(envelope, "malformed_response", usage=usage)
        pieces.append(block["text"])
    text = "".join(pieces)
    if not _text(text) or (not content and native != "refusal"):
        return error_result(envelope, "malformed_response", usage=usage)
    finish = finishes[native]
    if finish == "refusal" and len(text) > 65536:
        return error_result(envelope, "malformed_response", usage=usage)
    return _result(envelope, text=None if finish == "refusal" else text,
                   refusal=(text or "Provider declined this request.") if finish == "refusal" else None,
                   finish=finish, native=native, request_id=response.get("id"), usage=usage)

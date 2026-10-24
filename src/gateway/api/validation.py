"""Bounded exact JSON validation shared by HTTP and controller inputs."""
from __future__ import annotations

import json
from pydantic import ValidationError
from gateway.schemas import ChatCompletionInput, ErrorCode, GatewayError

MAX_BODY_BYTES = 65536


def _constant(_: str):
    raise ValueError("invalid_json")


def _object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate_key")
        value[key] = item
    return value


def parse_body(raw: bytes) -> ChatCompletionInput:
    if len(raw) > MAX_BODY_BYTES or not raw:
        raise GatewayError(ErrorCode.INVALID_REQUEST)
    try:
        value = json.loads(raw.decode("utf-8"), parse_constant=_constant,
                           object_pairs_hook=_object)
        if not isinstance(value, dict):
            raise ValueError("invalid_json")
        # Strict Pydantic tuple fields need an explicit wire-array conversion.
        if type(value.get("messages")) is not list:
            raise ValueError("invalid_messages")
        if type(value.get("max_completion_tokens")) is not int:
            raise ValueError("invalid_cap")
        value["messages"] = tuple(value["messages"])
        return ChatCompletionInput.model_validate(value)
    except (ValueError, TypeError, UnicodeError, RecursionError, ValidationError):
        raise GatewayError(ErrorCode.INVALID_REQUEST) from None

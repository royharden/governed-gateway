"""A09/A11 wire rejection must precede any controller/funding capability."""
import asyncio
import copy
import hashlib
import json

import pytest

from gateway.api.app import create_app
from gateway.api.auth import ClientAuthenticator
from gateway.api.validation import parse_body
from gateway.schemas import CallerContext, GatewayError

VALID = {"model": "default", "messages": [{"role": "user", "content": "synthetic"}], "max_completion_tokens": 128}


def invalid_cases():
    cases = []
    for name, value in [("tools", []), ("tool_choice", "auto"), ("temperature", 0), ("stop", "x"),
                        ("metadata", {}), ("base_url", "https://example.invalid"), ("provider_headers", {}),
                        ("response_format", {}), ("stream", True), ("stream", 0), ("n", 2), ("n", True),
                        ("schema_version", 1), ("max_completion_tokens", 0), ("max_completion_tokens", 1025),
                        ("max_completion_tokens", True), ("max_completion_tokens", "128")]:
        cases.append((f"{name}-{value}", {**copy.deepcopy(VALID), name: value}))
    for messages in [[], [{"role": "assistant", "content": "x"}], [{"role": "system", "content": "x"}],
                     [{"role": "user", "content": ""}], [{"role": "tool", "content": "x"}],
                     [{"role": "user", "content": [{"type": "text", "text": "x"}]}],
                     [{"role": "user", "content": "x", "name": "spoof"}],
                     [{"role": "user", "content": "x"}] * 33,
                     [{"role": "user", "content": "x"}, {"role": "system", "content": "x"}]]:
        cases.append((f"messages-{len(cases)}", {**copy.deepcopy(VALID), "messages": messages}))
    return cases


INVALID = invalid_cases()
assert len(INVALID) >= 25


@pytest.mark.parametrize("name,body", INVALID, ids=[x[0] for x in INVALID])
def test_unsupported_rejected(name, body):
    with pytest.raises(GatewayError):
        parse_body(json.dumps(body).encode())


@pytest.mark.parametrize("raw", [b"", b"null", b"[]", b"{", b"\xff", b'{"model":"a","model":"b"}',
                                 b'{"messages":[],"max_completion_tokens":NaN}', b" " * 65537,
                                 json.dumps({**VALID, "messages": [{"role": "user", "content": "\u754c" * 22000}]}).encode()],
                         ids=["empty", "null", "array", "truncated", "invalid-utf8", "duplicate-key", "nan", "oversized", "oversized-unicode"])
def test_invalid_bytes(raw):
    with pytest.raises(GatewayError):
        parse_body(raw)


def test_defaults_and_exact_unicode():
    body = {**VALID, "messages": [{"role": "user", "content": "\u754c\U0001f600 e\u0301\n"}]}
    parsed = parse_body(json.dumps(body).encode())
    assert parsed.messages[0].content == body["messages"][0]["content"]
    assert parsed.n == 1 and parsed.stream is False


async def http_request(raw, *, headers=None, controller=None):
    caller = CallerContext(authority_id="m8-test", caller_id="client")
    token = "synthetic-client-token-for-tests-0001"
    auth = ClientAuthenticator({hashlib.sha256(token.encode()).hexdigest(): caller}, key_digest_secret=b"s" * 32)
    class ForbiddenController:
        calls = 0
        async def complete(self, *args, **kwargs):
            self.calls += 1
            raise AssertionError("Invalid wire reached controller")
    controller = controller or ForbiddenController()
    app = create_app(controller, auth)
    default_headers = [(b"content-type", b"application/json"), (b"authorization", ("Bearer " + token).encode()), (b"idempotency-key", b"synthetic-key")]
    events = []
    async def receive():
        return {"type": "http.request", "body": raw, "more_body": False}
    async def send(event):
        events.append(event)
    await app({"type": "http", "path": "/v1/chat/completions", "method": "POST", "headers": default_headers if headers is None else headers}, receive, send)
    return events, controller


@pytest.mark.parametrize("name,body", INVALID, ids=[x[0] for x in INVALID])
def test_http_invalid_has_zero_controller_calls(name, body):
    events, spy = asyncio.run(http_request(json.dumps(body).encode()))
    assert events[0]["status"] == 400
    assert spy.calls == 0


@pytest.mark.parametrize("headers,status", [([], 400), ([(b"content-type", b"application/json")], 401),
    ([(b"content-type", b"application/json"), (b"content-type", b"application/json")], 400),
    ([(b"content-type", b"application/json"), (b"content-encoding", b"gzip")], 400)])
def test_headers_fail_before_controller(headers, status):
    events, spy = asyncio.run(http_request(json.dumps(VALID).encode(), headers=headers))
    assert events[0]["status"] == status
    assert spy.calls == 0

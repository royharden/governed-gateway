"""No-listener ASGI callable. Server startup is external and remains deferred."""
from __future__ import annotations

import asyncio
import json

from gateway.schemas import ErrorCode, GatewayError
from gateway.controller.ports import CancellationToken
from .auth import ClientAuthenticator
from .errors import error_reply
from .validation import MAX_BODY_BYTES, parse_body


def _headers(scope) -> tuple[str, str]:
    headers = {}
    relevant = {b"authorization", b"idempotency-key", b"content-type", b"content-encoding"}
    total = 0
    for name, value in scope.get("headers", ()):
        total += len(name) + len(value)
        if total > 16384:
            raise GatewayError(ErrorCode.INVALID_REQUEST)
        name = name.lower()
        if name in relevant:
            if name in headers:
                raise GatewayError(ErrorCode.INVALID_REQUEST)
            headers[name] = value
    if b"content-encoding" in headers:
        raise GatewayError(ErrorCode.UNSUPPORTED_REQUEST)
    content_type = headers.get(b"content-type", b"").lower().replace(b" ", b"")
    if content_type not in (b"application/json", b"application/json;charset=utf-8"):
        raise GatewayError(ErrorCode.UNSUPPORTED_REQUEST)
    try:
        authorization = headers.get(b"authorization", b"").decode("ascii")
        key = headers.get(b"idempotency-key", b"").decode("ascii")
    except UnicodeError:
        raise GatewayError(ErrorCode.INVALID_REQUEST) from None
    return authorization, key


def create_app(controller, authenticator: ClientAuthenticator):
    async def app(scope, receive, send):
        if scope["type"] == "lifespan":
            # No implicit migrations, recovery, services or serving policy bootstrap.
            while True:
                event = await receive()
                if event["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                elif event["type"] == "lifespan.shutdown":
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        if scope["type"] != "http":
            return
        if scope.get("path") != "/v1/chat/completions" or scope.get("method") != "POST":
            await _send(send, 404, {"error": {"code": "not_found"}})
            return
        cancel = CancellationToken()
        disconnected = False
        try:
            authorization, key = _headers(scope)
            caller = authenticator.authenticate(authorization)
            # Validate key before reading any large body or creating policy state.
            authenticator.key_digest(caller, key)
            chunks, size = [], 0
            async with asyncio.timeout(60):
                while True:
                    event = await receive()
                    if event["type"] == "http.disconnect":
                        return
                    if event["type"] != "http.request":
                        raise GatewayError(ErrorCode.INVALID_REQUEST)
                    chunk = event.get("body", b"")
                    if not isinstance(chunk, bytes):
                        raise GatewayError(ErrorCode.INVALID_REQUEST)
                    size += len(chunk)
                    if size > MAX_BODY_BYTES:
                        raise GatewayError(ErrorCode.INVALID_REQUEST)
                    chunks.append(chunk)
                    if not event.get("more_body", False):
                        break
            body = parse_body(b"".join(chunks))

            async def observe_disconnect():
                nonlocal disconnected
                while True:
                    event = await receive()
                    if event["type"] == "http.disconnect":
                        disconnected = True
                        cancel.cancel()
                        return

            observer = asyncio.create_task(observe_disconnect())
            try:
                reply = await controller.complete(caller, body, key, cancel=cancel)
            finally:
                observer.cancel()
                await asyncio.gather(observer, return_exceptions=True)
            if not disconnected:
                await _send(send, reply.http_status, reply.model_dump(mode="json"))
        except TimeoutError:
            await _send_error(send, ErrorCode.DEADLINE_EXCEEDED)
        except GatewayError as error:
            if not disconnected:
                await _send_error(send, error.code)
        except asyncio.CancelledError:
            cancel.cancel()
            raise
        except Exception:
            if not disconnected:
                await _send_error(send, ErrorCode.STORE_UNAVAILABLE)
    return app


async def _send_error(send, code):
    reply = error_reply(code)
    await _send(send, reply.http_status, {"error": {"code": code.value,
        "safe_message": code.value.replace("_", " ")}})


async def _send(send, status, value):
    # model_dump(json) is required for enums/dates; no request values in safe errors.
    payload = json.dumps(value, ensure_ascii=False, allow_nan=False,
                         separators=(",", ":")).encode("utf-8")
    await send({"type": "http.response.start", "status": status,
        "headers": [(b"content-type", b"application/json; charset=utf-8"),
                    (b"cache-control", b"no-store"), (b"content-length", str(len(payload)).encode("ascii"))]})
    await send({"type": "http.response.body", "body": payload})

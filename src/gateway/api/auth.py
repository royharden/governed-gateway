"""Injected server-owned identity; client strings never become operator authority."""
from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Mapping

from gateway.schemas import CallerContext, ErrorCode, GatewayError, canonical_bytes


class ClientAuthenticator:
    def __init__(self, token_digests: Mapping[str, CallerContext], *, key_digest_secret: bytes):
        if not token_digests or len(key_digest_secret) < 32:
            raise GatewayError(ErrorCode.CONFIG_MISMATCH)
        if any(not re.fullmatch(r"[0-9a-f]{64}", key) for key in token_digests):
            raise GatewayError(ErrorCode.CONFIG_MISMATCH)
        self._clients = tuple(token_digests.items())
        self._key_secret = bytes(key_digest_secret)

    def authenticate(self, authorization: str) -> CallerContext:
        # Bound work before digesting. Never retain or include a token in exceptions.
        if not authorization.startswith("Bearer "):
            raise GatewayError(ErrorCode.UNAUTHENTICATED)
        token = authorization[7:]
        if not re.fullmatch(r"[A-Za-z0-9._~+/=-]{32,512}", token):
            raise GatewayError(ErrorCode.UNAUTHENTICATED)
        candidate = hashlib.sha256(token.encode("ascii")).hexdigest()
        identity = None
        for expected, caller in self._clients:
            if hmac.compare_digest(candidate, expected):
                identity = caller
        if identity is None:
            raise GatewayError(ErrorCode.UNAUTHENTICATED)
        return identity

    def key_digest(self, caller: CallerContext, key: str, *, purpose: str = "serve") -> str:
        if purpose not in ("serve", "eval"):
            raise GatewayError(ErrorCode.FORBIDDEN)
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}", key):
            raise GatewayError(ErrorCode.INVALID_REQUEST)
        return hmac.new(self._key_secret, canonical_bytes({
            "domain": "gateway.idempotency.v1" if purpose == "serve" else "gateway.evaluation-idempotency.v1",
            "authority": caller.authority_id,
            "caller": caller.caller_id, "key": key,
        }), hashlib.sha256).hexdigest()

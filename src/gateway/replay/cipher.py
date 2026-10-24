"""AES-GCM with per-write nonce and scoped associated data; no key loaders/logging."""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
from collections.abc import Mapping

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import ValidationError

from gateway.schemas import (EncryptedResult, ErrorCode, GatewayError,
                             GatewayResult, ReplayBinding, canonical_bytes, digest)


class ReplayCipher:
    def __init__(self, keys: Mapping[str, bytes], *, active_key_id: str):
        if active_key_id not in keys or any(len(key) != 32 for key in keys.values()):
            raise GatewayError(ErrorCode.CONFIG_MISMATCH)
        self._keys = {name: bytes(value) for name, value in keys.items()}
        self._active = active_key_id

    @staticmethod
    def _aad(binding: ReplayBinding) -> bytes:
        # Exact INT005 bridge encoding; schema version in binding is domain/version.
        return canonical_bytes(binding)

    @staticmethod
    def _bound(result: GatewayResult, binding: ReplayBinding) -> None:
        if (result.operation_id, result.policy_bundle_sha256) != (
            binding.operation_id, binding.policy_bundle_sha256
        ):
            raise GatewayError(ErrorCode.INVALID_JOIN)

    def encrypt(self, result: GatewayResult, binding: ReplayBinding) -> EncryptedResult:
        self._bound(result, binding)
        plaintext = canonical_bytes(result)
        result_hash = hashlib.sha256(plaintext).hexdigest()
        aad = self._aad(binding)
        nonce = os.urandom(12)
        ciphertext = AESGCM(self._keys[self._active]).encrypt(nonce, plaintext, aad)
        return EncryptedResult(key_id=self._active,
            nonce_b64=base64.b64encode(nonce).decode("ascii"),
            ciphertext_b64=base64.b64encode(ciphertext).decode("ascii"),
            aad_sha256=hashlib.sha256(aad).hexdigest(), result_sha256=result_hash)

    def decrypt(self, record: EncryptedResult, binding: ReplayBinding) -> GatewayResult:
        try:
            aad = self._aad(binding)
            if not hmac.compare_digest(hashlib.sha256(aad).hexdigest(), record.aad_sha256):
                raise ValueError("binding")
            plaintext = AESGCM(self._keys[record.key_id]).decrypt(
                base64.b64decode(record.nonce_b64, validate=True),
                base64.b64decode(record.ciphertext_b64, validate=True), aad)
            if not hmac.compare_digest(hashlib.sha256(plaintext).hexdigest(), record.result_sha256):
                raise ValueError("digest")
            result = GatewayResult.model_validate_json(plaintext)
            if digest(result) != record.result_sha256:
                raise ValueError("canonical")
            self._bound(result, binding)
            return result
        except (KeyError, ValueError, InvalidTag, binascii.Error, ValidationError):
            raise GatewayError(ErrorCode.STORE_UNAVAILABLE) from None

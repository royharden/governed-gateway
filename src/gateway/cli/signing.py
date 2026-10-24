"""CLI-only signing source. Nothing here executes on import or signs in Dirty Mode."""
from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
import stat
from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gateway.schemas import (
    ApprovalPayload, ApprovalRecord, ErrorCode, EvaluationAuthorization,
    EvaluationAuthorizationPayload, GatewayError, digest, signed_bytes, signed_payload,
)
from gateway.runtime import require_local_runtime_root


def observed_os_account() -> str:
    """Effective OS account; environment variables are never audit identity."""
    try:
        if os.name == "posix":
            import pwd
            return pwd.getpwuid(os.geteuid()).pw_name
        if os.name == "nt":
            return os.getlogin()
    except (OSError, KeyError):
        raise GatewayError(ErrorCode.FORBIDDEN) from None
    raise GatewayError(ErrorCode.FORBIDDEN)


def confirmation_digest(payload: ApprovalPayload | EvaluationAuthorizationPayload) -> str:
    """The exact shared signed payload, including domain/account/fingerprint/time."""
    return digest(signed_payload(payload))


def _sign(payload: ApprovalPayload | EvaluationAuthorizationPayload, *,
          key_env_name: str, confirmed_tuple_sha256: str,
          protected_key_loader: Callable[[str], Ed25519PrivateKey] | None = None) -> str:
    # This comparison MUST precede environment/path/key access.
    if confirmation_digest(payload) != confirmed_tuple_sha256:
        raise GatewayError(ErrorCode.INVALID_APPROVAL)
    if payload.declared_os_account != observed_os_account():
        raise GatewayError(ErrorCode.FORBIDDEN)
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        if protected_key_loader is not None:
            # Trusted composition owns Windows ACL/token/path verification, with no request override.
            # Receiving a key object is not enough: algorithm/fingerprint are rechecked below.
            key = protected_key_loader(key_env_name)
        else:
            if os.name != "posix":
                raise GatewayError(ErrorCode.DEPENDENCY_UNAVAILABLE)
            key_name = os.environ.get(key_env_name)
            if key_name is None:
                raise GatewayError(ErrorCode.DEPENDENCY_UNAVAILABLE)
            key_path = Path(key_name)
            if not key_path.is_absolute():
                raise GatewayError(ErrorCode.FORBIDDEN)
            parent = require_local_runtime_root(key_path.parent)
            if key_path.parent.resolve(strict=True) != parent or key_path.is_symlink():
                raise GatewayError(ErrorCode.UNSAFE_RUNTIME_PATH)
            descriptor = os.open(key_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(descriptor, "rb") as source:
                info = os.fstat(source.fileno())
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                        or stat.S_IMODE(info.st_mode) & 0o077 or not 0 < info.st_size <= 16384):
                    raise GatewayError(ErrorCode.FORBIDDEN)
                raw = source.read(16385)
                if len(raw) > 16384:
                    raise GatewayError(ErrorCode.FORBIDDEN)
            key = serialization.load_pem_private_key(raw, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise GatewayError(ErrorCode.INVALID_SIGNATURE)
        public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        if hashlib.sha256(public).hexdigest() != payload.signer_fingerprint_sha256:
            raise GatewayError(ErrorCode.INVALID_SIGNATURE)
        return base64.b64encode(key.sign(signed_bytes(payload))).decode("ascii")
    except GatewayError:
        raise
    except (OSError, ValueError, TypeError, ImportError):
        raise GatewayError(ErrorCode.INVALID_SIGNATURE) from None


def sign_approval(payload: ApprovalPayload, *, key_env_name: str,
                  confirmed_tuple_sha256: str,
                  protected_key_loader: Callable[[str], Ed25519PrivateKey] | None = None) -> ApprovalRecord:
    if type(payload) is not ApprovalPayload:
        raise GatewayError(ErrorCode.INVALID_APPROVAL)
    signature = _sign(payload, key_env_name=key_env_name, confirmed_tuple_sha256=confirmed_tuple_sha256,
                      protected_key_loader=protected_key_loader)
    return ApprovalRecord(**signed_payload(payload), signature=signature)


def sign_evaluation_authorization(payload: EvaluationAuthorizationPayload, *,
                                  key_env_name: str,
                                  confirmed_tuple_sha256: str,
                                  protected_key_loader: Callable[[str], Ed25519PrivateKey] | None = None) -> EvaluationAuthorization:
    if type(payload) is not EvaluationAuthorizationPayload:
        raise GatewayError(ErrorCode.INVALID_AUTHORIZATION)
    signature = _sign(payload, key_env_name=key_env_name, confirmed_tuple_sha256=confirmed_tuple_sha256,
                      protected_key_loader=protected_key_loader)
    return EvaluationAuthorization(**signed_payload(payload), signature=signature)

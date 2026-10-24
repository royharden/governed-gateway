"""Ed25519 verification only; signed-payload encoding belongs to shared schemas.

Importing this module does not load key files, create databases, or sign anything.
The runtime receives the public key from trusted local configuration. Callers must
construct the exact domain-separated payload using the shared signing helper used
by the operator CLI, then compare the returned fingerprint to the signed claim.
"""

from hashlib import sha256

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


class SignatureVerificationError(ValueError):
    """Safe closed error without key, payload, or library exception content."""

    code = "invalid_operator_signature"

    def __init__(self) -> None:
        super().__init__(self.code)


def verify_ed25519(
    public_key: bytes, signature: bytes, signed_payload: bytes
) -> str:
    """Verify exact payload bytes and return SHA256 of the raw public key.

    This proves key possession and payload integrity, not a human action or an
    authorization grant. PolicyStore must separately check domain, authority,
    complete evidence tuple, decision, freshness, revocation, and generation.
    No fallback algorithm, private-key handling, or signature creation exists.
    """
    if (
        type(public_key) is not bytes
        or len(public_key) != 32
        or type(signature) is not bytes
        or len(signature) != 64
        or type(signed_payload) is not bytes
        or not signed_payload
    ):
        raise SignatureVerificationError()
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, signed_payload)
    except (InvalidSignature, ValueError, TypeError):
        raise SignatureVerificationError() from None
    return sha256(public_key).hexdigest()

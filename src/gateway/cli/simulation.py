"""Future injected no-key demo signer. Never registered for external mode here."""
from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

from gateway.schemas import (
    ApprovalPayload, ApprovalRecord, ErrorCode, EvaluationAuthorization,
    EvaluationAuthorizationPayload, EvidenceTuple, GatewayError,
)
from .signing import observed_os_account, sign_approval, sign_evaluation_authorization

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class SimulationSigner:
    """An ephemeral key restricted to explicitly configured synthetic evidence tuples.

    Trusted demo composition registers its public key only with a simulation store.
    This object supplies no evaluation result, eligibility flag or serving approval.
    An administrator can replace local code; this is not separation of duties.
    """
    mode = "simulation"

    def __init__(self, key: Ed25519PrivateKey, *, allowed_evidence: tuple[EvidenceTuple, ...]):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        if not isinstance(key, Ed25519PrivateKey) or not allowed_evidence:
            raise GatewayError(ErrorCode.INVALID_AUTHORIZATION)
        self._key = key
        self._allowed = allowed_evidence
        self.public_key_bytes = key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.fingerprint_sha256 = hashlib.sha256(self.public_key_bytes).hexdigest()
        self.declared_os_account = observed_os_account()

    def _check(self, payload: ApprovalPayload | EvaluationAuthorizationPayload) -> None:
        if (payload.tuple not in self._allowed or payload.signer_fingerprint_sha256 != self.fingerprint_sha256
                or payload.declared_os_account != self.declared_os_account):
            raise GatewayError(ErrorCode.INVALID_AUTHORIZATION)

    def sign_approval(self, payload: ApprovalPayload, *, confirmed_tuple_sha256: str) -> ApprovalRecord:
        self._check(payload)
        return sign_approval(payload, key_env_name="SIMULATION_ONLY_EPHEMERAL",
                             confirmed_tuple_sha256=confirmed_tuple_sha256,
                             protected_key_loader=lambda _: self._key)

    def sign_evaluation_authorization(self, payload: EvaluationAuthorizationPayload, *,
                                      confirmed_tuple_sha256: str) -> EvaluationAuthorization:
        self._check(payload)
        if payload.mode != "simulation":
            raise GatewayError(ErrorCode.EXTERNAL_DISABLED)
        return sign_evaluation_authorization(payload, key_env_name="SIMULATION_ONLY_EPHEMERAL",
                                             confirmed_tuple_sha256=confirmed_tuple_sha256,
                                             protected_key_loader=lambda _: self._key)


def create_simulation_signer(*, allowed_evidence: tuple[EvidenceTuple, ...]) -> SimulationSigner:
    """Source only in Dirty Mode: never invoked during construction/static checks."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    return SimulationSigner(Ed25519PrivateKey.generate(), allowed_evidence=allowed_evidence)

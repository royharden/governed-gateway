"""Independent exact-tuple/signature and simulation-only governance consumers."""
from datetime import timedelta
import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from gateway.policies.eligibility import check_bundle_tuple, verify_operator
from gateway.policies.store import decode_record
from gateway.policies.verification import SignatureVerificationError, verify_ed25519
from gateway.schemas import GatewayError, PolicyBundle, canonical_bytes, digest


@pytest.mark.parametrize("mutation", ["none", "wrong-key", "payload", "signature", "empty", "wrong-type"])
def test_real_ed25519_integrity_with_ephemeral_memory_keys(mutation):
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    payload = b"gateway.policy-approval.v1:synthetic-exact-tuple"
    signature = key.sign(payload)
    if mutation == "wrong-key":
        public = Ed25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    elif mutation == "payload":
        payload += b"altered"
    elif mutation == "signature":
        signature = bytes([signature[0] ^ 1]) + signature[1:]
    elif mutation == "empty":
        payload = b""
    elif mutation == "wrong-type":
        signature = bytearray(signature)
    if mutation == "none":
        assert verify_ed25519(public, signature, payload) == hashlib.sha256(public).hexdigest()
    else:
        with pytest.raises(SignatureVerificationError):
            verify_ed25519(public, signature, payload)


@pytest.mark.parametrize("field,value", [("authority_id", "spoofed-authority"),
    ("maximum_liability_usd", "0.999999"), ("declared_os_account", "spoofed-actor"),
    ("signer_fingerprint_sha256", "f" * 64), ("nonce", "changed-nonce")])
def test_signed_evaluation_payload_mutation_denied(evaluation_case, field, value):
    case = evaluation_case
    verify_operator(case["authorization"], case["signer"].public_key_bytes)
    altered = case["authorization"].model_copy(update={field: value})
    with pytest.raises(GatewayError):
        verify_operator(altered, case["signer"].public_key_bytes)


@pytest.mark.parametrize("field", ["policy_bundle_sha256", "eval_spec_sha256",
                                  "feature_schema_sha256", "price_sha256", "bound_sha256"])
def test_policy_exact_evidence_tuple_required(evaluation_case, field):
    record = evaluation_case["record"]
    check_bundle_tuple(record.bundle, record.evidence)
    with pytest.raises(GatewayError):
        check_bundle_tuple(record.bundle, record.evidence.model_copy(update={field: "f" * 64}))


def test_durable_canonical_decode_rejects_changed_bytes_and_wrong_hash(evaluation_case):
    bundle = evaluation_case["record"].bundle
    raw = canonical_bytes(bundle)
    assert decode_record(raw, PolicyBundle, digest(bundle)) == bundle
    with pytest.raises(GatewayError):
        decode_record(raw + b" ", PolicyBundle, digest(bundle))
    with pytest.raises(GatewayError):
        decode_record(raw, PolicyBundle, "f" * 64)


def test_model_copy_cannot_reuse_old_bundle_identity(evaluation_case):
    record = evaluation_case["record"]
    changed = record.bundle.model_copy(update={"expires_utc": record.bundle.expires_utc + timedelta(seconds=1)})
    with pytest.raises(GatewayError):
        check_bundle_tuple(changed, record.evidence)

"""A16 crypto boundary; ephemeral test bytes only, no key/credential files."""
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest

from gateway.replay.cipher import ReplayCipher
from gateway.schemas import GatewayError, GatewayResult, ReplayBinding, ResultChoice, ResultCost, Usage


def values():
    result = GatewayResult(operation_id="operation", provider="openai", model="mock-openai-v1", policy_bundle_sha256="a"*64,
        choice=ResultChoice(text="SYNTHETIC PRIVATE RESULT", refusal=None, finish_reason="stop", native_finish_reason="stop"),
        usage=Usage(input_tokens=8, output_tokens=4, cache_read_tokens=None, cache_write_tokens=None, reasoning_tokens=None),
        cost=ResultCost(status="known", amount_usd=Decimal("0.000016"), price_sha256="b"*64),
        attempt_ids=("attempt",), replayed=False, result_expires_utc=datetime.now(timezone.utc)+timedelta(hours=24), error=None)
    binding = ReplayBinding(authority_id="authority", caller_id="caller", operation_id="operation", request_sha256="c"*64,
        policy_bundle_sha256="a"*64)
    return result, binding


def test_encrypted_roundtrip_unique_nonce_and_no_plaintext():
    result, binding = values()
    cipher = ReplayCipher({"ephemeral": b"x"*32}, active_key_id="ephemeral")
    first, second = cipher.encrypt(result, binding), cipher.encrypt(result, binding)
    assert first.nonce_b64 != second.nonce_b64
    assert "SYNTHETIC PRIVATE RESULT" not in first.model_dump_json()
    assert cipher.decrypt(first, binding) == result


@pytest.mark.parametrize("field", ["authority_id", "caller_id", "operation_id", "request_sha256", "policy_bundle_sha256"])
def test_every_replay_binding_field_authenticated(field):
    result, binding = values()
    cipher = ReplayCipher({"ephemeral": b"x"*32}, active_key_id="ephemeral")
    encrypted = cipher.encrypt(result, binding)
    replacement = "d"*64 if field.endswith("sha256") else "different"
    with pytest.raises(GatewayError):
        cipher.decrypt(encrypted, binding.model_copy(update={field: replacement}))


def test_wrong_key_and_ciphertext_tamper_fail_closed():
    result, binding = values()
    cipher = ReplayCipher({"ephemeral": b"x"*32}, active_key_id="ephemeral")
    encrypted = cipher.encrypt(result, binding)
    with pytest.raises(GatewayError):
        ReplayCipher({"ephemeral": b"y"*32}, active_key_id="ephemeral").decrypt(encrypted, binding)
    replacement = ("A" if encrypted.ciphertext_b64[0] != "A" else "B") + encrypted.ciphertext_b64[1:]
    with pytest.raises(GatewayError):
        cipher.decrypt(encrypted.model_copy(update={"ciphertext_b64": replacement}), binding)

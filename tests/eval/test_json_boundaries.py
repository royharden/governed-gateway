"""Regression: pinned Pydantic must accept JSON arrays without Python coercion.

what_bug_this_catches: Record.exact_literals before-validation turns strict JSON
tuple fields into Python-mode lists, preventing public corpus and wire loading.
Repair must retain strict Python types and exact bool/int literals.
"""
from pathlib import Path
import json

import pytest
from pydantic import ValidationError

from gateway.evaluation.dataset import load_development
from gateway.schemas import ChatCompletionInput, CorpusManifest, canonical_bytes, digest

ROOT = Path(__file__).resolve().parents[2]


def wire(**updates):
    value = dict(model="default", messages=[dict(role="user", content="synthetic")],
                 max_completion_tokens=128, stream=False, n=1)
    value.update(updates)
    return value


def test_committed_public_manifest_json_roundtrip():
    raw = (ROOT / "fixtures/tasks/dev/manifest.json").read_bytes()
    manifest = CorpusManifest.model_validate_json(raw)
    assert len(manifest.tasks) == 60 and type(manifest.tasks) is tuple
    assert CorpusManifest.model_validate_json(canonical_bytes(manifest)) == manifest
    assert digest(manifest) == digest(CorpusManifest.model_validate_json(raw))


def test_public_loader_roundtrip():
    manifest, tasks = load_development(ROOT / "fixtures/tasks/dev")
    assert len(tasks) == len(manifest.tasks) == 60


def test_wire_json_array_acceptance_and_canonical_roundtrip():
    request = ChatCompletionInput.model_validate_json(json.dumps(wire()))
    assert type(request.messages) is tuple
    assert request.messages[0].content == "synthetic"
    assert ChatCompletionInput.model_validate_json(canonical_bytes(request)) == request


def test_python_list_not_silently_coerced_to_tuple():
    with pytest.raises(ValidationError):
        ChatCompletionInput.model_validate(wire())
    with pytest.raises(ValidationError):
        CorpusManifest.model_validate(json.loads((ROOT / "fixtures/tasks/dev/manifest.json").read_bytes()))


@pytest.mark.parametrize("field,value", [("schema_version", True), ("schema_version", 1.0),
    ("schema_version", "1"), ("n", True), ("n", 1.0), ("n", "1"),
    ("stream", 0), ("stream", "false"), ("stream", None),
    ("max_completion_tokens", True), ("max_completion_tokens", "128"),
    ("max_completion_tokens", 128.0)])
def test_json_literal_and_scalar_types_remain_exact(field, value):
    with pytest.raises(ValidationError):
        ChatCompletionInput.model_validate_json(json.dumps(wire(**{field: value})))


@pytest.mark.parametrize("value", [1, "true", None])
def test_corpus_synthetic_literal_is_boolean(value):
    raw = json.loads((ROOT / "fixtures/tasks/dev/manifest.json").read_bytes())
    raw["synthetic"] = value
    with pytest.raises(ValidationError):
        CorpusManifest.model_validate_json(json.dumps(raw))


def test_unknown_wire_field_still_refused():
    with pytest.raises(ValidationError):
        ChatCompletionInput.model_validate_json(json.dumps(wire(temperature=0)))

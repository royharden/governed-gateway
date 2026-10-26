"""D8 same-operation locality reuse: fresh validator calls and unchanged refusal."""
from contextlib import nullcontext
from datetime import datetime, timezone
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from gateway.policies.store import PolicyStore
from gateway.schemas import GatewayError


@pytest.fixture
def policy_path(artifact_dir, monkeypatch):
    path = artifact_dir / "m8-policy.sqlite3"
    path.write_bytes(b"public path-only fixture; not an initialized policy database")
    monkeypatch.setenv("GATEWAY_RUNTIME_ROOT", str(artifact_dir))
    store = PolicyStore(path, authority_id="m8-path", verification_key=b"x"*32,
        authority_lock=lambda: nullcontext(), clock=lambda: datetime.now(timezone.utc))
    return store, artifact_dir, path


def validator_spy(monkeypatch):
    import gateway.policies.store as implementation
    real = implementation.require_local_runtime_root
    calls = []
    def checked(path):
        calls.append(path)
        return real(path)
    monkeypatch.setattr(implementation, "require_local_runtime_root", checked)
    return calls


def test_same_parent_validated_once_each_invocation(policy_path, monkeypatch):
    store, root, path = policy_path
    calls = validator_spy(monkeypatch)
    for count in range(1, 4):
        assert store._runtime_path() == path.resolve()
        assert calls == [root] * count


def test_nested_parent_gets_both_fresh_validations(policy_path, monkeypatch):
    store, root, _ = policy_path
    nested = root / "nested"
    nested.mkdir()
    store._path = nested / "m8-nested.sqlite3"
    store._path.write_bytes(b"synthetic")
    calls = validator_spy(monkeypatch)
    for _ in range(2):
        assert store._runtime_path() == store._path.resolve()
    assert calls == [root, nested, root, nested]


def test_differently_expressed_parent_not_borrowed(policy_path, monkeypatch):
    store, root, path = policy_path
    nested = root / "nested"
    nested.mkdir()
    store._path = nested / ".." / path.name
    calls = validator_spy(monkeypatch)
    assert store._runtime_path() == path.resolve()
    assert calls == [root, store._path.parent]


@pytest.mark.parametrize("environment", ["absent", "empty", "relative", "repository"])
def test_current_invalid_root_refused_after_previous_success(policy_path, monkeypatch, environment):
    store, root, path = policy_path
    assert store._runtime_path() == path.resolve()
    if environment == "absent":
        monkeypatch.delenv("GATEWAY_RUNTIME_ROOT")
    else:
        value = {"empty": "", "relative": "m8-relative-root", "repository": os.environ.get("M8_SOURCE_ROOT", str(Path(__file__).resolve().parents[1]))}[environment]
        monkeypatch.setenv("GATEWAY_RUNTIME_ROOT", value)
    with pytest.raises(GatewayError):
        store._runtime_path()


def test_changed_current_root_cannot_reuse_prior_validation(policy_path, monkeypatch):
    store, root, path = policy_path
    calls = validator_spy(monkeypatch)
    assert store._runtime_path() == path.resolve()
    new_root = root / "new-root"
    new_root.mkdir()
    monkeypatch.setenv("GATEWAY_RUNTIME_ROOT", str(new_root))
    with pytest.raises(GatewayError):
        store._runtime_path()
    assert calls[:2] == [root, new_root]


@pytest.mark.parametrize("kind", ["relative", "outside-root", "directory"])
def test_changed_database_path_is_revalidated(policy_path, kind):
    store, root, path = policy_path
    assert store._runtime_path() == path.resolve()
    if kind == "relative":
        store._path = Path("m8-relative.sqlite3")
    elif kind == "directory":
        store._path = root
    else:
        outside = root.parent / (root.name + "-outside")
        outside.mkdir()
        store._path = outside / "m8-outside.sqlite3"
        store._path.write_bytes(b"synthetic outside runtime root")
    with pytest.raises(GatewayError):
        store._runtime_path()


@pytest.mark.parametrize("kind", ["database", "nested-parent"])
def test_symlink_refused_for_database_or_parent(policy_path, kind):
    store, root, path = policy_path
    if kind == "database":
        linked = root / "m8-db-link.sqlite3"
        destination = path
    else:
        real_parent = root / "real-parent"
        real_parent.mkdir()
        (real_parent / path.name).write_bytes(b"synthetic")
        linked = root / "m8-parent-link"
        destination = real_parent
    try:
        linked.symlink_to(destination, target_is_directory=kind == "nested-parent")
    except OSError:
        pytest.skip("OS symlink privilege unavailable; no security change attempted")
    store._path = linked if kind == "database" else linked / path.name
    with pytest.raises(GatewayError):
        store._runtime_path()


def test_reparse_database_attribute_refused(policy_path, monkeypatch):
    store, root, path = policy_path
    original = Path.lstat
    def attributes(candidate, *args, **kwargs):
        value = original(candidate, *args, **kwargs)
        if candidate == path:
            return SimpleNamespace(st_mode=value.st_mode, st_file_attributes=0x400)
        return value
    monkeypatch.setattr(Path, "lstat", attributes)
    with pytest.raises(GatewayError):
        store._runtime_path()


def test_shared_validator_failure_never_bypassed_by_same_parent(policy_path, monkeypatch):
    import gateway.policies.store as implementation
    from gateway.schemas import ErrorCode
    store, _, _ = policy_path
    def failed(path):
        raise GatewayError(ErrorCode.UNSAFE_RUNTIME_PATH)
    monkeypatch.setattr(implementation, "require_local_runtime_root", failed)
    with pytest.raises(GatewayError):
        store._runtime_path()

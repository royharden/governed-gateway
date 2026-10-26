"""R40 filesystem boundaries: no authority, database initialization, or cleanup."""
from pathlib import Path
from types import SimpleNamespace

import pytest

from gateway.bootstrap import _database_path
from gateway.runtime import require_local_runtime_root
from gateway.schemas import ErrorCode, GatewayError


@pytest.mark.parametrize("filename", [
    "", ".", "..", "../outside", "nested/file", "nested\\file", "/absolute",
    "C:\\absolute", "C:relative", "db:stream", "\\\\host\\share", "nul\0db",
    "trailing.", "trailing ", "CON", "con.sqlite3", "PRN", "AUX.txt", "NUL",
    "COM1.db", "LPT9", "COM¹", "LPT².txt",
])
def test_filename_alias_or_escape_refused(artifact_dir, filename):
    with pytest.raises(GatewayError) as error:
        _database_path(artifact_dir, filename, existing=False)
    assert error.value.code == ErrorCode.UNSAFE_RUNTIME_PATH


@pytest.mark.parametrize("existing", [False, True])
def test_regular_child_and_current_root_validate_each_call(artifact_dir, monkeypatch, existing):
    import gateway.bootstrap as implementation
    path = artifact_dir / "m8-ordinary.sqlite3"
    path.write_bytes(b"public path fixture, not a database")
    real = implementation.require_local_runtime_root
    calls = []
    def checked(root):
        calls.append(root)
        return real(root)
    monkeypatch.setattr(implementation, "require_local_runtime_root", checked)
    for _ in range(2):
        assert _database_path(artifact_dir, path.name, existing=existing) == path
    assert calls == [artifact_dir, artifact_dir]


def test_missing_child_preserves_existing_semantics(artifact_dir):
    name = "m8-missing.sqlite3"
    assert _database_path(artifact_dir, name, existing=False) == artifact_dir / name
    assert not (artifact_dir / name).exists()
    with pytest.raises(GatewayError) as error:
        _database_path(artifact_dir, name, existing=True)
    assert error.value.code == ErrorCode.STORE_UNAVAILABLE


def test_directory_child_refused(artifact_dir):
    child = artifact_dir / "m8-directory.sqlite3"
    child.mkdir()
    with pytest.raises(GatewayError) as error:
        _database_path(artifact_dir, child.name, existing=True)
    assert error.value.code == ErrorCode.UNSAFE_RUNTIME_PATH


def test_permission_error_never_becomes_missing_success(artifact_dir, monkeypatch):
    path = artifact_dir / "m8-denied.sqlite3"
    original = Path.lstat
    def denied(candidate, *args, **kwargs):
        if candidate == path:
            raise PermissionError("reviewer injected denied metadata")
        return original(candidate, *args, **kwargs)
    monkeypatch.setattr(Path, "lstat", denied)
    with pytest.raises(PermissionError):
        _database_path(artifact_dir, path.name, existing=False)


@pytest.mark.parametrize("kind", ["file", "ancestor"])
def test_actual_symlink_refused(artifact_dir, kind):
    real = artifact_dir / "m8-real"
    real.mkdir()
    child = real / "m8-database.sqlite3"
    child.write_bytes(b"public synthetic path fixture")
    link = artifact_dir / "m8-link"
    target = child if kind == "file" else real
    try:
        link.symlink_to(target, target_is_directory=kind == "ancestor")
    except OSError:
        pytest.skip("OS symlink privilege unavailable")
    with pytest.raises(GatewayError) as error:
        _database_path(artifact_dir if kind == "file" else link,
                       link.name if kind == "file" else child.name, existing=True)
    assert error.value.code == ErrorCode.UNSAFE_RUNTIME_PATH


@pytest.mark.parametrize("kind", ["file", "root"])
def test_reparse_attribute_refused(artifact_dir, monkeypatch, kind):
    path = artifact_dir / "m8-reparse.sqlite3"
    path.write_bytes(b"synthetic")
    original = Path.lstat
    def attributes(candidate, *args, **kwargs):
        value = original(candidate, *args, **kwargs)
        if candidate == (path if kind == "file" else artifact_dir):
            return SimpleNamespace(st_mode=value.st_mode, st_file_attributes=0x400)
        return value
    monkeypatch.setattr(Path, "lstat", attributes)
    with pytest.raises(GatewayError) as error:
        _database_path(artifact_dir, path.name, existing=True)
    assert error.value.code == ErrorCode.UNSAFE_RUNTIME_PATH


def test_changed_environment_and_git_marker_rechecked(artifact_dir, monkeypatch):
    root = artifact_dir / "m8-root"
    root.mkdir()
    assert require_local_runtime_root(root) == root
    monkeypatch.setenv("OneDrive", str(artifact_dir))
    with pytest.raises(GatewayError):
        require_local_runtime_root(root)
    monkeypatch.delenv("OneDrive")
    (root / ".git").write_text("public marker only", encoding="utf-8")
    with pytest.raises(GatewayError):
        require_local_runtime_root(root)


def test_root_replaced_with_file_during_validation_refused(artifact_dir, monkeypatch):
    """Retain the fresh directory-type check after canonicalization, within this call."""
    root = artifact_dir / "m8-root"
    root.mkdir()
    preserved = artifact_dir / "m8-original-root-preserved"
    original = Path.resolve
    changed = False
    def replace_before_resolve(candidate, *args, **kwargs):
        nonlocal changed
        if candidate == root and not changed:
            changed = True
            root.rename(preserved)
            root.write_bytes(b"public file substituted for directory; original preserved")
        return original(candidate, *args, **kwargs)
    monkeypatch.setattr(Path, "resolve", replace_before_resolve)
    with pytest.raises(GatewayError) as error:
        require_local_runtime_root(root)
    assert error.value.code == ErrorCode.UNSAFE_RUNTIME_PATH
    assert changed and root.is_file() and preserved.is_dir()

"""Pure mocked pipe/process checks for a separately pinned observer helper.

Set M8_OBSERVER_BOUNDS_PATH and M8_OBSERVER_BOUNDS_SHA256 to reviewed public
helper bytes. No sampler, launcher, Docker command or real subprocess executes.
"""
import hashlib
import importlib.util
import io
import os
from types import SimpleNamespace
from unittest.mock import Mock

import pytest


@pytest.fixture
def bounds(monkeypatch):
    from pathlib import Path

    path = os.environ.get("M8_OBSERVER_BOUNDS_PATH")
    expected = os.environ.get("M8_OBSERVER_BOUNDS_SHA256")
    if not path and not expected:
        pytest.skip("Observer helper requires an exact independent input pin")
    assert path and expected, "Both helper path and SHA256 are required"
    assert hashlib.sha256(Path(path).read_bytes()).hexdigest() == expected
    spec = importlib.util.spec_from_file_location("r04_observer_bounds", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module.subprocess, "Popen", Mock(side_effect=AssertionError("real process forbidden")))
    return module


@pytest.mark.parametrize("size,overflow", [(4, False), (5, False), (6, True), (20000, True)])
@pytest.mark.parametrize("retain", [False, True])
def test_capture_caps_and_closes_without_retaining_stderr(bounds, size, overflow, retain):
    # what_bug_this_catches: stderr/stdout overflow retained unbounded or
    # discarded stderr falsely reported as retained plaintext evidence.
    pipe = io.BytesIO(b"x" * size)
    capture = bounds.Capture(pipe, 5, retain=retain)
    capture.pump()  # Synchronous in-memory I/O; never start a thread.
    assert pipe.closed
    assert capture.size == min(size, 5)
    assert bytes(capture.data) == (b"x" * min(size, 5) if retain else b"")
    assert capture.overflow is overflow
    assert capture.failed.is_set() is overflow
    record = capture.record()
    assert record["bounded_prefix_bytes"] == min(size, 5)
    assert record["retained_bytes"] == (min(size, 5) if retain else 0)
    assert record["bounded_prefix_sha256"] == hashlib.sha256(b"x" * min(size, 5)).hexdigest()


@pytest.mark.parametrize("cap", [0, -1, True, 1.5])
def test_invalid_cap_refused(bounds, cap):
    with pytest.raises(ValueError, match="invalid_cap"):
        bounds.Capture(io.BytesIO(), cap)


def test_destination_error_is_closed_and_redacted(bounds):
    # what_bug_this_catches: disk write failure becomes a complete capture or
    # leaks arbitrary exception text into the diagnostic record.
    pipe = io.BytesIO(b"synthetic")
    output = SimpleNamespace(write=Mock(side_effect=OSError("synthetic-private-text")), flush=Mock())
    capture = bounds.Capture(pipe, 5, destination=output)
    capture.pump()
    assert pipe.closed and capture.failed.is_set()
    assert capture.record()["error_type"] == "OSError"
    assert "synthetic-private-text" not in str(capture.record())


def test_spawn_thread_failure_cleans_exact_returned_handle(bounds, monkeypatch):
    # what_bug_this_catches: Popen succeeds but Thread.start fails, leaking the
    # newly owned process and its pipes before a handle reaches the launcher.
    process = SimpleNamespace(stdout=io.BytesIO(), stderr=io.BytesIO(),
                              poll=Mock(return_value=None), kill=Mock(), wait=Mock())
    monkeypatch.setattr(bounds.subprocess, "Popen", Mock(return_value=process))
    monkeypatch.setattr(bounds.Thread, "start", Mock(side_effect=RuntimeError("thread unavailable")))
    with pytest.raises(RuntimeError, match="thread unavailable"):
        bounds.spawn(["synthetic-never-executed"], stdout_cap=5, stderr_cap=5)
    process.kill.assert_called_once_with()
    process.wait.assert_called_once_with(timeout=1)
    assert process.stdout.closed and process.stderr.closed


def test_capture_construction_failure_cleans_exact_returned_handle(bounds, monkeypatch):
    # what_bug_this_catches: Capture/Thread construction can fail after Popen
    # returns, before the caller owns the handle. Cleanup must cover this gap.
    process = SimpleNamespace(stdout=io.BytesIO(), stderr=io.BytesIO(),
                              poll=Mock(return_value=None), kill=Mock(), wait=Mock())
    monkeypatch.setattr(bounds.subprocess, "Popen", Mock(return_value=process))
    monkeypatch.setattr(bounds, "Capture", Mock(side_effect=RuntimeError("capture unavailable")))
    with pytest.raises(RuntimeError, match="capture unavailable"):
        bounds.spawn(["synthetic-never-executed"], stdout_cap=5, stderr_cap=5)
    process.kill.assert_called_once_with()
    process.wait.assert_called_once_with(timeout=1)
    assert process.stdout.closed and process.stderr.closed


@pytest.mark.parametrize("cause", ["timeout", "capture", "exit", "cleanup"])
def test_control_failure_always_finishes_owned_handle(bounds, monkeypatch, cause):
    # what_bug_this_catches: timeout/capture/cleanup/nonzero exit reported as
    # success, or control-command failure skipping exact-handle cleanup.
    process = SimpleNamespace(poll=Mock(return_value=0 if cause in ("exit", "cleanup") else None), returncode=1 if cause == "exit" else 0)
    readers = [SimpleNamespace(failed=SimpleNamespace(is_set=lambda: cause == "capture"), data=b"ok")]
    spawn = Mock(return_value=(process, readers))
    finish = Mock(return_value=["reader_not_joined"] if cause == "cleanup" else [])
    monkeypatch.setattr(bounds, "spawn", spawn)
    monkeypatch.setattr(bounds, "finish", finish)
    monkeypatch.setattr(bounds.time, "monotonic", Mock(side_effect=[0, 2]))
    with pytest.raises(ValueError, match="bounded_control_incomplete"):
        bounds.control(["synthetic-never-executed"], timeout=1)
    finish.assert_called_once_with(process, readers)
    assert spawn.call_args.kwargs["stdout_cap"] == 65536
    assert spawn.call_args.kwargs["stderr_cap"] == 65536

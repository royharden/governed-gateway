"""Native process/filesystem controls, independent of a bootstrap journey.

what_bug_this_catches: PID monkeypatches cannot prove inherited OS lock/SQLite
behavior, and Windows refuses renaming open SQLite files. These controls require
real fork/rename on Linux; a platform skip never closes either gap.
"""
from datetime import datetime, timedelta, timezone
import multiprocessing
import os
from pathlib import Path
import sqlite3
import threading
import uuid

import pytest

from gateway.bootstrap import _PolicyHighWater
from gateway.controller.authority_lock import AuthorityLock
from gateway.schemas import ErrorCode, GatewayError


pytestmark = pytest.mark.skipif(os.name != "posix", reason="requires actual Linux fork/SQLite rename")
AUTHORITY = "m8-r04-rv4-native"


def create_database(path, initial):
    with sqlite3.connect(path) as db:
        assert db.execute("PRAGMA journal_mode=WAL").fetchone()[0].lower() == "wal"
        db.execute("CREATE TABLE authority_state(authority_id TEXT PRIMARY KEY, "
                   "config_sha256 TEXT NOT NULL,max_observed_utc TEXT NOT NULL)")
        db.execute("INSERT INTO authority_state VALUES(?,?,?)", (
            AUTHORITY, "a" * 64, initial.isoformat(timespec="microseconds").replace("+00:00", "Z")))


@pytest.fixture
def native_store():
    parent = os.environ.get("M8_TEST_RUNTIME_PARENT")
    assert parent, "explicit fresh owned runtime parent required"
    root = Path(parent) / ("native-" + uuid.uuid4().hex)
    root.mkdir(parents=True, exist_ok=False)
    path = root / "policy.sqlite3"
    initial = datetime.now(timezone.utc)
    create_database(path, initial)
    guard = AuthorityLock(root)
    store = _PolicyHighWater(path, authority_id=AUTHORITY, guard=guard, policy_config_sha256="a" * 64)
    try:
        assert store.read() == initial
        yield store, initial, path, guard
    finally:
        store.close()


def child_observations(store, guard, initial, sender):
    """Report only closed error codes; never SQLite handles or private material."""
    result = {}
    for label, call in (
        ("read", store.read),
        ("cas", lambda: store.compare_and_advance(initial, initial + timedelta(seconds=1))),
        ("inherited_guard", lambda: guard.assert_held(authority_id=AUTHORITY)),
    ):
        try:
            call()
            result[label] = "UNSAFE_SUCCESS"
        except GatewayError as error:
            result[label] = error.code.value
    try:
        with guard.hold(AUTHORITY, timeout_seconds=0.1):
            result["contended_guard"] = "UNSAFE_SUCCESS"
    except GatewayError as error:
        result["contended_guard"] = error.code.value
    sender.send(result)
    sender.close()


def test_actual_fork_refuses_inherited_handles_and_parent_lock(native_store):
    store, initial, _, guard = native_store
    context = multiprocessing.get_context("fork")
    receiver, sender = context.Pipe(duplex=False)
    child = context.Process(target=child_observations, args=(store, guard, initial, sender))
    try:
        with guard.hold(AUTHORITY):
            child.start()
            sender.close()
            child.join(timeout=5)
            assert not child.is_alive(), "fork child hung on inherited synchronization"
            assert child.exitcode == 0
            assert receiver.poll(0.5), "child exited without all boundary observations"
            assert receiver.recv() == {
                "read": ErrorCode.CLOCK_UNTRUSTED.value,
                "cas": ErrorCode.CLOCK_UNTRUSTED.value,
                "inherited_guard": ErrorCode.LOCK_UNAVAILABLE.value,
                "contended_guard": ErrorCode.LOCK_UNAVAILABLE.value,
            }
        # Child refusal must neither release the parent's lock nor poison its DB.
        assert store.read() == initial
        assert store.compare_and_advance(initial, initial + timedelta(microseconds=1))
    finally:
        if child.pid is not None and child.is_alive():
            child.kill()
            child.join(timeout=2)
        receiver.close()
        sender.close()


def test_actual_open_sqlite_replacement_latches_closed(native_store):
    store, initial, path, _ = native_store
    replacement = path.with_name("replacement.sqlite3")
    preserved = path.with_name("preserved-original.sqlite3")
    create_database(replacement, initial)
    old_identity = (path.stat().st_dev, path.stat().st_ino)
    # Preserve both files; neither unlink nor replace overwrites an artifact.
    path.rename(preserved)
    replacement.rename(path)
    assert (path.stat().st_dev, path.stat().st_ino) != old_identity
    with pytest.raises(GatewayError):
        store.read()
    assert store._connection is None
    with pytest.raises(GatewayError):
        store.compare_and_advance(initial, initial + timedelta(seconds=1))
    assert preserved.is_file() and path.is_file()


def child_assertion(guard, sender):
    sender.send("entered")
    try:
        guard.assert_held(authority_id=AUTHORITY)
        sender.send("UNSAFE_SUCCESS")
    except GatewayError as error:
        sender.send(error.code.value)
    sender.close()


def test_fork_during_other_thread_registry_lock_is_bounded(native_store):
    """D11-H1: an inherited locked mutex must not hang a child ownership check."""
    from gateway.controller import authority_lock
    _, _, _, guard = native_store
    held, release = threading.Event(), threading.Event()
    def hold_registry():
        with authority_lock._entries_mutex:
            held.set()
            release.wait(8)
    holder = threading.Thread(target=hold_registry)
    context = multiprocessing.get_context("fork")
    receiver, sender = context.Pipe(duplex=False)
    child = context.Process(target=child_assertion, args=(guard, sender))
    holder.start()
    try:
        assert held.wait(1), "test failed to establish fork boundary"
        child.start()
        sender.close()
        release.set()
        holder.join(timeout=2)
        assert receiver.poll(2), "child never reached ownership probe"
        assert receiver.recv() == "entered"
        child.join(timeout=3)
        assert not child.is_alive(), "D11-H1: inherited locked registry mutex hung child"
        assert child.exitcode == 0
        assert receiver.poll(0.5)
        assert receiver.recv() == ErrorCode.LOCK_UNAVAILABLE.value
    finally:
        release.set()
        holder.join(timeout=2)
        if child.pid is not None and child.is_alive():
            child.kill()
            child.join(timeout=2)
        receiver.close()
        sender.close()

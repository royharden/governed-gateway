"""D6 high-water performance safety controls, independent public SQLite fixtures."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import os
import sqlite3

import pytest

from gateway.bootstrap import _AuthorityClock, _PolicyHighWater
from gateway.controller.authority_lock import AuthorityLock
from gateway.schemas import ErrorCode, GatewayError


def stamp(value):
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def database(path, time, *, authority="m8-highwater", config="a"*64):
    with sqlite3.connect(path) as db:
        assert db.execute("PRAGMA journal_mode=WAL").fetchone()[0].lower() == "wal"
        db.execute("CREATE TABLE authority_state(authority_id TEXT PRIMARY KEY,config_sha256 TEXT NOT NULL,max_observed_utc TEXT NOT NULL)")
        db.execute("INSERT INTO authority_state VALUES(?,?,?)", (authority, config, stamp(time)))


@pytest.fixture
def highwater(artifact_dir):
    initial = datetime.now(timezone.utc)
    path = artifact_dir / "m8-policy.sqlite3"
    database(path, initial)
    guard = AuthorityLock(artifact_dir)
    store = _PolicyHighWater(path, authority_id="m8-highwater", guard=guard, policy_config_sha256="a"*64)
    yield store, initial, path
    store.close()


def clock_for(store, initial):
    state = {"wall": initial, "ticks": 0}
    clock = _AuthorityClock(guard=store.guard, authority_id="m8-highwater", high_water=store,
        utc_now=lambda: state["wall"], monotonic_ns=lambda: state["ticks"], clock_identity_sha256="b"*64,
        max_drift=timedelta(seconds=1), max_startup_advance=timedelta(hours=1))
    return clock, state


def test_every_clock_invocation_reads_cas_and_commits(highwater):
    store, initial, path = highwater
    assert store.read() == initial
    connection = store._connection
    statements = []
    connection.set_trace_callback(statements.append)
    clock, state = clock_for(store, initial)
    for step in range(3):
        state.update(wall=initial+timedelta(seconds=step), ticks=step*1_000_000_000)
        assert clock() == state["wall"]
        assert store._connection is connection
        with sqlite3.connect(path) as observer:
            assert observer.execute("SELECT max_observed_utc FROM authority_state").fetchone()[0] == stamp(state["wall"])
    assert sum(s.startswith("SELECT max_observed_utc,config_sha256") for s in statements) == 3
    assert sum(s.startswith("UPDATE authority_state") for s in statements) == 3
    assert statements.count("BEGIN IMMEDIATE") == statements.count("COMMIT") == 3


@pytest.mark.parametrize("fault", ["rollback", "drift"])
def test_rollback_or_drift_latches_clock_closed(highwater, fault):
    store, initial, _ = highwater
    clock, state = clock_for(store, initial)
    assert clock() == initial
    state.update(wall=initial-timedelta(microseconds=1) if fault == "rollback" else initial+timedelta(seconds=10), ticks=1)
    with pytest.raises(GatewayError) as failure:
        clock()
    assert failure.value.code == (ErrorCode.CLOCK_ROLLBACK if fault == "rollback" else ErrorCode.CLOCK_UNTRUSTED)
    state.update(wall=initial, ticks=0)
    with pytest.raises(GatewayError):
        clock()
    with pytest.raises(GatewayError):
        clock.evidence_sha256()


def test_cas_conflict_keeps_durable_value(highwater):
    store, initial, path = highwater
    assert store.compare_and_advance(initial, initial+timedelta(seconds=1))
    assert not store.compare_and_advance(initial, initial+timedelta(seconds=2))
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT max_observed_utc FROM authority_state").fetchone()[0] == stamp(initial+timedelta(seconds=1))


@pytest.mark.parametrize("field,value", [("config_sha256", "c"*64), ("authority_id", "foreign")])
def test_foreign_config_or_authority_refused_and_handle_not_reopened(highwater, field, value):
    store, initial, path = highwater
    assert store.read() == initial
    with sqlite3.connect(path) as db:
        db.execute("UPDATE authority_state SET " + field + "=?", (value,))
    with pytest.raises(GatewayError):
        store.read()
    assert store._connection is None
    with sqlite3.connect(path) as db:
        db.execute("UPDATE authority_state SET " + field + "=?", ("a"*64 if field == "config_sha256" else "m8-highwater",))
    with pytest.raises(GatewayError):
        store.read()


@pytest.mark.parametrize("fault", ["read", "update", "commit"])
def test_sqlite_faults_rollback_and_close_connection(highwater, fault):
    store, initial, path = highwater
    store.read()
    def authorization(action, first, second, db, trigger):
        deny = ((fault == "read" and action == sqlite3.SQLITE_READ)
                or (fault == "update" and action == sqlite3.SQLITE_UPDATE)
                or (fault == "commit" and action == sqlite3.SQLITE_TRANSACTION and first == "COMMIT"))
        return sqlite3.SQLITE_DENY if deny else sqlite3.SQLITE_OK
    store._connection.set_authorizer(authorization)
    clock, state = clock_for(store, initial)
    state["wall"] += timedelta(seconds=1)
    with pytest.raises(GatewayError):
        clock()
    assert store._connection is None
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT max_observed_utc FROM authority_state").fetchone()[0] == stamp(initial)
    with pytest.raises(GatewayError):
        store.read()


def test_closed_handle_and_unexpected_observation_failure_refused(highwater):
    store, initial, _ = highwater
    assert store.read() == initial
    with pytest.raises(RuntimeError, match="m8-injected"):
        with store.observation():
            raise RuntimeError("m8-injected")
    assert store._connection is None
    with pytest.raises(GatewayError):
        store.read()


def test_explicit_close_blocks_clock_and_evidence(highwater):
    store, initial, _ = highwater
    clock, _ = clock_for(store, initial)
    clock()
    store.close()
    with pytest.raises(GatewayError):
        clock()
    with pytest.raises(GatewayError):
        clock.evidence_sha256()


def test_foreign_pid_refused_without_inherited_connection_use(highwater, monkeypatch):
    store, initial, _ = highwater
    store.read()
    connection = store._connection
    real_pid = os.getpid()
    with monkeypatch.context() as patch:
        patch.setattr(os, "getpid", lambda: real_pid+1)
        with pytest.raises(GatewayError):
            store.read()
    # PID fault injection, not an actual fork execution on Windows.
    assert store._connection is connection


def test_parallel_observations_serialize_fresh_reads_and_cas(highwater):
    store, initial, path = highwater
    def update(_):
        with store.observation():
            previous = store.read()
            assert store.compare_and_advance(previous, previous+timedelta(microseconds=1))
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(update, range(24)))
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT max_observed_utc FROM authority_state").fetchone()[0] == stamp(initial+timedelta(microseconds=24))


def test_parallel_clock_calls_preserve_os_before_thread_lock_order(highwater):
    store, initial, _ = highwater
    clock, _ = clock_for(store, initial)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: clock(), range(24)))
    assert results == [initial] * 24
    assert clock.evidence_sha256()


def process_observations(job):
    from pathlib import Path
    path, repetitions = job
    path = Path(path)
    store = _PolicyHighWater(path, authority_id="m8-highwater", guard=AuthorityLock(path.parent), policy_config_sha256="a"*64)
    try:
        for _ in range(repetitions):
            with store.observation():
                before = store.read()
                assert store.compare_and_advance(before, before+timedelta(microseconds=1))
        return repetitions
    finally:
        store.close()


def test_fresh_process_connections_observe_shared_durable_cas(highwater):
    from concurrent.futures import ProcessPoolExecutor
    import multiprocessing
    store, initial, path = highwater
    with ProcessPoolExecutor(2, mp_context=multiprocessing.get_context("spawn")) as pool:
        assert list(pool.map(process_observations, [(str(path), 4)] * 2)) == [4, 4]
    assert store.read() == initial+timedelta(microseconds=8)


def test_nested_observation_refused(highwater):
    store, _, _ = highwater
    with pytest.raises(GatewayError):
        with store.observation():
            with store.observation():
                pytest.fail("Nested observation admitted")
    with pytest.raises(GatewayError):
        store.read()


def test_database_replacement_identity_refused(highwater):
    store, initial, path = highwater
    store.read()
    replacement = path.with_name("m8-replacement.sqlite3")
    database(replacement, initial)
    backup = path.with_name("m8-preserved-original.sqlite3")
    try:
        path.rename(backup)
    except PermissionError:
        pytest.skip("OS denied rename of open SQLite file; actual replacement path not exercised on this platform")
    replacement.rename(path)
    with pytest.raises(GatewayError):
        store.read()
    assert store._connection is None


def test_symlink_database_path_refused(highwater):
    store, _, path = highwater
    linked = path.with_name("m8-link.sqlite3")
    try:
        linked.symlink_to(path)
    except OSError:
        pytest.skip("OS symlink privilege unavailable; no privilege or security change attempted")
    store.path = linked
    with pytest.raises(GatewayError):
        store.read()


def test_missing_schema_refused(artifact_dir):
    path = artifact_dir / "m8-missing-schema.sqlite3"
    with sqlite3.connect(path) as db:
        db.execute("PRAGMA journal_mode=WAL")
    store = _PolicyHighWater(path, authority_id="m8-highwater", guard=AuthorityLock(artifact_dir), policy_config_sha256="a"*64)
    try:
        with pytest.raises(GatewayError):
            store.read()
        assert store._connection is None
    finally:
        store.close()


def test_bootstrap_error_closes_owned_highwater(loaded_simulation, monkeypatch):
    import gateway.bootstrap as bootstrap
    spec, _, _, _, _ = loaded_simulation
    real_factory = bootstrap._PolicyHighWater
    created = []
    def highwater_factory(*args, **kwargs):
        value = real_factory(*args, **kwargs)
        created.append(value)
        return value
    def refused_ledger(*args, **kwargs):
        raise GatewayError(ErrorCode.STORE_UNAVAILABLE)
    monkeypatch.setattr(bootstrap, "_PolicyHighWater", highwater_factory)
    monkeypatch.setattr(bootstrap, "LedgerAdapter", refused_ledger)
    with pytest.raises(GatewayError) as error:
        bootstrap.build_mock_context(spec, initialize=True)
    assert error.value.code == ErrorCode.STORE_UNAVAILABLE
    assert len(created) == 1 and created[0]._closed and created[0]._connection is None


def test_normal_context_close_closes_ledger_and_clock(loaded_simulation):
    from gateway.bootstrap import build_mock_context
    spec, _, _, _, _ = loaded_simulation
    context = build_mock_context(spec, initialize=True)
    context.clock()
    context.close()
    with pytest.raises(GatewayError):
        context.clock()
    with pytest.raises(GatewayError):
        context.clock.evidence_sha256()
    assert context.clock._high_water._connection is None
    assert context.clock._high_water._closed


def test_swallowed_recursive_clock_error_permanently_invalidates_trust(highwater):
    store, initial, _ = highwater
    attempted = []
    clock = None
    def callback():
        if not attempted:
            attempted.append(True)
            try:
                clock()
            except GatewayError:
                pass  # An untrusted callback must not be able to clear failure.
        return initial
    clock = _AuthorityClock(guard=store.guard, authority_id="m8-highwater", high_water=store,
        utc_now=callback, monotonic_ns=lambda: 0, clock_identity_sha256="b"*64,
        max_drift=timedelta(seconds=1), max_startup_advance=timedelta(hours=1))
    with pytest.raises(GatewayError):
        clock()
    assert attempted
    with pytest.raises(GatewayError):
        clock()
    with pytest.raises(GatewayError):
        clock.evidence_sha256()


def test_outer_guard_entry_failure_permanently_invalidates_clock(highwater, monkeypatch):
    store, initial, _ = highwater
    clock, _ = clock_for(store, initial)
    clock()
    class RefusedContext:
        def __enter__(self):
            raise GatewayError(ErrorCode.LOCK_UNAVAILABLE)
        def __exit__(self, *args):
            return False
    class RefusedGuard:
        def hold(self, *args, **kwargs):
            return RefusedContext()
    with monkeypatch.context() as patch:
        patch.setattr(clock, "_guard", RefusedGuard())
        with pytest.raises(GatewayError) as first:
            clock()
        assert first.value.code == ErrorCode.LOCK_UNAVAILABLE
    with pytest.raises(GatewayError):
        clock()
    with pytest.raises(GatewayError):
        clock.evidence_sha256()


@pytest.mark.parametrize("operation", ["read", "cas"])
def test_direct_foreign_pid_refused_before_any_guard_entry(highwater, monkeypatch, operation):
    store, initial, _ = highwater
    store.read()
    original_guard = store.guard
    entries = []
    class ObservedGuard:
        @contextmanager
        def hold(self, *args, **kwargs):
            entries.append(True)
            with original_guard.hold(*args, **kwargs):
                yield
    real_pid = os.getpid()
    with monkeypatch.context() as patch:
        patch.setattr(store, "guard", ObservedGuard())
        patch.setattr(os, "getpid", lambda: real_pid+1)
        with pytest.raises(GatewayError):
            if operation == "read":
                store.read()
            else:
                store.compare_and_advance(initial, initial+timedelta(microseconds=1))
    assert entries == [], "Foreign PID entered inherited guard before being refused"

"""Independent M8-S3-CLOCK-1 controls. No production repair code is copied here."""
from datetime import datetime, timedelta, timezone
import json
import sqlite3

import pytest

from gateway.shared.s3.callledger import LedgerError
from gateway.shared.s3.callledger import models as m
from ledger_support import configuration, inputs, open_ledger


class Clocks:
    def __init__(self, config):
        self.wall = datetime.fromisoformat(config.authority.run_deadline_utc.replace("Z", "+00:00")) - timedelta(hours=2)
        self.tick = 0.0


def admit(ledger, config, operation):
    context, plan, _ = inputs(config, operation=operation)
    return ledger.admit_operation(plan, context=context, limits=config.limits, mode="simulation")


def test_true_wall_rollback_refused_before_and_after_reopen(artifact_dir):
    config = configuration()
    clock = Clocks(config)
    path = artifact_dir / "m8-clock.sqlite3"
    ledger = open_ledger(path, config, clock=lambda: clock.wall, monotonic=lambda: clock.tick)
    try:
        admit(ledger, config, "first")
        clock.wall += timedelta(seconds=1)
        admit(ledger, config, "second")
        clock.wall -= timedelta(microseconds=1)
        with pytest.raises(LedgerError, match="clock_rollback"):
            admit(ledger, config, "rollback")
        before = ledger.totals()
    finally:
        ledger.close()
    reopened = None
    try:
        try:
            reopened = open_ledger(path, config, clock=lambda: clock.wall, monotonic=lambda: clock.tick)
        except LedgerError as error:
            assert str(error) == "clock_rollback"
        else:
            with pytest.raises(LedgerError, match="clock_rollback"):
                admit(reopened, config, "reopened-rollback")
            assert reopened.totals() == before
    finally:
        if reopened is not None:
            reopened.close()


def test_effective_monotonic_deadline_denies_new_attempt(artifact_dir):
    config = configuration()
    clock = Clocks(config)
    context, plan, request = inputs(config)
    path = artifact_dir / "m8-deadline.sqlite3"
    ledger = open_ledger(path, config, (request,), clock=lambda: clock.wall, monotonic=lambda: clock.tick)
    try:
        allocation = ledger.admit_operation(plan, context=context, limits=config.limits, mode="simulation")
        clock.tick = 61.0
        with pytest.raises(LedgerError, match="deadline"):
            ledger.begin_attempt(allocation, context=context, request=request)
        assert ledger.totals()["dispatched_attempts"] == 0
    finally:
        ledger.close()


def test_raw_wall_highwater_does_not_follow_effective_highwater(artifact_dir):
    config = configuration()
    clock = Clocks(config)
    path = artifact_dir / "m8-effective.sqlite3"
    ledger = open_ledger(path, config, clock=lambda: clock.wall, monotonic=lambda: clock.tick)
    try:
        clock.tick = 1.0
        admit(ledger, config, "one")
        clock.tick = 2.0
        admit(ledger, config, "two")
        # Actual raw-wall rollback must still fail, even when effective time is ahead.
        clock.wall -= timedelta(microseconds=1)
        with pytest.raises(LedgerError, match="clock_rollback"):
            admit(ledger, config, "bad")
    finally:
        ledger.close()


def legacy_database(path, config, *, halted=False):
    """Hand-authored schema1 snapshot from the pinned public ledger contract.

    No schema downgrade/drop or product private methods. Financial rows deliberately
    include future/active/known/unknown exposure and outbox history for preservation.
    """
    context, plan, _ = inputs(config, children=4)
    stamp = (datetime.fromisoformat(config.authority.run_deadline_utc.replace("Z", "+00:00")) - timedelta(hours=2)).isoformat()
    encode = lambda obj: json.dumps(obj, sort_keys=True, separators=(",", ":"))
    with sqlite3.connect(path) as db:
        db.executescript("""
        CREATE TABLE authorities(id TEXT PRIMARY KEY,definition TEXT NOT NULL,halted INTEGER NOT NULL DEFAULT 0,last_seen TEXT NOT NULL);
        CREATE TABLE operations(id TEXT PRIMARY KEY,authority_id TEXT NOT NULL REFERENCES authorities(id),allocation_id TEXT UNIQUE NOT NULL,plan_sha TEXT NOT NULL,plan TEXT NOT NULL,context TEXT NOT NULL,limits_json TEXT NOT NULL,mode TEXT NOT NULL,deadline TEXT NOT NULL,state TEXT NOT NULL);
        CREATE TABLE children(operation_id TEXT NOT NULL REFERENCES operations(id),child_id TEXT NOT NULL,definition TEXT NOT NULL,policy TEXT,remaining INTEGER NOT NULL,used INTEGER NOT NULL DEFAULT 0,repairs INTEGER NOT NULL DEFAULT 0,state TEXT NOT NULL,completion_proof TEXT,snapshot_sha TEXT,PRIMARY KEY(operation_id,child_id));
        CREATE TABLE attempts(id TEXT PRIMARY KEY,operation_id TEXT NOT NULL,child_id TEXT NOT NULL,authority_id TEXT NOT NULL REFERENCES authorities(id),request_sha TEXT NOT NULL,dispatch_sha TEXT NOT NULL,evidence_sha TEXT NOT NULL,context TEXT NOT NULL,reservation TEXT NOT NULL,state TEXT NOT NULL,cost TEXT,settlement_sha TEXT,settlement TEXT,FOREIGN KEY(operation_id,child_id) REFERENCES children(operation_id,child_id));
        CREATE TABLE events(sequence INTEGER PRIMARY KEY AUTOINCREMENT,authority_id TEXT NOT NULL REFERENCES authorities(id),payload TEXT NOT NULL,sha256 TEXT NOT NULL);
        CREATE TABLE outbox(sequence INTEGER PRIMARY KEY REFERENCES events(sequence),projected INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE price_snapshots(sha TEXT PRIMARY KEY,definition TEXT NOT NULL);
        PRAGMA user_version=1;
        """)
        db.execute("INSERT INTO authorities VALUES(?,?,?,?)", (config.authority.authority_id, encode(config.authority.model_dump(mode="json")), int(halted), stamp))
        db.execute("INSERT INTO operations VALUES(?,?,?,?,?,?,?,?,?,?,?)", ("operation", config.authority.authority_id, "allocation", plan.plan_sha256,
            encode(plan.model_dump(mode="json")), encode(context.model_dump(mode="json")), encode(config.limits.model_dump(mode="json")), "simulation", config.authority.run_deadline_utc, "pending"))
        for index, child in enumerate(plan.children):
            policy = next(p for p in config.price_snapshot.policies if p.model == child.model)
            db.execute("INSERT INTO children VALUES(?,?,?,?,?,?,?,?,?,?,?)", ("operation", child.child_id, encode(child.model_dump(mode="json")), encode(policy.model_dump(mode="json")),
                1 if index == 3 else 0, 0 if index == 3 else 1, 0, "pending", None, config.price_snapshot.snapshot_sha256))
            if index < 3:
                state = ("known", "unknown", "active")[index]
                db.execute("INSERT INTO attempts VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", (f"attempt-{index}", "operation", child.child_id, config.authority.authority_id,
                    "4"*64, "5"*64, "6"*64, encode(context.model_dump(mode="json")), child.reserved_usd_per_attempt, state, "0.000016" if index == 0 else None,
                    "7"*64 if index < 2 else None, "{}" if index < 2 else None))
        payload = {"schema_version": 1, "kind": "migration-test", "authority_id": config.authority.authority_id}
        db.execute("INSERT INTO events VALUES(1,?,?,?)", (config.authority.authority_id, encode(payload), m.canonical_digest(payload)))
        db.execute("INSERT INTO outbox VALUES(1,0)")
        db.execute("INSERT INTO price_snapshots VALUES(?,?)", (config.price_snapshot.snapshot_sha256, encode(config.price_snapshot.model_dump(mode="json"))))
    return datetime.fromisoformat(stamp)


def financial_snapshot(path):
    with sqlite3.connect(path) as db:
        return {table: db.execute("SELECT * FROM " + table).fetchall() for table in ("operations", "children", "attempts", "events", "outbox", "price_snapshots")}


@pytest.mark.parametrize("halted", [False, True])
def test_schema1_migrates_without_financial_reset(artifact_dir, halted):
    config = configuration()
    path = artifact_dir / "m8-legacy.sqlite3"
    wall = legacy_database(path, config, halted=halted)
    before = financial_snapshot(path)
    ledger = open_ledger(path, config, clock=lambda: wall, monotonic=lambda: 0.0)
    try:
        assert ledger.connection.execute("PRAGMA user_version").fetchone()[0] == 2
        row = ledger.connection.execute("SELECT last_seen,last_wall,halted,definition FROM authorities").fetchone()
        assert datetime.fromisoformat(row[0]) == datetime.fromisoformat(row[1]) == wall
        assert bool(row[2]) == halted
        totals = ledger.totals()
        assert totals["dispatched_attempts"] == 3
        assert totals["known_spend_usd"] == "0.000016"
        assert totals["halted"] == halted
        assert financial_snapshot(path) == before
    finally:
        ledger.close()


def test_legacy_migration_uses_conservative_clock_floor(artifact_dir):
    config = configuration()
    path = artifact_dir / "m8-legacy-floor.sqlite3"
    floor = legacy_database(path, config)
    ledger = None
    try:
        try:
            ledger = open_ledger(path, config, clock=lambda: floor-timedelta(microseconds=1), monotonic=lambda: 0.0)
        except LedgerError as error:
            assert str(error) == "clock_rollback"
        else:
            with pytest.raises(LedgerError, match="clock_rollback"):
                admit(ledger, config, "below-legacy-floor")
    finally:
        if ledger is not None:
            ledger.close()


def test_schema2_missing_clock_column_refused(artifact_dir):
    config = configuration()
    path = artifact_dir / "m8-malformed.sqlite3"
    wall = legacy_database(path, config)
    with sqlite3.connect(path) as db:
        db.execute("PRAGMA user_version=2")
    with pytest.raises(LedgerError):
        ledger = open_ledger(path, config, clock=lambda: wall)


def test_migration_failure_rolls_back_schema_and_data(artifact_dir):
    from gateway.shared.s3.callledger import Ledger
    config = configuration()
    path = artifact_dir / "m8-migration-fault.sqlite3"
    wall = legacy_database(path, config)
    before = financial_snapshot(path)
    class Interrupted(Ledger):
        def _checkpoint(self, phase):
            if phase == "before_commit":
                raise OSError("m8-test-injected-before-commit")
    with pytest.raises(OSError, match="m8-test-injected"):
        Interrupted(path, authority=config.authority, price_snapshot=config.price_snapshot,
            trusted_bounds=config.trusted_bounds, clock=lambda: wall, monotonic=lambda: 0.0)
    with sqlite3.connect(path) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 1
        assert "last_wall" not in {row[1] for row in db.execute("PRAGMA table_info(authorities)")}
    assert financial_snapshot(path) == before


_clock_barrier = None


def clock_worker_initialize(barrier):
    global _clock_barrier
    _clock_barrier = barrier


def clock_worker(job):
    config, database, worker = job
    clock = Clocks(config)
    ledger = open_ledger(database, config, clock=lambda: clock.wall, monotonic=lambda: clock.tick)
    try:
        _clock_barrier.wait(timeout=45)
        clock.tick = float(worker + 1)
        admit(ledger, config, f"worker-{worker}")
        return "funded"
    except LedgerError as error:
        return str(error)
    finally:
        ledger.close()


@pytest.mark.parametrize("processes", [2, 8])
def test_concurrent_effective_clocks_do_not_poison_raw_wall(artifact_dir, processes):
    from concurrent.futures import ProcessPoolExecutor
    import multiprocessing
    config = configuration()
    path = artifact_dir / "m8-concurrent-clock.sqlite3"
    ledger = open_ledger(path, config)
    ledger.close()
    context = multiprocessing.get_context("spawn")
    with ProcessPoolExecutor(processes, mp_context=context, initializer=clock_worker_initialize, initargs=(context.Barrier(processes),)) as pool:
        results = list(pool.map(clock_worker, [(config, path, worker) for worker in range(processes)]))
    assert results == ["funded"] * processes


def test_malformed_schema2_clock_is_closed_error(artifact_dir):
    config = configuration()
    clock = Clocks(config)
    path = artifact_dir / "m8-invalid-clock.sqlite3"
    ledger = open_ledger(path, config)
    ledger.close()
    with sqlite3.connect(path) as db:
        assert "last_wall" in {row[1] for row in db.execute("PRAGMA table_info(authorities)")}, "schema2 clock column required"
        db.execute("UPDATE authorities SET last_wall='not-a-clock'")
    reopened = None
    try:
        with pytest.raises(LedgerError):
            reopened = open_ledger(path, config, clock=lambda: clock.wall)
            admit(reopened, config, "bad-clock")
    finally:
        if reopened is not None:
            reopened.close()

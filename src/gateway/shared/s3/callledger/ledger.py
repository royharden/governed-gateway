"""SQLite-authoritative funding and metadata events; never dispatches a provider call."""

import json
import math
import os
import sqlite3
import tempfile
import time
from collections.abc import Iterable
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from decimal import Decimal, localcontext
from pathlib import Path
from typing import Literal
from uuid import uuid4

from .models import (
    Allocation,
    BudgetAuthority,
    CallContext,
    Digest,
    Identifier,
    Limits,
    MetadataRecord,
    Money,
    NonModelSpan,
    NormalizedUsage,
    OperationPlan,
    WireModel,
    canonical_digest,
)
from .pricing import FundingEvidence, PriceSnapshot, RequestEvidence


class LedgerError(ValueError):
    """Closed diagnostic code only: no SQL, paths, payloads or exception bodies."""


class ReuseAccounting(WireModel):
    schema_version: Literal[1]
    origin: Literal["mock", "replay"]
    capture_sha256: Digest
    request_identity_sha256: Digest
    source_run_id: Identifier
    source_model: Identifier | None
    source_cost_usd: Money | None
    source_usage_sha256: Digest | None
    source_price_sha256: Digest | None
    current_external_cost_usd: Literal["0"]


def _json(value) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _dump(model):
    return model.model_dump(mode="json")


def _utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class Ledger:
    """Each method is a short IMMEDIATE transaction; Decimal arithmetic stays in Python.

    Registry entries are trusted-process inputs, not imported state. A real controller
    must establish their token/source proofs. This primitive grants no network access.
    A dispatch reservation is durably consumed BEFORE transport, so a crash can only
    over-reserve liability. Reopening never releases or resets authority/counters.
    """

    def __init__(
        self,
        db_path: Path,
        *,
        authority: BudgetAuthority,
        price_snapshot: PriceSnapshot | None = None,
        trusted_bounds: Iterable[FundingEvidence] = (),
        trusted_requests: Iterable[RequestEvidence] = (),
        clock=None,
        monotonic=None,
    ):
        self.authority = BudgetAuthority.model_validate(_dump(authority))
        self.snapshot = (
            PriceSnapshot.model_validate(_dump(price_snapshot))
            if price_snapshot is not None
            else None
        )
        self.bounds = {
            b.evidence_sha256: FundingEvidence.model_validate(_dump(b)) for b in trusted_bounds
        }
        self.requests = {
            r.evidence_sha256: RequestEvidence.model_validate(_dump(r)) for r in trusted_requests
        }
        self.clock = clock or (lambda: datetime.now(UTC))
        self.monotonic = monotonic or time.monotonic
        self._anchor_wall = self._now()
        self._anchor_tick = self.monotonic()
        self.db_path = Path(db_path)
        if self.db_path.is_symlink():
            raise LedgerError("unsafe_store")
        self.connection = sqlite3.connect(self.db_path, timeout=5, isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys=ON")
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA synchronous=FULL")
        try:
            self._initialize()
        except BaseException:
            self.connection.close()
            raise

    def close(self):
        self.connection.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def _checkpoint(self, _phase: str):
        """Private no-op seam for process-exit durability tests."""

    @contextmanager
    def _transaction(self):
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            with localcontext() as context:
                context.prec = 150
                yield
                self._checkpoint("before_commit")
                self.connection.commit()
                self._checkpoint("after_commit")
        except BaseException as error:
            if self.connection.in_transaction:
                self.connection.rollback()
            if isinstance(error, sqlite3.Error):
                raise LedgerError("storage") from None
            raise

    def _initialize(self):
        with self._transaction():
            version = self.connection.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0, 1, 2):
                raise LedgerError("schema_version")
            # M8-S3-CLOCK-1: an unversioned store must be empty. Never guess
            # whether existing authority rows are safe to initialize or migrate.
            if version == 0 and self.connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='authorities'"
            ).fetchone() is not None:
                raise LedgerError("schema_version")
            statements = [
                "CREATE TABLE IF NOT EXISTS authorities (id TEXT PRIMARY KEY, "
                "definition TEXT NOT NULL, halted INTEGER NOT NULL DEFAULT 0, last_seen"
                " TEXT NOT NULL, last_wall TEXT NOT NULL)",
                "CREATE TABLE IF NOT EXISTS operations (id TEXT PRIMARY KEY, "
                "authority_id TEXT NOT NULL REFERENCES authorities(id), allocation_id "
                "TEXT UNIQUE NOT NULL, plan_sha TEXT NOT NULL, plan TEXT NOT NULL, "
                "context TEXT NOT NULL, limits_json TEXT NOT NULL, mode TEXT NOT NULL, "
                "deadline TEXT NOT NULL, state TEXT NOT NULL)",
                "CREATE TABLE IF NOT EXISTS children (operation_id TEXT NOT NULL "
                "REFERENCES operations(id), child_id TEXT NOT NULL, definition TEXT NOT"
                " NULL, policy TEXT, remaining INTEGER NOT NULL, used INTEGER NOT NULL "
                "DEFAULT 0, repairs INTEGER NOT NULL DEFAULT 0, state TEXT NOT NULL, "
                "completion_proof TEXT, snapshot_sha TEXT, "
                "PRIMARY KEY(operation_id,child_id))",
                "CREATE TABLE IF NOT EXISTS attempts (id TEXT PRIMARY KEY, operation_id"
                " TEXT NOT NULL, child_id TEXT NOT NULL, authority_id TEXT NOT NULL "
                "REFERENCES authorities(id), request_sha TEXT NOT NULL, dispatch_sha "
                "TEXT NOT NULL, evidence_sha TEXT NOT NULL, context TEXT NOT NULL, "
                "reservation TEXT NOT NULL, state TEXT NOT NULL, cost TEXT, "
                "settlement_sha TEXT, settlement TEXT, FOREIGN "
                "KEY(operation_id,child_id) REFERENCES children(operation_id,child_id))",
                "CREATE TABLE IF NOT EXISTS events (sequence INTEGER PRIMARY KEY "
                "AUTOINCREMENT, authority_id TEXT NOT NULL REFERENCES authorities(id), "
                "payload TEXT NOT NULL, sha256 TEXT NOT NULL)",
                "CREATE TABLE IF NOT EXISTS outbox (sequence INTEGER PRIMARY KEY "
                "REFERENCES events(sequence), projected INTEGER NOT NULL DEFAULT 0)",
                "CREATE TABLE IF NOT EXISTS price_snapshots "
                "(sha TEXT PRIMARY KEY, definition TEXT NOT NULL)",
            ]
            for statement in statements:
                self.connection.execute(statement)
            columns = {row["name"]: row for row in self.connection.execute(
                "PRAGMA table_info(authorities)"
            )}
            if version == 1:
                if "last_wall" in columns:
                    raise LedgerError("schema_version")
                # Legacy last_seen may include monotonic advancement. It is the
                # only durable floor available: preserve it conservatively rather
                # than inventing the raw historical wall clock. No financial rows
                # or existing effective deadlines change in this atomic migration.
                self.connection.execute(
                    "ALTER TABLE authorities ADD COLUMN last_wall TEXT NOT NULL DEFAULT ''"
                )
                self.connection.execute("UPDATE authorities SET last_wall=last_seen")
            elif "last_wall" not in columns or not columns["last_wall"]["notnull"]:
                raise LedgerError("schema_version")
            for row in self.connection.execute("SELECT last_seen,last_wall FROM authorities"):
                self._stored_times(row)
            self.connection.execute("PRAGMA user_version=2")
            if self.snapshot is not None:
                self.connection.execute(
                    "INSERT OR IGNORE INTO price_snapshots VALUES(?,?)",
                    (self.snapshot.snapshot_sha256, _json(_dump(self.snapshot))),
                )
            definition = _json(_dump(self.authority))
            previous = self.connection.execute(
                "SELECT definition FROM authorities WHERE id=?", (self.authority.authority_id,)
            ).fetchone()
            if previous is not None:
                if previous[0] != definition:
                    raise LedgerError("authority_conflict")
            else:
                observed = self._now().isoformat()
                self.connection.execute(
                    "INSERT INTO authorities(id,definition,last_seen,last_wall) VALUES(?,?,?,?)",
                    (self.authority.authority_id, definition, observed, observed),
                )
                self._emit("authority_created", {"scope_sha256": self.authority.scope_sha256})

    def _now(self):
        now = self.clock()
        if now.tzinfo is None or now.utcoffset().total_seconds() != 0:
            raise LedgerError("clock")
        return now

    def _emit(self, kind: str, fields: dict):
        payload = {
            "schema_version": 1,
            "kind": kind,
            "authority_id": self.authority.authority_id,
            **fields,
        }
        text = _json(payload)
        cursor = self.connection.execute(
            "INSERT INTO events(authority_id,payload,sha256) VALUES(?,?,?)",
            (self.authority.authority_id, text, canonical_digest(payload)),
        )
        self.connection.execute("INSERT INTO outbox(sequence) VALUES(?)", (cursor.lastrowid,))

    @staticmethod
    def _stored_times(row):
        """Validate the durable effective/raw UTC pair without repairing evidence."""
        try:
            if not isinstance(row["last_seen"], str) or not isinstance(row["last_wall"], str):
                raise ValueError
            effective = _utc(row["last_seen"])
            wall = _utc(row["last_wall"])
            if (effective.utcoffset() != timedelta(0)
                or wall.utcoffset() != timedelta(0) or wall > effective):
                raise ValueError
            return effective, wall
        except (ValueError, TypeError, KeyError, IndexError, OverflowError):
            raise LedgerError("clock_state") from None

    def _time(self, *, funded=True):
        now = self._now()
        effective = self._anchor_wall + timedelta(
            seconds=max(self.monotonic() - self._anchor_tick, 0)
        )
        row = self.connection.execute(
            "SELECT * FROM authorities WHERE id=?", (self.authority.authority_id,)
        ).fetchone()
        previous_effective, previous_wall = self._stored_times(row)
        if funded and now < previous_wall:
            raise LedgerError("clock_rollback")
        # Compare raw observations only; monotonic advancement must never be
        # mistaken for a backwards wall tick. Both high-water marks survive
        # reopen and competing workers through this same IMMEDIATE transaction.
        observed_wall = max(now, previous_wall)
        now = max(now, effective, previous_effective)
        if funded and row["halted"]:
            raise LedgerError("halted")
        if funded and (
            now >= _utc(self.authority.run_deadline_utc)
            or (self.authority.expires_at and now >= _utc(self.authority.expires_at))
        ):
            raise LedgerError("deadline")
        self.connection.execute(
            "UPDATE authorities SET last_seen=?,last_wall=? WHERE id=?",
            (now.isoformat(), observed_wall.isoformat(), self.authority.authority_id),
        )
        return now

    def _totals(self):
        known = active = unknown = future = Decimal(0)
        attempts = held_attempts = 0
        for row in self.connection.execute(
            "SELECT reservation,state,cost FROM attempts WHERE authority_id=?",
            (self.authority.authority_id,),
        ):
            attempts += 1
            if row["state"] == "known":
                known += Decimal(row["cost"])
            elif row["state"] == "active":
                active += Decimal(row["reservation"])
            else:
                unknown += Decimal(row["reservation"])
        for row in self.connection.execute(
            "SELECT c.definition,c.remaining FROM children c JOIN operations o ON "
            "c.operation_id=o.id WHERE o.authority_id=?",
            (self.authority.authority_id,),
        ):
            held_attempts += row["remaining"]
            future += (
                Decimal(json.loads(row["definition"])["reserved_usd_per_attempt"])
                * row["remaining"]
            )
        return {
            "known_spend_usd": format(known, "f"),
            "active_holds_usd": format(active, "f"),
            "unknown_liability_usd": format(unknown, "f"),
            "future_holds_usd": format(future, "f"),
            "total_exposure_usd": format(known + active + unknown + future, "f"),
            "dispatched_attempts": attempts,
            "future_attempts": held_attempts,
        }

    def totals(self):
        with self._transaction():
            result = self._totals()
            result["halted"] = bool(
                self.connection.execute(
                    "SELECT halted FROM authorities WHERE id=?", (self.authority.authority_id,)
                ).fetchone()[0]
            )
            return result

    def _operation(self, allocation: Allocation):
        allocation = Allocation.model_validate(_dump(allocation))
        row = self.connection.execute(
            "SELECT * FROM operations WHERE id=?", (allocation.operation_id,)
        ).fetchone()
        if row is None or (row["authority_id"], row["allocation_id"], row["plan_sha"]) != (
            self.authority.authority_id,
            allocation.allocation_id,
            allocation.plan_sha256,
        ):
            raise LedgerError("allocation_mismatch")
        if allocation.authority_id != self.authority.authority_id:
            raise LedgerError("allocation_mismatch")
        return row

    def _remaining_seconds(self, operation, now):
        return (_utc(operation["deadline"]) - now).total_seconds()

    def _quote(self, child, mode):
        if mode == "offline":
            if child.max_attempts or Decimal(child.reserved_usd_per_attempt):
                raise LedgerError("offline_dispatch")
            return None
        bound = self.bounds.get(child.bound_evidence_sha256)
        if (
            bound is None
            or self.snapshot is None
            or bound.snapshot_sha256 != self.snapshot.snapshot_sha256
        ):
            raise LedgerError("untrusted_bound")
        if mode == "external" and (
            bound.bound_kind == "synthetic_fixture"
            or self.snapshot.provenance.origin != "verified_primary"
        ):
            raise LedgerError("synthetic_not_live_proof")
        if (
            child.provider_config_sha256,
            child.model,
            child.request_shape_limit_sha256,
            child.input_token_maximum,
            child.output_token_maximum,
        ) != (
            bound.provider_config_sha256,
            bound.model,
            bound.request_shape_limit_sha256,
            bound.input_token_maximum,
            bound.output_token_maximum,
        ):
            raise LedgerError("bound_mismatch")
        policy = next(
            (p for p in self.snapshot.policies if p.policy_sha256 == bound.policy_sha256), None
        )
        if policy is None or policy.model != child.model:
            raise LedgerError("price_unknown")
        maximum = Decimal(
            policy.maximum_cost(bound.input_token_maximum, bound.output_token_maximum)
        )
        if Decimal(child.reserved_usd_per_attempt) < maximum:
            raise LedgerError("underfunded_bound")
        if policy.fee_usd is None or Decimal(child.fee_maximum_usd) < Decimal(policy.fee_usd):
            raise LedgerError("fee_bound")
        return _dump(policy)

    def admit_operation(
        self,
        plan: OperationPlan,
        *,
        context: CallContext,
        limits: Limits,
        mode: Literal["simulation", "external", "offline"],
    ) -> Allocation:
        plan = OperationPlan.model_validate(_dump(plan))
        context = CallContext.model_validate(_dump(context))
        limits = Limits.model_validate(_dump(limits))
        if mode not in {"simulation", "external", "offline"}:
            raise LedgerError("mode")
        if not (plan.authority_id == context.authority_id == self.authority.authority_id):
            raise LedgerError("authority_mismatch")
        if (
            context.operation_id != plan.operation_id
            or canonical_digest(_dump(context)) != plan.context_sha256
        ):
            raise LedgerError("context_mismatch")
        if any(
            c.max_attempts > limits.max_attempts_total or c.max_repairs > limits.max_content_repairs
            for c in plan.children
        ):
            raise LedgerError("caller_limits")
        if limits.max_outbound_attempts > self.authority.max_outbound_attempts:
            raise LedgerError("caller_limits")
        quotes = {c.child_id: self._quote(c, mode) for c in plan.children}
        with self._transaction():
            now = self._time()
            prior = self.connection.execute(
                "SELECT * FROM operations WHERE id=?", (plan.operation_id,)
            ).fetchone()
            if prior:
                if (
                    prior["authority_id"],
                    prior["plan_sha"],
                    prior["context"],
                    prior["limits_json"],
                    prior["mode"],
                ) != (
                    self.authority.authority_id,
                    plan.plan_sha256,
                    _json(_dump(context)),
                    _json(_dump(limits)),
                    mode,
                ):
                    raise LedgerError("operation_conflict")
                return Allocation(
                    schema_version=1,
                    allocation_id=prior["allocation_id"],
                    authority_id=self.authority.authority_id,
                    operation_id=plan.operation_id,
                    plan_sha256=plan.plan_sha256,
                )
            totals = self._totals()
            if Decimal(totals["total_exposure_usd"]) + plan.declared_worst_case_usd > Decimal(
                self.authority.cap_usd
            ):
                raise LedgerError("budget_rejected")
            quota = min(limits.max_outbound_attempts, self.authority.max_outbound_attempts)
            if (
                totals["dispatched_attempts"]
                + totals["future_attempts"]
                + sum(c.max_attempts for c in plan.children)
                > quota
            ):
                raise LedgerError("attempt_limit")
            active = list(
                self.connection.execute(
                    "SELECT limits_json FROM operations WHERE authority_id=? AND state='pending'",
                    (self.authority.authority_id,),
                )
            )
            concurrency_limit = min(
                [
                    limits.max_concurrent_operations,
                    *[json.loads(r[0])["max_concurrent_operations"] for r in active],
                ]
            )
            if len(active) >= concurrency_limit:
                raise LedgerError("concurrency_limit")
            deadline = min(
                _utc(self.authority.run_deadline_utc),
                _utc(limits.run_deadline_utc),
                now + timedelta(seconds=limits.operation_deadline_s),
            )
            if deadline <= now:
                raise LedgerError("deadline")
            allocation_id = uuid4().hex
            self.connection.execute(
                "INSERT INTO operations VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    plan.operation_id,
                    self.authority.authority_id,
                    allocation_id,
                    plan.plan_sha256,
                    _json(_dump(plan)),
                    _json(_dump(context)),
                    _json(_dump(limits)),
                    mode,
                    deadline.isoformat(),
                    "pending",
                ),
            )
            for child in plan.children:
                self.connection.execute(
                    "INSERT INTO "
                    "children(operation_id,child_id,definition,policy,remaining,state,"
                    "snapshot_sha) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (
                        plan.operation_id,
                        child.child_id,
                        _json(_dump(child)),
                        _json(quotes[child.child_id])
                        if quotes[child.child_id] is not None
                        else None,
                        child.max_attempts,
                        "pending",
                        self.snapshot.snapshot_sha256 if mode != "offline" else None,
                    ),
                )
            self._emit(
                "operation_admitted",
                {
                    "operation_id": plan.operation_id,
                    "plan_sha256": plan.plan_sha256,
                    "context_sha256": plan.context_sha256,
                    "mode": mode,
                    "held_usd": format(plan.declared_worst_case_usd, "f"),
                    "bound_evidence": [
                        _dump(self.bounds[c.bound_evidence_sha256]) for c in plan.children
                    ]
                    if mode != "offline"
                    else [],
                },
            )
            return Allocation(
                schema_version=1,
                allocation_id=allocation_id,
                authority_id=self.authority.authority_id,
                operation_id=plan.operation_id,
                plan_sha256=plan.plan_sha256,
            )

    def begin_attempt(
        self,
        allocation: Allocation,
        *,
        context: CallContext,
        request: RequestEvidence,
        content_repair: bool = False,
    ) -> str:
        if type(content_repair) is not bool:
            raise LedgerError("caller_limits")
        context = CallContext.model_validate(_dump(context))
        request = RequestEvidence.model_validate(_dump(request))
        if self.requests.get(request.evidence_sha256) != request:
            raise LedgerError("untrusted_request")
        with self._transaction():
            now = self._time()
            operation = self._operation(allocation)
            if operation["mode"] == "offline":
                raise LedgerError("offline_dispatch")
            if operation["state"] != "pending" or self._remaining_seconds(operation, now) <= 0:
                raise LedgerError("deadline")
            child = self.connection.execute(
                "SELECT * FROM children WHERE operation_id=? AND child_id=?",
                (operation["id"], context.child_id),
            ).fetchone()
            if child is None or child["state"] != "pending" or child["remaining"] <= 0:
                raise LedgerError("attempt_limit")
            definition = json.loads(child["definition"])
            root = json.loads(operation["context"])
            submitted = _dump(context)
            for field in ["child_id", "span_id", "parent_span_id", "purpose"]:
                root.pop(field, None)
                submitted.pop(field, None)
            if root != submitted or context.purpose != definition["purpose"]:
                raise LedgerError("context_mismatch")
            if request.bound_evidence_sha256 != definition["bound_evidence_sha256"]:
                raise LedgerError("bound_mismatch")
            if request.input_token_count > definition["input_token_maximum"] or (
                definition["output_token_maximum"] is not None
                and (
                    request.output_token_maximum is None
                    or request.output_token_maximum > definition["output_token_maximum"]
                )
            ):
                raise LedgerError("request_bound")
            if content_repair and child["repairs"] >= definition["max_repairs"]:
                raise LedgerError("repair_limit")
            if self.connection.execute(
                "SELECT 1 FROM attempts WHERE operation_id=? AND child_id=? AND state='active'",
                (operation["id"], context.child_id),
            ).fetchone():
                raise LedgerError("active_attempt")
            attempt = uuid4().hex
            self.connection.execute(
                "UPDATE children SET remaining=remaining-1, used=used+1, "
                "repairs=repairs+? WHERE operation_id=? AND child_id=?",
                (int(content_repair), operation["id"], context.child_id),
            )
            self.connection.execute(
                "INSERT INTO "
                "attempts(id,operation_id,child_id,authority_id,request_sha,dispatch_sha,evidence_sha,context,reservation,state)"
                " VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    attempt,
                    operation["id"],
                    context.child_id,
                    self.authority.authority_id,
                    request.request_identity_sha256,
                    request.dispatched_envelope_sha256,
                    request.evidence_sha256,
                    _json(_dump(context)),
                    definition["reserved_usd_per_attempt"],
                    "active",
                ),
            )
            self._emit(
                "attempt_reserved",
                {
                    "operation_id": operation["id"],
                    "child_id": context.child_id,
                    "attempt_id": attempt,
                    "context_sha256": canonical_digest(_dump(context)),
                    "request_identity_sha256": request.request_identity_sha256,
                    "dispatched_envelope_sha256": request.dispatched_envelope_sha256,
                    "bound_evidence_sha256": request.bound_evidence_sha256,
                    "held_usd": definition["reserved_usd_per_attempt"],
                },
            )
            return attempt

    def settle(self, attempt_id: str, *, metadata: MetadataRecord, usage: NormalizedUsage) -> str:
        from .pricing import PricePolicy

        metadata = MetadataRecord.model_validate(_dump(metadata))
        usage = NormalizedUsage.model_validate(_dump(usage))
        with self._transaction():
            # Settlement after expiration/halt is essential; it must not erase a paid attempt.
            self._time(funded=False)
            attempt = self.connection.execute(
                "SELECT * FROM attempts WHERE id=? AND authority_id=?",
                (attempt_id, self.authority.authority_id),
            ).fetchone()
            if attempt is None:
                raise LedgerError("attempt_unknown")
            if (
                metadata.request_identity_sha256 != attempt["request_sha"]
                or _json(_dump(metadata.context)) != attempt["context"]
            ):
                raise LedgerError("context_mismatch")
            projection = _dump(metadata.usage) if metadata.usage is not None else None
            if canonical_digest(projection) != metadata.usage_projection_sha256:
                raise LedgerError("usage_binding")
            if metadata.usage is None or metadata.usage.details != usage:
                raise LedgerError("usage_binding")
            child = self.connection.execute(
                "SELECT policy,snapshot_sha FROM children WHERE operation_id=? AND child_id=?",
                (attempt["operation_id"], attempt["child_id"]),
            ).fetchone()
            policy = PricePolicy.model_validate(json.loads(child["policy"]))
            observation = policy.price(usage, reservation_usd=attempt["reservation"])
            record = {
                "metadata": _dump(metadata),
                "usage": _dump(usage),
                "price_policy_sha256": policy.policy_sha256,
                "price_snapshot_sha256": child["snapshot_sha"],
                "cost": _dump(observation),
            }
            digest = canonical_digest(record)
            if attempt["settlement_sha"]:
                if attempt["settlement_sha"] != digest:
                    raise LedgerError("settlement_conflict")
                return digest
            self.connection.execute(
                "UPDATE attempts SET state=?,cost=?,settlement_sha=?,settlement=? WHERE id=?",
                (
                    observation.status,
                    observation.computed_cost_usd,
                    digest,
                    _json(record),
                    attempt_id,
                ),
            )
            breach = observation.computed_cost_usd is not None and Decimal(
                observation.computed_cost_usd
            ) > Decimal(attempt["reservation"])
            if breach:
                self.connection.execute(
                    "UPDATE authorities SET halted=1 WHERE id=?", (self.authority.authority_id,)
                )
            self._emit(
                "bound_breach" if breach else "attempt_settled",
                {
                    "attempt_id": attempt_id,
                    "operation_id": attempt["operation_id"],
                    "settlement_sha256": digest,
                    "accounting": record,
                },
            )
            return digest

    def mark_unknown(self, attempt_id: str) -> str:
        """Conservatively retain a dispatched reservation after lost/ambiguous response."""
        with self._transaction():
            row = self.connection.execute(
                "SELECT * FROM attempts WHERE id=? AND authority_id=?",
                (attempt_id, self.authority.authority_id),
            ).fetchone()
            if row is None:
                raise LedgerError("attempt_unknown")
            if row["state"] == "active":
                digest = canonical_digest({"attempt_id": attempt_id, "status": "unknown_dispatch"})
                self.connection.execute(
                    "UPDATE attempts SET state='unknown',settlement_sha=? WHERE id=?",
                    (digest, attempt_id),
                )
                self._emit(
                    "attempt_unknown",
                    {
                        "attempt_id": attempt_id,
                        "held_usd": row["reservation"],
                        "settlement_sha256": digest,
                    },
                )
                return digest
            if row["state"] != "unknown":
                raise LedgerError("settlement_conflict")
            return row["settlement_sha"]

    def finish_child(
        self,
        allocation: Allocation,
        *,
        child_id: str,
        outcome: Literal["complete", "failed", "skipped", "cancelled_before_dispatch"],
        proof_sha256: str,
    ):
        with self._transaction():
            operation = self._operation(allocation)
            child = self.connection.execute(
                "SELECT * FROM children WHERE operation_id=? AND child_id=?",
                (operation["id"], child_id),
            ).fetchone()
            if child is None or outcome not in {
                "complete",
                "failed",
                "skipped",
                "cancelled_before_dispatch",
            }:
                raise LedgerError("child_unknown")
            if child["state"] != "pending":
                if child["state"] != outcome or child["completion_proof"] != proof_sha256:
                    raise LedgerError("completion_conflict")
                return
            last = self.connection.execute(
                "SELECT * FROM attempts WHERE operation_id=? AND child_id=? ORDER BY "
                "rowid DESC LIMIT 1",
                (operation["id"], child_id),
            ).fetchone()
            if last and last["state"] == "active":
                raise LedgerError("active_attempt")
            if last:
                if proof_sha256 != last["settlement_sha"] or outcome not in {"complete", "failed"}:
                    raise LedgerError("completion_proof")
                if outcome == "complete" and (
                    last["state"] != "known"
                    or json.loads(last["settlement"])["metadata"]["status"] != "ok"
                ):
                    raise LedgerError("completion_proof")
            else:
                expected = canonical_digest(
                    {
                        "allocation_id": allocation.allocation_id,
                        "child_id": child_id,
                        "undispatched": True,
                    }
                )
                conditional = json.loads(child["definition"])["conditional"]
                if (
                    proof_sha256 != expected
                    or outcome not in {"skipped", "cancelled_before_dispatch"}
                    or (outcome == "skipped" and not conditional)
                ):
                    raise LedgerError("completion_proof")
            released = (
                Decimal(json.loads(child["definition"])["reserved_usd_per_attempt"])
                * child["remaining"]
            )
            self.connection.execute(
                "UPDATE children SET state=?,remaining=0,completion_proof=? "
                "WHERE operation_id=? AND child_id=?",
                (outcome, proof_sha256, operation["id"], child_id),
            )
            self._emit(
                "future_released",
                {
                    "operation_id": operation["id"],
                    "child_id": child_id,
                    "outcome": outcome,
                    "proof_sha256": proof_sha256,
                    "released_usd": format(released, "f"),
                },
            )
            states = [
                r[0]
                for r in self.connection.execute(
                    "SELECT state FROM children WHERE operation_id=?", (operation["id"],)
                )
            ]
            state = (
                "pending"
                if "pending" in states
                else (
                    "complete" if all(s in {"complete", "skipped"} for s in states) else "partial"
                )
            )
            self.connection.execute(
                "UPDATE operations SET state=? WHERE id=?", (state, operation["id"])
            )

    def retry_fits(self, allocation: Allocation, *, retry_after_s: float) -> bool:
        if not math.isfinite(retry_after_s) or retry_after_s < 0:
            raise LedgerError("deadline")
        with self._transaction():
            now = self._time()
            operation = self._operation(allocation)
            return operation["state"] == "pending" and retry_after_s < self._remaining_seconds(
                operation, now
            )

    def record_non_model(self, span: NonModelSpan):
        span = NonModelSpan.model_validate(_dump(span))
        if span.context.authority_id != self.authority.authority_id:
            raise LedgerError("context_mismatch")
        with self._transaction():
            self._emit("non_model", {"span": _dump(span)})

    def record_reuse(
        self,
        allocation: Allocation,
        *,
        context: CallContext,
        request: RequestEvidence,
        provenance: ReuseAccounting,
    ):
        """Account a caller's network-free lookup; never retrieves or invents a payload."""
        provenance = ReuseAccounting.model_validate(_dump(provenance))
        context = CallContext.model_validate(_dump(context))
        request = RequestEvidence.model_validate(_dump(request))
        if (
            self.requests.get(request.evidence_sha256) != request
            or provenance.request_identity_sha256 != request.request_identity_sha256
        ):
            raise LedgerError("untrusted_request")
        child_id = context.child_id
        with self._transaction():
            operation = self._operation(allocation)
            if operation["mode"] != "offline":
                raise LedgerError("offline_dispatch")
            submitted, root = _dump(context), json.loads(operation["context"])
            for field in ["child_id", "span_id", "parent_span_id"]:
                root.pop(field, None)
                submitted.pop(field, None)
            if root != submitted:
                raise LedgerError("context_mismatch")
            child = self.connection.execute(
                "SELECT * FROM children WHERE operation_id=? AND child_id=?",
                (operation["id"], child_id),
            ).fetchone()
            if child is None or child["state"] != "pending" or child["used"] != 0:
                raise LedgerError("completion_conflict")
            if (
                request.bound_evidence_sha256
                != json.loads(child["definition"])["bound_evidence_sha256"]
            ):
                raise LedgerError("bound_mismatch")
            self.connection.execute(
                "UPDATE children SET state='complete',remaining=0,completion_proof=? "
                "WHERE operation_id=? "
                "AND child_id=?",
                (canonical_digest(_dump(provenance)), operation["id"], child_id),
            )
            self._emit(
                "reuse_accounted",
                {
                    "operation_id": operation["id"],
                    "child_id": child_id,
                    "provenance": _dump(provenance),
                },
            )
            pending = self.connection.execute(
                "SELECT 1 FROM children WHERE operation_id=? AND state='pending'",
                (operation["id"],),
            ).fetchone()
            if pending is None:
                self.connection.execute(
                    "UPDATE operations SET state='complete' WHERE id=?", (operation["id"],)
                )

    def operation_state(self, allocation: Allocation) -> str:
        with self._transaction():
            return self._operation(allocation)["state"]

    def export_jsonl(self, path: Path) -> int:
        """Rebuild the derived projection, including after missing/torn/rolled-back export.

        SQLite's write transaction serializes concurrent exporters. A crash between
        atomic replacement and the outbox mark leaves pending rows, never lost events.
        """
        path = Path(path)
        protected = {
            self.db_path.resolve(),
            *[
                Path(str(self.db_path) + suffix).resolve()
                for suffix in ["-wal", "-shm", "-journal"]
            ],
        }
        if path.is_symlink() or path.resolve() in protected:
            raise LedgerError("unsafe_projection")
        with self._transaction():
            rows = list(
                self.connection.execute(
                    "SELECT * FROM events WHERE authority_id=? ORDER BY sequence",
                    (self.authority.authority_id,),
                )
            )
            if any(canonical_digest(json.loads(row["payload"])) != row["sha256"] for row in rows):
                raise LedgerError("event_integrity")
            payload = b"".join(
                (
                    _json(
                        {
                            "sequence": r["sequence"],
                            "event": json.loads(r["payload"]),
                            "sha256": r["sha256"],
                        }
                    )
                    + "\n"
                ).encode("utf-8")
                for r in rows
            )
            temporary = None
            try:
                with tempfile.NamedTemporaryFile(
                    dir=path.parent, prefix=".ledger-projection-", delete=False
                ) as output:
                    temporary = Path(output.name)
                    output.write(payload)
                    output.flush()
                    os.fsync(output.fileno())
                self._checkpoint("projection_before_replace")
                os.replace(temporary, path)
                temporary = None
                self._checkpoint("projection_after_replace")
                self.connection.execute(
                    "UPDATE outbox SET projected=1 WHERE sequence IN (SELECT sequence FROM "
                    "events WHERE authority_id=?)",
                    (self.authority.authority_id,),
                )
            except OSError:
                raise LedgerError("projection_io") from None
            finally:
                if temporary is not None:
                    try:
                        temporary.unlink(missing_ok=True)
                    except OSError:
                        raise LedgerError("projection_io") from None
            return len(rows)

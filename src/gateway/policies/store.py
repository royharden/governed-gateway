"""Durable local governance over INT-owned schema version 1.

No database or key file is created by import or by this class. Bootstrap owns the
schema, WAL configuration and initial authority row. Ledger state is authoritative
for money; lifecycle markers here never constitute a dispatch ticket.
"""

from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from contextvars import ContextVar
from datetime import datetime, timedelta
from decimal import Decimal
from hashlib import sha256
import base64
import json
import os
from pathlib import Path
import sqlite3
from time import monotonic
from typing import TypeVar

from gateway.schemas import (
    ActivationRecord, ActivePolicy, ApprovalRecord, CapabilityProfile, EligibilityContext,
    AttemptReceipt, CallerContext, EncryptedResult, EvaluationAuthorization,
    EvaluationRecord, GatewayRequest, HaltState,
    IncidentEvidence, IncidentRecord, IncidentSnapshot, LedgerJoin, LedgerOperationSnapshot,
    GatewayError, OperationPermit, OperationSnapshot, OperationState, PermitDecision,
    PermitPlan, PermitState, PolicyBundle, PolicyError, PolicyRecoveryPage, Record,
    ProviderResult, ReplayBinding, RoutingSnapshot, SettlementReceipt, StagedResult,
    canonical_bytes, digest, money_from_micros, usd_micros,
)
from gateway.runtime import adapter_manifest_digest, profile_manifest_digest, require_local_runtime_root

from .eligibility import (
    check_bundle_tuple, check_context, check_evaluation, check_plan, require,
    verify_operator,
)

T = TypeVar("T", bound=Record)
ZERO = Decimal("0")


def utc_text(value: datetime) -> str:
    require(value.utcoffset() is not None and value.utcoffset().total_seconds() == 0,
            "clock_untrusted")
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def utc_read(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    utc_text(parsed)
    return parsed


def decode_record(raw: bytes, record_type: type[T], expected_hash: str | None = None) -> T:
    """Revalidate canonical bytes and their identity on every durable read."""
    value = record_type.model_validate_json(raw)
    require(canonical_bytes(value) == raw, "invalid_evidence")
    if expected_hash is not None:
        require(sha256(raw).hexdigest() == expected_hash, "invalid_evidence")
    return value


class PolicyStore:
    def __init__(
        self, database_path: Path, *, authority_id: str, verification_key: bytes,
        authority_lock: Callable[[], AbstractContextManager[None]],
        clock: Callable[[], datetime],
    ) -> None:
        require(type(verification_key) is bytes and len(verification_key) == 32, "invalid_signature")
        self.authority_id = authority_id
        self._path = database_path
        self._key = verification_key
        self._lock = authority_lock
        self._clock = clock
        self._wall_origin: datetime | None = None
        self._monotonic_origin: float | None = None
        self._config_sha256 = digest({
            "schema_version": 1, "authority_id": authority_id,
            "verification_key_sha256": sha256(verification_key).hexdigest(),
        })
        self._context_loader: Callable[[str], EligibilityContext] | None = None
        self._ledger_reader: Callable[[str], LedgerOperationSnapshot | None] | None = None
        self._assert_lock_held: Callable[[], None] | None = None
        self._key_digest: Callable[[GatewayRequest], str] | None = None
        self._incident_reader: Callable[[IncidentEvidence], IncidentEvidence | None] | None = None
        self._profile_loader: Callable[[str], tuple[CapabilityProfile, ...]] | None = None
        self._retry_reader: Callable[[str, str], ProviderResult | None] | None = None
        self._bound = False
        self._used = False
        self._current: ContextVar[tuple | None] = ContextVar("governance_transaction", default=None)

    def _prepare_evidence(self, connection: sqlite3.Connection, *, policy_hash: str | None,
                          approval_hash: str | None, operation_id: str | None,
                          active_context: bool) -> tuple:
        """Load trusted callbacks under the authority lock before the SQL write lock.

        The runtime context/profile loaders read a durable clock. Its CAS must
        not contend with our already-open SQLite writer. Errors are deferred to
        eligibility so an existing idempotency tombstone does not need new policy.
        """
        try:
            if approval_hash is not None:
                policy_hash = self._load(connection, "decisions", approval_hash, ApprovalRecord).tuple.policy_bundle_sha256
            elif operation_id is not None:
                policy_hash = self._permit_value(self._permit_row(connection, operation_id)).policy_bundle_sha256
            elif active_context:
                policy_hash = self._authority(connection)["active_policy_sha256"]
            if policy_hash is None:
                return (None, None, None, None)
            require(self._context_loader is not None and self._profile_loader is not None,
                    "dependency_unavailable")
            context = self._context_loader(policy_hash)
            profiles = self._profile_loader(context.tuple.adapter_capability_sha256)
            return policy_hash, context, profiles, None
        except GatewayError as error:
            return policy_hash, None, None, PolicyError(error.code)
        except (OSError, ValueError, TypeError):
            return policy_hash, None, None, PolicyError("invalid_evidence")

    def bind_runtime(
        self, *, context_loader: Callable[[str], EligibilityContext],
        ledger_reader: Callable[[str], LedgerOperationSnapshot | None],
        key_digest: Callable[[GatewayRequest], str], assert_lock_held: Callable[[], None],
        profile_loader: Callable[[str], tuple[CapabilityProfile, ...]],
        incident_reader: Callable[[IncidentEvidence], IncidentEvidence | None],
        retry_reader: Callable[[str, str], ProviderResult | None] | None = None,
    ) -> None:
        """One trusted bootstrap binding, before first DB use; no default proofs."""
        require(not self._bound and not self._used, "config_mismatch")
        require(all(callable(callback) for callback in (
            context_loader, ledger_reader, key_digest, assert_lock_held, profile_loader, incident_reader,
        )), "config_mismatch")
        self._context_loader, self._ledger_reader = context_loader, ledger_reader
        self._key_digest, self._assert_lock_held = key_digest, assert_lock_held
        self._profile_loader, self._incident_reader = profile_loader, incident_reader
        require(retry_reader is None or callable(retry_reader), "config_mismatch")
        self._retry_reader = retry_reader
        self._bound = True

    def _runtime_path(self) -> Path:
        root_value = os.environ.get("GATEWAY_RUNTIME_ROOT")
        require(bool(root_value), "unsafe_runtime_path")
        root = require_local_runtime_root(Path(root_value))
        require(self._path.is_absolute(), "unsafe_runtime_path")
        # Reuse only this invocation's freshly validated canonical directory.
        # A nested or differently expressed parent still needs its own check.
        if self._path.parent != root:
            require_local_runtime_root(self._path.parent)
        require(not self._path.is_symlink()
                and not (getattr(self._path.lstat(), "st_file_attributes", 0) & 0x400), "unsafe_runtime_path")
        path = self._path.resolve(strict=True)
        require(path.is_file() and path.is_relative_to(root), "unsafe_runtime_path")
        require(not str(path).startswith(("\\\\", "//")), "unsafe_runtime_path")
        cloud_names = ("onedrive", "dropbox", "googledrive", "icloud")
        require(not any(any(name in part.lower() for name in cloud_names) for part in path.parts),
                "unsafe_runtime_path")
        return path

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._runtime_path().as_uri() + "?mode=rw",
                                     uri=True, isolation_level=None, timeout=5)
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            require(connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1, "schema_mismatch")
            require(connection.execute("PRAGMA user_version").fetchone()[0] == 1, "schema_mismatch")
            require([row[0] for row in connection.execute("SELECT version FROM schema_version")] == [1],
                    "schema_mismatch")
            require(connection.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal",
                    "schema_mismatch")
            return connection
        except BaseException:
            connection.close()
            raise

    def _authority(self, connection: sqlite3.Connection) -> sqlite3.Row:
        row = connection.execute("SELECT * FROM authority_state WHERE authority_id=?",
                                 (self.authority_id,)).fetchone()
        require(row is not None, "config_mismatch")
        require(row["config_sha256"] == self._config_sha256, "config_mismatch")
        return row

    def _audit(self, connection: sqlite3.Connection, event_kind: str, payload: dict,
               now: datetime) -> None:
        event = {"schema_version": 1, "authority_id": self.authority_id,
                 "event_kind": event_kind, "recorded_utc": now, "payload": payload}
        connection.execute(
            "INSERT OR IGNORE INTO governance_events(authority_id,hash,event_kind,recorded_utc,canonical) "
            "VALUES(?,?,?,?,?)", (self.authority_id, digest(event), event_kind, utc_text(now), canonical_bytes(event)),
        )

    def _add_halt(self, connection: sqlite3.Connection, reason: str,
                  evidence_sha256: str | None = None) -> None:
        row = self._authority(connection)
        reasons = set(json.loads(row["halt_reasons_json"]))
        reasons.add(reason)
        connection.execute(
            "UPDATE authority_state SET incident_halt=1,halt_reasons_json=? WHERE authority_id=?",
            (json.dumps(sorted(reasons), separators=(",", ":")), self.authority_id),
        )
        self._audit(connection, "halt", {"reason_code": reason, "evidence_sha256": evidence_sha256},
                    utc_read(row["max_observed_utc"]))

    def _checked_clock(self, connection: sqlite3.Connection, row: sqlite3.Row, now: datetime) -> datetime:
        try:
            utc_text(now)
            high_water = utc_read(row["max_observed_utc"])
            if self._wall_origin is None:
                self._wall_origin, self._monotonic_origin = now, monotonic()
            if now < high_water or now < self._wall_origin:
                reason = "clock_rollback"
            elif abs((now - self._wall_origin).total_seconds()
                     - (monotonic() - self._monotonic_origin)) > 5:
                reason = "clock_untrusted"
            else:
                return now
        except (ValueError, TypeError, AttributeError, GatewayError):
            reason = "clock_untrusted"
        # Persist the clock incident before raising; ordinary rollback must not
        # erase the very halt that caused this transaction to refuse admission.
        self._add_halt(connection, reason)
        connection.commit()
        raise PolicyError(reason)

    @contextmanager
    def _transaction(self, *, policy_hash: str | None = None, approval_hash: str | None = None,
                     operation_id: str | None = None, active_context: bool = False
                     ) -> Iterator[tuple[sqlite3.Connection, datetime, sqlite3.Row]]:
        existing = self._current.get()
        if existing is not None:
            # Ledger committed projections consult AccountingGate.incident_snapshot.
            # Reuse this transaction rather than recursively opening another writer.
            connection, now, _prepared = existing
            self._assert_lock_held()
            yield connection, now, self._authority(connection)
            return
        connection = None
        token = None
        try:
            with self._lock():
                require(self._bound and self._assert_lock_held is not None, "dependency_unavailable")
                self._assert_lock_held()
                self._used = True
                connection = self._connect()
                prepared = self._prepare_evidence(connection, policy_hash=policy_hash,
                                                  approval_hash=approval_hash, operation_id=operation_id,
                                                  active_context=active_context)
                # Read the trusted clock before opening a write transaction: its
                # durable high-water CAS may itself need the policy database.
                clock_failure = None
                try:
                    observed = self._clock()
                except GatewayError as error:
                    clock_failure = (error.code.value if error.code.value in ("clock_rollback", "clock_untrusted")
                                     else "clock_untrusted")
                connection.execute("BEGIN IMMEDIATE")
                state = self._authority(connection)
                if clock_failure is not None:
                    self._add_halt(connection, clock_failure)
                    connection.commit()
                    raise PolicyError(clock_failure)
                now = self._checked_clock(connection, state, observed)
                connection.execute("UPDATE authority_state SET max_observed_utc=? WHERE authority_id=?",
                                   (utc_text(now), self.authority_id))
                token = self._current.set((connection, now, prepared))
                yield connection, now, state
                connection.commit()
        except PolicyError:
            if connection is not None:
                connection.rollback()
            raise
        except sqlite3.IntegrityError:
            if connection is not None:
                connection.rollback()
            raise PolicyError("record_conflict") from None
        except (sqlite3.Error, OSError, ValueError, TypeError):
            if connection is not None:
                connection.rollback()
            raise PolicyError("store_unavailable") from None
        finally:
            if token is not None:
                self._current.reset(token)
            if connection is not None:
                connection.close()

    def _load(self, connection: sqlite3.Connection, table: str, key: str, record_type: type[T]) -> T:
        # Table names are private fixed call-site constants, never policy/client input.
        row = connection.execute(f"SELECT canonical FROM {table} WHERE hash=?", (key,)).fetchone()
        require(row is not None, "missing_evidence")
        value = decode_record(bytes(row[0]), record_type, key)
        if hasattr(value, "authority_id"):
            require(value.authority_id == self.authority_id, "authority_mismatch")
        return value

    @staticmethod
    def _healthy(state: sqlite3.Row) -> None:
        require(not state["emergency_stop"] and not state["incident_halt"], "halted")

    def _context(self, connection: sqlite3.Connection, bundle: PolicyBundle,
                 context: EligibilityContext, now: datetime) -> None:
        current = self._current.get()
        require(current is not None, "dependency_unavailable")
        policy_hash, trusted, _profiles, failure = current[2]
        if failure is not None:
            raise failure
        require(policy_hash == digest(bundle) and trusted is not None, "dependency_unavailable")
        check_context(bundle, context, trusted, authority_id=self.authority_id, now=now)
        self._profiles(bundle, context, now)

    def _profiles(self, bundle: PolicyBundle, context: EligibilityContext,
                  now: datetime) -> tuple[CapabilityProfile, ...]:
        current = self._current.get()
        require(current is not None, "dependency_unavailable")
        policy_hash, _trusted, profiles, failure = current[2]
        if failure is not None:
            raise failure
        require(policy_hash == digest(bundle) and profiles is not None, "dependency_unavailable")
        require(profile_manifest_digest(profiles) == context.tuple.adapter_capability_sha256
                and adapter_manifest_digest(profiles) == context.tuple.adapter_sha256, "invalid_evidence")
        for target in bundle.targets:
            matches = [profile for profile in profiles if (
                profile.provider, profile.exact_model, profile.api_version,
                profile.capability_sha256, profile.adapter_sha256,
            ) == (target.provider, target.exact_model, target.api_version,
                  target.capability_sha256, target.adapter_sha256)]
            require(len(matches) == 1, "missing_evidence")
        require(all(profile.mode == "simulation" for profile in profiles), "external_disabled")
        require(all(now < profile.expires_utc for profile in profiles), "stale_evidence")
        require(all(profile.price_sha256 == context.tuple.price_sha256
                    and profile.bound_sha256 == context.tuple.bound_sha256 for profile in profiles),
                "invalid_evidence")
        return profiles

    def freeze(self, bundle: PolicyBundle) -> str:
        key = digest(bundle)
        with self._transaction() as (connection, now, _state):
            require(now < bundle.expires_utc, "stale_evidence")
            for row in connection.execute("SELECT hash,canonical FROM policy_bundles WHERE policy_id=?",
                                          (bundle.policy_id,)):
                previous = decode_record(bytes(row["canonical"]), PolicyBundle, row["hash"])
                require(previous.version != bundle.version or row["hash"] == key, "record_conflict")
            connection.execute("INSERT OR IGNORE INTO policy_bundles(hash,policy_id,canonical) VALUES(?,?,?)",
                               (key, bundle.policy_id, canonical_bytes(bundle)))
            self._audit(connection, "freeze", {"policy_sha256": key}, now)
        return key

    def authorize_evaluation(self, authorization: EvaluationAuthorization) -> str:
        verify_operator(authorization, self._key)
        require(authorization.authority_id == self.authority_id, "authority_mismatch")
        require(authorization.mode == "simulation", "external_disabled")
        key = digest(authorization)
        with self._transaction() as (connection, now, state):
            self._healthy(state)
            bundle = self._load(connection, "policy_bundles", authorization.tuple.policy_bundle_sha256,
                                PolicyBundle)
            check_bundle_tuple(bundle, authorization.tuple)
            require(authorization.created_utc <= now < authorization.expires_utc <= bundle.expires_utc,
                    "invalid_authorization")
            require(authorization.maximum_liability_usd > 0, "invalid_authorization")
            existing = connection.execute(
                "SELECT hash FROM evaluation_authorizations WHERE authority_id=? AND authorization_id=?",
                (self.authority_id, authorization.authorization_id),
            ).fetchone()
            require(existing is None or existing[0] == key, "record_conflict")
            connection.execute(
                "INSERT OR IGNORE INTO evaluation_authorizations(hash,authority_id,authorization_id,canonical) "
                "VALUES(?,?,?,?)", (key, self.authority_id, authorization.authorization_id, canonical_bytes(authorization)),
            )
        return key

    def record_evaluation(self, record: EvaluationRecord) -> str:
        require(record.authority_id == self.authority_id, "authority_mismatch")
        require(record.mode == "simulation", "external_disabled")
        key = digest(record)
        with self._transaction() as (connection, now, _state):
            authorization = self._load(connection, "evaluation_authorizations", record.authorization_sha256,
                                       EvaluationAuthorization)
            verify_operator(authorization, self._key)
            require(record.tuple == authorization.tuple, "invalid_authorization")
            require((record.budget_authority_id, record.budget_reference_sha256)
                    == (authorization.budget_authority_id, authorization.budget_reference_sha256),
                    "invalid_authorization")
            require(authorization.created_utc <= record.frozen_utc <= now
                    and record.frozen_utc < authorization.expires_utc
                    and record.expires_utc <= authorization.expires_utc, "invalid_authorization")
            existing = connection.execute("SELECT hash FROM evaluations WHERE authority_id=? AND evaluation_id=?",
                                          (self.authority_id, record.evaluation_id)).fetchone()
            require(existing is None or existing[0] == key, "record_conflict")
            connection.execute(
                "INSERT OR IGNORE INTO evaluations(hash,authority_id,evaluation_id,authorization_sha256,"
                "policy_sha256,canonical) VALUES(?,?,?,?,?,?)",
                (key, self.authority_id, record.evaluation_id, record.authorization_sha256,
                 record.tuple.policy_bundle_sha256, canonical_bytes(record)),
            )
        return key

    def verify_approval(self, approval: ApprovalRecord) -> str:
        verify_operator(approval, self._key)
        require(approval.authority_id == self.authority_id, "authority_mismatch")
        key = digest(approval)
        with self._transaction() as (connection, now, _state):
            evaluation = self._load(connection, "evaluations", approval.evaluation_sha256, EvaluationRecord)
            require(approval.tuple == evaluation.tuple
                    and approval.artifact_manifest_sha256 == evaluation.artifact_manifest_sha256,
                    "invalid_approval")
            require(evaluation.frozen_utc <= approval.recorded_utc <= now, "invalid_approval")
            if approval.decision == "approve":
                require(evaluation.status == "pass", "ineligible_policy")
            if approval.decision == "revoke":
                target = self._load(connection, "decisions", approval.target_approval_sha256, ApprovalRecord)
                require(target.decision == "approve" and target.tuple == approval.tuple
                        and target.evaluation_sha256 == approval.evaluation_sha256, "invalid_approval")
            existing = connection.execute("SELECT hash FROM decisions WHERE authority_id=? AND decision_id=?",
                                          (self.authority_id, approval.decision_id)).fetchone()
            require(existing is None or existing[0] == key, "record_conflict")
            connection.execute(
                "INSERT OR IGNORE INTO decisions(hash,authority_id,decision_id,action,policy_sha256,"
                "evaluation_sha256,target_approval_sha256,canonical) VALUES(?,?,?,?,?,?,?,?)",
                (key, self.authority_id, approval.decision_id, approval.decision,
                 approval.tuple.policy_bundle_sha256, approval.evaluation_sha256,
                 approval.target_approval_sha256, canonical_bytes(approval)),
            )
        return key

    def _eligible(self, connection: sqlite3.Connection, approval_hash: str,
                  context: EligibilityContext, now: datetime, *,
                  grandfathered: bool = False) -> tuple[ApprovalRecord, PolicyBundle]:
        approval = self._load(connection, "decisions", approval_hash, ApprovalRecord)
        verify_operator(approval, self._key)
        require(approval.decision == "approve", "invalid_approval")
        if not grandfathered:
            require(connection.execute(
                "SELECT 1 FROM decisions WHERE authority_id=? AND policy_sha256=? AND evaluation_sha256=? "
                "AND action IN ('reject','revoke') LIMIT 1",
                (self.authority_id, approval.tuple.policy_bundle_sha256, approval.evaluation_sha256),
            ).fetchone() is None, "invalid_approval")
        evaluation = self._load(connection, "evaluations", approval.evaluation_sha256, EvaluationRecord)
        authorization = self._load(connection, "evaluation_authorizations", evaluation.authorization_sha256,
                                   EvaluationAuthorization)
        verify_operator(authorization, self._key)
        bundle = self._load(connection, "policy_bundles", approval.tuple.policy_bundle_sha256, PolicyBundle)
        self._context(connection, bundle, context, now)
        require(approval.tuple == evaluation.tuple
                and approval.artifact_manifest_sha256 == evaluation.artifact_manifest_sha256,
                "invalid_approval")
        check_evaluation(bundle, evaluation, authorization, context, authority_id=self.authority_id, now=now)
        require(approval.recorded_utc <= now, "invalid_approval")
        return approval, bundle

    def _activate(self, approval_sha256: str, *, expected_generation: int,
                  context: EligibilityContext, event_kind: str, reason: str | None) -> ActivationRecord:
        with self._transaction(approval_hash=approval_sha256) as (connection, now, state):
            require(type(expected_generation) is int and state["generation"] == expected_generation,
                    "generation_conflict")
            approval, _bundle = self._eligible(connection, approval_sha256, context, now)
            if event_kind == "rollback":
                require(connection.execute(
                    "SELECT 1 FROM activation_events WHERE authority_id=? AND approval_sha256=? LIMIT 1",
                    (self.authority_id, approval_sha256),
                ).fetchone() is not None, "ineligible_policy")
            event = ActivationRecord(
                authority_id=self.authority_id, generation=expected_generation + 1,
                expected_generation=expected_generation, event_kind=event_kind,
                policy_bundle_sha256=approval.tuple.policy_bundle_sha256,
                evaluation_sha256=approval.evaluation_sha256, approval_sha256=approval_sha256,
                recorded_utc=now, reason=reason,
            )
            connection.execute(
                "INSERT INTO activation_events(authority_id,generation,expected_generation,event_kind,"
                "policy_sha256,evaluation_sha256,approval_sha256,recorded_utc,hash,canonical) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                (self.authority_id, event.generation, expected_generation, event_kind,
                 event.policy_bundle_sha256, event.evaluation_sha256, approval_sha256,
                 utc_text(now), digest(event), canonical_bytes(event)),
            )
            cursor = connection.execute(
                "UPDATE authority_state SET generation=?,active_policy_sha256=?,active_approval_sha256=? "
                "WHERE authority_id=? AND generation=?",
                (event.generation, event.policy_bundle_sha256, approval_sha256,
                 self.authority_id, expected_generation),
            )
            require(cursor.rowcount == 1, "generation_conflict")
        return event

    def activate(self, approval_sha256: str, *, expected_generation: int,
                 context: EligibilityContext) -> ActivationRecord:
        return self._activate(approval_sha256, expected_generation=expected_generation,
                              context=context, event_kind="activate", reason=None)

    def rollback(self, approval_sha256: str, *, expected_generation: int,
                 context: EligibilityContext, reason: str) -> ActivationRecord:
        return self._activate(approval_sha256, expected_generation=expected_generation,
                              context=context, event_kind="rollback", reason=reason)

    def _active(self, connection: sqlite3.Connection, state: sqlite3.Row) -> ActivePolicy | None:
        if state["generation"] == 0:
            require(state["active_policy_sha256"] is None and state["active_approval_sha256"] is None,
                    "invalid_evidence")
            return None
        row = connection.execute("SELECT hash,canonical FROM activation_events WHERE authority_id=? AND generation=?",
                                 (self.authority_id, state["generation"])).fetchone()
        require(row is not None, "invalid_evidence")
        event = decode_record(bytes(row["canonical"]), ActivationRecord, row["hash"])
        require(event.authority_id == self.authority_id and event.generation == state["generation"]
                and event.policy_bundle_sha256 == state["active_policy_sha256"]
                and event.approval_sha256 == state["active_approval_sha256"], "invalid_evidence")
        return ActivePolicy(authority_id=self.authority_id, generation=event.generation,
                            policy_bundle_sha256=event.policy_bundle_sha256,
                            evaluation_sha256=event.evaluation_sha256,
                            approval_sha256=event.approval_sha256, activation_sha256=row["hash"])

    def active(self) -> ActivePolicy | None:
        with self._transaction() as (connection, _now, state):
            return self._active(connection, state)

    def _permit_row(self, connection: sqlite3.Connection, operation_id: str) -> sqlite3.Row:
        row = connection.execute("SELECT * FROM permits WHERE authority_id=? AND operation_id=?",
                                 (self.authority_id, operation_id)).fetchone()
        require(row is not None, "invalid_permit")
        return row

    def _permit_value(self, row: sqlite3.Row) -> OperationPermit:
        value = decode_record(bytes(row["canonical"]), OperationPermit, row["hash"])
        require(value.authority_id == self.authority_id and value.operation_id == row["operation_id"]
                and value.state == PermitState.PERMITTED
                and value.permit_id == row["permit_id"] and value.policy_bundle_sha256 == row["policy_sha256"]
                and value.policy_generation == row["generation"]
                and utc_text(value.expires_utc) == row["expires_utc"], "invalid_permit")
        return value

    def _create_permit(self, connection: sqlite3.Connection, request: GatewayRequest, plan: PermitPlan,
                       expected_generation: int, context: EligibilityContext,
                       now: datetime, state: sqlite3.Row) -> OperationPermit:
        self._healthy(state)
        require(request.authority_id == self.authority_id, "authority_mismatch")
        require(type(expected_generation) is int, "generation_conflict")
        if plan.purpose == "eval":
            # Evaluation0 is a purpose sentinel, not the active serving pointer.
            require(expected_generation == 0, "generation_conflict")
            authorization = self._load(connection, "evaluation_authorizations",
                                       plan.evaluation_authorization_sha256, EvaluationAuthorization)
            verify_operator(authorization, self._key)
            require(authorization.created_utc <= now < plan.expires_utc <= authorization.expires_utc,
                    "invalid_authorization")
            bundle = self._load(connection, "policy_bundles", plan.policy_bundle_sha256, PolicyBundle)
            self._context(connection, bundle, context, now)
            require(authorization.mode == "simulation" and authorization.tuple == context.tuple,
                    "invalid_authorization")
            require(authorization.budget_authority_id == self.authority_id, "authority_mismatch")
            total = sum(usd_micros(child.maximum_liability_usd) for child in plan.attempt_children)
            prior_liability = 0
            for prior_row in connection.execute("SELECT * FROM permits WHERE authority_id=? AND state!='abandoned'",
                                                 (self.authority_id,)):
                prior = self._permit_value(prior_row)
                if prior.evaluation_authorization_sha256 == plan.evaluation_authorization_sha256:
                    prior_liability += sum(usd_micros(child.maximum_liability_usd) for child in prior.attempt_children)
            require(prior_liability + total <= usd_micros(authorization.maximum_liability_usd), "budget_exceeded")
        else:
            require(state["generation"] == expected_generation, "generation_conflict")
            require(plan.purpose == "serve", "invalid_permit")
            active = self._active(connection, state)
            require(active is not None, "no_approved_policy")
            require(plan.policy_bundle_sha256 == active.policy_bundle_sha256, "invalid_permit")
            approval, bundle = self._eligible(connection, active.approval_sha256, context, now)
            evaluation = self._load(connection, "evaluations", approval.evaluation_sha256, EvaluationRecord)
            authorization = self._load(connection, "evaluation_authorizations", evaluation.authorization_sha256,
                                       EvaluationAuthorization)
            require(plan.expires_utc <= min(
                evaluation.expires_utc, authorization.expires_utc,
                evaluation.frozen_utc + timedelta(seconds=context.evaluation_max_age_seconds),
            ), "stale_evidence")
        check_plan(bundle, request, plan, context, self._profiles(bundle, context, now), now=now)
        permit = OperationPermit(
            **plan.model_dump(mode="python"), permit_id="permit-" + digest({
                "authority_id": self.authority_id, "operation_id": plan.operation_id,
            }), authority_id=self.authority_id, caller_id=request.caller_id,
            request_sha256=request.request_sha256, policy_generation=expected_generation,
            state=PermitState.PERMITTED,
        )
        connection.execute(
            "INSERT INTO permits(authority_id,operation_id,permit_id,hash,policy_sha256,generation,state,"
            "expires_utc,join_sha256,canonical) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (self.authority_id, permit.operation_id, permit.permit_id, digest(permit),
             permit.policy_bundle_sha256, permit.policy_generation, PermitState.PERMITTED.value,
             utc_text(permit.expires_utc), None, canonical_bytes(permit)),
        )
        return permit

    def permit(self, request: GatewayRequest, plan: PermitPlan, *, expected_generation: int,
               context: EligibilityContext) -> OperationPermit:
        require(self._key_digest is not None, "dependency_unavailable")
        decision = self.permit_operation(request, plan, key_digest=self._key_digest(request),
                                         expected_generation=expected_generation, context=context)
        return decision.operation.permit

    def get_permit(self, operation_id: str) -> OperationPermit | None:
        """Return immutable original bytes; lifecycle is a separate DB projection."""
        with self._transaction() as (connection, _now, _state):
            row = connection.execute("SELECT * FROM permits WHERE authority_id=? AND operation_id=?",
                                     (self.authority_id, operation_id)).fetchone()
            return None if row is None else self._permit_value(row)

    def _ledger(self, operation_id: str) -> LedgerOperationSnapshot | None:
        require(self._ledger_reader is not None and self._assert_lock_held is not None,
                "dependency_unavailable")
        self._assert_lock_held()
        snapshot = self._ledger_reader(operation_id)
        if snapshot is not None:
            require(snapshot.authority_id == self.authority_id and snapshot.operation_id == operation_id,
                    "invalid_join")
        return snapshot

    def _join(self, connection: sqlite3.Connection, permit: OperationPermit,
              supplied: LedgerJoin) -> LedgerOperationSnapshot:
        snapshot = self._ledger(permit.operation_id)
        require(snapshot is not None and snapshot.join == supplied, "invalid_join")
        require(
            supplied.authority_id == self.authority_id
            and supplied.operation_id == permit.operation_id
            and supplied.permit_sha256 == digest(permit)
            and supplied.policy_bundle_sha256 == permit.policy_bundle_sha256
            and supplied.request_sha256 == permit.request_sha256
            and supplied.serialized_envelope_sha256 == permit.serialized_envelope_sha256
            and supplied.bound_sha256 == permit.bound_sha256 and supplied.price_sha256 == permit.price_sha256
            and supplied.child_ids == tuple(child.child_id for child in permit.attempt_children),
            "invalid_join",
        )
        return snapshot

    def transition_permit(self, operation_id: str, *, expected_state: PermitState,
                          target_state: PermitState, join: LedgerJoin | None) -> OperationPermit:
        with self._transaction() as (connection, now, _state):
            row = self._permit_row(connection, operation_id)
            permit = self._permit_value(row)
            require(row["state"] in (expected_state.value, target_state.value), "invalid_transition")
            if target_state == PermitState.ABANDONED:
                require(expected_state == PermitState.PERMITTED and join is None
                        and now >= permit.expires_utc and self._ledger(operation_id) is None,
                        "invalid_transition")
            else:
                require(join is not None, "invalid_join")
                snapshot = self._join(connection, permit, join)
                if target_state == PermitState.FUNDED:
                    require(expected_state == PermitState.PERMITTED and not snapshot.breach and not snapshot.conflict,
                            "invalid_transition")
                elif target_state == PermitState.TERMINAL:
                    require(expected_state == PermitState.FUNDED and join.settlement_sha256 is not None
                            and all(attempt.state in ("known", "unknown", "closed_unstarted")
                                    for attempt in snapshot.attempts), "invalid_transition")
                else:
                    raise PolicyError("invalid_transition")
            if row["state"] != target_state.value:
                connection.execute("UPDATE permits SET state=?,join_sha256=? WHERE authority_id=? AND operation_id=?",
                                   (target_state.value, None if join is None else digest(join),
                                    self.authority_id, operation_id))
                operation_state = (OperationState.FUNDED if target_state == PermitState.FUNDED else
                                   OperationState.ABANDONED if target_state == PermitState.ABANDONED else
                                   OperationState.TERMINAL)
                # Terminal replay requires mark_terminal's full stage/settlement
                # checks; this lower-level lifecycle API cannot publish success.
                if target_state != PermitState.TERMINAL:
                    connection.execute("UPDATE operations SET state=?,join_canonical=? "
                                       "WHERE authority_id=? AND operation_id=?",
                                       (operation_state.value, None if join is None else canonical_bytes(join),
                                        self.authority_id, operation_id))
            return permit

    def assert_dispatch_allowed(self, operation_id: str, join: LedgerJoin,
                                *, context: EligibilityContext) -> None:
        with self._transaction(operation_id=operation_id) as (connection, now, state):
            self._healthy(state)
            row = self._permit_row(connection, operation_id)
            permit = self._permit_value(row)
            require(row["state"] == PermitState.FUNDED.value, "invalid_transition")
            operation = self._operation_row(connection, operation_id)
            require(not operation["cancelled"] and operation["state"] not in (
                OperationState.TERMINAL.value, OperationState.ABANDONED.value,
                OperationState.UNKNOWN_SETTLED.value, OperationState.RESULT_EXPIRED.value,
            ), "cancelled")
            require(now < permit.expires_utc, "permit_expired")
            snapshot = self._join(connection, permit, join)
            require(not snapshot.breach and not snapshot.conflict, "halted")
            bundle = self._load(connection, "policy_bundles", permit.policy_bundle_sha256, PolicyBundle)
            self._context(connection, bundle, context, now)
            # Check the permit's own activation/evaluation, not today's pointer.
            if permit.purpose == "serve":
                event_row = connection.execute(
                    "SELECT hash,canonical FROM activation_events WHERE authority_id=? AND generation=?",
                    (self.authority_id, permit.policy_generation),
                ).fetchone()
                require(event_row is not None, "invalid_permit")
                event = decode_record(bytes(event_row["canonical"]), ActivationRecord, event_row["hash"])
                require(event.policy_bundle_sha256 == permit.policy_bundle_sha256, "invalid_permit")
                # Revocation affects new permits; existing bounded permits keep
                # their signed tuple. Recheck its complete evaluation/authorization
                # freshness instead of inferring eligibility from bundle expiry.
                self._eligible(connection, event.approval_sha256, context, now, grandfathered=True)
            else:
                authorization = self._load(connection, "evaluation_authorizations",
                                           permit.evaluation_authorization_sha256, EvaluationAuthorization)
                verify_operator(authorization, self._key)
                require(authorization.created_utc <= now < authorization.expires_utc,
                        "invalid_authorization")
                require(authorization.mode == "simulation" and authorization.tuple == context.tuple
                        and authorization.budget_authority_id == self.authority_id,
                        "invalid_authorization")

    def _incident_basis(
        self, connection: sqlite3.Connection, evidence: IncidentEvidence,
    ) -> tuple[Decimal | None, Decimal | None, bool, bool]:
        """Derive R/U from committed state and authenticate content through its owner.

        Missing provenance is quarantined, never converted into a trusted caller
        boolean. A ledger read or content resolution failure is not a healthy
        incident; ingestion must still persist the evidence and halt together.
        """
        try:
            snapshot = self._ledger(evidence.operation_id)
            require(snapshot is not None, "missing_evidence")
            permit = self._permit_value(self._permit_row(connection, evidence.operation_id))
            self._join(connection, permit, snapshot.join)
            children = {child.child_id: child for child in permit.attempt_children}
            attempts = {attempt.child_id: attempt for attempt in snapshot.attempts}
            require(evidence.child_id in children and evidence.child_id in attempts, "invalid_evidence")
            child, attempt = children[evidence.child_id], attempts[evidence.child_id]
            require(attempt.attempt_id == evidence.attempt_id
                    and child.provider == evidence.provider
                    and attempt.state in ("known", "unknown"), "invalid_evidence")
            reserve = child.maximum_liability_usd
            unknown = reserve if attempt.state == "unknown" else ZERO
        except (GatewayError, OSError, ValueError, TypeError):
            return None, None, False, False
        credible = False
        if self._incident_reader is not None:
            try:
                resolved = self._incident_reader(evidence)
                credible = (
                    resolved is not None and canonical_bytes(resolved) == canonical_bytes(evidence)
                    and evidence.authenticated and evidence.observed_cost_usd is not None
                    and evidence.reserved_usd == reserve and evidence.terminal_unknown_usd == unknown
                )
            except (GatewayError, OSError, ValueError, TypeError):
                credible = False
        return reserve, unknown, credible, attempt.state == "unknown"

    def append_incident(self, evidence: IncidentEvidence) -> IncidentRecord:
        require(evidence.authority_id == self.authority_id, "authority_mismatch")
        key = digest(evidence)
        with self._transaction() as (connection, now, _state):
            require(evidence.recorded_utc <= now, "invalid_evidence")
            row = connection.execute(
                "SELECT canonical FROM incident_maxima WHERE authority_id=? AND operation_id=? AND child_id=?",
                (self.authority_id, evidence.operation_id, evidence.child_id),
            ).fetchone()
            previous = None if row is None else decode_record(bytes(row[0]), IncidentRecord)
            reserve, basis_unknown, credible, terminal_unknown = self._incident_basis(connection, evidence)
            basis_known = basis_unknown is not None
            duplicate = connection.execute("SELECT 1 FROM incident_evidence WHERE hash=?", (key,)).fetchone()
            if duplicate is not None:
                if previous is not None:
                    return previous
                # Previously quarantined evidence with no ledger basis never
                # acquires credibility merely because a retry supplies a flag.
                return IncidentRecord(
                    authority_id=self.authority_id, operation_id=evidence.operation_id,
                    child_id=evidence.child_id, terminal_unknown_usd=ZERO,
                    maximum_credible_usd=None, uncovered_excess_usd=ZERO,
                    conflict=True, evidence_sha256=key,
                )
            prior_rows = connection.execute(
                "SELECT hash,canonical,authenticated FROM incident_evidence "
                "WHERE authority_id=? AND operation_id=? AND child_id=?",
                (self.authority_id, evidence.operation_id, evidence.child_id),
            ).fetchall()
            priors = [(decode_record(bytes(item["canonical"]), IncidentEvidence, item["hash"]),
                       bool(item["authenticated"])) for item in prior_rows]
            conflict = evidence.conflict or not credible or (previous.conflict if previous else False)
            # A terminal unknown reference is immutable, even when a caller tries
            # to lower it. Retain mismatching evidence as conflict, never credit.
            unknown = previous.terminal_unknown_usd if previous else (basis_unknown or ZERO)
            conflict = conflict or not basis_known or unknown != basis_unknown
            conflict = conflict or evidence.terminal_unknown_usd != unknown or evidence.reserved_usd != reserve
            for prior, prior_credible in priors:
                conflict = conflict or prior.attempt_id != evidence.attempt_id or prior.provider != evidence.provider
                conflict = conflict or prior.reserved_usd != evidence.reserved_usd
                if prior_credible and credible:
                    conflict = conflict or prior.observed_cost_usd != evidence.observed_cost_usd
                if prior.source_sha256 == evidence.source_sha256 and digest(prior) != key:
                    conflict = True
            maximum = previous.maximum_credible_usd if previous else None
            if credible and terminal_unknown:
                maximum = max(maximum or ZERO, evidence.observed_cost_usd)
            excess = money_from_micros(max(usd_micros(maximum or ZERO) - usd_micros(unknown), 0))
            record = IncidentRecord(
                authority_id=self.authority_id, operation_id=evidence.operation_id, child_id=evidence.child_id,
                terminal_unknown_usd=unknown, maximum_credible_usd=maximum,
                uncovered_excess_usd=excess, conflict=conflict, evidence_sha256=key,
            )
            connection.execute(
                "INSERT INTO incident_evidence(hash,authority_id,operation_id,child_id,source_sha256,authenticated,"
                "conflict,canonical) VALUES(?,?,?,?,?,?,?,?)",
                (key, self.authority_id, evidence.operation_id, evidence.child_id,
                 evidence.source_sha256, int(credible), int(conflict), canonical_bytes(evidence)),
            )
            # Never persist a fabricated first U/R when the ledger basis is
            # unavailable. The raw quarantine and halt are durable; zero fields
            # in the conflict response are unavailable placeholders, not funds.
            if basis_known or previous is not None:
                connection.execute(
                    "INSERT INTO incident_maxima(authority_id,operation_id,child_id,terminal_unknown_usd,"
                    "maximum_credible_usd,uncovered_excess_usd,conflict,canonical) VALUES(?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(authority_id,operation_id,child_id) DO UPDATE SET "
                    "maximum_credible_usd=excluded.maximum_credible_usd,uncovered_excess_usd=excluded.uncovered_excess_usd,"
                    "conflict=excluded.conflict,canonical=excluded.canonical",
                    (self.authority_id, evidence.operation_id, evidence.child_id, str(unknown),
                     None if maximum is None else str(maximum), str(excess), int(conflict), canonical_bytes(record)),
                )
            if conflict:
                self._add_halt(connection, "evidence_conflict", key)
            if not credible:
                self._add_halt(connection, "unauthenticated_evidence", key)
            if evidence.reason_code in ("bound_breach", "settlement_conflict"):
                self._add_halt(connection, evidence.reason_code, key)
            # Known charge is already entirely in ledger K. Only terminal-unknown
            # observations contribute late D; a direct known excess is diagnostic
            # X and halt, never another debit through this projection.
            observed = evidence.observed_cost_usd if credible else maximum
            if observed is not None and reserve is not None and observed > reserve:
                self._add_halt(connection, "bound_breach", key)
            return record

    def halt(self, *, reason_code: str, evidence_sha256: str) -> HaltState:
        allowed = {"bound_breach", "late_evidence", "evidence_conflict", "unauthenticated_evidence",
                   "settlement_conflict", "clock_rollback", "clock_untrusted", "store_unavailable"}
        require(reason_code in allowed and len(evidence_sha256) == 64
                and all(char in "0123456789abcdef" for char in evidence_sha256), "invalid_evidence")
        with self._transaction() as (connection, _now, _state):
            self._add_halt(connection, reason_code, evidence_sha256)
            return self._status(connection)

    def set_emergency_stop(self, stopped: bool, *, reason: str) -> HaltState:
        require(type(stopped) is bool and 0 < len(reason) <= 128, "invalid_request")
        with self._transaction() as (connection, _now, _state):
            connection.execute("UPDATE authority_state SET emergency_stop=? WHERE authority_id=?",
                               (int(stopped), self.authority_id))
            self._audit(connection, "emergency_stop", {"stopped": stopped, "reason": reason}, _now)
            return self._status(connection)

    def _status(self, connection: sqlite3.Connection) -> HaltState:
        row = self._authority(connection)
        reasons = set(json.loads(row["halt_reasons_json"]))
        if row["emergency_stop"]:
            reasons.add("emergency_stop")
        return HaltState(authority_id=self.authority_id, generation=row["generation"],
                         emergency_stop=bool(row["emergency_stop"]), incident_halt=bool(row["incident_halt"]),
                         reason_codes=tuple(sorted(reasons)), max_observed_utc=utc_read(row["max_observed_utc"]))

    def status(self) -> HaltState:
        with self._transaction() as (connection, _now, _state):
            return self._status(connection)

    def list_unfinished_permits(self) -> tuple[OperationPermit, ...]:
        with self._transaction() as (connection, _now, _state):
            rows = connection.execute(
                "SELECT * FROM permits WHERE authority_id=? AND state IN ('permitted','funded') ORDER BY operation_id",
                (self.authority_id,),
            ).fetchall()
            return tuple(self._permit_value(row) for row in rows)

    def _operation_row(self, connection: sqlite3.Connection, operation_id: str) -> sqlite3.Row:
        row = connection.execute("SELECT * FROM operations WHERE authority_id=? AND operation_id=?",
                                 (self.authority_id, operation_id)).fetchone()
        require(row is not None, "invalid_permit")
        return row

    def _binding(self, row: sqlite3.Row, permit: OperationPermit) -> ReplayBinding:
        return ReplayBinding(authority_id=self.authority_id, caller_id=row["caller_id"],
                             operation_id=permit.operation_id, request_sha256=permit.request_sha256,
                             policy_bundle_sha256=permit.policy_bundle_sha256)

    def _stage_value(self, connection: sqlite3.Connection, operation: sqlite3.Row,
                     permit: OperationPermit) -> tuple[StagedResult | None, bool]:
        attempt_id = operation["replay_attempt_id"]
        if attempt_id is None:
            return None, False
        row = connection.execute("SELECT * FROM replay_results WHERE authority_id=? AND operation_id=? AND attempt_id=?",
                                 (self.authority_id, permit.operation_id, attempt_id)).fetchone()
        require(row is not None, "invalid_evidence")
        binding = decode_record(bytes(row["binding_canonical"]), ReplayBinding, row["binding_sha256"])
        require(binding == self._binding(operation, permit), "invalid_join")
        receipt = decode_record(bytes(row["receipt_canonical"]), AttemptReceipt, row["receipt_sha256"])
        require(receipt.attempt_id == attempt_id, "invalid_join")
        if row["purged_utc"] is not None:
            require(row["nonce"] is None and row["ciphertext"] is None, "invalid_evidence")
            return None, True
        require(row["nonce"] is not None and row["ciphertext"] is not None, "invalid_evidence")
        encrypted = EncryptedResult(
            key_id=row["key_id"], nonce_b64=base64.b64encode(bytes(row["nonce"])).decode("ascii"),
            ciphertext_b64=base64.b64encode(bytes(row["ciphertext"])).decode("ascii"),
            aad_sha256=row["binding_sha256"], result_sha256=row["result_sha256"],
        )
        return StagedResult(authority_id=self.authority_id, operation_id=permit.operation_id,
                            permit_sha256=digest(permit), binding=binding, encrypted_result=encrypted,
                            receipt=receipt, staged_utc=utc_read(row["staged_utc"])), False

    def _operation_value(self, connection: sqlite3.Connection, row: sqlite3.Row) -> OperationSnapshot:
        permit = self._permit_value(self._permit_row(connection, row["operation_id"]))
        require(row["permit_sha256"] == digest(permit)
                and (row["caller_id"], row["request_sha256"]) == (permit.caller_id, permit.request_sha256),
                "invalid_join")
        staged, purged = self._stage_value(connection, row, permit)
        settlement = (None if row["settlement_canonical"] is None else
                      decode_record(bytes(row["settlement_canonical"]), SettlementReceipt))
        if settlement is not None:
            require(settlement.settlement_sha256 == row["settlement_sha256"], "invalid_join")
        join = None if row["join_canonical"] is None else decode_record(bytes(row["join_canonical"]), LedgerJoin)
        return OperationSnapshot(
            authority_id=self.authority_id, caller_id=row["caller_id"], operation_id=row["operation_id"],
            key_digest=row["key_digest"], request_sha256=row["request_sha256"], permit=permit,
            state=OperationState(row["state"]), cancelled=bool(row["cancelled"]),
            staged_result=staged, settlement=settlement, join=join,
            result_expires_utc=None if row["result_expires_utc"] is None else utc_read(row["result_expires_utc"]),
            result_purged=purged,
        )

    def operation_snapshot(self, operation_id: str) -> OperationSnapshot | None:
        with self._transaction() as (connection, _now, _state):
            row = connection.execute("SELECT * FROM operations WHERE authority_id=? AND operation_id=?",
                                     (self.authority_id, operation_id)).fetchone()
            return None if row is None else self._operation_value(connection, row)

    def lookup_operation(self, caller: CallerContext, key_digest: str) -> OperationSnapshot | None:
        require(caller.authority_id == self.authority_id, "forbidden")
        with self._transaction() as (connection, _now, _state):
            row = connection.execute("SELECT * FROM operations WHERE authority_id=? AND caller_id=? AND key_digest=?",
                                     (self.authority_id, caller.caller_id, key_digest)).fetchone()
            return None if row is None else self._operation_value(connection, row)

    def permit_operation(self, request: GatewayRequest, plan: PermitPlan, *, key_digest: str,
                         expected_generation: int, context: EligibilityContext) -> PermitDecision:
        require(request.authority_id == self.authority_id, "authority_mismatch")
        require(key_digest == request.idempotency_key and len(key_digest) == 64
                and all(character in "0123456789abcdef" for character in key_digest), "invalid_request")
        with self._transaction(policy_hash=plan.policy_bundle_sha256) as (connection, now, state):
            row = connection.execute("SELECT * FROM operations WHERE authority_id=? AND caller_id=? AND key_digest=?",
                                     (self.authority_id, request.caller_id, key_digest)).fetchone()
            if row is not None:
                require(row["request_sha256"] == request.request_sha256, "idempotency_conflict")
                # Original state wins even with no currently eligible policy,
                # changed generation or expired evidence. Never create new spend.
                return PermitDecision(created=False, operation=self._operation_value(connection, row), permit=None)
            permit = self._create_permit(connection, request, plan, expected_generation, context, now, state)
            connection.execute(
                "INSERT INTO operations(authority_id,caller_id,key_digest,request_sha256,operation_id,permit_sha256,"
                "state,created_utc,deadline_utc) VALUES(?,?,?,?,?,?,?,?,?)",
                (self.authority_id, request.caller_id, key_digest, request.request_sha256,
                 permit.operation_id, digest(permit), OperationState.PERMITTED.value,
                 utc_text(now), utc_text(permit.expires_utc)),
            )
            snapshot = self._operation_value(connection, self._operation_row(connection, permit.operation_id))
            return PermitDecision(created=True, operation=snapshot, permit=permit)

    def routing_snapshot(self, caller: CallerContext, route_alias: str, *, now: datetime) -> RoutingSnapshot:
        require(caller.authority_id == self.authority_id, "forbidden")
        with self._transaction(active_context=True) as (connection, observed, state):
            require(abs((observed - now).total_seconds()) <= 5, "clock_untrusted")
            self._healthy(state)
            active = self._active(connection, state)
            require(active is not None, "no_approved_policy")
            context = self._current.get()[2][1]
            require(context is not None, "missing_evidence")
            approval, bundle = self._eligible(connection, active.approval_sha256, context, observed)
            require(route_alias in bundle.route_aliases, "unsupported_request")
            evaluation = self._load(connection, "evaluations", approval.evaluation_sha256, EvaluationRecord)
            authorization = self._load(connection, "evaluation_authorizations", evaluation.authorization_sha256,
                                       EvaluationAuthorization)
            profiles = self._profiles(bundle, context, observed)
            expiry = min(bundle.expires_utc, evaluation.expires_utc, authorization.expires_utc,
                         evaluation.frozen_utc + timedelta(seconds=context.evaluation_max_age_seconds),
                         *(dependency.expires_utc for dependency in context.dependency_expiries),
                         *(profile.expires_utc for profile in profiles))
            return RoutingSnapshot(
                authority_id=self.authority_id, generation=active.generation,
                policy_bundle_sha256=active.policy_bundle_sha256, approval_sha256=active.approval_sha256,
                bundle=bundle, eligible_target_ids=tuple(target.target_id for target in bundle.targets),
                evidence_context_sha256=digest(context.model_dump(exclude={"observed_utc"})), expires_utc=expiry,
            )

    def stage_result(self, operation_id: str, encrypted: EncryptedResult, receipt: AttemptReceipt,
                     *, now: datetime) -> StagedResult:
        with self._transaction() as (connection, observed, _state):
            require(abs((observed - now).total_seconds()) <= 5, "clock_untrusted")
            operation = self._operation_row(connection, operation_id)
            permit = self._permit_value(self._permit_row(connection, operation_id))
            binding = self._binding(operation, permit)
            require(encrypted.aad_sha256 == digest(binding), "invalid_join")
            require(receipt.operation_id == operation_id and receipt.permit_sha256 == digest(permit)
                    and receipt.request_sha256 == permit.request_sha256
                    and receipt.policy_bundle_sha256 == permit.policy_bundle_sha256
                    and receipt.price_sha256 == permit.price_sha256 and receipt.bound_sha256 == permit.bound_sha256
                    and receipt.state in ("known", "unknown") and receipt.completed_utc is not None
                    and receipt.completed_utc <= now, "invalid_join")
            child = next((child for child in permit.attempt_children if child.child_id == receipt.child_id), None)
            require(child is not None and (receipt.provider, receipt.model, receipt.reserved_usd)
                    == (child.provider, child.model, child.maximum_liability_usd), "invalid_join")
            if child == permit.attempt_children[0]:
                require(receipt.serialized_envelope_sha256 == permit.serialized_envelope_sha256, "invalid_join")
            nonce = base64.b64decode(encrypted.nonce_b64, validate=True)
            ciphertext = base64.b64decode(encrypted.ciphertext_b64, validate=True)
            existing = connection.execute(
                "SELECT * FROM replay_results WHERE authority_id=? AND operation_id=? AND attempt_id=?",
                (self.authority_id, operation_id, receipt.attempt_id),
            ).fetchone()
            if existing is not None:
                require(existing["purged_utc"] is None, "result_expired")
                require(existing["receipt_sha256"] == digest(receipt)
                        and bytes(existing["receipt_canonical"]) == canonical_bytes(receipt)
                        and existing["result_sha256"] == encrypted.result_sha256
                        and existing["key_id"] == encrypted.key_id
                        and bytes(existing["nonce"]) == nonce and bytes(existing["ciphertext"]) == ciphertext
                        and bytes(existing["binding_canonical"]) == canonical_bytes(binding), "record_conflict")
                return StagedResult(authority_id=self.authority_id, operation_id=operation_id,
                                    permit_sha256=digest(permit), binding=binding, encrypted_result=encrypted,
                                    receipt=receipt, staged_utc=utc_read(existing["staged_utc"]))
            require(operation["state"] in (OperationState.FUNDED.value, OperationState.STAGED.value),
                    "invalid_transition")
            ledger = self._ledger(operation_id)
            require(ledger is not None, "invalid_join")
            self._join(connection, permit, ledger.join)
            attempt = next((attempt for attempt in ledger.attempts if attempt.child_id == receipt.child_id), None)
            require(attempt is not None and attempt.attempt_id == receipt.attempt_id and attempt.state == "active",
                    "invalid_join")
            if operation["replay_attempt_id"] is not None:
                self._require_retry_event(connection, operation_id, receipt.child_id)
            connection.execute(
                "INSERT INTO replay_results(authority_id,operation_id,attempt_id,key_id,nonce,ciphertext,result_sha256,"
                "binding_canonical,binding_sha256,receipt_sha256,receipt_canonical,staged_utc) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (self.authority_id, operation_id, receipt.attempt_id, encrypted.key_id, nonce, ciphertext,
                 encrypted.result_sha256, canonical_bytes(binding), digest(binding), digest(receipt),
                 canonical_bytes(receipt), utc_text(now)),
            )
            connection.execute("UPDATE operations SET state=?,replay_attempt_id=? WHERE authority_id=? AND operation_id=?",
                               (OperationState.STAGED.value, receipt.attempt_id, self.authority_id, operation_id))
            return StagedResult(authority_id=self.authority_id, operation_id=operation_id,
                                permit_sha256=digest(permit), binding=binding, encrypted_result=encrypted,
                                receipt=receipt, staged_utc=now)

    def mark_terminal(self, operation_id: str, settlement: SettlementReceipt,
                      *, now: datetime, result_expires_utc: datetime | None) -> OperationSnapshot:
        with self._transaction() as (connection, observed, _state):
            require(abs((observed - now).total_seconds()) <= 5, "clock_untrusted")
            operation = self._operation_row(connection, operation_id)
            permit = self._permit_value(self._permit_row(connection, operation_id))
            ledger = self._ledger(operation_id)
            require(ledger is not None, "invalid_join")
            self._join(connection, permit, ledger.join)
            require((settlement.authority_id, settlement.operation_id) == (self.authority_id, operation_id),
                    "invalid_join")
            attempt = next((item for item in ledger.attempts if item.child_id == settlement.child_id), None)
            require(attempt is not None and attempt.attempt_id == settlement.attempt_id
                    and attempt.state == settlement.state
                    and attempt.settlement_sha256 == settlement.settlement_sha256
                    and ledger.join.settlement_sha256 == settlement.settlement_sha256, "invalid_join")
            require(all(item.state in ("known", "unknown", "closed_unstarted") for item in ledger.attempts),
                    "invalid_transition")
            child = next((item for item in permit.attempt_children if item.child_id == settlement.child_id), None)
            require(child is not None and settlement.reserved_usd == child.maximum_liability_usd, "invalid_join")
            if operation["settlement_canonical"] is not None:
                previous = decode_record(bytes(operation["settlement_canonical"]), SettlementReceipt)
                require(canonical_bytes(previous.model_dump(exclude={"already_settled"}))
                        == canonical_bytes(settlement.model_dump(exclude={"already_settled"})), "record_conflict")
                if previous.state == "unknown":
                    # Also repair unservable ciphertext left by a prior source
                    # version. This never changes the immutable unknown charge.
                    self._purge_operation_ciphertext(connection, operation_id, observed)
                return self._operation_value(connection, operation)
            require(operation["state"] in (OperationState.FUNDED.value, OperationState.STAGED.value),
                    "invalid_transition")
            stage, purged = self._stage_value(connection, operation, permit)
            if settlement.state == "known":
                require(stage is not None and not purged
                        and stage.receipt.attempt_id == settlement.attempt_id
                        and stage.receipt.child_id == settlement.child_id
                        and stage.receipt.state == "known"
                        and stage.receipt.known_usage_cost_usd == settlement.known_usage_cost_usd,
                        "invalid_join")
                require(result_expires_utc == now + timedelta(hours=24), "invalid_transition")
                terminal_state = OperationState.TERMINAL
            else:
                require(result_expires_utc is None and settlement.terminal_unknown_usd == settlement.reserved_usd,
                        "invalid_join")
                terminal_state = OperationState.UNKNOWN_SETTLED
            connection.execute(
                "UPDATE operations SET state=?,terminal_utc=?,result_expires_utc=?,settlement_sha256=?,"
                "settlement_canonical=?,join_canonical=? WHERE authority_id=? AND operation_id=?",
                (terminal_state.value, utc_text(now), None if result_expires_utc is None else utc_text(result_expires_utc),
                 settlement.settlement_sha256, canonical_bytes(settlement), canonical_bytes(ledger.join),
                 self.authority_id, operation_id),
            )
            connection.execute("UPDATE permits SET state=?,join_sha256=? WHERE authority_id=? AND operation_id=?",
                               (PermitState.TERMINAL.value, digest(ledger.join), self.authority_id, operation_id))
            if settlement.state == "unknown":
                # No successful replay/TTL exists for terminal unknown. Discard
                # unservable bodies in this SAME terminal transaction; preserve
                # receipts, result/binding digests, tombstone, joins and full U.
                self._purge_operation_ciphertext(connection, operation_id, observed)
            return self._operation_value(connection, self._operation_row(connection, operation_id))

    def cancel_operation(self, caller: CallerContext, operation_id: str, *, now: datetime) -> OperationSnapshot:
        require(caller.authority_id == self.authority_id, "forbidden")
        with self._transaction() as (connection, observed, _state):
            require(abs((observed - now).total_seconds()) <= 5, "clock_untrusted")
            row = self._operation_row(connection, operation_id)
            require(row["caller_id"] == caller.caller_id, "forbidden")
            connection.execute("UPDATE operations SET cancelled=1 WHERE authority_id=? AND operation_id=?",
                               (self.authority_id, operation_id))
            self._audit(connection, "cancel_operation", {"operation_id": operation_id}, now)
            return self._operation_value(connection, self._operation_row(connection, operation_id))

    def abandon_unfunded(self, operation_id: str, *, now: datetime) -> bool:
        with self._transaction() as (connection, observed, _state):
            require(abs((observed - now).total_seconds()) <= 5, "clock_untrusted")
            operation = self._operation_row(connection, operation_id)
            row = self._permit_row(connection, operation_id)
            permit = self._permit_value(row)
            if operation["state"] == OperationState.ABANDONED.value:
                self._purge_operation_ciphertext(connection, operation_id, observed)
                return True
            if row["state"] != PermitState.PERMITTED.value:
                return False
            require(operation["cancelled"] or observed >= permit.expires_utc, "invalid_transition")
            require(self._ledger(operation_id) is None, "invalid_join")
            connection.execute("UPDATE permits SET state=? WHERE authority_id=? AND operation_id=?",
                               (PermitState.ABANDONED.value, self.authority_id, operation_id))
            connection.execute("UPDATE operations SET state=? WHERE authority_id=? AND operation_id=?",
                               (OperationState.ABANDONED.value, self.authority_id, operation_id))
            self._purge_operation_ciphertext(connection, operation_id, observed)
            return True

    def recovery_candidates(self, authority_id: str, *, cursor: str | None = None,
                            limit: int) -> PolicyRecoveryPage:
        require(authority_id == self.authority_id, "authority_mismatch")
        require(type(limit) is int and 1 <= limit <= 1024, "invalid_request")
        with self._transaction() as (connection, _now, _state):
            rows = connection.execute("SELECT * FROM operations WHERE authority_id=? AND operation_id>? "
                                      "ORDER BY operation_id LIMIT ?",
                                      (self.authority_id, cursor or "", limit + 1)).fetchall()
            return PolicyRecoveryPage(authority_id=self.authority_id,
                                      items=tuple(self._operation_value(connection, row) for row in rows[:limit]),
                                      next_cursor=rows[limit - 1]["operation_id"] if len(rows) > limit else None)

    def _purge_operation_ciphertext(self, connection: sqlite3.Connection, operation_id: str,
                                    now: datetime) -> int:
        return connection.execute(
            "UPDATE replay_results SET nonce=NULL,ciphertext=NULL,purged_utc=? "
            "WHERE authority_id=? AND operation_id=? AND purged_utc IS NULL",
            (utc_text(now), self.authority_id, operation_id),
        ).rowcount

    def purge_expired_results(self, authority_id: str, *, now: datetime, limit: int) -> int:
        require(authority_id == self.authority_id, "authority_mismatch")
        require(type(limit) is int and 1 <= limit <= 1024, "invalid_request")
        with self._transaction() as (connection, observed, _state):
            require(abs((observed - now).total_seconds()) <= 5, "clock_untrusted")
            rows = connection.execute(
                "SELECT operation_id,state FROM operations o WHERE authority_id=? AND "
                "((state=? AND result_expires_utc<=?) OR (state IN (?,?) AND EXISTS "
                "(SELECT 1 FROM replay_results r WHERE r.authority_id=o.authority_id "
                "AND r.operation_id=o.operation_id AND r.purged_utc IS NULL))) "
                "ORDER BY operation_id LIMIT ?",
                (self.authority_id, OperationState.TERMINAL.value, utc_text(now),
                 OperationState.UNKNOWN_SETTLED.value, OperationState.ABANDONED.value, limit),
            ).fetchall()
            count = 0
            for row in rows:
                count += self._purge_operation_ciphertext(connection, row["operation_id"], observed)
                if row["state"] == OperationState.TERMINAL.value:
                    connection.execute("UPDATE operations SET state=? WHERE authority_id=? AND operation_id=?",
                                       (OperationState.RESULT_EXPIRED.value, self.authority_id, row["operation_id"]))
            return count

    def _require_retry_event(self, connection: sqlite3.Connection, operation_id: str, child_id: str) -> None:
        rows = connection.execute("SELECT hash,canonical FROM governance_events WHERE authority_id=? AND event_kind=?",
                                  (self.authority_id, "retry_stage_ready")).fetchall()
        allowed = False
        for row in rows:
            raw = bytes(row["canonical"])
            event = json.loads(raw)
            require(sha256(raw).hexdigest() == row["hash"] and canonical_bytes(event) == raw
                    and event["authority_id"] == self.authority_id, "invalid_evidence")
            if (event["payload"]["operation_id"], event["payload"]["next_child_id"]) == (operation_id, child_id):
                permit = self._permit_value(self._permit_row(connection, operation_id))
                require(event["payload"]["permit_sha256"] == digest(permit), "invalid_evidence")
                allowed = True
        require(allowed, "invalid_authorization")

    def assert_retry_stage_ready(self, operation_id: str, child_id: str, *, now: datetime) -> None:
        """Check actual known-zero and trusted pre-send proof, never issue a ticket."""
        with self._transaction(operation_id=operation_id) as (connection, observed, state):
            require(abs((observed - now).total_seconds()) <= 5, "clock_untrusted")
            self._healthy(state)
            operation = self._operation_row(connection, operation_id)
            permit = self._permit_value(self._permit_row(connection, operation_id))
            require(not operation["cancelled"] and observed < permit.expires_utc, "cancelled")
            require(len(permit.attempt_children) == 2 and child_id == permit.attempt_children[1].child_id
                    and permit.attempt_children[1].conditional, "invalid_authorization")
            ledger = self._ledger(operation_id)
            require(ledger is not None, "invalid_join")
            self._join(connection, permit, ledger.join)
            previous, next_attempt = ledger.attempts
            require(previous.state == "known" and previous.settlement_sha256 is not None
                    and next_attempt.child_id == child_id and next_attempt.state in ("future", "active"),
                    "invalid_authorization")
            stage, purged = self._stage_value(connection, operation, permit)
            require(stage is not None and not purged and stage.receipt.attempt_id == previous.attempt_id
                    and stage.receipt.known_usage_cost_usd == ZERO and stage.receipt.status == "provider_error"
                    and stage.receipt.state == "known", "invalid_authorization")
            context = self._current.get()[2][1]
            require(context is not None, "missing_evidence")
            self.assert_dispatch_allowed(operation_id, ledger.join, context=context)
            require(self._retry_reader is not None, "dependency_unavailable")
            proof = self._retry_reader(operation_id, previous.child_id)
            require(proof is not None and proof.provider == stage.receipt.provider
                    and proof.model == stage.receipt.model and proof.status == "provider_error"
                    and proof.dispatch_state == "not_sent" and proof.retry_evidence == "pre_send_certain"
                    and proof.usage.complete and proof.usage.input_tokens == 0
                    and proof.usage.output_tokens == 0 and not proof.usage.unknown_components,
                    "invalid_authorization")
            if next_attempt.state == "active":
                self._require_retry_event(connection, operation_id, child_id)
            self._audit(connection, "retry_stage_ready", {
                "operation_id": operation_id, "next_child_id": child_id,
                "prior_attempt_id": previous.attempt_id, "settlement_sha256": previous.settlement_sha256,
                "permit_sha256": digest(permit), "stage_receipt_sha256": digest(stage.receipt),
                "retry_proof_sha256": digest(proof.model_dump(exclude={"text", "refusal", "provider_request_id"})),
            }, observed)

    def close_unstarted_operation(self, operation_id: str, *, now: datetime) -> OperationSnapshot:
        with self._transaction() as (connection, observed, _state):
            require(abs((observed - now).total_seconds()) <= 5, "clock_untrusted")
            operation = self._operation_row(connection, operation_id)
            permit = self._permit_value(self._permit_row(connection, operation_id))
            require(operation["cancelled"] or observed >= permit.expires_utc, "invalid_transition")
            ledger = self._ledger(operation_id)
            require(ledger is not None, "invalid_join")
            self._join(connection, permit, ledger.join)
            require(all(item.state == "closed_unstarted" and item.attempt_id is None for item in ledger.attempts),
                    "invalid_transition")
            connection.execute("UPDATE permits SET state=?,join_sha256=? WHERE authority_id=? AND operation_id=?",
                               (PermitState.TERMINAL.value, digest(ledger.join), self.authority_id, operation_id))
            connection.execute("UPDATE operations SET state=?,join_canonical=? WHERE authority_id=? AND operation_id=?",
                               (OperationState.ABANDONED.value, canonical_bytes(ledger.join), self.authority_id, operation_id))
            self._purge_operation_ciphertext(connection, operation_id, observed)
            return self._operation_value(connection, self._operation_row(connection, operation_id))

    def get_approval(self, approval_sha256: str) -> ApprovalRecord:
        with self._transaction() as (connection, _now, _state):
            approval = self._load(connection, "decisions", approval_sha256, ApprovalRecord)
            verify_operator(approval, self._key)
            return approval

    def get_evaluation_authorization(self, authorization_sha256: str) -> EvaluationAuthorization:
        with self._transaction() as (connection, _now, _state):
            authorization = self._load(connection, "evaluation_authorizations", authorization_sha256,
                                       EvaluationAuthorization)
            verify_operator(authorization, self._key)
            return authorization

    def get_bundle(self, bundle_sha256: str) -> PolicyBundle:
        with self._transaction() as (connection, _now, _state):
            return self._load(connection, "policy_bundles", bundle_sha256, PolicyBundle)

    def operation_incident_snapshot(self, operation_id: str) -> IncidentSnapshot:
        from .gate import AccountingGate
        return AccountingGate(self).operation_incident_snapshot(operation_id)

    def list_policy_bundles(self, *, limit: int) -> tuple[PolicyBundle, ...]:
        require(type(limit) is int and 1 <= limit <= 1024, "invalid_request")
        with self._transaction() as (connection, _now, _state):
            # policy_bundles is content-addressed across the DB; authority-owned
            # freeze events establish the local operator's visible set.
            events = connection.execute("SELECT hash,canonical FROM governance_events WHERE authority_id=? "
                                        "AND event_kind='freeze' ORDER BY recorded_utc DESC,hash DESC",
                                        (self.authority_id,)).fetchall()
            keys = []
            for row in events:
                raw = bytes(row["canonical"])
                event = json.loads(raw)
                require(sha256(raw).hexdigest() == row["hash"] and canonical_bytes(event) == raw
                        and event["authority_id"] == self.authority_id, "invalid_evidence")
                key = event["payload"]["policy_sha256"]
                if key not in keys:
                    keys.append(key)
                if len(keys) == limit:
                    break
            return tuple(self._load(connection, "policy_bundles", key, PolicyBundle) for key in keys)

    def list_operation_snapshots(self, *, limit: int) -> tuple[OperationSnapshot, ...]:
        require(type(limit) is int and 1 <= limit <= 1024, "invalid_request")
        with self._transaction() as (connection, _now, _state):
            rows = connection.execute("SELECT * FROM operations WHERE authority_id=? ORDER BY operation_id LIMIT ?",
                                      (self.authority_id, limit)).fetchall()
            return tuple(self._operation_value(connection, row) for row in rows)

"""Explicit simulation-only composition. No bootstrap runs on module import.

Calling build_mock_context in a future authorized runtime opens local stores.
Construction of this source does not execute databases, crypto, or services.
"""
from __future__ import annotations

from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
from time import monotonic_ns
import uuid

from .accounting.adapter import LedgerAdapter
from .accounting.configuration import LedgerConfiguration
from .accounting.synthetic import synthetic_configuration
from .adapters.anthropic import AnthropicAdapter
from .adapters.openai import OpenAIAdapter
from .api.auth import ClientAuthenticator
from .cli.operator import OperatorServices
from .cli.simulation import SimulationSigner, create_simulation_signer
from .controller.authority_lock import AuthorityLock
from .controller.planning import PermitPlanner
from .controller.ports import CancellationToken
from .controller.service import GatewayController
from .policies.gate import AccountingGate
from .policies.store import PolicyStore
from .replay.cipher import ReplayCipher
from .runtime import (
    ApprovedProfileRegistry, ClockHighWater, EvidenceContextLoader,
    RuntimeEvidenceRecord, TrustedClock, adapter_manifest_digest, profile_manifest_digest,
    require_local_runtime_root,
)
from .schemas import (
    AccountingTotals, ApprovalPayload, BudgetAuthority, CallerContext, ChatCompletionInput,
    DependencyExpiry, EligibilityContext, ErrorCode,
    EvaluationAuthorization, EvaluationAuthorizationPayload, EvaluationRecord, EvidenceTuple,
    FamilyMetrics, GatewayError, GatewayReply, GatewayRequest, IncidentEvidence,
    MetricInterval, OperationState, PermitState, PolicyBundle, PolicyRule, PolicyTarget,
    RequestFeatures, WireMessage, canonical_bytes, digest, request_digest, request_features,
    money_from_micros, usd_micros,
)
from .schemas.operator import (
    AcquisitionReceipt, CorpusManifest, EvaluationSpec, LiabilityEvidence,
    OperationSummary, OverviewSnapshot, PolicySummary, ShadowContext,
)
from .shared.s3.callledger.pricing import PriceSnapshot


def _require(condition: bool, code: ErrorCode = ErrorCode.CONFIG_MISMATCH) -> None:
    if not condition:
        raise GatewayError(code)


def _utc(value: datetime) -> datetime:
    _require(isinstance(value, datetime) and value.utcoffset() == timedelta(0),
             ErrorCode.CLOCK_UNTRUSTED)
    return value.astimezone(timezone.utc)


def _stamp(value: datetime) -> str:
    return _utc(value).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _read_stamp(value: str) -> datetime:
    return _utc(datetime.fromisoformat(value.replace("Z", "+00:00")))


def _latency_ms(nanoseconds: int) -> Decimal:
    _require(type(nanoseconds) is int and nanoseconds >= 0, ErrorCode.CLOCK_UNTRUSTED)
    return Decimal((0, Decimal(nanoseconds).as_tuple().digits, -6))


def _database_path(root: Path, filename: str, *, existing: bool) -> Path:
    root = require_local_runtime_root(root)
    path = root / filename
    if path.exists():
        info = path.lstat()
        _require(stat.S_ISREG(info.st_mode) and not path.is_symlink()
                 and not (getattr(info, "st_file_attributes", 0) & 0x400),
                 ErrorCode.UNSAFE_RUNTIME_PATH)
    else:
        _require(not existing, ErrorCode.STORE_UNAVAILABLE)
    _require(path.resolve(strict=existing).parent == root, ErrorCode.UNSAFE_RUNTIME_PATH)
    return path


@contextmanager
def _policy_connection(path: Path):
    """Root-owned initialization/high-water only; never producer evidence queries."""
    connection = None
    try:
        _database_path(path.parent, path.name, existing=True)
        connection = sqlite3.connect(path.as_uri() + "?mode=rw", uri=True,
                                     isolation_level=None, timeout=5)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA synchronous=FULL")
        _require(connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1,
                 ErrorCode.SCHEMA_MISMATCH)
        _require(connection.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal",
                 ErrorCode.SCHEMA_MISMATCH)
        yield connection
    except GatewayError:
        raise
    except (sqlite3.Error, OSError, ValueError, TypeError):
        raise GatewayError(ErrorCode.STORE_UNAVAILABLE) from None
    finally:
        if connection is not None:
            connection.close()


@dataclass(frozen=True)
class MockRuntimeSpec:
    """Trusted explicit lifetime/configuration; never constructed from client JSON.

    Reopen requires the same cap, deadline, quotas, snapshots, records and secret
    identities. No date-based authority reset or mutable budget replacement.
    Secret bytes are supplied in memory, never printed or read by this module.
    """
    runtime_root: Path
    authority_id: str
    created_utc: datetime
    deadline_utc: datetime
    cap_usd: Decimal
    max_outbound_attempts: int
    price_snapshot: PriceSnapshot
    records: tuple[RuntimeEvidenceRecord, ...]
    evaluation_specs: tuple[EvaluationSpec, ...]
    migration_path: Path
    migration_sha256: str
    replay_key: bytes = field(repr=False)
    key_digest_secret: bytes = field(repr=False)
    clients: tuple[tuple[str, CallerContext], ...]
    max_clock_drift: timedelta
    max_clock_startup_advance: timedelta


class _PolicyHighWater(ClockHighWater):
    """One private process-local connection; every observation still commits time."""
    def __init__(self, path: Path, *, authority_id: str, guard: AuthorityLock,
                 policy_config_sha256: str) -> None:
        self.path, self.authority_id, self.guard = path, authority_id, guard
        self.config_sha256 = policy_config_sha256
        self._pid = os.getpid()
        self._connection = None
        self._identity = None
        self._observing = False
        self._closed = False

    def assert_owner(self) -> None:
        _require(os.getpid() == self._pid and not self._closed,
                 ErrorCode.CLOCK_UNTRUSTED)

    def _invalidate(self) -> None:
        connection, self._connection = self._connection, None
        self._closed = True
        # Never use an inherited SQLite handle in a forked process.
        if connection is not None and os.getpid() == self._pid:
            try:
                connection.close()
            except sqlite3.Error:
                pass

    def close(self) -> None:
        if os.getpid() != self._pid:
            self._closed = True
            return
        with self.guard.hold(self.authority_id):
            self._invalidate()

    @contextmanager
    def observation(self):
        self.assert_owner()
        with self.guard.hold(self.authority_id):
            self.assert_owner()
            # Recursive clock invocations must validate independently, not borrow
            # a partially checked outer observation or its connection.
            _require(not self._observing, ErrorCode.CLOCK_UNTRUSTED)
            try:
                path = _database_path(self.path.parent, self.path.name, existing=True)
                info = path.stat()
                identity = (info.st_dev, info.st_ino)
                _require(info.st_ino != 0, ErrorCode.STORE_UNAVAILABLE)
                if self._identity is None:
                    self._identity = identity
                _require(identity == self._identity, ErrorCode.STORE_UNAVAILABLE)
                if self._connection is None:
                    connection = sqlite3.connect(path.as_uri() + "?mode=rw", uri=True,
                        isolation_level=None, timeout=5, check_same_thread=False)
                    self._connection = connection
                    connection.execute("PRAGMA foreign_keys=ON")
                    connection.execute("PRAGMA synchronous=FULL")
                    _require(connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
                        and connection.execute("PRAGMA synchronous").fetchone()[0] == 2
                        and connection.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal",
                        ErrorCode.SCHEMA_MISMATCH)
                    checked = _database_path(self.path.parent, self.path.name, existing=True).stat()
                    _require((checked.st_dev, checked.st_ino) == identity,
                             ErrorCode.STORE_UNAVAILABLE)
                self._observing = True
                yield
            except GatewayError:
                self._invalidate()
                raise
            except (sqlite3.Error, OSError, ValueError, TypeError):
                self._invalidate()
                raise GatewayError(ErrorCode.STORE_UNAVAILABLE) from None
            except BaseException:
                self._invalidate()
                raise
            finally:
                self._observing = False

    def _active_connection(self):
        self.assert_owner()
        self.guard.assert_held(authority_id=self.authority_id)
        _require(self._observing and self._connection is not None,
                 ErrorCode.CLOCK_UNTRUSTED)
        return self._connection

    def read(self) -> datetime:
        with self.guard.hold(self.authority_id):
            if not self._observing:
                with self.observation():
                    return self.read()
            row = self._active_connection().execute(
                "SELECT max_observed_utc,config_sha256 FROM authority_state WHERE authority_id=?",
                (self.authority_id,),
            ).fetchone()
            _require(row is not None and row[1] == self.config_sha256, ErrorCode.CLOCK_UNTRUSTED)
            return _read_stamp(row[0])

    def compare_and_advance(self, expected: datetime, observed: datetime) -> bool:
        _require(_utc(observed) >= _utc(expected), ErrorCode.CLOCK_ROLLBACK)
        with self.guard.hold(self.authority_id):
            if not self._observing:
                with self.observation():
                    return self.compare_and_advance(expected, observed)
            connection = self._active_connection()
            connection.execute("BEGIN IMMEDIATE")
            changed = connection.execute(
                "UPDATE authority_state SET max_observed_utc=? WHERE authority_id=? "
                "AND config_sha256=? AND max_observed_utc=?",
                (_stamp(observed), self.authority_id, self.config_sha256, _stamp(expected)),
            ).rowcount
            if changed != 1:
                connection.rollback()
                return False
            connection.commit()
            return True


class _AuthorityClock(TrustedClock):
    """OS guard, one high-water observation, then TrustedClock's thread lock."""
    def __init__(self, *, guard: AuthorityLock, authority_id: str, **kwargs) -> None:
        self._guard, self._authority_id = guard, authority_id
        super().__init__(**kwargs)

    def __call__(self) -> datetime:
        self._high_water.assert_owner()
        with self._guard.hold(self._authority_id):
            with self._high_water.observation():
                return super().__call__()

    def evidence_sha256(self) -> str:
        self._high_water.assert_owner()
        with self._guard.hold(self._authority_id):
            return super().evidence_sha256()

    def close(self) -> None:
        self._high_water.close()


def _initialize_policy_database(path: Path, *, spec: MockRuntimeSpec,
                                policy_config_sha256: str, bootstrap_config: dict,
                                guard: AuthorityLock, initialize: bool) -> None:
    """Initialize only an absent store; existing mismatches are never repaired/reset."""
    with guard.hold(spec.authority_id):
        expected = canonical_bytes(bootstrap_config)
        if not path.exists():
            _require(initialize, ErrorCode.STORE_UNAVAILABLE)
            migration = spec.migration_path.read_bytes()
            _require(hashlib.sha256(migration).hexdigest() == spec.migration_sha256,
                     ErrorCode.SCHEMA_MISMATCH)
            # Exclusive creation denies replacement; failure leaves a closed store
            # for operator inspection rather than deleting or silently reinitializing.
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
            os.close(fd)
            connection = sqlite3.connect(path.as_uri() + "?mode=rw", uri=True,
                                         isolation_level=None, timeout=5)
            try:
                _require(connection.execute("PRAGMA journal_mode=WAL").fetchone()[0].lower() == "wal",
                         ErrorCode.SCHEMA_MISMATCH)
                connection.execute("PRAGMA foreign_keys=ON")
                connection.executescript("BEGIN IMMEDIATE;\n" + migration.decode("utf-8"))
                connection.execute(
                    "CREATE TABLE runtime_bootstrap(authority_id TEXT PRIMARY KEY, "
                    "config_sha256 TEXT NOT NULL, canonical BLOB NOT NULL)"
                )
                connection.execute(
                    "INSERT INTO runtime_bootstrap VALUES(?,?,?)",
                    (spec.authority_id, digest(bootstrap_config), expected),
                )
                connection.execute(
                    "INSERT INTO authority_state(authority_id,config_sha256,max_observed_utc) VALUES(?,?,?)",
                    (spec.authority_id, policy_config_sha256, _stamp(spec.created_utc)),
                )
                connection.commit()
            except BaseException:
                connection.rollback()
                raise
            finally:
                connection.close()
        with _policy_connection(path) as connection:
            _require(connection.execute("PRAGMA user_version").fetchone()[0] == 1,
                     ErrorCode.SCHEMA_MISMATCH)
            _require(connection.execute("SELECT version FROM schema_version").fetchall() == [(1,)],
                     ErrorCode.SCHEMA_MISMATCH)
            rows = connection.execute("SELECT authority_id,config_sha256,canonical FROM runtime_bootstrap").fetchall()
            _require(rows == [(spec.authority_id, digest(bootstrap_config), expected)])
            state = connection.execute("SELECT authority_id,config_sha256 FROM authority_state").fetchall()
            _require(state == [(spec.authority_id, policy_config_sha256)])


@dataclass(frozen=True)
class MockRuntimeContext:
    spec: MockRuntimeSpec
    configuration: LedgerConfiguration
    authority: BudgetAuthority
    guard: AuthorityLock
    clock: _AuthorityClock
    profiles: ApprovedProfileRegistry
    contexts: EvidenceContextLoader
    policies: PolicyStore
    ledger: LedgerAdapter
    accounting_gate: AccountingGate
    authenticator: ClientAuthenticator
    replay_cipher: ReplayCipher
    controller: GatewayController
    signer: SimulationSigner
    observations: SimulationObservationJournal

    def evaluation_inputs(self, authorization_sha256: str
                          ) -> tuple[PolicyBundle, EvaluationAuthorization, EligibilityContext]:
        """Actual persisted signed authorization plus frozen trusted candidate."""
        with self.guard.hold(self.authority.authority_id):
            authorization = self.policies.get_evaluation_authorization(authorization_sha256)
            _require(digest(authorization) == authorization_sha256, ErrorCode.INVALID_AUTHORIZATION)
            _require(authorization.authority_id == self.authority.authority_id
                     and authorization.mode == "simulation", ErrorCode.INVALID_AUTHORIZATION)
            record = next((r for r in self.spec.records
                           if digest(r.bundle) == authorization.tuple.policy_bundle_sha256), None)
            _require(record is not None and record.evidence == authorization.tuple,
                     ErrorCode.INVALID_AUTHORIZATION)
            _require(self.policies.get_bundle(digest(record.bundle)) == record.bundle,
                     ErrorCode.INVALID_EVIDENCE)
            context = self.contexts(digest(record.bundle))
            _require(authorization.created_utc <= context.observed_utc < authorization.expires_utc,
                     ErrorCode.STALE_EVIDENCE)
            return record.bundle, authorization, context

    async def acquire_evaluation(self, request: GatewayRequest, authorization_sha256: str,
                                 *, cancel: CancellationToken) -> GatewayReply:
        """Only the controller owns evaluation funding, claim, handoff and settlement."""
        with self.guard.hold(self.authority.authority_id):
            self.observations.assert_available()
        bundle, authorization, _ = self.evaluation_inputs(authorization_sha256)
        started = monotonic_ns()
        reply = await self.controller.complete_evaluation(request, authorization_sha256, cancel=cancel)
        self.observations.observe(self, request=request, authorization=authorization,
                                  bundle=bundle, reply=reply, elapsed_ns=monotonic_ns() - started)
        return reply

    def close(self) -> None:
        with self.guard.hold(self.authority.authority_id):
            try:
                self.ledger.close()
            finally:
                self.clock.close()


def build_mock_context(spec: MockRuntimeSpec, *, initialize: bool = False,
                       signer: SimulationSigner | None = None,
                       utc_now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
                       monotonic_source: Callable[[], int] = monotonic_ns) -> MockRuntimeContext:
    """Future explicit mock bootstrap. No real keys/APIs or implicit environment load.

    initialize=True authorizes this function's local simulation DB initialization
    when called in a separately authorized runtime. It is never invoked by imports.
    Keep the same in-memory signer/replay/HMAC secrets on reopen; changed identities
    fail rather than reset the finite authority. Protected file key loaders are absent.
    """
    ledger = None
    high_water = None
    try:
        root = require_local_runtime_root(spec.runtime_root)
        configured_root = os.environ.get("GATEWAY_RUNTIME_ROOT")
        _require(bool(configured_root) and require_local_runtime_root(Path(configured_root)) == root,
                 ErrorCode.UNSAFE_RUNTIME_PATH)
        _require(_utc(spec.created_utc) < _utc(spec.deadline_utc))
        _require(type(initialize) is bool and type(spec.max_outbound_attempts) is int
                 and spec.max_outbound_attempts > 0 and type(spec.records) is tuple
                 and bool(spec.records) and type(spec.evaluation_specs) is tuple)
        _require(type(spec.replay_key) is bytes and len(spec.replay_key) == 32
                 and type(spec.key_digest_secret) is bytes and len(spec.key_digest_secret) >= 32)
        _require(type(spec.clients) is tuple and bool(spec.clients)
                 and len({token for token, _ in spec.clients}) == len(spec.clients)
                 and all(caller.authority_id == spec.authority_id for _, caller in spec.clients))
        configuration = synthetic_configuration(
            authority_id=spec.authority_id, cap_usd=spec.cap_usd,
            run_deadline_utc=spec.deadline_utc, max_outbound_attempts=spec.max_outbound_attempts,
            price_snapshot=spec.price_snapshot,
        )
        _require({p.exact_model for p in configuration.profiles}
                 == {"mock-openai-v1", "mock-anthropic-v1"}, ErrorCode.UNSUPPORTED_PROFILE)
        authority = BudgetAuthority(authority_id=spec.authority_id, cap_usd=spec.cap_usd,
                                    config_sha256=configuration.config_sha256)
        guard = AuthorityLock(root)
        if signer is None:
            _require(initialize, ErrorCode.DEPENDENCY_UNAVAILABLE)
            signer = create_simulation_signer(allowed_evidence=tuple(r.evidence for r in spec.records))
        _require(signer.mode == "simulation" and len(signer.public_key_bytes) == 32,
                 ErrorCode.EXTERNAL_DISABLED)
        policy_config = digest({"schema_version": 1, "authority_id": spec.authority_id,
                                "verification_key_sha256": hashlib.sha256(signer.public_key_bytes).hexdigest()})
        bootstrap_config = {
            "schema_version": 1, "mode": "simulation", "authority_id": spec.authority_id,
            "created_utc": spec.created_utc, "deadline_utc": spec.deadline_utc,
            "ledger_config_sha256": configuration.config_sha256,
            "policy_config_sha256": policy_config, "migration_sha256": spec.migration_sha256,
            "records": [{"bundle": r.bundle, "evidence": r.evidence,
                         "dependency_expiries": r.dependency_expiries,
                         "evaluation_max_age_seconds": r.evaluation_max_age_seconds} for r in spec.records],
            "evaluation_specs": spec.evaluation_specs, "clients": spec.clients,
            "replay_key_sha256": hashlib.sha256(spec.replay_key).hexdigest(),
            "key_digest_secret_sha256": hashlib.sha256(spec.key_digest_secret).hexdigest(),
            "max_clock_drift_microseconds": spec.max_clock_drift // timedelta(microseconds=1),
            "max_clock_startup_advance_microseconds": spec.max_clock_startup_advance // timedelta(microseconds=1),
        }
        policy_path = _database_path(root, "policy.sqlite3", existing=False)
        ledger_path = _database_path(root, "accounting.sqlite3", existing=False)
        # A missing half of the durable pair is an investigation, never a fresh
        # financial authority. No initialize flag can reset just the ledger.
        _require(policy_path.exists() == ledger_path.exists(), ErrorCode.STORE_UNAVAILABLE)
        _initialize_policy_database(policy_path, spec=spec, policy_config_sha256=policy_config,
                                    bootstrap_config=bootstrap_config, guard=guard, initialize=initialize)
        high_water = _PolicyHighWater(policy_path, authority_id=spec.authority_id,
                                      guard=guard, policy_config_sha256=policy_config)
        clock = _AuthorityClock(guard=guard, authority_id=spec.authority_id,
            utc_now=utc_now, monotonic_ns=monotonic_source, high_water=high_water,
            clock_identity_sha256=digest(bootstrap_config), max_drift=spec.max_clock_drift,
            max_startup_advance=spec.max_clock_startup_advance)
        _require(spec.created_utc <= clock() < spec.deadline_utc, ErrorCode.STALE_EVIDENCE)
        profiles = ApprovedProfileRegistry(manifests=(configuration.profiles,), clock=clock)
        contexts = EvidenceContextLoader(authority_id=spec.authority_id, records=spec.records,
                                         profile_loader=profiles, clock=clock)
        policies = PolicyStore(policy_path, authority_id=spec.authority_id,
            verification_key=signer.public_key_bytes,
            authority_lock=lambda: guard.hold(spec.authority_id), clock=clock)
        gate = AccountingGate(policies)
        with guard.hold(spec.authority_id):
            ledger = LedgerAdapter(authority=authority, database_path=ledger_path, guard=guard,
                                    gate=gate, clock=clock, configuration=configuration)

        def incident_reader(evidence: IncidentEvidence) -> IncidentEvidence | None:
            guard.assert_held(authority_id=spec.authority_id)
            original = ledger.incident_source(operation_id=evidence.operation_id,
                child_id=evidence.child_id, attempt_id=evidence.attempt_id,
                source_sha256=evidence.source_sha256)
            return None if original is None else IncidentEvidence.model_validate(original.model_dump(mode="python"))

        controller_ref: list[GatewayController] = []

        def retry_reader(operation_id: str, child_id: str):
            guard.assert_held(authority_id=spec.authority_id)
            _require(len(controller_ref) == 1, ErrorCode.DEPENDENCY_UNAVAILABLE)
            return controller_ref[0].retry_source(operation_id, child_id)

        policies.bind_runtime(context_loader=contexts, ledger_reader=ledger.operation_state,
            key_digest=lambda request: request.idempotency_key,
            assert_lock_held=lambda: guard.assert_held(authority_id=spec.authority_id),
            profile_loader=profiles, incident_reader=incident_reader, retry_reader=retry_reader)
        adapters = {}
        for record in spec.records:
            contexts(digest(record.bundle))  # Full trusted tuple/profile/expiry checks before use.
            for target in record.bundle.targets:
                profile = next((p for p in configuration.profiles
                    if (p.provider, p.exact_model, p.api_version, p.capability_sha256, p.adapter_sha256)
                    == (target.provider, target.exact_model, target.api_version,
                        target.capability_sha256, target.adapter_sha256)), None)
                _require(profile is not None, ErrorCode.UNSUPPORTED_PROFILE)
                adapter = OpenAIAdapter(profile, mode="mock") if profile.provider == "openai" else AnthropicAdapter(profile, mode="mock")
                if target.target_id in adapters:
                    _require(adapters[target.target_id].capability_profile() == profile, ErrorCode.EVIDENCE_CONFLICT)
                adapters[target.target_id] = adapter
        authenticator = ClientAuthenticator(dict(spec.clients), key_digest_secret=spec.key_digest_secret)
        cipher = ReplayCipher({"simulation-v1": spec.replay_key}, active_key_id="simulation-v1")
        planner = PermitPlanner(adapters, ledger, contexts, profiles)
        # DL4's approved evaluation loader constructor seam is pending source.
        def evaluation_loader(key: str):
            with guard.hold(spec.authority_id):
                authorization = policies.get_evaluation_authorization(key)
                _require(digest(authorization) == key and authorization.mode == "simulation"
                         and authorization.authority_id == spec.authority_id,
                         ErrorCode.INVALID_AUTHORIZATION)
                record = next((r for r in spec.records if digest(r.bundle)
                               == authorization.tuple.policy_bundle_sha256), None)
                _require(record is not None and record.evidence == authorization.tuple,
                         ErrorCode.INVALID_AUTHORIZATION)
                bundle = policies.get_bundle(digest(record.bundle))
                _require(bundle == record.bundle, ErrorCode.INVALID_EVIDENCE)
                context = contexts(digest(bundle))
                _require(authorization.budget_authority_id == spec.authority_id
                         and authorization.created_utc <= context.observed_utc < authorization.expires_utc,
                         ErrorCode.INVALID_AUTHORIZATION)
                return bundle, authorization
        controller = GatewayController(policies=policies, ledger=ledger, planner=planner,
            authority_lock=guard, authenticator=authenticator, replay_cipher=cipher,
            clock=clock, evaluation_loader=evaluation_loader)
        controller_ref.append(controller)
        return MockRuntimeContext(spec, configuration, authority, guard, clock, profiles,
                                  contexts, policies, ledger, gate, authenticator, cipher, controller, signer,
                                  SimulationObservationJournal())
    except BaseException as error:
        # Preserve the original failure while attempting every owned close.
        # A failed bootstrap never returns a usable context or resets stores.
        try:
            if ledger is not None:
                ledger.close()
        except Exception:
            pass
        try:
            if high_water is not None:
                high_water.close()
        except Exception:
            pass
        if isinstance(error, GatewayError):
            raise
        if isinstance(error, (OSError, sqlite3.Error, ValueError, TypeError,
                              AttributeError, ImportError)):
            raise GatewayError(ErrorCode.DEPENDENCY_UNAVAILABLE) from None
        raise


def build_operator_services(context: MockRuntimeContext) -> OperatorServices:
    """Read projections use only actual public producers, under the common guard."""
    authority_id = context.authority.authority_id

    def context_for_approval(key: str) -> EligibilityContext:
        with context.guard.hold(authority_id):
            approval = context.policies.get_approval(key)
            _require(digest(approval) == key and approval.authority_id == authority_id,
                     ErrorCode.INVALID_APPROVAL)
            return context.contexts(approval.tuple.policy_bundle_sha256)

    def overview() -> OverviewSnapshot:
        with context.guard.hold(authority_id):
            now = context.clock()
            halt = context.policies.status()
            active = context.policies.active()
            totals = context.ledger.totals(authority_id=authority_id)
            incidents = context.accounting_gate.incident_snapshot(authority_id=authority_id)
            return OverviewSnapshot(authority_id=authority_id, generation=halt.generation,
                active_policy_sha256=None if active is None else active.policy_bundle_sha256,
                accounting=totals, halt=halt, maximum_credible_late_charge_usd=incidents.maximum_credible_usd,
                observed_utc=now)

    def operations(limit: int) -> tuple[OperationSummary, ...]:
        _require(type(limit) is int and 1 <= limit <= 1024, ErrorCode.INVALID_REQUEST)
        with context.guard.hold(authority_id):
            snapshots = context.policies.list_operation_snapshots(limit=limit)
            result = []
            for snapshot in snapshots:
                # Required producer-owned operation projections, never authority
                # totals mislabelled as per-operation money or guessed prior costs.
                incidents = context.accounting_gate.operation_incident_snapshot(snapshot.operation_id)
                ledger_state = context.ledger.operation_state(snapshot.operation_id)
                if ledger_state is None:
                    _require(snapshot.permit.state in (PermitState.PERMITTED, PermitState.ABANDONED)
                             and snapshot.state in (OperationState.PERMITTED, OperationState.ABANDONED),
                             ErrorCode.INVALID_JOIN)
                    # Committed ledger absence under the shared guard proves
                    # there are no ledger amounts for this unfunded operation.
                    zero = Decimal("0")
                    totals = AccountingTotals(authority_id=authority_id, cap_usd=context.authority.cap_usd,
                        reserved_usd=zero, future_usd=zero, active_usd=zero, released_usd=zero,
                        known_usd=zero, unknown_usd=zero, excess_usd=zero,
                        uncovered_excess_usd=incidents.uncovered_excess_usd,
                        exposure_usd=incidents.uncovered_excess_usd,
                        halted=incidents.halted, conflict=incidents.conflict)
                else:
                    totals = context.ledger.operation_totals(snapshot.operation_id)
                result.append(OperationSummary(authority_id=authority_id,
                    operation_id=snapshot.operation_id, caller_id=snapshot.caller_id,
                    policy_bundle_sha256=snapshot.permit.policy_bundle_sha256,
                    state=snapshot.state, accounting=totals,
                    maximum_credible_late_charge_usd=incidents.maximum_credible_usd,
                    cancelled=snapshot.cancelled, result_expires_utc=snapshot.result_expires_utc))
            return tuple(result)

    def policies(limit: int) -> tuple[PolicySummary, ...]:
        _require(type(limit) is int and 1 <= limit <= 1024, ErrorCode.INVALID_REQUEST)
        with context.guard.hold(authority_id):
            active = context.policies.active()
            result = []
            for bundle in context.policies.list_policy_bundles(limit=limit):
                key = digest(bundle)
                is_active = active is not None and active.policy_bundle_sha256 == key
                eligible, reason = False, "missing_evidence"
                if is_active:
                    try:
                        caller = context.spec.clients[0][1]
                        snapshot = context.policies.routing_snapshot(
                            caller, bundle.route_aliases[0], now=context.clock())
                        _require(snapshot.policy_bundle_sha256 == key, ErrorCode.INVALID_EVIDENCE)
                        eligible, reason = True, None
                    except GatewayError as error:
                        if error.code in (ErrorCode.STALE_EVIDENCE, ErrorCode.PERMIT_EXPIRED):
                            reason = "stale_evidence"
                        elif error.code in (ErrorCode.INVALID_APPROVAL, ErrorCode.INELIGIBLE_POLICY,
                                           ErrorCode.NO_APPROVED_POLICY, ErrorCode.HALTED):
                            reason = "missing_evidence"
                        else:
                            raise
                # Nonactive rows assert only the known frozen bundle. Public
                # getters do not expose full rejection/revocation history yet.
                result.append(PolicySummary(policy_id=bundle.policy_id, version=bundle.version,
                    policy_bundle_sha256=key,
                    evaluation_sha256=active.evaluation_sha256 if is_active else None,
                    approval_sha256=active.approval_sha256 if is_active else None,
                    state="active" if is_active else "frozen",
                    generation=active.generation if is_active else None,
                    expires_utc=bundle.expires_utc, eligible=eligible, incomplete_reason=reason))
            return tuple(result)

    return OperatorServices(context.policies, context_for_approval, overview, operations, policies)


class SimulationObservationJournal:
    """Developer-owned observations, never a ledger or independent acceptance oracle.

    Only actual post-controller committed snapshots are observed under the same
    authority guard. Store canonical body-free facts; callers cannot insert a
    passing hash, count, approval, or money state. No observation means no proof.
    """
    def __init__(self, *, max_facts: int = 512, max_bytes: int = 2 * 1024 * 1024) -> None:
        _require(type(max_facts) is int and 1 <= max_facts <= 512
                 and type(max_bytes) is int and 32768 <= max_bytes <= 2 * 1024 * 1024)
        self._max_facts, self._max_bytes = max_facts, max_bytes
        # Reserve room for the fixed artifact envelope, tuple and separators.
        # The exact complete canonical artifact is checked again before return.
        self._fact_byte_budget = max_bytes - 16384
        self._fact_bytes = 0
        self._facts: tuple[bytes, ...] = ()
        self._identities: dict[str, str] = {}
        self._failure: ErrorCode | None = None
        self._rejected_fact_sha256: str | None = None

    def _open(self) -> None:
        if self._failure is not None:
            raise GatewayError(self._failure)

    def assert_available(self) -> None:
        """Stop new observation-dependent acquisition after an evidence failure."""
        self._open()

    def _retain_fact(self, fact: dict, *, identity: str) -> None:
        self._open()
        # Replay latency/time and unrelated authority-wide totals can advance
        # without changing this operation's observation. Preserve its original
        # acquisition timing/cost; repeated reads are not new acquisitions.
        stable = {key: value for key, value in fact.items()
                  if key not in {"observed_utc", "latency_ms", "accounting"}}
        fingerprint = digest(stable)
        previous = self._identities.get(identity)
        if previous == fingerprint:
            return
        raw = canonical_bytes(fact)
        if (len(self._facts) >= self._max_facts
                or self._fact_bytes + len(raw) + 1 > self._fact_byte_budget):
            # Keep all previously observed history and the rejected identity.
            # No truncation, replacement, clear/reset, or healthy freeze follows.
            self._rejected_fact_sha256 = hashlib.sha256(raw).hexdigest()
            self._failure = ErrorCode.INVALID_EVIDENCE
            raise GatewayError(self._failure)
        self._facts = (*self._facts, raw)
        self._fact_bytes += len(raw) + 1
        if previous is not None:
            # Both bounded conflicting records remain available as diagnostics;
            # neither overwrites the original or enters an eligible artifact.
            self._failure = ErrorCode.EVIDENCE_CONFLICT
            raise GatewayError(self._failure)
        self._identities[identity] = fingerprint

    def diagnostic_snapshot(self) -> dict:
        """Bounded immutable body-free history, including any conflicting pair.

        This is not an eligible evaluation artifact and cannot clear failure.
        Call under the owning context's authority guard, as with frozen_artifact.
        """
        return {"failure_code": None if self._failure is None else self._failure.value,
                "max_facts": self._max_facts, "max_bytes": self._max_bytes,
                "retained_fact_bytes": self._fact_bytes, "facts_canonical": self._facts,
                "rejected_fact_sha256": self._rejected_fact_sha256}

    def observe(self, context: MockRuntimeContext, *, request: GatewayRequest,
                authorization: EvaluationAuthorization, bundle: PolicyBundle,
                reply: GatewayReply, elapsed_ns: int) -> None:
        with context.guard.hold(context.authority.authority_id):
            self._open()
            totals = context.ledger.totals(authority_id=context.authority.authority_id)
            snapshot = (None if reply.operation_id is None else
                        context.policies.operation_snapshot(reply.operation_id))
            ledger = (None if reply.operation_id is None else
                      context.ledger.operation_state(reply.operation_id))
            operation_totals = (None if reply.operation_id is None else
                                None if ledger is None else context.ledger.operation_totals(reply.operation_id))
            known_cost = None
            settlement_matches = False
            public_cost_matches = reply.result is None
            if snapshot is not None and ledger is not None and operation_totals is not None:
                settlement, staged = snapshot.settlement, snapshot.staged_result
                if settlement is not None and staged is not None:
                    attempt = next((a for a in ledger.attempts
                                    if a.child_id == settlement.child_id), None)
                    settlement_matches = (
                        snapshot.join == ledger.join and settlement.state == "known"
                        and ledger.join.settlement_sha256 == settlement.settlement_sha256
                        and attempt is not None and attempt.state == "known"
                        and attempt.attempt_id == settlement.attempt_id
                        and attempt.settlement_sha256 == settlement.settlement_sha256
                        and staged.receipt.state == "known" and staged.receipt.cost_status == "known"
                        and staged.receipt.attempt_id == settlement.attempt_id
                        and staged.receipt.child_id == settlement.child_id
                        and staged.receipt.known_usage_cost_usd == settlement.known_usage_cost_usd
                    )
                if (settlement_matches
                        and all(a.state in ("known", "closed_unstarted") for a in ledger.attempts)
                        and all(value == 0 for value in (operation_totals.future_usd,
                            operation_totals.active_usd, operation_totals.unknown_usd,
                            operation_totals.uncovered_excess_usd))):
                    # Aggregate ALL committed attempts, not only the latest/public
                    # result. A known-zero failure is an actual Decimal0 here.
                    known_cost = operation_totals.known_usd
                if reply.result is not None:
                    public_cost_matches = (
                        known_cost is not None and reply.result.cost.status == "known"
                        and reply.result.cost.amount_usd == known_cost
                        and reply.result.cost.price_sha256 == snapshot.permit.price_sha256
                        and settlement_matches
                    )
            checks = {
                "configured_simulation_authority": authorization.mode == "simulation"
                    and authorization.authority_id == context.authority.authority_id,
                "candidate_exact_tuple": authorization.tuple.policy_bundle_sha256 == digest(bundle),
                "bounded_authority_exposure": usd_micros(totals.exposure_usd) <= usd_micros(totals.cap_usd),
                "no_observed_breach_or_conflict": not totals.halted and not totals.conflict
                    and totals.excess_usd == 0 and totals.uncovered_excess_usd == 0,
                "successful_terminal_observed": reply.http_status == 200 and reply.result is not None,
                "committed_policy_and_ledger_observed": snapshot is not None and ledger is not None,
            }
            if snapshot is not None and ledger is not None:
                permit = snapshot.permit
                settlement, staged = snapshot.settlement, snapshot.staged_result
                checks.update({
                    "immutable_request_binding": snapshot.request_sha256 == request.request_sha256
                        and permit.policy_bundle_sha256 == digest(bundle)
                        and permit.evaluation_authorization_sha256 == digest(authorization)
                        and permit.purpose == "eval",
                    "actual_committed_join": snapshot.join == ledger.join
                        and ledger.permit_sha256 == digest(permit),
                    "single_claim_per_declared_child": len(ledger.attempts) == len(permit.attempt_children)
                        and len({a.child_id for a in ledger.attempts}) == len(ledger.attempts)
                        and all(a.child_id in {c.child_id for c in permit.attempt_children}
                                for a in ledger.attempts),
                    "known_staged_original_settlement": settlement_matches and public_cost_matches,
                    "terminal_expiry_is_policy_owned": reply.result is not None
                        and snapshot.result_expires_utc is not None
                        and reply.result.result_expires_utc == snapshot.result_expires_utc,
                })
            fact = {
                "schema_version": 1, "scope": "developer-observed-simulation-only",
                "authority_id": context.authority.authority_id,
                "tuple_sha256": digest(authorization.tuple),
                "dependency_tuple_sha256": digest(authorization.tuple.model_dump(
                    exclude={"policy_bundle_sha256"})),
                "candidate_sha256": digest(bundle),
                "evaluator_code_sha256": authorization.tuple.evaluator_code_sha256,
                "authorization_sha256": digest(authorization),
                "operation_id": reply.operation_id, "request_sha256": request.request_sha256,
                "reply_http_status": reply.http_status,
                "reply_code": reply.code, "checks": checks,
                "policy_snapshot_sha256": None if snapshot is None else digest(snapshot),
                "ledger_snapshot_sha256": None if ledger is None else digest(ledger),
                "provider_receipt_sha256": (None if snapshot is None or snapshot.staged_result is None
                                             else digest(snapshot.staged_result.receipt)),
                "target_id": (None if snapshot is None or ledger is None else
                    next((child.target_id for attempt in reversed(ledger.attempts)
                          if attempt.attempt_id is not None for child in snapshot.permit.attempt_children
                          if child.child_id == attempt.child_id), None)),
                "outcome_status": (None if snapshot is None or snapshot.staged_result is None
                                   else snapshot.staged_result.receipt.status),
                "response_text_sha256": (None if reply.result is None or reply.result.choice.text is None else
                    hashlib.sha256(reply.result.choice.text.encode("utf-8")).hexdigest()),
                "known_cost_usd": known_cost,
                "attempt_count": None if ledger is None else sum(a.attempt_id is not None for a in ledger.attempts),
                "retained_liability_usd": (None if operation_totals is None else money_from_micros(sum(
                    usd_micros(value) for value in (operation_totals.future_usd, operation_totals.active_usd,
                        operation_totals.unknown_usd, operation_totals.uncovered_excess_usd)))),
                "latency_ms": _latency_ms(elapsed_ns),
                "accounting": totals, "operation_accounting": operation_totals,
                "observed_utc": context.clock(),
            }
            identity = digest({
                "authority_id": context.authority.authority_id,
                "operation_id": reply.operation_id,
                "provider_receipt_sha256": fact["provider_receipt_sha256"],
                # Unfunded failures have no operation/receipt. Bound their
                # identity without retaining the raw opaque operation key.
                "unfunded_request_identity": (None if reply.operation_id is not None else digest({
                    "authorization_sha256": digest(authorization),
                    "request_sha256": request.request_sha256,
                    "operation_key_sha256": hashlib.sha256(request.idempotency_key.encode("utf-8")).hexdigest(),
                })),
            })
            self._retain_fact(fact, identity=identity)

    def frozen_artifact(self, evidence: EvidenceTuple, *, authorization_sha256: str) -> dict | None:
        """Return exact observed facts; their digest is supplied to the scorer.

        Must be called under the context authority guard. This does not assert
        A01-A16 coverage, custody, biological-human approval, or runtime acceptance.
        """
        self._open()
        _require(type(authorization_sha256) is str and len(authorization_sha256) == 64
                 and all(c in "0123456789abcdef" for c in authorization_sha256),
                 ErrorCode.INVALID_AUTHORIZATION)
        _require(len(self._facts) <= self._max_facts and self._fact_bytes <= self._fact_byte_budget,
                 ErrorCode.INVALID_EVIDENCE)
        key = digest(evidence.model_dump(exclude={"policy_bundle_sha256"}))
        facts = tuple(fact for raw in self._facts for fact in (json.loads(raw),)
                      if fact["dependency_tuple_sha256"] == key)
        if not facts:
            return None
        artifact = {"schema_version": 1, "domain": "gateway.simulation-observations.v1",
                "scope": "developer-owned-limited-observations",
                "tuple": evidence, "candidate_sha256": evidence.policy_bundle_sha256,
                "evaluator_code_sha256": evidence.evaluator_code_sha256,
                "authorization_sha256": authorization_sha256, "facts": facts,
                "violation_count": sum(not passed for fact in facts for passed in fact["checks"].values())}
        if len(canonical_bytes(artifact)) > self._max_bytes:
            self._failure = ErrorCode.INVALID_EVIDENCE
            raise GatewayError(self._failure)
        return artifact

    def verify_receipt_coverage(self, evidence: EvidenceTuple, receipts, *, authorization_sha256: str) -> None:
        """An observed call cannot bless unrelated caller-supplied JSON receipts."""
        artifact = self.frozen_artifact(evidence, authorization_sha256=authorization_sha256)
        _require(artifact is not None, ErrorCode.MISSING_EVIDENCE)
        facts = artifact["facts"]
        for receipt in receipts:
            # Reuse needs a separate trusted original-source registry. This
            # acquisition-only mock composition does not invent reuse evidence.
            _require(not receipt.reused, ErrorCode.INVALID_EVIDENCE)
            text_hash = (None if receipt.response_text is None else
                         hashlib.sha256(receipt.response_text.encode("utf-8")).hexdigest())
            missing = receipt.provider_receipt_sha256 is None and receipt.outcome_status == "missing"
            _require(any(fact["provider_receipt_sha256"] == receipt.provider_receipt_sha256
                         and fact["request_sha256"] == receipt.request_sha256
                         and fact["target_id"] == receipt.target_id
                         and (receipt.response_ref is None if missing else fact["operation_id"] == receipt.response_ref)
                         and (fact["outcome_status"] is None if missing else fact["outcome_status"] == receipt.outcome_status)
                         and fact["response_text_sha256"] == text_hash
                         and fact["known_cost_usd"] == (None if receipt.known_cost_usd is None else
                             json.loads(canonical_bytes(receipt.known_cost_usd)))
                         and receipt.original_acquisition_cost_usd == receipt.known_cost_usd
                         and receipt.current_reuse_cost_usd is None
                         and fact["attempt_count"] == receipt.attempt_count
                         and fact["retained_liability_usd"] == json.loads(canonical_bytes(receipt.retained_liability_usd))
                         and fact["latency_ms"] == (None if receipt.latency_ms is None else
                             json.loads(canonical_bytes(receipt.latency_ms)))
                         for fact in facts), ErrorCode.MISSING_EVIDENCE)


def build_runner_factory(context: MockRuntimeContext):
    """Bind DL5 EvalCommandServices.runner_factory to canonical packaged scorer.

    Actual authorization registration and exact trusted spec/corpus are checked.
    No invariant evidence is fabricated; absent independent evidence remains null
    and the scorer must report inconclusive rather than mint an eligible pass.
    """
    def factory(tasks, manifest: CorpusManifest, spec: EvaluationSpec,
                policy: PolicyBundle, authorization: EvaluationAuthorization):
        from .evaluation.scoring import EvalRunner
        from .shadow.evaluator import recommend_target
        with context.guard.hold(context.authority.authority_id):
            bundle, registered, trusted = context.evaluation_inputs(digest(authorization))
            _require(registered == authorization and bundle == policy
                     and digest(spec) == policy.eval_spec_sha256
                     and any(item == spec for item in context.spec.evaluation_specs)
                     and digest(manifest) == trusted.tuple.corpus_sha256,
                     ErrorCode.INVALID_EVIDENCE)
            targets = tuple(sorted(policy.targets, key=lambda target: target.target_id))
            _require(len(targets) == 2, ErrorCode.MISSING_EVIDENCE)
            expectations = {target.target_id: {
                "exact_model": target.exact_model, "profile_sha256": target.capability_sha256,
                "adapter_sha256": target.adapter_sha256, "price_sha256": policy.price_sha256,
                "bound_sha256": policy.bound_bundle_sha256,
            } for target in targets}

            def verified(value: EvaluationAuthorization) -> str:
                _, actual, _ = context.evaluation_inputs(digest(value))
                _require(actual == value, ErrorCode.INVALID_AUTHORIZATION)
                return digest(actual)
            observed = context.observations.frozen_artifact(
                authorization.tuple, authorization_sha256=digest(authorization))
            runner = EvalRunner(tasks=tuple(tasks), baseline_target_id=targets[0].target_id,
                second_target_id=targets[1].target_id, candidate=policy,
                provenance_expectations=expectations,
                selector=lambda features, candidate: recommend_target(features, candidate)[0],
                authorization=authorization, verify_authorization=verified,
                verified_spec_sha256=digest(spec), evaluator_code_sha256=spec.evaluator_code_sha256,
                frozen_utc=context.clock(), report_id="simulation-" + digest(authorization)[:32],
                authority_invariant_evidence_sha256=None if observed is None else digest(observed),
                authority_violation_count=None if observed is None else observed["violation_count"],
                authority_invariant_artifact=None if observed is None else canonical_bytes(observed))
            class ObservedRunner:
                def run(self, frozen_spec, corpus_manifest, receipts):
                    with context.guard.hold(context.authority.authority_id):
                        context.observations.verify_receipt_coverage(
                            authorization.tuple, receipts, authorization_sha256=digest(authorization))
                    return runner.run(frozen_spec, corpus_manifest, receipts)

                def artifacts_for(self, report):
                    return runner.artifacts_for(report)
            return ObservedRunner()
    return factory


def build_evaluation_services(context: MockRuntimeContext):
    """Canonical packaged EvalCommandServices, with actual-observation receipt checks."""
    from .cli.evaluation import EvalCommandServices
    return EvalCommandServices(runner_factory=build_runner_factory(context))


@dataclass(frozen=True)
class DemoEvaluationPlan:
    """Explicit trusted candidate and two static acquisition-policy identities.

    Tasks/manifest come from the frozen development loader, not generated answers.
    All referenced policies/specs must already be in MockRuntimeSpec's trusted
    immutable registry. Liability is finite and uses the same lifetime authority.
    """
    name: str
    policy_sha256: str
    acquisition_policy_sha256s: tuple[str, str]
    manifest: CorpusManifest
    tasks: tuple
    authorization_maxima: tuple[tuple[str, Decimal], ...]


def build_demo_services(context: MockRuntimeContext, *, plans: tuple[DemoEvaluationPlan, ...],
                        original_request: GatewayRequest, boundary_request: GatewayRequest):
    """Bind actual asynchronous evaluation, scoring, simulation signing and journey.

    This recipe does not guarantee runtime success or invent a budget-reset route.
    The caller must provision a finite synthetic schedule/cap that permits both
    development evaluations and makes the declared boundary request too costly.
    Missing actual observations/artifacts or an inconclusive report refuses approval.
    """
    from .cli.demo import DemoPolicyEvidence, DemoServices, controller_request
    from .cli.signing import confirmation_digest
    from .shadow.evaluator import evaluate_local, recommend_target
    operator = build_operator_services(context)
    authority_id = context.authority.authority_id
    _require(type(plans) is tuple and {p.name for p in plans} == {"baseline", "candidate"}
             and len(plans) == 2)
    caller = CallerContext(authority_id=original_request.authority_id, caller_id=original_request.caller_id)
    _require(caller in tuple(client for _, client in context.spec.clients)
             and (boundary_request.authority_id, boundary_request.caller_id)
             == (caller.authority_id, caller.caller_id), ErrorCode.FORBIDDEN)

    def configured_record(key: str) -> RuntimeEvidenceRecord:
        record = next((record for record in context.spec.records if digest(record.bundle) == key), None)
        _require(record is not None, ErrorCode.MISSING_EVIDENCE)
        return record

    # Governance counts original nonabandoned permit maxima cumulatively for
    # EACH signed authorization. That work bound differs from the one ledger's
    # permanent cap on K+F+A+U+D. Validate explicit complete campaign quotes before
    # signing; neither limit is reset or amended after an acquisition.
    _require(all(type(plan.authorization_maxima) is tuple for plan in plans))
    provided = dict(plans[0].authorization_maxima)
    _require(len(provided) == len(plans[0].authorization_maxima)
             and all(plan.authorization_maxima == plans[0].authorization_maxima for plan in plans))
    required: dict[str, int] = {}

    def quote_campaign(key: str, tasks, *, expected_target: str | None = None) -> None:
        record = configured_record(key)
        with context.guard.hold(authority_id):
            context.contexts(key)
            amount = 0
            for task in tasks:
                target = recommend_target(task.features(), record.bundle)[0]
                _require(expected_target is None or target == expected_target, ErrorCode.INVALID_EVIDENCE)
                now = context.clock()
                request = GatewayRequest(authority_id=authority_id, caller_id=caller.caller_id,
                    idempotency_key="quote-" + digest({"policy": key, "task": task.task_id})[:48],
                    request_sha256=task.request_sha256(), route_alias=task.route_alias,
                    messages=(WireMessage(role="user", content=task.input_text),),
                    max_completion_tokens=task.max_completion_tokens,
                    deadline_utc=min(now + timedelta(seconds=60), record.bundle.expires_utc))
                envelope = context.controller.planner.adapters[target].serialize(request)
                amount += usd_micros(context.ledger.reserve_for(envelope)) * record.bundle.max_attempts_total
            required[key] = required.get(key, 0) + amount

    for plan in plans:
        # Scoring authorization also declares its complete potential candidate
        # plan; C scoring itself reuses the two acquired static outcome tables.
        quote_campaign(plan.policy_sha256, plan.tasks)
        targets = sorted(configured_record(plan.policy_sha256).bundle.targets,
                         key=lambda target: target.target_id)
        _require(len(targets) == len(plan.acquisition_policy_sha256s) == 2)
        for target, key in zip(targets, plan.acquisition_policy_sha256s):
            quote_campaign(key, plan.tasks, expected_target=target.target_id)
    _require(set(provided) == set(required), ErrorCode.INVALID_AUTHORIZATION)
    _require(all(usd_micros(provided[key]) == amount and amount > 0
                 for key, amount in required.items()), ErrorCode.INVALID_AUTHORIZATION)

    registered_authorizations: dict[str, EvaluationAuthorization] = {}

    def register_authorization(record: RuntimeEvidenceRecord) -> EvaluationAuthorization:
        with context.guard.hold(authority_id):
            current = context.contexts(digest(record.bundle))
            maximum = provided[digest(record.bundle)]
            _require(isinstance(maximum, Decimal) and maximum.is_finite()
                     and maximum > 0, ErrorCode.INVALID_AUTHORIZATION)
            key = digest(record.bundle)
            if key in registered_authorizations:
                signed = registered_authorizations[key]
                _require(signed.maximum_liability_usd == maximum
                         and signed.created_utc <= current.observed_utc < signed.expires_utc
                         and context.policies.get_evaluation_authorization(digest(signed)) == signed,
                         ErrorCode.INVALID_AUTHORIZATION)
                return signed
            context.policies.freeze(record.bundle)
            payload = EvaluationAuthorizationPayload(
                authorization_id="simulation-eval-" + digest(record.evidence)[:32],
                authority_id=authority_id, mode="simulation", tuple=record.evidence,
                budget_authority_id=authority_id, budget_reference_sha256=context.authority.config_sha256,
                maximum_liability_usd=maximum, created_utc=current.observed_utc,
                expires_utc=min(context.spec.deadline_utc, record.bundle.expires_utc,
                                *(d.expires_utc for d in current.dependency_expiries)),
                nonce="simulation-" + digest(record.evidence)[:32],
                declared_os_account=context.signer.declared_os_account,
                signer_fingerprint_sha256=context.signer.fingerprint_sha256,
            )
            signed = context.signer.sign_evaluation_authorization(
                payload, confirmed_tuple_sha256=confirmation_digest(payload))
            _require(context.policies.authorize_evaluation(signed) == digest(signed),
                     ErrorCode.INVALID_AUTHORIZATION)
            registered_authorizations[key] = signed
            return signed

    async def evaluate_and_sign(name: str):
        plan = next((p for p in plans if p.name == name), None)
        _require(plan is not None, ErrorCode.MISSING_EVIDENCE)
        record = configured_record(plan.policy_sha256)
        spec = next((item for item in context.spec.evaluation_specs
                     if digest(item) == record.bundle.eval_spec_sha256), None)
        _require(spec is not None and digest(plan.manifest) == spec.corpus_sha256
                 and type(plan.tasks) is tuple and len(plan.tasks) == 60,
                 ErrorCode.MISSING_EVIDENCE)
        targets = tuple(sorted(record.bundle.targets, key=lambda target: target.target_id))
        _require(len(targets) == 2 and len(set(plan.acquisition_policy_sha256s)) == 2,
                 ErrorCode.MISSING_EVIDENCE)
        authorization = register_authorization(record)
        run_identity = uuid.uuid4().hex  # Unique acquisition keys; never a new wallet/authority.
        receipts = []
        for target, key in zip(targets, plan.acquisition_policy_sha256s):
            acquisition = configured_record(key)
            _require(acquisition.evidence.model_dump(exclude={"policy_bundle_sha256"})
                     == record.evidence.model_dump(exclude={"policy_bundle_sha256"}),
                     ErrorCode.INVALID_EVIDENCE)
            signed = authorization if key == plan.policy_sha256 else register_authorization(acquisition)
            for task in plan.tasks:
                _require(recommend_target(task.features(), acquisition.bundle)[0] == target.target_id,
                         ErrorCode.INVALID_EVIDENCE)
                now = context.clock()
                request = GatewayRequest(authority_id=authority_id, caller_id=caller.caller_id,
                    idempotency_key="eval-" + digest({"policy": key, "task": task.task_id,
                        "target": target.target_id, "authorization": digest(signed),
                        "run_identity": run_identity})[:48],
                    request_sha256=task.request_sha256(), route_alias=task.route_alias,
                    messages=(WireMessage(role="user", content=task.input_text),),
                    max_completion_tokens=task.max_completion_tokens,
                    deadline_utc=min(now + timedelta(seconds=60), signed.expires_utc))
                reply = await context.acquire_evaluation(request, digest(signed), cancel=CancellationToken())
                _require(reply.operation_id is not None,
                         ErrorCode.MISSING_EVIDENCE)
                with context.guard.hold(authority_id):
                    snapshot = context.policies.operation_snapshot(reply.operation_id)
                    _require(snapshot is not None,
                             ErrorCode.MISSING_EVIDENCE)
                    staged = snapshot.staged_result
                    artifact = context.observations.frozen_artifact(
                        record.evidence, authorization_sha256=digest(authorization))
                    _require(artifact is not None, ErrorCode.MISSING_EVIDENCE)
                    fact = next((f for f in reversed(artifact["facts"])
                                 if f["operation_id"] == reply.operation_id), None)
                    _require(fact is not None and fact["target_id"] == target.target_id,
                             ErrorCode.MISSING_EVIDENCE)
                    receipts.append(AcquisitionReceipt(acquisition_id="acq-" + reply.operation_id,
                        task_id=task.task_id, target_id=target.target_id,
                        request_sha256=task.request_sha256(), exact_model=target.exact_model,
                        parameters_sha256=task.parameters_sha256(), profile_sha256=target.capability_sha256,
                        adapter_sha256=target.adapter_sha256, price_sha256=record.evidence.price_sha256,
                        bound_sha256=record.evidence.bound_sha256,
                        outcome_status="missing" if staged is None else staged.receipt.status,
                        response_ref=None if staged is None else reply.operation_id,
                        response_text=None if reply.result is None else reply.result.choice.text,
                        provider_receipt_sha256=None if staged is None else digest(staged.receipt),
                        mode="simulation", synthetic=True,
                        reused=False, reuse_source_sha256=None,
                        original_acquisition_cost_usd=fact["known_cost_usd"],
                        current_reuse_cost_usd=None, known_cost_usd=fact["known_cost_usd"],
                        retained_liability_usd=fact["retained_liability_usd"],
                        attempt_count=fact["attempt_count"], latency_ms=Decimal(fact["latency_ms"]),
                        acquired_utc=fact["observed_utc"]))
        runner = build_runner_factory(context)(plan.tasks, plan.manifest, spec, record.bundle, authorization)
        report = runner.run(spec, plan.manifest, tuple(receipts))
        artifacts = runner.artifacts_for(report)
        _require(report.status == report.compatibility_status == "pass"
                 and report.authority_invariant_evidence_sha256 is not None
                 and report.authority_violation_count == 0, ErrorCode.INELIGIBLE_POLICY)
        rows = {row.family: row for row in report.route_rows if row.route == "C"}
        families = tuple(FamilyMetrics(family_id=family, task_count=rows[family].success.assigned_count,
            observed_count=rows[family].success.observed_count,
            missing_count=rows[family].success.assigned_count - rows[family].success.observed_count,
            metrics=(MetricInterval(metric_id="success", numerator=rows[family].success.success_count,
                denominator=rows[family].success.assigned_count,
                lower=rows[family].success.wilson95_lower, upper=rows[family].success.wilson95_upper),))
            for family in ("extraction", "evidence_qa", "transformation"))
        evaluation = EvaluationRecord(evaluation_id="evaluation-" + digest(authorization)[:32],
            authority_id=authority_id, tuple=record.evidence, mode="simulation",
            authorization_sha256=digest(authorization), budget_authority_id=authority_id,
            budget_reference_sha256=authorization.budget_reference_sha256,
            task_count=report.task_count, attempt_count=report.attempt_count,
            observed_count=rows[None].success.observed_count,
            missing_count=rows[None].success.assigned_count - rows[None].success.observed_count,
            artifact_manifest_sha256=report.artifact_manifest_sha256, families=families,
            status=report.status, frozen_utc=report.frozen_utc, expires_utc=report.expires_utc)
        payload = ApprovalPayload(decision_id="approve-" + digest(evaluation)[:32], authority_id=authority_id,
            decision="approve", tuple=record.evidence, evaluation_sha256=digest(evaluation),
            artifact_manifest_sha256=report.artifact_manifest_sha256, target_approval_sha256=None,
            signer_fingerprint_sha256=context.signer.fingerprint_sha256,
            declared_os_account=context.signer.declared_os_account, recorded_utc=context.clock(),
            reason="automated synthetic compatibility demonstration")
        approval = context.signer.sign_approval(payload, confirmed_tuple_sha256=confirmation_digest(payload))
        return DemoPolicyEvidence(record.bundle, authorization, report, evaluation, approval, artifacts)

    def claimed_attempt_count() -> int:
        with context.guard.hold(authority_id):
            count, cursor = 0, None
            while True:
                page = context.ledger.recovery_candidates(authority_id, cursor=cursor, limit=1024)
                count += sum(attempt.attempt_id is not None for item in page.items for attempt in item.attempts)
                if page.next_cursor is None:
                    return count
                _require(cursor is None or page.next_cursor > cursor, ErrorCode.INVALID_EVIDENCE)
                cursor = page.next_cursor

    def shadow(request: GatewayRequest, reply: GatewayReply):
        with context.guard.hold(authority_id):
            _require(reply.result is not None and reply.operation_id is not None, ErrorCode.MISSING_EVIDENCE)
            snapshot = context.policies.operation_snapshot(reply.operation_id)
            _require(snapshot is not None, ErrorCode.MISSING_EVIDENCE)
            candidate = configured_record(next(p.policy_sha256 for p in plans if p.name == "candidate"))
            trusted = context.contexts(digest(candidate.bundle))
            liabilities = []
            for target in candidate.bundle.targets:
                adapter = context.controller.planner.adapters[target.target_id]
                envelope = adapter.serialize(request)
                liabilities.append(LiabilityEvidence(target_id=target.target_id,
                    maximum_liability_usd=context.ledger.reserve_for(envelope),
                    price_sha256=envelope.price_sha256, bound_sha256=envelope.bound_sha256,
                    expires_utc=adapter.capability_profile().expires_utc))
            shadow_context = ShadowContext(operation_id=reply.operation_id,
                approved_bundle_sha256=snapshot.permit.policy_bundle_sha256,
                served_target_id=snapshot.permit.attempt_children[0].target_id,
                observed_result_ref=reply.operation_id,
                eligible_target_ids=tuple(target.target_id for target in candidate.bundle.targets),
                target_liabilities=tuple(liabilities), observed_utc=trusted.observed_utc,
                candidate_evidence_expires_utc=min(d.expires_utc for d in trusted.dependency_expiries))
            return evaluate_local(request_features(request), candidate.bundle, context=shadow_context)

    return DemoServices(operator, evaluate_and_sign, controller_request(context.controller, caller=caller),
                        original_request, boundary_request, shadow, claimed_attempt_count)


def _config_shape(value, keys: set[str]) -> None:
    _require(type(value) is dict and set(value) == keys, ErrorCode.INVALID_EVIDENCE)


def _load_demo_configuration(path: Path):
    """One bounded nonsecret simulation recipe, not a general config platform.

    Identities are computed from actual declared content and frozen development
    source. This prepares configuration, never evaluation/pass/approval evidence.
    """
    from .evaluation.dataset import load_development
    from .shared.s3.callledger.models import canonical_digest
    from .shared.s3.callledger.pricing import PricePolicy, PriceProvenance
    _require(path.is_absolute() and not str(path).startswith(("\\\\", "//")),
             ErrorCode.UNSAFE_RUNTIME_PATH)
    require_local_runtime_root(path.parent)
    info = path.lstat()
    _require(stat.S_ISREG(info.st_mode) and not path.is_symlink()
             and not (getattr(info, "st_file_attributes", 0) & 0x400)
             and 0 < info.st_size <= 2097152, ErrorCode.INVALID_EVIDENCE)

    def unique(pairs):
        result = {}
        for key, value in pairs:
            _require(key not in result, ErrorCode.INVALID_EVIDENCE)
            result[key] = value
        return result

    with path.open("rb") as source:
        config_bytes = source.read(2097153)
    _require(0 < len(config_bytes) <= 2097152, ErrorCode.INVALID_EVIDENCE)
    raw = json.loads(config_bytes, object_pairs_hook=unique,
                     parse_constant=lambda _: _require(False, ErrorCode.INVALID_EVIDENCE))
    _config_shape(raw, {"schema_version", "mode", "runtime_root", "authority_id", "created_utc",
        "deadline_utc", "cap_usd", "max_outbound_attempts", "caller_id", "development_directory",
        "prices", "bootstrap_seed", "serving_max_attempts", "acquisition_max_attempts", "plans",
        "evaluation_authorization_maxima_usd",
        "clock_max_drift_microseconds", "clock_max_startup_advance_seconds", "original", "boundary"})
    _require(type(raw["schema_version"]) is int and raw["schema_version"] == 1
             and raw["mode"] == "simulation" and raw["development_directory"] == "fixtures/tasks/dev")
    _require(type(raw["serving_max_attempts"]) is int and raw["serving_max_attempts"] == 2
             and type(raw["acquisition_max_attempts"]) is int and raw["acquisition_max_attempts"] == 1)
    for key in ("clock_max_drift_microseconds", "clock_max_startup_advance_seconds", "bootstrap_seed"):
        _require(type(raw[key]) is int and raw[key] >= 0)
    _config_shape(raw["plans"], {"baseline", "candidate"})
    _config_shape(raw["plans"]["baseline"], {"fallback_target", "boundary_target", "boundary_output_tokens_gt"})
    _config_shape(raw["plans"]["candidate"], {"fallback_target"})
    _config_shape(raw["evaluation_authorization_maxima_usd"],
                  {"baseline", "candidate", "acquire-B0", "acquire-B1"})
    _require(all(type(value) is str for value in raw["evaluation_authorization_maxima_usd"].values()))
    _require(raw["plans"]["baseline"]["fallback_target"] == "B0"
             and raw["plans"]["baseline"]["boundary_target"] == "B1"
             and raw["plans"]["candidate"]["fallback_target"] == "B1")
    threshold = raw["plans"]["baseline"]["boundary_output_tokens_gt"]
    _require(type(threshold) is int and 1 <= threshold < 1024)
    created, deadline = _read_stamp(raw["created_utc"]), _read_stamp(raw["deadline_utc"])
    product = Path(__file__).resolve(strict=True).parents[2]
    manifest, tasks = load_development(product / raw["development_directory"])
    _require(all(task.route_alias == "default" and task.max_completion_tokens <= threshold for task in tasks))
    _require(type(raw["prices"]) is list and len(raw["prices"]) == 2)
    policies = []
    for row in raw["prices"]:
        _config_shape(row, {"provider", "model", "input_usd_per_million", "output_usd_per_million", "fee_usd"})
        _require((row["provider"], row["model"]) in {
            ("openai", "mock-openai-v1"), ("anthropic", "mock-anthropic-v1")})
        _require(all(type(row[key]) is str for key in
                     ("input_usd_per_million", "output_usd_per_million", "fee_usd")))
        policies.append(PricePolicy(schema_version=1, provider=row["provider"], model=row["model"],
            context_sha256=digest({"schema_version": 1, "kind": "explicit-synthetic-cli-price", **row}),
            cache_mode="flat_inclusive", input_usd_per_million=row["input_usd_per_million"],
            output_usd_per_million=row["output_usd_per_million"], fee_usd=row["fee_usd"],
            cache_read_usd_per_million=None, cache_write_usd_per_million=None))
    snapshot = PriceSnapshot(schema_version=1,
        provenance=PriceProvenance(origin="synthetic", source_url=None, retrieved_at=_stamp(created),
            official_verified_at=None, source_commit=None), policies=policies,
        data_sha256=canonical_digest([item.model_dump(mode="json") for item in policies]))
    _require(type(raw["cap_usd"]) is str)
    configuration = synthetic_configuration(authority_id=raw["authority_id"], cap_usd=Decimal(raw["cap_usd"]),
        run_deadline_utc=deadline, max_outbound_attempts=raw["max_outbound_attempts"], price_snapshot=snapshot)
    code_paths = ("src/gateway/bootstrap.py", "src/gateway/evaluation/scoring.py",
        "src/gateway/evaluation/dataset.py", "src/gateway/evaluation/diagnostics.py",
        "src/gateway/evaluation/artifacts.py", "src/gateway/evaluation/observations.py",
        "src/gateway/shadow/evaluator.py")
    code_hash = digest({"schema_version": 1, "source_files": tuple({"path": name,
        "sha256": hashlib.sha256((product / name).read_bytes()).hexdigest()} for name in code_paths)})
    feature_hash = digest(RequestFeatures.model_json_schema())
    metric_hash = digest({"schema_version": 1, "kind": "synthetic-development-exact-match",
        "matching_rules_sha256": manifest.matching_rules_sha256, "intervals": "wilson95-and-paired-task-bootstrap95",
        "resamples": 10000, "family_weighting": "equal", "benefit": "unmeasured"})
    spec = EvaluationSpec(spec_id="explicit-simulation-cli", version=1, evaluator_code_sha256=code_hash,
        corpus_sha256=digest(manifest), metric_sha256=metric_hash,
        adapter_capability_sha256=profile_manifest_digest(configuration.profiles),
        adapter_sha256=adapter_manifest_digest(configuration.profiles), price_sha256=snapshot.snapshot_sha256,
        bound_sha256=configuration.bound_bundle_sha256, feature_schema_sha256=feature_hash, mode="simulation",
        matching_rules_sha256=manifest.matching_rules_sha256, freshness_seconds=86400,
        bootstrap_seed=raw["bootstrap_seed"], confidence_level=Decimal("0.95"),
        noninferiority_tolerance=Decimal("0.05"), benefit_metric_id="synthetic_quality_unmeasured_benefit",
        template_split_sha256=manifest.template_split_sha256, created_utc=created, expires_utc=deadline)
    targets = tuple(PolicyTarget(target_id="B0" if profile.provider == "openai" else "B1",
        provider=profile.provider, exact_model=profile.exact_model, api_version=profile.api_version,
        capability_sha256=profile.capability_sha256, adapter_sha256=profile.adapter_sha256)
        for profile in configuration.profiles)
    bundles = []
    for name, target, attempts, rules in (
        ("baseline", "B0", raw["serving_max_attempts"], (PolicyRule(rule_id="declared-boundary-route",
            feature="max_completion_tokens", operator="gt", operand=threshold, target_id="B1"),)),
        ("candidate", "B1", raw["serving_max_attempts"], ()),
        ("acquire-B0", "B0", raw["acquisition_max_attempts"], ()),
        ("acquire-B1", "B1", raw["acquisition_max_attempts"], ()),
    ):
        bundles.append(PolicyBundle(policy_id="explicit-simulation-" + name, version=1,
            route_aliases=("default",), targets=targets, rules=rules, fallback_target_id=target,
            max_attempts_total=attempts, operation_timeout_seconds=60, attempt_timeout_seconds=30,
            max_backoff_milliseconds=0, price_sha256=snapshot.snapshot_sha256,
            bound_bundle_sha256=configuration.bound_bundle_sha256, eval_spec_sha256=digest(spec),
            feature_schema_sha256=feature_hash, expires_utc=deadline))
    records = []
    dependencies = {"policy": "policy_bundle_sha256", "eval_spec": "eval_spec_sha256",
        "evaluator_code": "evaluator_code_sha256", "corpus": "corpus_sha256", "metric": "metric_sha256",
        "adapter_capability": "adapter_capability_sha256", "adapter": "adapter_sha256",
        "price": "price_sha256", "bound": "bound_sha256", "feature_schema": "feature_schema_sha256"}
    for bundle in bundles:
        evidence = EvidenceTuple(policy_bundle_sha256=digest(bundle), eval_spec_sha256=digest(spec),
            evaluator_code_sha256=code_hash, corpus_sha256=digest(manifest), metric_sha256=metric_hash,
            adapter_capability_sha256=spec.adapter_capability_sha256, adapter_sha256=spec.adapter_sha256,
            price_sha256=spec.price_sha256, bound_sha256=spec.bound_sha256, feature_schema_sha256=feature_hash)
        records.append(RuntimeEvidenceRecord(bundle, evidence, tuple(DependencyExpiry(
            dependency=name, sha256=getattr(evidence, field), expires_utc=deadline)
            for name, field in dependencies.items()), 86400))
    caller = CallerContext(authority_id=raw["authority_id"], caller_id=raw["caller_id"])
    runtime_spec = MockRuntimeSpec(runtime_root=Path(raw["runtime_root"]), authority_id=caller.authority_id,
        created_utc=created, deadline_utc=deadline, cap_usd=Decimal(raw["cap_usd"]),
        max_outbound_attempts=raw["max_outbound_attempts"], price_snapshot=snapshot,
        records=tuple(records), evaluation_specs=(spec,), migration_path=product / "migrations/001_governance.sql",
        migration_sha256=hashlib.sha256((product / "migrations/001_governance.sql").read_bytes()).hexdigest(),
        # Generated only when the explicit future CLI is invoked. No secret file
        # reads, provider keys, printed bearer token, or existing-store rotation.
        replay_key=os.urandom(32), key_digest_secret=os.urandom(32),
        clients=((hashlib.sha256(os.urandom(32)).hexdigest(), caller),),
        max_clock_drift=timedelta(microseconds=raw["clock_max_drift_microseconds"]),
        max_clock_startup_advance=timedelta(seconds=raw["clock_max_startup_advance_seconds"]))
    maxima = tuple((digest(bundle), Decimal(raw["evaluation_authorization_maxima_usd"][name]))
                   for name, bundle in zip(("baseline", "candidate", "acquire-B0", "acquire-B1"), bundles))
    plans = tuple(DemoEvaluationPlan(name, digest(bundles[i]), (digest(bundles[2]), digest(bundles[3])),
        manifest, tasks, maxima) for i, name in enumerate(("baseline", "candidate")))
    for name in ("original", "boundary"):
        _config_shape(raw[name], {"idempotency_key", "body"})
        ChatCompletionInput.model_validate_json(canonical_bytes(raw[name]["body"]))
    return runtime_spec, plans, raw["original"], raw["boundary"], caller


def main(argv=None) -> int:
    """Explicit source entrypoint: python -m gateway.bootstrap --config PATH --initialize."""
    import argparse
    import sys
    from .cli.demo import main as demo_main
    parser = argparse.ArgumentParser(description="Explicit no-key simulation; source/runtime acceptance unverified")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--initialize", action="store_true")
    args = parser.parse_args(argv)
    context = None
    try:
        spec, plans, original, boundary, caller = _load_demo_configuration(args.config)
        context = build_mock_context(spec, initialize=args.initialize)

        def request(value) -> GatewayRequest:
            body = ChatCompletionInput.model_validate_json(canonical_bytes(value["body"]))
            return GatewayRequest(authority_id=caller.authority_id, caller_id=caller.caller_id,
                idempotency_key=value["idempotency_key"], route_alias=body.model, messages=body.messages,
                max_completion_tokens=body.max_completion_tokens,
                request_sha256=request_digest(route_alias=body.model, messages=body.messages,
                                               max_completion_tokens=body.max_completion_tokens),
                deadline_utc=min(context.clock() + timedelta(seconds=60), spec.deadline_utc))

        services = build_demo_services(context, plans=plans, original_request=request(original),
                                        boundary_request=request(boundary))
        return demo_main([], services=services)
    except GatewayError as error:
        sys.stderr.write(canonical_bytes({"error": error.code.value}).decode("utf-8") + "\n")
        return 2
    except (OSError, ValueError, TypeError, KeyError, AttributeError, ImportError):
        sys.stderr.write('{"error":"invalid_evidence"}\n')
        return 2
    finally:
        if context is not None:
            context.close()


if __name__ == "__main__":
    raise SystemExit(main())

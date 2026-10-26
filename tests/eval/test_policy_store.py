"""Direct SQLite governance consumers with explicit trusted unit doubles.

These tests supply synthetic signed evaluation records to isolate PolicyStore
transactions. They do NOT execute acquisition, certify a real evaluation pass,
or replace the full bootstrap/controller journey. No transport is reachable.
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import json
import os
from pathlib import Path
import sqlite3
from types import SimpleNamespace
import uuid

import pytest

from gateway.accounting.synthetic import synthetic_configuration
from gateway.bootstrap import _load_demo_configuration
from gateway.cli.signing import confirmation_digest
from gateway.cli.simulation import create_simulation_signer
from gateway.controller.authority_lock import AuthorityLock
from gateway.policies.store import PolicyStore, utc_text
from gateway.schemas import (ApprovalPayload, EligibilityContext, EvaluationAuthorizationPayload,
    EvaluationRecord, FamilyMetrics, GatewayError, IncidentEvidence, digest)

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def store_case(monkeypatch):
    root = Path(os.environ.get("M8_TEST_RUNTIME_PARENT", "C:/agent-runtime/m8-r03-rv2")) / ("store-" + uuid.uuid4().hex)
    root.mkdir(parents=True, exist_ok=False)
    now = datetime.now(timezone.utc)
    raw = json.loads((ROOT / "fixtures/bootstrap/simulation.example.json").read_text())
    raw.update(runtime_root=str(root), authority_id="rv2-store-" + uuid.uuid4().hex,
               created_utc=(now - timedelta(minutes=1)).isoformat(),
               deadline_utc=(now + timedelta(hours=1)).isoformat())
    path = root / "unit-simulation.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    spec, *_ = _load_demo_configuration(path)
    config = synthetic_configuration(authority_id=spec.authority_id, cap_usd=spec.cap_usd,
        run_deadline_utc=spec.deadline_utc, max_outbound_attempts=spec.max_outbound_attempts,
        price_snapshot=spec.price_snapshot)
    signer = create_simulation_signer(allowed_evidence=tuple(r.evidence for r in spec.records))
    guard = AuthorityLock(root)
    def clock():
        return datetime.now(timezone.utc)

    records = {digest(r.bundle): r for r in spec.records}

    def context(key):
        record = records[key]
        return EligibilityContext(authority_id=spec.authority_id, mode="simulation",
            tuple=record.evidence, dependency_expiries=record.dependency_expiries,
            evaluation_max_age_seconds=record.evaluation_max_age_seconds,
            observed_utc=clock(), clock_evidence_sha256=digest("unit-clock-not-bootstrap"))

    def opened():
        store = PolicyStore(root / "unit-policy.sqlite3", authority_id=spec.authority_id,
            verification_key=signer.public_key_bytes,
            authority_lock=lambda: guard.hold(spec.authority_id), clock=clock)
        store.bind_runtime(context_loader=context, ledger_reader=lambda _: None,
            key_digest=lambda request: request.idempotency_key,
            assert_lock_held=lambda: guard.assert_held(authority_id=spec.authority_id),
            profile_loader=lambda _: config.profiles, incident_reader=lambda _: None)
        return store

    store = opened()
    with sqlite3.connect(root / "unit-policy.sqlite3") as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.executescript(spec.migration_path.read_text())
        db.execute("INSERT INTO authority_state(authority_id,config_sha256,max_observed_utc) VALUES(?,?,?)",
                   (spec.authority_id, store._config_sha256, utc_text(now)))
    monkeypatch.setenv("GATEWAY_RUNTIME_ROOT", str(root))

    def approved(index):
        record = spec.records[index]
        store.freeze(record.bundle)
        payload = EvaluationAuthorizationPayload(authorization_id="unit-authorization-" + str(index),
            authority_id=spec.authority_id, mode="simulation", tuple=record.evidence,
            budget_authority_id=spec.authority_id, budget_reference_sha256=digest("unit-no-ledger"),
            maximum_liability_usd="0.245760", created_utc=now, expires_utc=spec.deadline_utc,
            nonce="unit-nonce-" + str(index), declared_os_account=signer.declared_os_account,
            signer_fingerprint_sha256=signer.fingerprint_sha256)
        authorization = signer.sign_evaluation_authorization(payload, confirmed_tuple_sha256=confirmation_digest(payload))
        store.authorize_evaluation(authorization)
        evaluation = EvaluationRecord(evaluation_id="unit-double-not-acquired-" + str(index),
            authority_id=spec.authority_id, tuple=record.evidence, mode="simulation",
            authorization_sha256=digest(authorization), budget_authority_id=spec.authority_id,
            budget_reference_sha256=authorization.budget_reference_sha256, task_count=60,
            attempt_count=0, observed_count=60, missing_count=0,
            artifact_manifest_sha256=digest(["unit-double-not-runtime-evidence", index]),
            families=tuple(FamilyMetrics(family_id=family, task_count=20, observed_count=20,
                missing_count=0, metrics=()) for family in ("extraction", "evidence_qa", "transformation")),
            status="pass", frozen_utc=now, expires_utc=spec.deadline_utc)
        store.record_evaluation(evaluation)
        approval_payload = ApprovalPayload(decision_id="unit-approval-" + str(index),
            authority_id=spec.authority_id, decision="approve", tuple=record.evidence,
            evaluation_sha256=digest(evaluation), artifact_manifest_sha256=evaluation.artifact_manifest_sha256,
            target_approval_sha256=None, signer_fingerprint_sha256=signer.fingerprint_sha256,
            declared_os_account=signer.declared_os_account, recorded_utc=clock(),
            reason="isolated unit fixture no acquisition evidence")
        approval = signer.sign_approval(approval_payload, confirmed_tuple_sha256=confirmation_digest(approval_payload))
        return store.verify_approval(approval), record

    return SimpleNamespace(store=store, opened=opened, approved=approved, context=context,
                           root=root, spec=spec, clock=clock)


def test_store_generation_cas_and_eligible_rollback(store_case):
    case = store_case
    first, baseline = case.approved(0)
    second, candidate = case.approved(1)
    assert case.store.active() is None

    def compete(_):
        try:
            return case.store.activate(first, expected_generation=0, context=case.context(digest(baseline.bundle))).generation
        except GatewayError as error:
            return error.code.value

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(compete, range(2)))
    assert results.count(1) == results.count("generation_conflict") == 1
    with pytest.raises(GatewayError):
        case.store.rollback(second, expected_generation=1, context=case.context(digest(candidate.bundle)), reason="never active")
    active = case.store.activate(second, expected_generation=1, context=case.context(digest(candidate.bundle)))
    assert active.generation == 2
    with pytest.raises(GatewayError):
        case.store.rollback(first, expected_generation=2, context=case.context(digest(candidate.bundle)), reason="wrong tuple")
    restored = case.store.rollback(first, expected_generation=2,
        context=case.context(digest(baseline.bundle)), reason="unit rollback")
    assert restored.generation == 3 and restored.policy_bundle_sha256 == digest(baseline.bundle)
    assert case.opened().active().generation == 3
    with sqlite3.connect(case.root / "unit-policy.sqlite3") as db:
        assert db.execute("SELECT event_kind FROM activation_events ORDER BY generation").fetchall() == [
            ("activate",), ("activate",), ("rollback",)]
        assert db.execute("PRAGMA foreign_key_check").fetchall() == []


def test_store_stop_and_incident_halt_survive_reopen(store_case):
    case = store_case
    assert case.store.set_emergency_stop(True, reason="unit stop").emergency_stop
    assert case.opened().status().emergency_stop
    halted = case.store.halt(reason_code="bound_breach", evidence_sha256=digest("unit breach"))
    assert halted.incident_halt
    case.store.set_emergency_stop(False, reason="unit resume stop only")
    reopened = case.opened().status()
    assert reopened.incident_halt and not reopened.emergency_stop
    assert "bound_breach" in reopened.reason_codes


def test_store_untrusted_incident_quarantined_idempotently(store_case):
    case = store_case
    evidence = IncidentEvidence(authority_id=case.spec.authority_id,
        operation_id="no-ledger-operation", child_id="no-ledger-child", attempt_id="no-ledger-attempt",
        provider="openai", source_sha256=digest("untrusted-source"), observed_cost_usd="0.15",
        reserved_usd="0.10", terminal_unknown_usd="0.10", authenticated=False,
        conflict=False, reason_code="unauthenticated_evidence", recorded_utc=case.clock())
    first = case.store.append_incident(evidence)
    second = case.store.append_incident(evidence)
    assert first.conflict and second.conflict
    assert first.maximum_credible_usd is None and second.maximum_credible_usd is None
    assert first.uncovered_excess_usd == second.uncovered_excess_usd == Decimal(0)
    assert case.opened().status().incident_halt
    with sqlite3.connect(case.root / "unit-policy.sqlite3") as db:
        assert db.execute("SELECT COUNT(*) FROM incident_evidence").fetchone() == (1,)

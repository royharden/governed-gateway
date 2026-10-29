"""Actual controller/evaluation/policy/replay journey plus independent SQLite reads."""
import asyncio
from dataclasses import replace
from datetime import timedelta
from decimal import Decimal
from io import StringIO
import os
from pathlib import Path
import sqlite3

import pytest

from gateway.bootstrap import _load_demo_configuration, build_demo_services, build_mock_context
from gateway.cli.demo import run_demo
from gateway.cli.simulation import create_simulation_signer
from gateway.evaluation.reporting import evaluation_json
from gateway.schemas import ChatCompletionInput, GatewayError, GatewayRequest, canonical_bytes, request_digest


def test_sqlite_packaged_journey_and_reopen():
    config_path = os.environ.get("M8_DOCKER_CONFIG")
    if config_path is None:
        pytest.skip("requires explicit Docker runtime config; use docker/run_sqlite_e2e.py")
    spec, plans, original, boundary, caller = _load_demo_configuration(Path(config_path))
    signer = create_simulation_signer(allowed_evidence=tuple(r.evidence for r in spec.records))
    context = build_mock_context(spec, initialize=True, signer=signer)

    def request(value):
        body = ChatCompletionInput.model_validate_json(canonical_bytes(value["body"]))
        return GatewayRequest(authority_id=caller.authority_id, caller_id=caller.caller_id,
            idempotency_key=value["idempotency_key"], route_alias=body.model, messages=body.messages,
            max_completion_tokens=body.max_completion_tokens,
            request_sha256=request_digest(route_alias=body.model, messages=body.messages,
                                          max_completion_tokens=body.max_completion_tokens),
            deadline_utc=min(context.clock() + timedelta(seconds=60), spec.deadline_utc))

    reports = []
    try:
        services = build_demo_services(context, plans=plans, original_request=request(original),
                                      boundary_request=request(boundary))
        evaluate = services.evaluate_and_sign

        async def record_report(name):
            evidence = await evaluate(name)
            reports.append(evidence.report)
            (spec.runtime_root / (name + "-evaluation.json")).write_text(
                evaluation_json(evidence.report, artifacts=evidence.artifacts), encoding="utf-8")
            return evidence

        services = replace(services, evaluate_and_sign=record_report)
        output = StringIO()
        asyncio.run(run_demo(services, output=output))
        text = output.getvalue()
        (spec.runtime_root / "journey.log").write_text(text, encoding="utf-8")
        assert "Original retained result replayed" in text
        assert "Boundary request rejected for budget" in text
        assert "stale CAS rejected" in text
        assert len(reports) == 2 and all(r.task_count == 60 and r.attempt_count == 120 for r in reports)
        assert all(r.synthetic and r.mode == "simulation" for r in reports)
        assert services.dispatched_attempt_count() == 241
        totals = services.operator.overview().accounting
        assert totals.cap_usd == Decimal("0.004500")
        assert totals.known_usd == Decimal("0.001444")
        assert totals.future_usd == totals.active_usd == totals.unknown_usd == 0
    finally:
        context.close()

    # Real database file, FK/integrity checks and durable generations independently
    # of the application's success flag; no production DB cleanup or DROP.
    with sqlite3.connect(f"file:{spec.runtime_root / 'policy.sqlite3'}?mode=ro", uri=True) as db:
        assert db.execute("PRAGMA integrity_check").fetchall() == [("ok",)]
        assert db.execute("PRAGMA foreign_key_check").fetchall() == []
        assert db.execute("SELECT generation FROM authority_state").fetchall() == [(3,)]
        assert db.execute("SELECT event_kind FROM activation_events ORDER BY generation").fetchall() == [
            ("activate",), ("activate",), ("rollback",)]
    with sqlite3.connect(f"file:{spec.runtime_root / 'accounting.sqlite3'}?mode=ro", uri=True) as db:
        assert db.execute("PRAGMA integrity_check").fetchall() == [("ok",)]
        assert db.execute("SELECT COUNT(*) FROM attempts").fetchone() == (241,)
        assert db.execute("SELECT COUNT(*) FROM authorities").fetchone() == (1,)

    # Reopen with retained in-memory identity verifies durable continuity; a new
    # process with lost keys is deliberately not claimed as supported recovery.
    reopened = build_mock_context(spec, initialize=False, signer=signer)
    try:
        with reopened.guard.hold(spec.authority_id):
            assert reopened.ledger.totals(authority_id=spec.authority_id) == totals
    finally:
        reopened.close()
    with pytest.raises(GatewayError):
        build_mock_context(replace(spec, cap_usd=Decimal("0.005000")), initialize=False, signer=signer)

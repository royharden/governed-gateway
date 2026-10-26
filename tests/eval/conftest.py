"""Independent, synthetic development-only fixtures; never opens a secret file."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import json
import os
import uuid

import pytest

from gateway.bootstrap import _load_demo_configuration
from gateway.cli.signing import confirmation_digest
from gateway.cli.simulation import create_simulation_signer
from gateway.evaluation.dataset import load_development
from gateway.evaluation.scoring import EvalRunner
from gateway.schemas import EvaluationAuthorizationPayload, digest
from gateway.schemas.operator import AcquisitionReceipt
from gateway.shadow.evaluator import recommend_target

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session")
def evaluation_case():
    # Fresh authority, chosen before execution; preserve every store/config after
    # the run. Never extend/reopen the expired example or change its cap/quota.
    parent = Path(os.environ.get("M8_TEST_RUNTIME_PARENT", "C:/agent-runtime/m8-r03-rv2"))
    runtime = parent / ("eval-" + uuid.uuid4().hex)
    runtime.mkdir(parents=True, exist_ok=False)
    now = datetime.now(timezone.utc)
    raw = json.loads((ROOT / "fixtures/bootstrap/simulation.example.json").read_text())
    raw.update(runtime_root=str(runtime), authority_id="rv2-" + uuid.uuid4().hex,
               created_utc=(now - timedelta(minutes=1)).isoformat(),
               deadline_utc=(now + timedelta(hours=1)).isoformat())
    config = runtime / "simulation.json"
    config.write_text(json.dumps(raw), encoding="utf-8")
    runtime_spec, plans, *_ = _load_demo_configuration(config)
    manifest, tasks = load_development(ROOT / "fixtures/tasks/dev")
    record = runtime_spec.records[1]  # candidate selects B1
    spec = runtime_spec.evaluation_specs[0]
    signer = create_simulation_signer(allowed_evidence=(record.evidence,))
    payload = EvaluationAuthorizationPayload(
        authorization_id="rv2-public-dev", authority_id=raw["authority_id"],
        budget_authority_id=raw["authority_id"], budget_reference_sha256=digest(raw),
        maximum_liability_usd="0.245760", mode="simulation", tuple=record.evidence,
        created_utc=now - timedelta(seconds=1), expires_utc=spec.expires_utc,
        nonce="rv2-public-dev-nonce", declared_os_account=signer.declared_os_account,
        signer_fingerprint_sha256=signer.fingerprint_sha256)
    auth = signer.sign_evaluation_authorization(payload, confirmed_tuple_sha256=confirmation_digest(payload))
    expectations = {target.target_id: dict(exact_model=target.exact_model,
        profile_sha256=target.capability_sha256, adapter_sha256=target.adapter_sha256,
        price_sha256=spec.price_sha256, bound_sha256=spec.bound_sha256) for target in record.bundle.targets}

    def runner(**overrides):
        settings = dict(tasks=tasks, baseline_target_id="B0", second_target_id="B1",
            candidate=record.bundle, provenance_expectations=expectations,
            selector=lambda features, policy: recommend_target(features, policy)[0],
            authorization=auth, verify_authorization=lambda value: digest(auth) if value == auth else None,
            verified_spec_sha256=digest(spec), evaluator_code_sha256=spec.evaluator_code_sha256,
            frozen_utc=now, report_id="rv2-independent-development")
        settings.update(overrides)
        return EvalRunner(**settings)

    receipts = tuple(AcquisitionReceipt(acquisition_id=f"rv2-{task.task_id}-{target}",
        task_id=task.task_id, target_id=target, request_sha256=task.request_sha256(),
        parameters_sha256=task.parameters_sha256(), **expectations[target],
        outcome_status="ok", response_ref=f"response-{task.task_id}-{target}",
        response_text=task.expected_answers[0], provider_receipt_sha256=digest([task.task_id, target]),
        mode="simulation", synthetic=True, reused=False, reuse_source_sha256=None,
        original_acquisition_cost_usd="0.000004", current_reuse_cost_usd=None,
        known_cost_usd="0.000004", retained_liability_usd="0", attempt_count=1,
        latency_ms="1", acquired_utc=now - timedelta(seconds=1))
        for task in tasks for target in ("B0", "B1"))
    return dict(runner=runner, spec=spec, manifest=manifest, tasks=tasks, receipts=receipts,
                now=now, runtime=runtime, config=config, runtime_spec=runtime_spec, plans=plans)

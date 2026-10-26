"""Independent, synthetic development-only fixtures; never opens a secret file."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import os
from types import SimpleNamespace
import uuid

import pytest

from gateway.cli.signing import confirmation_digest
from gateway.cli.simulation import create_simulation_signer
from gateway.evaluation.dataset import load_development
from gateway.evaluation.scoring import EvalRunner
from gateway.schemas import EvaluationAuthorizationPayload, EvidenceTuple, PolicyBundle, PolicyTarget, digest
from gateway.schemas.operator import AcquisitionReceipt, EvaluationSpec
from gateway.shadow.evaluator import recommend_target

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session")
def evaluation_case():
    # Pure scoring fixtures have no DB, adapter, bootstrap or network capability.
    # Dependencies below are explicit synthetic unit-test identities, never
    # evidence of executing production authorities. Docker covers real bootstrap.
    parent = Path(os.environ.get("M8_TEST_RUNTIME_PARENT", "C:/agent-runtime/m8-r03-rv2"))
    runtime = parent / ("eval-" + uuid.uuid4().hex)
    runtime.mkdir(parents=True, exist_ok=False)
    now = datetime.now(timezone.utc)
    manifest, tasks = load_development(ROOT / "fixtures/tasks/dev")
    def identity(name):
        return digest({"kind": "rv2-public-unit-fixture", "name": name})

    expiry = now + timedelta(hours=1)
    targets = tuple(PolicyTarget(target_id=target, provider=provider, exact_model=model,
        api_version="synthetic-v1", capability_sha256=identity(target + "-profile"),
        adapter_sha256=identity(target + "-adapter"))
        for target, provider, model in (("B0", "openai", "mock-openai-v1"),
                                       ("B1", "anthropic", "mock-anthropic-v1")))
    spec = EvaluationSpec(spec_id="rv2-public-unit", version=1,
        evaluator_code_sha256=identity("code"), corpus_sha256=digest(manifest),
        metric_sha256=identity("metric"), adapter_capability_sha256=identity("profiles"),
        adapter_sha256=identity("adapters"), price_sha256=identity("price"),
        bound_sha256=identity("bound"), feature_schema_sha256=identity("features"),
        mode="simulation", matching_rules_sha256=manifest.matching_rules_sha256,
        freshness_seconds=86400, bootstrap_seed=1729, confidence_level="0.95",
        noninferiority_tolerance="0.05", benefit_metric_id="synthetic-unmeasured-benefit",
        template_split_sha256=manifest.template_split_sha256,
        created_utc=now - timedelta(minutes=1), expires_utc=expiry)
    bundle = PolicyBundle(policy_id="rv2-public-unit-candidate", version=1,
        route_aliases=("default",), targets=targets, rules=(), fallback_target_id="B1",
        max_attempts_total=1, operation_timeout_seconds=60, attempt_timeout_seconds=30,
        max_backoff_milliseconds=0, price_sha256=spec.price_sha256,
        bound_bundle_sha256=spec.bound_sha256, eval_spec_sha256=digest(spec),
        feature_schema_sha256=spec.feature_schema_sha256, expires_utc=expiry)
    evidence = EvidenceTuple(policy_bundle_sha256=digest(bundle), eval_spec_sha256=digest(spec),
        evaluator_code_sha256=spec.evaluator_code_sha256, corpus_sha256=digest(manifest),
        metric_sha256=spec.metric_sha256, adapter_capability_sha256=spec.adapter_capability_sha256,
        adapter_sha256=spec.adapter_sha256, price_sha256=spec.price_sha256,
        bound_sha256=spec.bound_sha256, feature_schema_sha256=spec.feature_schema_sha256)
    record = SimpleNamespace(bundle=bundle, evidence=evidence)
    signer = create_simulation_signer(allowed_evidence=(record.evidence,))
    payload = EvaluationAuthorizationPayload(
        authorization_id="rv2-public-dev", authority_id="rv2-public-unit",
        budget_authority_id="rv2-public-unit", budget_reference_sha256=identity("budget"),
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
                now=now, runtime=runtime,
                signer=signer, authorization=auth, record=record)

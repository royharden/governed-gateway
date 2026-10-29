"""Public S3 consumer fixtures: a finite synthetic authority and request witness."""
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import json
import os
from pathlib import Path

from gateway.accounting.synthetic import synthetic_configuration
from gateway.shared.s3.callledger import Ledger
from gateway.shared.s3.callledger import models as m
from gateway.shared.s3.callledger.pricing import PriceSnapshot, RequestEvidence


def configuration(authority_id="m8-test", cap="1"):
    root = Path(os.environ.get("M8_SOURCE_ROOT", Path(__file__).resolve().parents[1])).resolve()
    snapshot = PriceSnapshot.model_validate(json.loads((root / "fixtures/prices/mock-v1.json").read_text()))
    return synthetic_configuration(authority_id=authority_id, cap_usd=Decimal(cap),
        run_deadline_utc=datetime.now(timezone.utc) + timedelta(hours=2), max_outbound_attempts=2048,
        price_snapshot=snapshot)


def open_ledger(path, config, requests=(), *, clock=None, monotonic=None):
    # Freeze both clocks together to isolate transaction invariants from the
    # separate default-clock precision regression. Identical across reopen.
    fixed = datetime.fromisoformat(config.authority.run_deadline_utc.replace("Z", "+00:00")) - timedelta(hours=2)
    return Ledger(path, authority=config.authority, price_snapshot=config.price_snapshot,
        trusted_bounds=config.trusted_bounds, trusted_requests=requests,
        clock=clock or (lambda: fixed), monotonic=monotonic or (lambda: 0.0))


def inputs(config, operation="operation", children=1, run="run"):
    bound = config.trusted_bounds[0]
    policy = next(p for p in config.price_snapshot.policies if p.policy_sha256 == bound.policy_sha256)
    context = m.CallContext(schema_version=1, authority_id=config.authority.authority_id, run_id=run,
        operation_id=operation, child_id="child-0", task_id="synthetic-task", span_id="span", consumer_namespace="m8-tests",
        purpose="serve", consumer_context_sha256="1"*64, policy_sha256="2"*64, template_sha256="3"*64, config_sha256=config.config_sha256)
    child = m.ChildBound(child_id="child-0", purpose="serve", provider_config_sha256=bound.provider_config_sha256,
        model=bound.model, bound_evidence_sha256=bound.evidence_sha256, max_attempts=1, max_repairs=0,
        input_token_maximum=bound.input_token_maximum, output_token_maximum=bound.output_token_maximum,
        fee_maximum_usd=policy.fee_usd, reserved_usd_per_attempt=policy.maximum_cost(bound.input_token_maximum, bound.output_token_maximum),
        request_shape_limit_sha256=bound.request_shape_limit_sha256, conditional=False)
    plan = m.OperationPlan(schema_version=1, authority_id=config.authority.authority_id, operation_id=operation,
        context_sha256=m.canonical_digest(context.model_dump(mode="json")),
        children=[child.model_copy(update={"child_id": f"child-{i}", "conditional": i > 0}) for i in range(children)])
    request = RequestEvidence(schema_version=1, bound_evidence_sha256=bound.evidence_sha256,
        request_identity_sha256="4"*64, dispatched_envelope_sha256="5"*64, input_token_count=8,
        output_token_maximum=4, proof_sha256="6"*64)
    return context, plan, request


def settle(ledger, attempt, context, *, input_tokens=8, output_tokens=4):
    usage = m.NormalizedUsage(input_tokens=input_tokens, output_tokens=output_tokens)
    projection = m.MetadataUsage(input_tokens=input_tokens, output_tokens=output_tokens, details=usage)
    metadata = m.MetadataRecord(schema_version=1, context=context, request_identity_sha256="4"*64,
        usage=projection, usage_projection_sha256=m.canonical_digest(projection.model_dump(mode="json")),
        usage_redacted_fields=False, status="ok", duration_ms=0.0)
    return ledger.settle(attempt, metadata=metadata, usage=usage)


_barrier = None


def race_initialize(barrier):
    global _barrier
    _barrier = barrier


def race_admit(job):
    from gateway.shared.s3.callledger import LedgerError
    config, database, operation, children = job
    context, plan, _ = inputs(config, operation=operation, children=children)
    ledger = open_ledger(Path(database), config)
    try:
        _barrier.wait(timeout=45)
        try:
            ledger.admit_operation(plan, context=context, limits=config.limits, mode="simulation")
            return {"operation": operation, "status": "funded"}
        except LedgerError as error:
            return {"operation": operation, "status": str(error)}
    finally:
        ledger.close()

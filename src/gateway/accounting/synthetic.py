"""Keyless bootstrap declarations. Fixed synthetic capacity is never a live token proof."""
from datetime import datetime
from dataclasses import replace
from decimal import Decimal
from gateway.schemas import CapabilityProfile, ErrorCode, digest
from gateway.shared.s3.callledger import models as s3
from gateway.shared.s3.callledger.pricing import FundingEvidence, PriceSnapshot
from .configuration import LedgerConfiguration
from .errors import AccountingError


def synthetic_configuration(*, authority_id: str, cap_usd: Decimal,
                            run_deadline_utc: datetime, max_outbound_attempts: int,
                            price_snapshot: PriceSnapshot,
                            max_concurrent_operations: int=8) -> LedgerConfiguration:
    """Caller explicitly supplies finite authority lifetime/quota and frozen table.

    No filesystem lookup, wall-clock inference, key access or DB initialization.
    Authorizes simulation configuration only; it cannot authorize live generation.
    """
    if run_deadline_utc.utcoffset() is None or run_deadline_utc.utcoffset().total_seconds()!=0:
        raise AccountingError(ErrorCode.CLOCK_UNTRUSTED)
    if not isinstance(cap_usd,Decimal) or not cap_usd.is_finite() or cap_usd<0:
        raise AccountingError(ErrorCode.INVALID_EVIDENCE)
    snapshot=PriceSnapshot.model_validate(price_snapshot.model_dump(mode="json"))
    if snapshot.provenance.origin!="synthetic" or len(snapshot.policies)!=2:
        raise AccountingError(ErrorCode.UNSUPPORTED_PROFILE)
    if {p.provider for p in snapshot.policies}!={"openai","anthropic"}:
        raise AccountingError(ErrorCode.UNSUPPORTED_PROFILE)
    rows=[]
    for p in snapshot.policies:
        if not p.model.startswith("mock-"):
            raise AccountingError(ErrorCode.UNSUPPORTED_PROFILE)
        capability=digest({"schema_version":1,"simulation_only":True,"provider":p.provider,
            "model":p.model,"max_input_bytes":65536,"max_messages":32,"max_output_tokens":1024})
        bound=FundingEvidence(schema_version=1,snapshot_sha256=snapshot.snapshot_sha256,
            policy_sha256=p.policy_sha256,provider_config_sha256=capability,model=p.model,
            request_shape_limit_sha256=digest({"schema_version":1,"simulation_shape":p.provider}),
            input_token_maximum=65536,output_token_maximum=1024,bound_kind="synthetic_fixture",
            proof_sha256=digest({"schema_version":1,"synthetic_model_capacity":65536,
                "provider":p.provider,"model":p.model}))
        rows.append((p,bound,capability))
    bound_sha=digest({"schema_version":1,"synthetic_bounds":[b.model_dump(mode="json")
        for b in sorted((b for _,b,_ in rows),key=lambda b:b.evidence_sha256)]})
    profiles=tuple(CapabilityProfile(provider=p.provider,exact_model=p.model,api_version="mock-v1",
        mode="simulation",capability_sha256=capability,
        adapter_sha256=digest({"schema_version":1,"synthetic_adapter":p.provider,"api_version":"mock-v1"}),
        price_sha256=snapshot.snapshot_sha256,bound_sha256=bound_sha,max_input_bytes=65536,
        max_messages=32,max_output_tokens=1024,expires_utc=run_deadline_utc,
        supported_billable_components=("input_tokens","output_tokens")) for p,_,capability in rows)
    deadline=run_deadline_utc.isoformat().replace("+00:00","Z")
    authority=s3.BudgetAuthority(schema_version=1,authority_id=authority_id,
        scope_sha256=digest({"schema_version":1,"authority_id":authority_id,"scope":"m8-simulation"}),
        cap_usd=format(cap_usd,"f"),max_outbound_attempts=max_outbound_attempts,
        run_deadline_utc=deadline,expires_at=None)
    limits=s3.Limits(schema_version=1,max_attempts_total=2,max_content_repairs=0,
        operation_deadline_s=60.0,attempt_timeout_s=30.0,run_deadline_utc=deadline,
        max_outbound_attempts=max_outbound_attempts,max_concurrent_operations=max_concurrent_operations,
        max_total_input_tokens=65536,max_state_plus_longest_question_tokens=None,
        max_request_bytes=65536,max_response_bytes=1048576,max_questions=1,
        max_choice_options=1,max_total_output_tokens=1024)
    result=LedgerConfiguration(authority=authority,price_snapshot=snapshot,
        trusted_bounds=tuple(b for _,b,_ in rows),trusted_requests=(),limits=limits,profiles=profiles)
    result=replace(result,authority=authority.model_copy(update={"scope_sha256":result.scope_sha256}))
    result.validate()
    return result
"""Mock-only M8 bridge to the unchanged S3 ledger. No provider dispatch or payload store."""
from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from contextlib import contextmanager
from datetime import datetime
from decimal import Decimal, localcontext
from pathlib import Path

from pydantic import ValidationError
from gateway.schemas import (
    AccountingIncident, AccountingTotals, AttemptReceipt, BudgetAuthority, ChildClosureReceipt,
    DispatchTicket, ErrorCode, FundingReceipt, LedgerJoin, OperationPermit,
    ProviderEnvelope, ProviderResult, ProviderUsage, RecoveryAction, RecoveryEvidence, RecoveryReport,
    SettlementReceipt, UnknownReason, UnstartedProof, canonical_bytes, digest,
    envelope_digest, reserve_up,
)
from gateway.schemas.journey import LedgerAttemptSnapshot, LedgerOperationSnapshot, LedgerRecoveryPage
from gateway.shared.s3.callledger import Ledger, LedgerError
from gateway.shared.s3.callledger import models as s3
from gateway.shared.s3.callledger.pricing import PricePolicy, RequestEvidence
from .configuration import LedgerConfiguration
from .errors import AccountingError, upstream_error
from .mapping import amount, settlement_projection, totals_projection
from .ports import AccountingGate, AuthorityGuard


def _utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _stamp(value: datetime) -> str:
    if value.utcoffset() is None or value.utcoffset().total_seconds() != 0:
        raise AccountingError(ErrorCode.CLOCK_UNTRUSTED)
    return value.isoformat().replace("+00:00", "Z")


def _permit_hash(permit: OperationPermit) -> str:
    return digest(permit)


class LedgerAdapter:
    def __init__(self, *, authority: BudgetAuthority, database_path: Path,
                 guard: AuthorityGuard, gate: AccountingGate,
                 clock: Callable[[], datetime], configuration: LedgerConfiguration) -> None:
        # Constructor is explicit trusted bootstrap, never run at import time.
        self.authority = BudgetAuthority.model_validate_json(canonical_bytes(authority))
        self.guard, self.gate, self.clock = guard, gate, clock
        self.guard.assert_held(authority_id=self.authority.authority_id)
        configuration.validate()
        if (authority.authority_id != configuration.authority.authority_id
            or authority.cap_usd != Decimal(configuration.authority.cap_usd)
            or authority.config_sha256 != configuration.config_sha256):
            raise AccountingError(ErrorCode.AUTHORITY_MISMATCH)
        path = Path(database_path)
        resolved = path.resolve()
        lower = str(resolved).replace("\\", "/").lower()
        if (not path.is_absolute() or str(path).startswith("\\\\") or path.is_symlink()
            or any(x in lower for x in ("onedrive", "/.chatexports/", "/.git/"))
            or not path.parent.is_dir()):
            raise AccountingError(ErrorCode.UNSAFE_RUNTIME_PATH)
        # Copy/revalidate trusted mutable nested upstream containers. No ambient lookup.
        self._base_bounds = tuple(configuration.trusted_bounds)
        self._profiles = tuple(type(p).model_validate_json(canonical_bytes(p)) for p in configuration.profiles)
        self._snapshot = type(configuration.price_snapshot).model_validate(
            configuration.price_snapshot.model_dump(mode="json"))
        self._bounds = {b.evidence_sha256:type(b).model_validate(b.model_dump(mode="json"))
                        for b in configuration.trusted_bounds}
        self._limits = s3.Limits.model_validate(configuration.limits.model_dump(mode="json"))
        self._bound_bundle_sha = configuration.bound_bundle_sha256
        # Process-local provenance only. This never grants funding/dispatch or
        # replaces S3/policy authorities; unknown sources after restart quarantine.
        self._observations: dict[tuple[str,str,str,str], AccountingIncident] = {}
        try:
            self._ledger = Ledger(resolved, authority=configuration.authority,
                price_snapshot=self._snapshot, trusted_bounds=tuple(self._bounds.values()),
                trusted_requests=configuration.trusted_requests, clock=clock)
        except LedgerError as error:
            raise upstream_error(str(error)) from None
        except (sqlite3.Error, OSError):
            raise AccountingError(ErrorCode.STORAGE_UNAVAILABLE) from None

    def close(self) -> None:
        self._ledger.close()

    def _held(self) -> None:
        self.guard.assert_held(authority_id=self.authority.authority_id)

    def _now(self) -> datetime:
        now = self.clock()
        _stamp(now)
        return now

    @contextmanager
    def _read(self):
        self._held()
        try:
            # A read transaction freezes all SELECTs of one projection. This is not
            # a second claim authority and does not use S3 private transaction APIs.
            self._ledger.connection.execute("BEGIN")
            yield self._ledger.connection
            self._ledger.connection.commit()
        except sqlite3.Error:
            self._ledger.connection.rollback()
            raise AccountingError(ErrorCode.STORAGE_UNAVAILABLE) from None
        except BaseException:
            self._ledger.connection.rollback()
            raise

    def _operation(self, connection, operation_id: str):
        return connection.execute("SELECT * FROM operations WHERE authority_id=? AND id=?",
            (self.authority.authority_id,operation_id)).fetchone()

    def _allocation(self, row):
        return s3.Allocation(schema_version=1, allocation_id=row["allocation_id"],
            authority_id=self.authority.authority_id, operation_id=row["id"], plan_sha256=row["plan_sha"])

    def _profile_bound(self, envelope: ProviderEnvelope):
        # Revalidate model_copy bypasses and retain no payload beyond this call.
        envelope = ProviderEnvelope.model_validate_json(canonical_bytes(envelope))
        if envelope_digest(envelope) != envelope.serialized_envelope_sha256:
            raise AccountingError(ErrorCode.INVALID_EVIDENCE)
        profiles=[p for p in self._profiles if (p.provider,p.exact_model,p.api_version,
            p.capability_sha256,p.adapter_sha256,p.price_sha256,p.bound_sha256)==(
            envelope.provider,envelope.model,envelope.api_version,envelope.capability_sha256,
            envelope.adapter_sha256,envelope.price_sha256,envelope.bound_sha256)]
        if len(profiles)!=1 or profiles[0].expires_utc <= self._now():
            raise AccountingError(ErrorCode.UNSUPPORTED_PROFILE)
        p=profiles[0]
        payload=json.loads(envelope.payload_json)
        cap=payload.get("max_completion_tokens" if p.provider=="openai" else "max_tokens")
        if (type(cap) is not int or not 0 < cap <= p.max_output_tokens
            or len(envelope.payload_json.encode("utf-8")) > p.max_input_bytes):
            raise AccountingError(ErrorCode.INVALID_EVIDENCE)
        b=next(b for b in self._base_bounds
               if b.provider_config_sha256==p.capability_sha256 and b.model==p.exact_model)
        policy=next(x for x in self._snapshot.policies if x.policy_sha256==b.policy_sha256)
        return p,b,policy

    def reserve_for(self, envelope: ProviderEnvelope) -> Decimal:
        self._held()
        _,bound,policy=self._profile_bound(envelope)
        return reserve_up(Decimal(policy.maximum_cost(bound.input_token_maximum,bound.output_token_maximum)))

    def price_usage(self, envelope: ProviderEnvelope, usage: ProviderUsage) -> Decimal | None:
        self._held()
        _,_,policy=self._profile_bound(envelope)
        usage=ProviderUsage.model_validate_json(canonical_bytes(usage))
        if not usage.complete or usage.unknown_components:
            return None
        normalized=s3.NormalizedUsage(input_tokens=usage.input_tokens,output_tokens=usage.output_tokens)
        observation=policy.price(normalized,reservation_usd=format(self.reserve_for(envelope),"f"))
        return amount(observation.computed_cost_usd) if observation.status=="known" else None

    def retry_authorized(self, result: ProviderResult, envelope: ProviderEnvelope) -> bool:
        """Only exact synthetic pre-send certainty; hints never prove no-charge."""
        self._held()
        self._profile_bound(envelope)
        result=ProviderResult.model_validate_json(canonical_bytes(result))
        if (result.provider,result.model)!=(envelope.provider,envelope.model):
            raise AccountingError(ErrorCode.INVALID_EVIDENCE)
        return (result.dispatch_state=="not_sent" and result.retry_evidence=="pre_send_certain"
                and result.status=="provider_error" and result.error_code=="pre_send_failure")

    def register_envelope(self, envelope: ProviderEnvelope) -> str:
        """Trusted synthetic evidence registration, no funding/claim/dispatch capability.

        Uses the configured fixed synthetic model capacity, never bytes/token guesses.
        Call before constructing the immutable permit's child request-evidence digest.
        No raw payload or request bodies are persisted by this method.
        """
        self._held()
        _,base,_=self._profile_bound(envelope)
        # Bind a synthetic model-capacity witness to THIS exact request shape.
        # Token maxima/prices stay from trusted configuration; only shape/proof
        # hashes specialize the witness. This is never a live token-bound proof.
        b=type(base).model_validate({**base.model_dump(mode="json"),
            "request_shape_limit_sha256":digest({"schema_version":1,
                "simulation_envelope_sha256":envelope.serialized_envelope_sha256}),
            "proof_sha256":digest({"schema_version":1,"simulation_only":True,
                "base_evidence_sha256":base.evidence_sha256,
                "envelope_sha256":envelope.serialized_envelope_sha256})})
        self._bounds[b.evidence_sha256]=b
        self._ledger.bounds[b.evidence_sha256]=b
        evidence=RequestEvidence(schema_version=1,bound_evidence_sha256=b.evidence_sha256,
            request_identity_sha256=envelope.request_sha256,
            dispatched_envelope_sha256=envelope.serialized_envelope_sha256,
            input_token_count=b.input_token_maximum,output_token_maximum=b.output_token_maximum,
            proof_sha256=digest({"schema_version":1,"simulation_only":True,
                "envelope_sha256":envelope.serialized_envelope_sha256,
                "bound_evidence_sha256":b.evidence_sha256}))
        self._ledger.requests[evidence.evidence_sha256]=evidence
        return evidence.evidence_sha256

    def _admission_inputs(self, permit: OperationPermit):
        permit=OperationPermit.model_validate_json(canonical_bytes(permit))
        if permit.authority_id!=self.authority.authority_id:
            raise AccountingError(ErrorCode.AUTHORITY_MISMATCH)
        if (permit.state.value not in ("permitted","funded") or permit.expires_utc<=self._now()
            or permit.price_sha256!=self._snapshot.snapshot_sha256
            or permit.bound_sha256!=self._bound_bundle_sha):
            raise AccountingError(ErrorCode.INVALID_EVIDENCE)
        children=[]
        for i,child in enumerate(permit.attempt_children):
            request=self._ledger.requests.get(child.request_evidence_sha256)
            bound=self._bounds.get(request.bound_evidence_sha256) if request is not None else None
            if bound is None or request.request_identity_sha256!=permit.request_sha256:
                raise AccountingError(ErrorCode.INVALID_EVIDENCE)
            policy=next(p for p in self._snapshot.policies if p.policy_sha256==bound.policy_sha256)
            profile=next((p for p in self._profiles if p.provider==child.provider and p.exact_model==child.model),None)
            if (profile is None or profile.expires_utc<=self._now()
                or profile.capability_sha256!=bound.provider_config_sha256
                or (i==0 and request.dispatched_envelope_sha256!=permit.serialized_envelope_sha256)
                or child.model!=bound.model or child.max_attempts!=1
                or child.maximum_liability_usd!=reserve_up(Decimal(policy.maximum_cost(
                    bound.input_token_maximum,bound.output_token_maximum)))):
                raise AccountingError(ErrorCode.INVALID_EVIDENCE)
            children.append(s3.ChildBound(child_id=child.child_id,purpose=child.purpose,
                provider_config_sha256=bound.provider_config_sha256,model=child.model,
                bound_evidence_sha256=bound.evidence_sha256,max_attempts=1,max_repairs=0,
                input_token_maximum=bound.input_token_maximum,output_token_maximum=bound.output_token_maximum,
                fee_maximum_usd=policy.fee_usd,reserved_usd_per_attempt=format(child.maximum_liability_usd,"f"),
                request_shape_limit_sha256=bound.request_shape_limit_sha256,conditional=child.conditional))
        context=s3.CallContext(schema_version=1,authority_id=permit.authority_id,run_id=permit.authority_id,
            operation_id=permit.operation_id,child_id=permit.attempt_children[0].child_id,
            task_id=permit.caller_id,span_id=permit.serialized_envelope_sha256,
            parent_span_id=permit.bound_sha256,consumer_namespace="m8",purpose=permit.purpose,
            source_generation=str(permit.policy_generation),consumer_context_sha256=_permit_hash(permit),
            policy_sha256=permit.policy_bundle_sha256,template_sha256=permit.request_sha256,
            config_sha256=permit.price_sha256)
        plan=s3.OperationPlan(schema_version=1,operation_id=permit.operation_id,authority_id=permit.authority_id,
            context_sha256=s3.canonical_digest(context.model_dump(mode="json")),children=children)
        limits=self._limits.model_copy(update={"run_deadline_utc":_stamp(permit.expires_utc),
            "operation_deadline_s":float((permit.expires_utc-permit.created_utc).total_seconds())})
        return permit,context,plan,limits

    def fund_plan(self, permit: OperationPermit) -> FundingReceipt:
        self._held()
        try:
            permit,context,plan,limits=self._admission_inputs(permit)
            self.gate.validate_funding(permit,now=self._now())
            totals=self.totals(authority_id=self.authority.authority_id)
            if totals.halted:
                raise AccountingError(ErrorCode.HALTED)
            with self._read() as connection:
                prior=self._operation(connection,permit.operation_id)
            _allocation=self._ledger.admit_operation(plan,context=context,limits=limits,mode="simulation")
            # S3's property sums Decimal values under the caller's context. Protect
            # the returned projection just as S3 protects its committed funding.
            with localcontext() as context_precision:
                context_precision.prec=150
                reserved_total=amount(plan.declared_worst_case_usd)
            return FundingReceipt(authority_id=permit.authority_id,operation_id=permit.operation_id,
                permit_sha256=_permit_hash(permit),funded_children=tuple(c.child_id for c in permit.attempt_children),
                plan_reserved_usd=reserved_total,already_funded=prior is not None)
        except LedgerError as error:
            raise upstream_error(str(error)) from None
        except (ValidationError,ValueError,ArithmeticError,StopIteration):
            raise AccountingError(ErrorCode.INVALID_EVIDENCE) from None

    def begin_attempt(self, *, operation_id: str, child_id: str, permit_sha256: str) -> DispatchTicket:
        self._held()
        try:
            self.gate.validate_dispatch(operation_id=operation_id,child_id=child_id,
                permit_sha256=permit_sha256,now=self._now())
            if self.totals(authority_id=self.authority.authority_id).halted:
                raise AccountingError(ErrorCode.HALTED)
            with self._read() as connection:
                op=self._operation(connection,operation_id)
                if op is None:
                    raise AccountingError(ErrorCode.INVALID_JOIN)
                root=json.loads(op["context"])
                child=connection.execute("SELECT * FROM children WHERE operation_id=? AND child_id=?",
                    (operation_id,child_id)).fetchone()
                if root["consumer_context_sha256"]!=permit_sha256 or child is None:
                    raise AccountingError(ErrorCode.PERMIT_MISMATCH)
                if child["remaining"]!=1:
                    raise AccountingError(ErrorCode.ALREADY_CLAIMED)
                definition=json.loads(child["definition"])
                requests=[r for r in self._ledger.requests.values() if
                    r.bound_evidence_sha256==definition["bound_evidence_sha256"]
                    and r.request_identity_sha256==root["template_sha256"]]
                if child_id==root["child_id"]:
                    requests=[r for r in requests if r.dispatched_envelope_sha256==root["span_id"]]
                if len(requests)!=1:
                    raise AccountingError(ErrorCode.INVALID_EVIDENCE)
                request=requests[0]
                context=s3.CallContext.model_validate({**root,"child_id":child_id,"purpose":definition["purpose"]})
            # Successful new return only. There is deliberately no ticket recovery API.
            attempt_id=self._ledger.begin_attempt(self._allocation(op),context=context,request=request)
            return DispatchTicket(authority_id=self.authority.authority_id,operation_id=operation_id,
                child_id=child_id,attempt_id=attempt_id,permit_sha256=permit_sha256,
                envelope_sha256=request.dispatched_envelope_sha256,reserved_usd=amount(definition["reserved_usd_per_attempt"]))
        except LedgerError as error:
            raise upstream_error(str(error)) from None
        except (ValidationError,ValueError,ArithmeticError):
            raise AccountingError(ErrorCode.INVALID_EVIDENCE) from None
    def _attempt(self, connection, *, operation_id: str, child_id: str, attempt_id: str):
        row=connection.execute("SELECT * FROM attempts WHERE authority_id=? AND operation_id=? AND child_id=? AND id=?",
            (self.authority.authority_id,operation_id,child_id,attempt_id)).fetchone()
        if row is None:
            raise AccountingError(ErrorCode.INVALID_JOIN)
        return row

    def _incident(self, row, *, provider: str, source: str, observed: Decimal | None,
                  authenticated: bool, reason: str) -> None:
        incident=AccountingIncident(authority_id=self.authority.authority_id,
            operation_id=row["operation_id"],child_id=row["child_id"],attempt_id=row["id"],
            provider=provider,source_sha256=source,observed_cost_usd=observed,
            reserved_usd=amount(row["reservation"]),
            terminal_unknown_usd=amount(row["reservation"]) if row["state"]=="unknown" else Decimal(0),
            authenticated=authenticated,conflict=reason in ("settlement_conflict","evidence_conflict","unauthenticated_evidence"),
            reason_code=reason,recorded_utc=self._now())
        if authenticated:
            key=(incident.operation_id,incident.child_id,incident.attempt_id,incident.source_sha256)
            prior=self._observations.get(key)
            if prior is not None:
                # An identical observed source gets identical evidence/time on
                # replay. Changed facts under its exact digest never replace it.
                if canonical_bytes(prior.model_dump(exclude={"recorded_utc"})) != canonical_bytes(incident.model_dump(exclude={"recorded_utc"})):
                    # Keep the original provenance entry and let governance
                    # durably quarantine the conflicting observation and halt.
                    self.gate.record_accounting_incident(incident.model_copy(update={
                        "authenticated":False,"conflict":True,"reason_code":"evidence_conflict"}))
                    raise AccountingError(ErrorCode.EVIDENCE_CONFLICT)
                incident=prior
            else:
                self._observations[key]=incident
        self.gate.record_accounting_incident(incident)

    def incident_source(self, *, operation_id: str, child_id: str, attempt_id: str,
                        source_sha256: str) -> AccountingIncident | None:
        """Trusted body-free source resolver for the governance incident reader.

        Entries originate only in validated wrapper settlement/normalization code.
        Source recognition establishes a synthetic observation, never an invoice.
        The policy transaction independently persists credibility/maxima/halt.
        """
        self._held()
        observed=self._observations.get((operation_id,child_id,attempt_id,source_sha256))
        if observed is None:
            return None
        with self._read() as connection:
            row=self._attempt(connection,operation_id=operation_id,child_id=child_id,attempt_id=attempt_id)
            child=connection.execute("SELECT policy FROM children WHERE operation_id=? AND child_id=?",
                (operation_id,child_id)).fetchone()
        if row["state"] not in ("known","unknown") or child is None:
            return None
        policy=PricePolicy.model_validate(json.loads(child["policy"]))
        if (observed.provider!=policy.provider or observed.reserved_usd!=amount(row["reservation"])
            or observed.terminal_unknown_usd!=(amount(row["reservation"]) if row["state"]=="unknown" else Decimal(0))):
            return None
        return AccountingIncident.model_validate_json(canonical_bytes(observed))

    def _finish_settlement(self, row, *, success: bool) -> None:
        with self._read() as connection:
            op=self._operation(connection,row["operation_id"])
        self._ledger.finish_child(self._allocation(op),child_id=row["child_id"],
            outcome="complete" if success else "failed",proof_sha256=row["settlement_sha"])

    def settle(self, receipt: AttemptReceipt) -> SettlementReceipt:
        self._held()
        try:
            receipt=AttemptReceipt.model_validate_json(canonical_bytes(receipt))
            with self._read() as connection:
                row=self._attempt(connection,operation_id=receipt.operation_id,child_id=receipt.child_id,attempt_id=receipt.attempt_id)
                op=self._operation(connection,receipt.operation_id)
                child=connection.execute("SELECT * FROM children WHERE operation_id=? AND child_id=?",
                    (receipt.operation_id,receipt.child_id)).fetchone()
            root=json.loads(op["context"])
            policy=PricePolicy.model_validate(json.loads(child["policy"]))
            if ((receipt.request_sha256,receipt.dispatch_sha256,receipt.serialized_envelope_sha256,
                 receipt.permit_sha256,receipt.policy_bundle_sha256,receipt.price_sha256,receipt.bound_sha256,
                 receipt.reserved_usd,receipt.provider,receipt.model)!=(
                 row["request_sha"],row["dispatch_sha"],row["dispatch_sha"],root["consumer_context_sha256"],
                 root["policy_sha256"],root["config_sha256"],root["parent_span_id"],
                 amount(row["reservation"]),policy.provider,policy.model)):
                raise AccountingError(ErrorCode.PERMIT_MISMATCH)
            prior=row["state"]!="active"
            # Unknown is immutable. A different terminal receipt is incident evidence,
            # never a replayable settlement or permission to release the old U.
            if receipt.cost_status=="unknown":
                if row["state"]=="known":
                    self._incident(row,provider=receipt.provider,source=digest(receipt),observed=None,
                        authenticated=False,reason="settlement_conflict")
                    raise AccountingError(ErrorCode.SETTLEMENT_CONFLICT)
                return self.mark_unknown(operation_id=receipt.operation_id,child_id=receipt.child_id,
                    attempt_id=receipt.attempt_id,reason=UnknownReason.MISSING_USAGE)
            try:
                usage=s3.NormalizedUsage(input_tokens=receipt.usage.input_tokens,output_tokens=receipt.usage.output_tokens,
                    cache_read_input_tokens=receipt.usage.cache_read_tokens,
                    cache_write_input_tokens=receipt.usage.cache_write_tokens,
                    reasoning_output_tokens=receipt.usage.reasoning_tokens)
                observation=policy.price(usage,reservation_usd=row["reservation"])
            except (ValidationError,ValueError,ArithmeticError):
                # Even malformed partitions/oversized counts can accompany a
                # conflicting claimed charge. Retain the safe scoped evidence.
                self._incident(row,provider=receipt.provider,source=digest(receipt),
                    observed=receipt.known_usage_cost_usd,authenticated=False,
                    reason="settlement_conflict" if prior else "unauthenticated_evidence")
                if prior:
                    raise AccountingError(ErrorCode.SETTLEMENT_CONFLICT) from None
                return self.mark_unknown(operation_id=receipt.operation_id,child_id=receipt.child_id,
                    attempt_id=receipt.attempt_id,reason=UnknownReason.MALFORMED_USAGE)
            if (observation.status!="known" or receipt.usage.cache_read_tokens is not None
                or receipt.usage.cache_write_tokens is not None or receipt.usage.reasoning_tokens is not None):
                # A claimed known amount with incompatible usage is evidence too.
                # Quarantine it durably even if S3 would only reject the conflict.
                self._incident(row,provider=receipt.provider,source=digest(receipt),
                    observed=receipt.known_usage_cost_usd,authenticated=False,
                    reason="settlement_conflict" if prior else "unauthenticated_evidence")
                if prior:
                    raise AccountingError(ErrorCode.SETTLEMENT_CONFLICT)
                return self.mark_unknown(operation_id=receipt.operation_id,child_id=receipt.child_id,
                    attempt_id=receipt.attempt_id,reason=UnknownReason.UNSUPPORTED_COMPONENT)
            computed=amount(observation.computed_cost_usd)
            if computed!=receipt.known_usage_cost_usd:
                self._incident(row,provider=receipt.provider,source=digest(receipt),
                    observed=receipt.known_usage_cost_usd,authenticated=False,reason="unauthenticated_evidence")
                raise AccountingError(ErrorCode.INVALID_EVIDENCE)
            if row["state"]=="unknown":
                # A validated synthetic late observation does not rewrite U or
                # replay settlement. Governance verifies this exact registered
                # source and durably advances only its monotone maximum/D.
                self._incident(row,provider=receipt.provider,source=digest(receipt),observed=computed,
                    authenticated=True,reason="late_evidence")
                self._finish_settlement(row,success=False)
                return settlement_projection(authority_id=self.authority.authority_id,row=row,already_settled=True)
            metadata_usage=s3.MetadataUsage(details=usage)
            metadata=s3.MetadataRecord(schema_version=1,context=s3.CallContext.model_validate(json.loads(row["context"])),
                request_identity_sha256=row["request_sha"],usage=metadata_usage,
                usage_projection_sha256=s3.canonical_digest(metadata_usage.model_dump(mode="json")),
                usage_redacted_fields=False,status={"ok":"ok","refused":"refused","truncated":"invalid_output",
                    "provider_error":"provider_error","cancelled":"cancelled","timeout":"deadline_exceeded"}[receipt.status],
                duration_ms=0.0,error_code=None)
            try:
                self._ledger.settle(receipt.attempt_id,metadata=metadata,usage=usage)
            except LedgerError as error:
                if str(error)=="settlement_conflict":
                    self._incident(row,provider=receipt.provider,source=digest(receipt),observed=computed,
                        authenticated=True,reason="settlement_conflict")
                raise
            with self._read() as connection:
                settled=self._attempt(connection,operation_id=receipt.operation_id,child_id=receipt.child_id,attempt_id=receipt.attempt_id)
            if computed>amount(row["reservation"]):
                # S3 committed the full cost AND halt atomically before this projection.
                self._incident(settled,provider=receipt.provider,source=settled["settlement_sha"],
                    observed=computed,authenticated=True,reason="bound_breach")
            self._finish_settlement(settled,success=receipt.status=="ok")
            return settlement_projection(authority_id=self.authority.authority_id,row=settled,already_settled=prior)
        except LedgerError as error:
            raise upstream_error(str(error)) from None
        except (ValidationError,ValueError,ArithmeticError):
            raise AccountingError(ErrorCode.INVALID_EVIDENCE) from None

    def mark_unknown(self, *, operation_id: str, child_id: str,
                     attempt_id: str, reason: UnknownReason) -> SettlementReceipt:
        self._held()
        if not isinstance(reason,UnknownReason):
            raise AccountingError(ErrorCode.INVALID_EVIDENCE)
        try:
            with self._read() as connection:
                prior=self._attempt(connection,operation_id=operation_id,child_id=child_id,attempt_id=attempt_id)
            if prior["state"]=="known":
                with self._read() as connection:
                    child=connection.execute("SELECT policy FROM children WHERE operation_id=? AND child_id=?",
                        (operation_id,child_id)).fetchone()
                provider=json.loads(child["policy"])["provider"]
                self._incident(prior,provider=provider,source=digest({"schema_version":1,
                    "operation_id":operation_id,"child_id":child_id,"attempt_id":attempt_id,
                    "unknown_reason":reason.value}),observed=None,authenticated=False,reason="settlement_conflict")
                raise AccountingError(ErrorCode.SETTLEMENT_CONFLICT)
            self._ledger.mark_unknown(attempt_id)
            with self._read() as connection:
                row=self._attempt(connection,operation_id=operation_id,child_id=child_id,attempt_id=attempt_id)
            self._finish_settlement(row,success=False)
            return settlement_projection(authority_id=self.authority.authority_id,row=row,already_settled=prior["state"]!="active")
        except LedgerError as error:
            raise upstream_error(str(error)) from None

    def _expired(self, op, evidence: RecoveryEvidence) -> bool:
        if evidence.authority_id!=self.authority.authority_id or evidence.operation_id!=op["id"]:
            raise AccountingError(ErrorCode.INVALID_EVIDENCE)
        # Neither a caller's expiry field nor its owner-exit digest is authority.
        # Only the committed S3 deadline and trusted current clock justify this
        # automatic path. Earlier cancellation/process-exit cleanup is conservative
        # until the governance bridge authenticates its evidence.
        now=self._now()
        return now>=_utc(op["deadline"]) and evidence.observed_utc<=now

    def close_unstarted(self, proof: UnstartedProof) -> ChildClosureReceipt:
        self._held()
        try:
            proof=UnstartedProof.model_validate_json(canonical_bytes(proof))
            with self._read() as connection:
                op=self._operation(connection,proof.operation_id)
                if op is None or (proof.recovery_evidence.authority_id,proof.recovery_evidence.operation_id)!=(self.authority.authority_id,proof.operation_id):
                    raise AccountingError(ErrorCode.INVALID_EVIDENCE)
                if (proof.recovery_evidence.child_id not in (None,proof.child_id)
                    or proof.recovery_evidence.attempt_id is not None):
                    raise AccountingError(ErrorCode.INVALID_EVIDENCE)
                child=connection.execute("SELECT * FROM children WHERE operation_id=? AND child_id=?",
                    (proof.operation_id,proof.child_id)).fetchone()
                if child is None or proof.authority_id!=self.authority.authority_id or proof.allocation_id!=op["allocation_id"]:
                    raise AccountingError(ErrorCode.INVALID_EVIDENCE)
                expected=s3.canonical_digest({"allocation_id":op["allocation_id"],"child_id":proof.child_id,"undispatched":True})
                if proof.proof_sha256!=expected:
                    raise AccountingError(ErrorCode.INVALID_EVIDENCE)
                definition=json.loads(child["definition"])
            # Only GOVERNANCE can authenticate actual cancel/expiry or an unused
            # conditional branch after a matching immutable prior settlement.
            # Caller DTOs alone never release a hold; S3 separately proves no attempt.
            self.gate.authorize_unstarted(proof,now=self._now())
            self._ledger.finish_child(self._allocation(op),child_id=proof.child_id,outcome=proof.reason,proof_sha256=expected)
            return ChildClosureReceipt(authority_id=self.authority.authority_id,operation_id=proof.operation_id,
                child_id=proof.child_id,closure_sha256=expected,
                released_usd=amount(definition["reserved_usd_per_attempt"]),already_closed=child["state"]!="pending")
        except LedgerError as error:
            raise upstream_error(str(error)) from None
        except (ValidationError,ValueError,ArithmeticError):
            raise AccountingError(ErrorCode.INVALID_EVIDENCE) from None

    def totals(self, *, authority_id: str):
        self._held()
        if authority_id!=self.authority.authority_id:
            raise AccountingError(ErrorCode.AUTHORITY_MISMATCH)
        incident=self.gate.incident_snapshot(authority_id=authority_id)
        with self._read() as connection:
            authority=connection.execute("SELECT * FROM authorities WHERE id=?",(authority_id,)).fetchone()
            raw_children=connection.execute("SELECT c.* FROM children c JOIN operations o ON o.id=c.operation_id WHERE o.authority_id=?",(authority_id,)).fetchall()
            children=[{**dict(r),**json.loads(r["definition"])} for r in raw_children]
            attempts=[dict(r) for r in connection.execute("SELECT * FROM attempts WHERE authority_id=?",(authority_id,))]
        return totals_projection(authority_id=authority_id,cap_usd=self.authority.cap_usd,children=children,
            attempts=attempts,incident=incident,ledger_halted=bool(authority["halted"]))

    def operation_totals(self, operation_id: str) -> AccountingTotals:
        """Operation-scoped conserved amounts; cap_usd is the AUTHORITY ceiling.

        Call outside a policy write transaction. The actual shared guard keeps
        ledger/journal views stable, and no governance call occurs inside the
        committed ledger read. This does not create a per-operation wallet.
        """
        self._held()
        with self._read() as connection:
            op=self._operation(connection,operation_id)
            if op is None:
                raise AccountingError(ErrorCode.INVALID_JOIN)
            # Validate the same immutable admitted context/plan/child closure.
            self._join(connection,op)
            authority=connection.execute("SELECT * FROM authorities WHERE id=?",
                (self.authority.authority_id,)).fetchone()
            raw_children=connection.execute("SELECT * FROM children WHERE operation_id=?",
                (operation_id,)).fetchall()
            children=[{**dict(r),**json.loads(r["definition"])} for r in raw_children]
            attempts=[dict(r) for r in connection.execute(
                "SELECT * FROM attempts WHERE authority_id=? AND operation_id=?",
                (self.authority.authority_id,operation_id))]
        incident=self.gate.operation_incident_snapshot(operation_id)
        return totals_projection(authority_id=self.authority.authority_id,
            cap_usd=self.authority.cap_usd,children=children,attempts=attempts,
            incident=incident,ledger_halted=bool(authority["halted"]))

    def _join(self, connection, op) -> LedgerJoin:
        root=json.loads(op["context"])
        plan=s3.OperationPlan.model_validate(json.loads(op["plan"]))
        if (plan.plan_sha256!=op["plan_sha"] or plan.context_sha256!=s3.canonical_digest(root)
            or plan.operation_id!=op["id"] or plan.authority_id!=self.authority.authority_id):
            raise AccountingError(ErrorCode.INVALID_JOIN)
        rows=connection.execute("SELECT * FROM children WHERE operation_id=? ORDER BY rowid",(op["id"],)).fetchall()
        if tuple(r["child_id"] for r in rows)!=tuple(c.child_id for c in plan.children):
            raise AccountingError(ErrorCode.INVALID_JOIN)
        for row,declared in zip(rows,plan.children):
            if json.loads(row["definition"])!=declared.model_dump(mode="json"):
                raise AccountingError(ErrorCode.INVALID_JOIN)
        settlements=connection.execute("SELECT settlement_sha FROM attempts WHERE operation_id=? ORDER BY rowid",(op["id"],)).fetchall()
        last=settlements[-1][0] if settlements else None
        return LedgerJoin(authority_id=self.authority.authority_id,operation_id=op["id"],
            permit_sha256=root["consumer_context_sha256"],policy_bundle_sha256=root["policy_sha256"],
            request_sha256=root["template_sha256"],serialized_envelope_sha256=root["span_id"],
            bound_sha256=root["parent_span_id"],price_sha256=root["config_sha256"],
            allocation_id=op["allocation_id"],child_ids=tuple(c.child_id for c in plan.children),
            ledger_context_sha256=plan.context_sha256,settlement_sha256=last)

    def committed_join(self, *, operation_id: str) -> LedgerJoin | None:
        with self._read() as connection:
            op=self._operation(connection,operation_id)
            return self._join(connection,op) if op is not None else None

    def _state(self, connection, op) -> LedgerOperationSnapshot:
        join=self._join(connection,op)
        children=connection.execute("SELECT * FROM children WHERE operation_id=? ORDER BY rowid",(op["id"],)).fetchall()
        snapshots=[]
        breach=False
        for child in children:
            attempts=connection.execute("SELECT * FROM attempts WHERE operation_id=? AND child_id=?",(op["id"],child["child_id"])).fetchall()
            if len(attempts)>1:
                raise AccountingError(ErrorCode.INVALID_EVIDENCE)
            row=attempts[0] if attempts else None
            if row and row["state"]=="known" and amount(row["cost"])>amount(row["reservation"]):
                breach=True
            snapshots.append(LedgerAttemptSnapshot(child_id=child["child_id"],attempt_id=row["id"] if row else None,
                state=row["state"] if row else ("future" if child["remaining"] else "closed_unstarted"),
                owner=None,settlement_sha256=row["settlement_sha"] if row else None,deadline_utc=_utc(op["deadline"])))
        return LedgerOperationSnapshot(authority_id=self.authority.authority_id,operation_id=op["id"],
            permit_sha256=join.permit_sha256,ledger_context_sha256=join.ledger_context_sha256,
            # Ledger-only projection: S3 has no durable conflicting-observation
            # journal. Combined governance conflict/stop is checked by the gate,
            # never by recursively entering governance from its ledger reader.
            join=join,attempts=tuple(snapshots),breach=breach,conflict=False)

    def operation_state(self, operation_id: str) -> LedgerOperationSnapshot | None:
        with self._read() as connection:
            op=self._operation(connection,operation_id)
            return self._state(connection,op) if op is not None else None

    def recovery_candidates(self, authority_id: str, *, cursor: str | None=None, limit: int=100) -> LedgerRecoveryPage:
        if authority_id!=self.authority.authority_id:
            raise AccountingError(ErrorCode.AUTHORITY_MISMATCH)
        if type(limit) is not int or not 1<=limit<=1024:
            raise AccountingError(ErrorCode.INVALID_EVIDENCE)
        with self._read() as connection:
            rows=connection.execute("SELECT * FROM operations WHERE authority_id=? AND id>? ORDER BY id LIMIT ?",
                (authority_id,cursor or "",limit+1)).fetchall()
            items=tuple(self._state(connection,r) for r in rows[:limit])
            return LedgerRecoveryPage(items=items,next_cursor=rows[limit-1]["id"] if len(rows)>limit else None)

    def recover(self, evidence: RecoveryEvidence) -> RecoveryReport:
        self._held()
        evidence=RecoveryEvidence.model_validate_json(canonical_bytes(evidence))
        with self._read() as connection:
            op=self._operation(connection,evidence.operation_id)
            if op is None:
                return RecoveryReport(authority_id=self.authority.authority_id,actions=(),retained=(),blocked=(evidence.operation_id,))
            expired=self._expired(op,evidence)
        state=self.operation_state(evidence.operation_id)
        actions=[]
        retained=[]
        for attempt in state.attempts:
            if evidence.child_id is not None and evidence.child_id!=attempt.child_id:
                continue
            if evidence.attempt_id is not None and evidence.attempt_id!=attempt.attempt_id:
                continue
            action="retained"
            if (expired or evidence.cancelled) and attempt.state=="future":
                proof_hash=s3.canonical_digest({"allocation_id":op["allocation_id"],"child_id":attempt.child_id,"undispatched":True})
                self.close_unstarted(UnstartedProof(authority_id=self.authority.authority_id,
                    operation_id=evidence.operation_id,child_id=attempt.child_id,allocation_id=op["allocation_id"],
                    reason="cancelled_before_dispatch",proof_sha256=proof_hash,recovery_evidence=evidence))
                action="closed_unstarted"
            elif expired and attempt.state=="active":
                # A staged receipt is recovered by controller via settle(original receipt).
                # A bare stage hash is not enough to synthesize that receipt here.
                if evidence.staged_settlement_sha256 is None:
                    self.mark_unknown(operation_id=evidence.operation_id,child_id=attempt.child_id,
                        attempt_id=attempt.attempt_id,reason=UnknownReason.AMBIGUOUS_DISPATCH)
                    action="marked_unknown"
            if action=="retained":
                retained.append(attempt.child_id)
            actions.append(RecoveryAction(operation_id=evidence.operation_id,child_id=attempt.child_id,
                action=action,evidence_sha256=digest(evidence)))
        return RecoveryReport(authority_id=self.authority.authority_id,actions=tuple(actions),retained=tuple(retained),blocked=())
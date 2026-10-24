"""Local deterministic selection and immutable plans; no invented funding evidence."""
from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime, timedelta
import uuid

from gateway.schemas import (
    AttemptChild, CapabilityProfile, EligibilityContext, ErrorCode, EvaluationAuthorization,
    GatewayError, GatewayRequest, PolicyBundle,
    PermitPlan, ProviderEnvelope, RoutingSnapshot, digest, request_features, reserve_up, usd_micros,
)
from .ports import ProviderAdapter, QuotePort
from gateway.runtime import adapter_manifest_digest, profile_manifest_digest


class PermitPlanner:
    def __init__(self, adapters: Mapping[str, ProviderAdapter], quotes: QuotePort,
                 context_loader: Callable[[str], EligibilityContext],
                 profile_loader: Callable[[str], tuple[CapabilityProfile, ...]]):
        self.adapters = dict(adapters)
        self.quotes = quotes
        self.context_loader = context_loader
        self.profile_loader = profile_loader

    def build(self, request: GatewayRequest, snapshot: RoutingSnapshot, *, now: datetime
              ) -> tuple[PermitPlan, ProviderEnvelope, ProviderAdapter, EligibilityContext]:
        context = self.context_loader(snapshot.policy_bundle_sha256)
        if (snapshot.authority_id != request.authority_id
            or digest(context.model_dump(exclude={"observed_utc"})) != snapshot.evidence_context_sha256):
            raise GatewayError(ErrorCode.INVALID_JOIN)
        return self._build_for(request, bundle=snapshot.bundle, context=context,
            eligible_target_ids=snapshot.eligible_target_ids, scope_expiry=snapshot.expires_utc,
            now=now, purpose="serve", authorization_sha256=None)

    def build_evaluation(self, request: GatewayRequest, bundle: PolicyBundle,
                         authorization: EvaluationAuthorization, *, authorization_sha256: str,
                         now: datetime):
        # No RoutingSnapshot/approval is fabricated for evaluated genesis.
        if (digest(authorization) != authorization_sha256
            or digest(bundle) != authorization.tuple.policy_bundle_sha256
            or authorization.authority_id != request.authority_id
            or authorization.budget_authority_id != request.authority_id
            or authorization.mode != "simulation"
            or not authorization.created_utc <= now < authorization.expires_utc):
            raise GatewayError(ErrorCode.INVALID_AUTHORIZATION)
        context = self.context_loader(digest(bundle))
        if context.tuple != authorization.tuple:
            raise GatewayError(ErrorCode.INVALID_AUTHORIZATION)
        result = self._build_for(request, bundle=bundle, context=context,
            eligible_target_ids=tuple(t.target_id for t in bundle.targets),
            scope_expiry=authorization.expires_utc, now=now, purpose="eval",
            authorization_sha256=authorization_sha256)
        if sum(usd_micros(c.maximum_liability_usd) for c in result[0].attempt_children) > usd_micros(
            authorization.maximum_liability_usd
        ):
            raise GatewayError(ErrorCode.BUDGET_EXCEEDED)
        return result

    def _build_for(self, request: GatewayRequest, *, bundle: PolicyBundle,
                   context: EligibilityContext, eligible_target_ids: tuple[str, ...],
                   scope_expiry: datetime, now: datetime, purpose: str,
                   authorization_sha256: str | None):
        if request.route_alias not in bundle.route_aliases:
            raise GatewayError(ErrorCode.INVALID_REQUEST)
        features = request_features(request)
        target_id = bundle.fallback_target_id
        for rule in bundle.rules:
            value = getattr(features, rule.feature)
            if value is None:
                raise GatewayError(ErrorCode.MISSING_EVIDENCE)
            operand = rule.operand
            # Schemas freeze the predicate type; no eval/import/regex execution.
            matched = {"eq": lambda: value == operand, "ne": lambda: value != operand,
                       "lt": lambda: value < operand, "le": lambda: value <= operand,
                       "gt": lambda: value > operand, "ge": lambda: value >= operand,
                       "in": lambda: value in operand}[rule.operator]()
            if matched:
                target_id = rule.target_id
                break
        if target_id not in eligible_target_ids or target_id not in self.adapters:
            raise GatewayError(ErrorCode.INELIGIBLE_POLICY)
        target = next(t for t in bundle.targets if t.target_id == target_id)
        adapter = self.adapters[target_id]
        profile = adapter.capability_profile()
        if profile.mode != "simulation" or not profile.exact_model.startswith("mock-"):
            raise GatewayError(ErrorCode.EXTERNAL_DISABLED)
        if set(profile.supported_billable_components) != {"input_tokens", "output_tokens"}:
            # Shared ProviderUsage cannot represent nonzero cache/reasoning amounts.
            raise GatewayError(ErrorCode.UNSUPPORTED_PROFILE)
        if (profile.provider, profile.exact_model, profile.api_version,
            profile.capability_sha256, profile.adapter_sha256) != (
            target.provider, target.exact_model, target.api_version,
            target.capability_sha256, target.adapter_sha256
        ):
            raise GatewayError(ErrorCode.INVALID_JOIN)
        if (request.max_completion_tokens > profile.max_output_tokens
            or len(request.messages) > profile.max_messages
            or features.input_utf8_bytes > profile.max_input_bytes):
            raise GatewayError(ErrorCode.UNSUPPORTED_REQUEST)
        if (context.authority_id != request.authority_id or context.mode != "simulation"
            or context.tuple.policy_bundle_sha256 != digest(bundle)):
            raise GatewayError(ErrorCode.INVALID_JOIN)
        profiles = self.profile_loader(context.tuple.adapter_capability_sha256)
        if (profile_manifest_digest(profiles) != context.tuple.adapter_capability_sha256
            or adapter_manifest_digest(profiles) != context.tuple.adapter_sha256):
            raise GatewayError(ErrorCode.INVALID_EVIDENCE)
        identities = {(p.provider, p.exact_model, p.api_version, p.capability_sha256, p.adapter_sha256)
                      for p in profiles}
        if any((t.provider, t.exact_model, t.api_version, t.capability_sha256, t.adapter_sha256)
               not in identities for t in bundle.targets):
            raise GatewayError(ErrorCode.MISSING_EVIDENCE)
        envelope = adapter.serialize(request)
        if (envelope.request_sha256, envelope.capability_sha256, envelope.adapter_sha256,
            envelope.price_sha256, envelope.bound_sha256) != (
            request.request_sha256, profile.capability_sha256, profile.adapter_sha256,
            bundle.price_sha256, bundle.bound_bundle_sha256
        ):
            raise GatewayError(ErrorCode.INVALID_JOIN)
        expires = min(request.deadline_utc, now + timedelta(seconds=bundle.operation_timeout_seconds),
                      scope_expiry, bundle.expires_utc, profile.expires_utc,
                      *(dependency.expires_utc for dependency in context.dependency_expiries))
        if expires <= now:
            raise GatewayError(ErrorCode.STALE_EVIDENCE)
        operation = uuid.uuid4().hex
        bound = reserve_up(self.quotes.reserve_for(envelope))
        evidence = self.quotes.register_envelope(envelope)
        children = tuple(AttemptChild(child_id=operation + ("-primary" if i == 0 else "-retry"),
            target_id=target_id, purpose=purpose if i == 0 else "retry", conditional=i > 0,
            provider=envelope.provider, model=envelope.model, maximum_liability_usd=bound,
            request_evidence_sha256=evidence) for i in range(bundle.max_attempts_total))
        plan = PermitPlan(operation_id=operation, policy_bundle_sha256=digest(bundle),
            chosen_target_ids=(target_id,), attempt_children=children,
            adapter_capability_sha256=context.tuple.adapter_capability_sha256, price_sha256=envelope.price_sha256,
            bound_sha256=envelope.bound_sha256, serialized_envelope_sha256=envelope.serialized_envelope_sha256,
            created_utc=now, expires_utc=expires, evaluation_authorization_sha256=authorization_sha256,
            purpose=purpose)
        return plan, envelope, adapter, context

"""Pure governance checks over the single shared schema namespace."""

from datetime import datetime, timedelta
import base64
import binascii
import hmac

from gateway.schemas import (
    ApprovalRecord, CapabilityProfile, EligibilityContext, EvaluationAuthorization, EvaluationRecord,
    EvidenceTuple, GatewayRequest, PermitPlan, PolicyBundle, PolicyError,
    canonical_bytes, digest, request_features, signed_bytes,
)

from .verification import SignatureVerificationError, verify_ed25519


def require(condition: bool, code: str) -> None:
    if not condition:
        raise PolicyError(code)


def verify_operator(record: ApprovalRecord | EvaluationAuthorization, key: bytes) -> None:
    """Verify the exact shared domain-separated signing representation."""
    try:
        signature = base64.b64decode(record.signature, validate=True)
        fingerprint = verify_ed25519(key, signature, signed_bytes(record))
    except (binascii.Error, ValueError, SignatureVerificationError):
        raise PolicyError("invalid_signature") from None
    require(hmac.compare_digest(fingerprint, record.signer_fingerprint_sha256), "invalid_signature")


def check_bundle_tuple(bundle: PolicyBundle, evidence: EvidenceTuple) -> None:
    require(digest(bundle) == evidence.policy_bundle_sha256, "ineligible_policy")
    require(
        bundle.eval_spec_sha256 == evidence.eval_spec_sha256
        and bundle.feature_schema_sha256 == evidence.feature_schema_sha256
        and bundle.price_sha256 == evidence.price_sha256
        and bundle.bound_bundle_sha256 == evidence.bound_sha256,
        "ineligible_policy",
    )


def check_context(
    bundle: PolicyBundle, context: EligibilityContext, trusted: EligibilityContext,
    *, authority_id: str, now: datetime,
) -> None:
    """Caller data cannot replace locally configured current evidence."""
    require(context.authority_id == trusted.authority_id == authority_id, "authority_mismatch")
    require(context.mode == trusted.mode == "simulation", "external_disabled")
    # observed_utc is a reading, not a selectable evidence dependency.
    require(
        canonical_bytes(context.model_dump(exclude={"observed_utc"}))
        == canonical_bytes(trusted.model_dump(exclude={"observed_utc"})),
        "invalid_evidence",
    )
    require(abs((now - context.observed_utc).total_seconds()) <= 5, "clock_untrusted")
    require(abs((now - trusted.observed_utc).total_seconds()) <= 5, "clock_untrusted")
    require(context.evaluation_max_age_seconds > 0, "stale_evidence")
    check_bundle_tuple(bundle, context.tuple)
    require(now < bundle.expires_utc, "stale_evidence")
    require(all(now < item.expires_utc for item in context.dependency_expiries), "stale_evidence")


def check_evaluation(
    bundle: PolicyBundle, evaluation: EvaluationRecord,
    authorization: EvaluationAuthorization, context: EligibilityContext,
    *, authority_id: str, now: datetime,
) -> None:
    require(evaluation.authority_id == authorization.authority_id == authority_id, "authority_mismatch")
    require(evaluation.mode == authorization.mode == context.mode == "simulation", "external_disabled")
    require(evaluation.tuple == authorization.tuple == context.tuple, "invalid_evidence")
    require(evaluation.authorization_sha256 == digest(authorization), "invalid_authorization")
    require(
        evaluation.budget_authority_id == authorization.budget_authority_id
        and evaluation.budget_reference_sha256 == authorization.budget_reference_sha256,
        "invalid_authorization",
    )
    require(evaluation.status == "pass" and evaluation.task_count > 0 and evaluation.missing_count == 0,
            "ineligible_policy")
    require(authorization.created_utc <= evaluation.frozen_utc < authorization.expires_utc,
            "invalid_authorization")
    require(evaluation.frozen_utc <= now < evaluation.expires_utc, "stale_evidence")
    require(now < authorization.expires_utc, "stale_evidence")
    require(now - evaluation.frozen_utc <= timedelta(seconds=context.evaluation_max_age_seconds),
            "stale_evidence")
    check_bundle_tuple(bundle, evaluation.tuple)


def select_target(bundle: PolicyBundle, request: GatewayRequest) -> str:
    """First matching allowlisted deterministic rule; no executable policy code."""
    require(request.route_alias in bundle.route_aliases, "invalid_permit")
    features = request_features(request)
    for rule in bundle.rules:
        value = getattr(features, rule.feature)
        require(value is not None, "missing_evidence")
        operand = rule.operand
        if rule.operator == "eq":
            matches = value == operand
        elif rule.operator == "ne":
            matches = value != operand
        elif rule.operator == "in":
            matches = value in operand
        elif rule.operator == "lt":
            matches = value < operand
        elif rule.operator == "le":
            matches = value <= operand
        elif rule.operator == "gt":
            matches = value > operand
        else:  # Shared schema closes the remaining operator to ge.
            matches = value >= operand
        if matches:
            return rule.target_id
    return bundle.fallback_target_id


def check_plan(
    bundle: PolicyBundle, request: GatewayRequest, plan: PermitPlan,
    context: EligibilityContext, profiles: tuple[CapabilityProfile, ...], *, now: datetime,
) -> None:
    require(plan.policy_bundle_sha256 == digest(bundle), "invalid_permit")
    require(plan.created_utc <= now < plan.expires_utc <= request.deadline_utc, "permit_expired")
    require((plan.expires_utc - plan.created_utc).total_seconds() <= bundle.operation_timeout_seconds,
            "invalid_permit")
    require(plan.expires_utc <= bundle.expires_utc and all(
        plan.expires_utc <= item.expires_utc for item in context.dependency_expiries
    ), "stale_evidence")
    require(plan.price_sha256 == bundle.price_sha256 and plan.bound_sha256 == bundle.bound_bundle_sha256,
            "invalid_permit")
    require(len(plan.attempt_children) <= bundle.max_attempts_total, "invalid_permit")
    targets = {target.target_id: target for target in bundle.targets}
    first = plan.attempt_children[0]
    require(first.target_id == select_target(bundle, request), "invalid_permit")
    for child in plan.attempt_children:
        require(child.target_id in targets, "invalid_permit")
        target = targets[child.target_id]
        require((child.provider, child.model) == (target.provider, target.exact_model), "invalid_permit")
        matching = [profile for profile in profiles if (
            profile.provider, profile.exact_model, profile.api_version,
            profile.capability_sha256, profile.adapter_sha256,
        ) == (target.provider, target.exact_model, target.api_version,
              target.capability_sha256, target.adapter_sha256)]
        require(len(matching) == 1, "missing_evidence")
        profile = matching[0]
        require(profile.mode == "simulation" and plan.expires_utc <= profile.expires_utc,
                "stale_evidence")
        require(request.max_completion_tokens <= profile.max_output_tokens
                and len(request.messages) <= profile.max_messages
                and sum(len(message.content.encode("utf-8")) for message in request.messages)
                    <= profile.max_input_bytes, "unsupported_profile")
        # request_evidence_sha256 addresses DL1's original RequestEvidence, not
        # the envelope itself. The accounting producer validates that registry
        # entry against the exact child/envelope before it can fund or claim.
    require(plan.adapter_capability_sha256 == context.tuple.adapter_capability_sha256, "invalid_permit")

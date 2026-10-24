"""Deterministic allowlisted predicates over body-free features only."""
from __future__ import annotations

from gateway.schemas import PolicyBundle, PolicyRule, RequestFeatures, digest, money_from_micros, usd_micros
from gateway.schemas.operator import ShadowContext, ShadowRecord


def _matches(rule: PolicyRule, features: RequestFeatures) -> bool:
    value = getattr(features, rule.feature)
    operand = rule.operand
    # An absent evidenced token bound never matches a rule, including `ne`.
    if value is None:
        return False
    if rule.operator == "in":
        return isinstance(operand, tuple) and value in operand
    if type(value) is not type(operand):
        return False
    if rule.operator == "eq":
        return value == operand
    if rule.operator == "ne":
        return value != operand
    if type(value) is not int or type(operand) is not int:
        return False
    if rule.operator == "lt":
        return value < operand
    if rule.operator == "le":
        return value <= operand
    if rule.operator == "gt":
        return value > operand
    if rule.operator == "ge":
        return value >= operand
    return False


def recommend_target(features: RequestFeatures, policy: PolicyBundle) -> tuple[str, tuple[str, ...]]:
    """First matching rule, otherwise the declared fallback; no authority checks."""
    for rule in policy.rules:
        if _matches(rule, features):
            return rule.target_id, (rule.rule_id,)
    return policy.fallback_target_id, ()


def evaluate_local(features: RequestFeatures, frozen_candidate: PolicyBundle,
                   *, context: ShadowContext) -> ShadowRecord:
    common = dict(operation_id=context.operation_id,
                  approved_bundle_sha256=context.approved_bundle_sha256,
                  candidate_bundle_sha256=digest(frozen_candidate),
                  served_target_id=context.served_target_id)

    def ineligible(reason: str) -> ShadowRecord:
        return ShadowRecord(**common, recommended_target_id=None, rule_ids=(),
                            recommendation_status="ineligible", incomplete_reason=reason,
                            agreement=None, outcome_status=None, observed_result_ref=None,
                            candidate_max_liability_usd=None, reservation_delta_usd=None,
                            price_sha256=None, bound_sha256=None)

    if context.candidate_evidence_expires_utc is None:
        return ineligible("missing_evidence")
    if min(context.candidate_evidence_expires_utc, frozen_candidate.expires_utc) <= context.observed_utc:
        return ineligible("stale_evidence")
    if features.route_alias not in frozen_candidate.route_aliases:
        return ineligible("no_eligible_target")
    target, rules = recommend_target(features, frozen_candidate)
    if target not in context.eligible_target_ids:
        return ineligible("no_eligible_target")
    agreement = target == context.served_target_id
    # A matching route alone is not evidence of an observed result.
    if agreement and context.observed_result_ref is None:
        return ineligible("missing_observation")
    amounts = {item.target_id: item for item in context.target_liabilities}
    selected = amounts.get(target)
    served = amounts.get(context.served_target_id)
    comparable = (
        selected is not None and served is not None
        and all(item.maximum_liability_usd is not None
                and item.expires_utc is not None and item.expires_utc > context.observed_utc
                and item.price_sha256 == frozen_candidate.price_sha256
                and item.bound_sha256 == frozen_candidate.bound_bundle_sha256
                for item in (selected, served))
    )
    maximum = selected.maximum_liability_usd if comparable else None
    delta = None
    if comparable:
        units = usd_micros(maximum) - usd_micros(served.maximum_liability_usd)
        magnitude = money_from_micros(abs(units))
        delta = magnitude.copy_negate() if units < 0 else magnitude
    return ShadowRecord(**common, recommended_target_id=target, rule_ids=rules,
                        recommendation_status="eligible", incomplete_reason=None,
                        agreement=agreement,
                        outcome_status="same_target_observed" if agreement else "different_target_unobserved",
                        observed_result_ref=context.observed_result_ref if agreement else None,
                        candidate_max_liability_usd=maximum, reservation_delta_usd=delta,
                        price_sha256=selected.price_sha256 if comparable else None,
                        bound_sha256=selected.bound_sha256 if comparable else None)

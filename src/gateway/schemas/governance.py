"""Frozen policy, exact signed evidence tuple and durable governance projections."""
from __future__ import annotations

from typing import Annotated, Literal, Tuple
from pydantic import Field, model_validator
from .core import (Hash, Identifier, Mode, Money, NonnegativeInt, PositiveInt,
                   Provider, Record, SafeLabel, Signature, SignedDecimal, UTC, canonical_bytes, usd_micros)


class EvidenceTuple(Record):
    policy_bundle_sha256: Hash
    eval_spec_sha256: Hash
    evaluator_code_sha256: Hash
    corpus_sha256: Hash
    metric_sha256: Hash
    adapter_capability_sha256: Hash
    adapter_sha256: Hash
    price_sha256: Hash
    bound_sha256: Hash
    feature_schema_sha256: Hash


class PolicyTarget(Record):
    target_id: Identifier
    provider: Provider
    exact_model: Identifier
    api_version: SafeLabel
    capability_sha256: Hash
    adapter_sha256: Hash


class PolicyRule(Record):
    rule_id: Identifier
    feature: Literal["route_alias", "input_utf8_bytes", "message_count", "has_system", "max_completion_tokens", "length_bucket", "input_token_bound"]
    operator: Literal["eq", "ne", "lt", "le", "gt", "ge", "in"]
    operand: str | int | bool | Tuple[str, ...]
    target_id: Identifier

    @model_validator(mode="after")
    def typed_predicate(self):
        numeric = self.feature in ("input_utf8_bytes", "message_count", "max_completion_tokens", "input_token_bound")
        if numeric and (type(self.operand) is not int or self.operand < 0 or self.operator == "in"):
            raise ValueError("invalid_rule_operand")
        if self.feature == "has_system" and (type(self.operand) is not bool or self.operator not in ("eq", "ne")):
            raise ValueError("invalid_rule_operand")
        if not numeric and self.feature != "has_system":
            if self.operator == "in":
                if not isinstance(self.operand, tuple) or not 1 <= len(self.operand) <= 32 or any(len(s) > 128 for s in self.operand):
                    raise ValueError("invalid_rule_operand")
            elif self.operator not in ("eq", "ne") or type(self.operand) is not str or len(self.operand) > 128:
                raise ValueError("invalid_rule_operand")
        return self


class PolicyBundle(Record):
    policy_id: Identifier
    version: PositiveInt
    route_aliases: Annotated[Tuple[Identifier, ...], Field(min_length=1, max_length=32)]
    targets: Annotated[Tuple[PolicyTarget, ...], Field(min_length=1, max_length=2)]
    rules: Annotated[Tuple[PolicyRule, ...], Field(max_length=64)]
    fallback_target_id: Identifier
    max_attempts_total: Annotated[int, Field(ge=1, le=2)]
    operation_timeout_seconds: Annotated[int, Field(gt=0, le=60)]
    attempt_timeout_seconds: Annotated[int, Field(gt=0, le=30)]
    max_backoff_milliseconds: Annotated[int, Field(ge=0, le=1000)]
    price_sha256: Hash
    bound_bundle_sha256: Hash
    eval_spec_sha256: Hash
    feature_schema_sha256: Hash
    expires_utc: UTC

    @model_validator(mode="after")
    def valid_policy(self):
        ids = {target.target_id for target in self.targets}
        if len(ids) != len(self.targets) or self.fallback_target_id not in ids or any(rule.target_id not in ids for rule in self.rules):
            raise ValueError("invalid_target")
        if len({r.rule_id for r in self.rules}) != len(self.rules) or len(set(self.route_aliases)) != len(self.route_aliases):
            raise ValueError("duplicate_identifier")
        if self.attempt_timeout_seconds > self.operation_timeout_seconds:
            raise ValueError("invalid_deadline")
        return self


class EvaluationAuthorizationPayload(Record):
    domain: Literal["gateway.evaluation-authorization.v1"] = "gateway.evaluation-authorization.v1"
    authorization_id: Identifier
    authority_id: Identifier
    purpose: Literal["eval"] = "eval"
    mode: Mode
    tuple: EvidenceTuple
    budget_authority_id: Identifier
    budget_reference_sha256: Hash
    maximum_liability_usd: Money
    created_utc: UTC
    expires_utc: UTC
    nonce: Identifier
    declared_os_account: SafeLabel
    signer_fingerprint_sha256: Hash
    @model_validator(mode="after")
    def expiry(self):
        if self.expires_utc <= self.created_utc:
            raise ValueError("invalid_expiry")
        return self


class EvaluationAuthorization(EvaluationAuthorizationPayload):
    signature: Signature


class MetricInterval(Record):
    metric_id: Identifier
    numerator: NonnegativeInt | None
    denominator: NonnegativeInt
    lower: SignedDecimal | None
    upper: SignedDecimal | None
    # Signed dimensionless intervals, six fractional places; liabilities remain Money.
    @model_validator(mode="after")
    def interval(self):
        if self.numerator is not None and self.numerator > self.denominator:
            raise ValueError("invalid_metric")
        if (self.lower is None) != (self.upper is None) or (self.lower is not None and self.lower > self.upper):
            raise ValueError("invalid_interval")
        return self


class FamilyMetrics(Record):
    family_id: Identifier
    task_count: NonnegativeInt
    observed_count: NonnegativeInt
    missing_count: NonnegativeInt
    metrics: Annotated[Tuple[MetricInterval, ...], Field(max_length=64)]
    @model_validator(mode="after")
    def counts(self):
        if self.observed_count + self.missing_count != self.task_count:
            raise ValueError("invalid_counts")
        return self


class EvaluationRecord(Record):
    evaluation_id: Identifier
    authority_id: Identifier
    tuple: EvidenceTuple
    mode: Mode
    authorization_sha256: Hash
    budget_authority_id: Identifier
    budget_reference_sha256: Hash
    task_count: NonnegativeInt
    attempt_count: NonnegativeInt
    observed_count: NonnegativeInt
    missing_count: NonnegativeInt
    artifact_manifest_sha256: Hash
    families: Annotated[Tuple[FamilyMetrics, ...], Field(min_length=1, max_length=32)]
    status: Literal["pass", "fail", "inconclusive"]
    frozen_utc: UTC
    expires_utc: UTC
    @model_validator(mode="after")
    def evaluation(self):
        if self.expires_utc <= self.frozen_utc or self.observed_count + self.missing_count != self.task_count:
            raise ValueError("invalid_evaluation")
        if sum(f.task_count for f in self.families) != self.task_count or sum(f.observed_count for f in self.families) != self.observed_count:
            raise ValueError("invalid_counts")
        if len({f.family_id for f in self.families}) != len(self.families):
            raise ValueError("duplicate_identifier")
        if self.status == "pass" and (self.task_count == 0 or self.missing_count > 0):
            raise ValueError("incomplete_evaluation")
        return self


class ApprovalPayload(Record):
    domain: Literal["gateway.policy-approval.v1"] = "gateway.policy-approval.v1"
    decision_id: Identifier
    authority_id: Identifier
    decision: Literal["approve", "reject", "revoke"]
    tuple: EvidenceTuple
    evaluation_sha256: Hash
    artifact_manifest_sha256: Hash
    target_approval_sha256: Hash | None
    signer_fingerprint_sha256: Hash
    declared_os_account: SafeLabel
    recorded_utc: UTC
    reason: SafeLabel
    @model_validator(mode="after")
    def revocation_target(self):
        if (self.decision == "revoke") != (self.target_approval_sha256 is not None):
            raise ValueError("invalid_revocation_target")
        return self


class ApprovalRecord(ApprovalPayload):
    signature: Signature


def signed_payload(record: EvaluationAuthorizationPayload | ApprovalPayload) -> dict:
    """One payload contract for operator signing and runtime verification; no signing here."""
    if not isinstance(record, (EvaluationAuthorizationPayload, ApprovalPayload)):
        raise TypeError("unsupported_signed_record")
    return record.model_dump(mode="python", exclude={"signature"}, exclude_none=False)


def signed_bytes(record: EvaluationAuthorizationPayload | ApprovalPayload) -> bytes:
    return canonical_bytes(signed_payload(record))


class DependencyExpiry(Record):
    dependency: Literal["policy", "eval_spec", "evaluator_code", "corpus", "metric", "adapter_capability", "adapter", "price", "bound", "feature_schema"]
    sha256: Hash
    expires_utc: UTC


class EligibilityContext(Record):
    authority_id: Identifier
    mode: Mode
    tuple: EvidenceTuple
    dependency_expiries: Annotated[Tuple[DependencyExpiry, ...], Field(min_length=10, max_length=10)]
    evaluation_max_age_seconds: PositiveInt
    observed_utc: UTC
    clock_evidence_sha256: Hash
    @model_validator(mode="after")
    def dependency_identity(self):
        mapping = {"policy": "policy_bundle_sha256", "eval_spec": "eval_spec_sha256", "evaluator_code": "evaluator_code_sha256", "corpus": "corpus_sha256", "metric": "metric_sha256", "adapter_capability": "adapter_capability_sha256", "adapter": "adapter_sha256", "price": "price_sha256", "bound": "bound_sha256", "feature_schema": "feature_schema_sha256"}
        if len({d.dependency for d in self.dependency_expiries}) != 10:
            raise ValueError("missing_evidence")
        if any(d.sha256 != getattr(self.tuple, mapping[d.dependency]) for d in self.dependency_expiries):
            raise ValueError("evidence_mismatch")
        return self


class ActivationRecord(Record):
    authority_id: Identifier
    generation: PositiveInt
    expected_generation: NonnegativeInt
    event_kind: Literal["activate", "rollback"]
    policy_bundle_sha256: Hash
    evaluation_sha256: Hash
    approval_sha256: Hash
    recorded_utc: UTC
    reason: SafeLabel | None
    @model_validator(mode="after")
    def generation_step(self):
        if self.generation != self.expected_generation + 1:
            raise ValueError("generation_conflict")
        if self.event_kind == "rollback" and self.reason is None:
            raise ValueError("missing_reason")
        return self


class ActivePolicy(Record):
    authority_id: Identifier
    generation: PositiveInt
    policy_bundle_sha256: Hash
    evaluation_sha256: Hash
    approval_sha256: Hash
    activation_sha256: Hash


class IncidentEvidence(Record):
    authority_id: Identifier
    operation_id: Identifier
    child_id: Identifier
    attempt_id: Identifier
    provider: Provider
    source_sha256: Hash
    observed_cost_usd: Money | None
    reserved_usd: Money
    terminal_unknown_usd: Money
    authenticated: bool
    conflict: bool
    reason_code: Literal["bound_breach", "late_evidence", "evidence_conflict", "unauthenticated_evidence", "settlement_conflict"]
    recorded_utc: UTC


class IncidentRecord(Record):
    authority_id: Identifier
    operation_id: Identifier
    child_id: Identifier
    terminal_unknown_usd: Money
    maximum_credible_usd: Money | None
    uncovered_excess_usd: Money
    conflict: bool
    evidence_sha256: Hash
    @model_validator(mode="after")
    def excess(self):
        credible = 0 if self.maximum_credible_usd is None else usd_micros(self.maximum_credible_usd)
        expected = max(credible - usd_micros(self.terminal_unknown_usd), 0)
        if usd_micros(self.uncovered_excess_usd) != expected:
            raise ValueError("invalid_excess")
        return self


class HaltState(Record):
    authority_id: Identifier
    generation: NonnegativeInt
    emergency_stop: bool
    incident_halt: bool
    reason_codes: Annotated[Tuple[Literal["emergency_stop", "bound_breach", "late_evidence", "evidence_conflict", "unauthenticated_evidence", "settlement_conflict", "clock_rollback", "clock_untrusted", "store_unavailable"], ...], Field(max_length=16)]
    max_observed_utc: UTC

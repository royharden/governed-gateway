"""Operator/development report boundaries. Advisory data never grants dispatch authority."""
from __future__ import annotations

from decimal import Decimal
from typing import Annotated, Literal, Tuple

from pydantic import Field, model_validator

from .core import Hash, Identifier, Mode, Money, NonnegativeInt, PositiveInt, Record, SignedDecimal, UTC, money_from_micros, usd_micros
from .requests import RequestFeatures as RequestFeatures
from .governance import ApprovalPayload, EvidenceTuple, EvaluationRecord, HaltState
from .accounting import AccountingTotals
from .journey import OperationState


# Existing unsigned approval payload is the sole operator approval tuple.
ApprovalTuple = ApprovalPayload

# Signed dimensionless metrics/deltas share the canonical six-place primitive.

Probability = Annotated[SignedDecimal, Field(ge=Decimal("0"), le=Decimal("1"))]
Difference = Annotated[SignedDecimal, Field(ge=Decimal("-1"), le=Decimal("1"))]
Family = Literal["extraction", "evidence_qa", "transformation"]
IncompleteReason = Literal[
    "missing_evidence", "stale_evidence", "no_eligible_target", "missing_observation",
    "missing_pair", "missing_cost", "missing_bound", "missing_price", "missing_latency",
    "provenance_mismatch", "incompatible_mode", "missing_authorization", "insufficient_budget",
    "authority_violation", "unmeasured_benefit", "external_disabled",
]


class LiabilityEvidence(Record):
    target_id: Identifier
    maximum_liability_usd: Money | None
    price_sha256: Hash | None
    bound_sha256: Hash | None
    expires_utc: UTC | None


class ShadowContext(Record):
    operation_id: Identifier
    approved_bundle_sha256: Hash
    served_target_id: Identifier
    observed_result_ref: Identifier | None
    eligible_target_ids: Annotated[Tuple[Identifier, ...], Field(max_length=2)]
    target_liabilities: Annotated[Tuple[LiabilityEvidence, ...], Field(max_length=2)]
    observed_utc: UTC
    candidate_evidence_expires_utc: UTC | None
    @model_validator(mode="after")
    def identities(self):
        if len(set(self.eligible_target_ids)) != len(self.eligible_target_ids) or len({e.target_id for e in self.target_liabilities}) != len(self.target_liabilities):
            raise ValueError("duplicate_target")
        return self


class ShadowRecord(Record):
    operation_id: Identifier
    approved_bundle_sha256: Hash
    candidate_bundle_sha256: Hash
    served_target_id: Identifier
    recommended_target_id: Identifier | None
    rule_ids: Annotated[Tuple[Identifier, ...], Field(max_length=64)]
    recommendation_status: Literal["eligible", "ineligible"]
    incomplete_reason: IncompleteReason | None
    agreement: bool | None
    outcome_status: Literal["same_target_observed", "different_target_unobserved", "recorded_offline"] | None
    observed_result_ref: Identifier | None
    candidate_max_liability_usd: Money | None
    reservation_delta_usd: SignedDecimal | None
    price_sha256: Hash | None
    bound_sha256: Hash | None
    @model_validator(mode="after")
    def advisory_only(self):
        if self.recommendation_status == "ineligible":
            if self.incomplete_reason is None or any(v is not None for v in (self.recommended_target_id, self.agreement, self.outcome_status, self.observed_result_ref, self.candidate_max_liability_usd, self.reservation_delta_usd)):
                raise ValueError("invalid_ineligible_shadow")
        else:
            if self.recommended_target_id is None or self.agreement != (self.recommended_target_id == self.served_target_id):
                raise ValueError("invalid_shadow_recommendation")
            if self.outcome_status is None:
                raise ValueError("missing_shadow_outcome")
            if self.outcome_status == "same_target_observed" and (not self.agreement or self.observed_result_ref is None):
                raise ValueError("invalid_shadow_observation")
            if self.outcome_status == "different_target_unobserved" and (self.agreement or self.observed_result_ref is not None):
                raise ValueError("invalid_shadow_observation")
        if (self.candidate_max_liability_usd is None) != (self.reservation_delta_usd is None):
            raise ValueError("incomplete_reservation_comparison")
        if self.candidate_max_liability_usd is not None and (self.price_sha256 is None or self.bound_sha256 is None):
            raise ValueError("missing_liability_evidence")
        return self


class EvaluationSpec(Record):
    spec_id: Identifier
    version: PositiveInt
    evaluator_code_sha256: Hash
    corpus_sha256: Hash
    metric_sha256: Hash
    adapter_capability_sha256: Hash
    adapter_sha256: Hash
    price_sha256: Hash
    bound_sha256: Hash
    feature_schema_sha256: Hash
    mode: Mode
    matching_rules_sha256: Hash
    freshness_seconds: PositiveInt
    bootstrap_seed: NonnegativeInt
    bootstrap_resamples: Literal[10000] = 10000
    confidence_level: Annotated[Probability, Field(ge=Decimal("0.95"), le=Decimal("0.95"))]
    noninferiority_tolerance: Annotated[Probability, Field(ge=Decimal("0.05"), le=Decimal("0.05"))]
    benefit_metric_id: Identifier
    template_split_sha256: Hash
    family_weighting: Literal["equal"] = "equal"
    created_utc: UTC
    expires_utc: UTC
    @model_validator(mode="after")
    def expiry(self):
        if self.expires_utc <= self.created_utc or (self.mode == "simulation" and self.freshness_seconds != 86400):
            raise ValueError("invalid_evaluation_freshness")
        return self


class CorpusTask(Record):
    task_id: Identifier
    family: Family
    source_id: Identifier
    template_id: Identifier
    content_sha256: Hash
    matching_rules_sha256: Hash


class CorpusManifest(Record):
    corpus_id: Identifier
    version: PositiveInt
    split: Literal["development"] = "development"
    synthetic: Literal[True] = True
    tasks: Annotated[Tuple[CorpusTask, ...], Field(min_length=60, max_length=60)]
    matching_rules_sha256: Hash
    template_split_sha256: Hash
    created_utc: UTC
    @model_validator(mode="after")
    def development_counts(self):
        if len({t.task_id for t in self.tasks}) != 60 or any(sum(t.family == family for t in self.tasks) != 20 for family in ("extraction", "evidence_qa", "transformation")):
            raise ValueError("invalid_development_manifest")
        if any(t.matching_rules_sha256 != self.matching_rules_sha256 for t in self.tasks):
            raise ValueError("matching_rule_mismatch")
        return self


class AcquisitionReceipt(Record):
    acquisition_id: Identifier
    task_id: Identifier
    target_id: Identifier
    request_sha256: Hash
    exact_model: Identifier
    parameters_sha256: Hash
    profile_sha256: Hash
    adapter_sha256: Hash
    price_sha256: Hash
    bound_sha256: Hash
    outcome_status: Literal["ok", "refused", "truncated", "provider_error", "cancelled", "timeout", "missing"]
    response_ref: Identifier | None
    response_text: Annotated[str, Field(max_length=1048576, repr=False)] | None
    provider_receipt_sha256: Hash | None
    mode: Mode
    synthetic: bool
    reused: bool
    reuse_source_sha256: Hash | None
    original_acquisition_cost_usd: Money | None
    current_reuse_cost_usd: Money | None
    known_cost_usd: Money | None
    retained_liability_usd: Money
    attempt_count: NonnegativeInt
    latency_ms: Annotated[SignedDecimal, Field(ge=0)] | None
    acquired_utc: UTC
    @model_validator(mode="after")
    def provenance(self):
        if self.synthetic != (self.mode == "simulation"):
            raise ValueError("incompatible_provenance_mode")
        if self.response_text is not None and not self.synthetic:
            raise ValueError("nondevelopment_response_content")
        if self.reused != (self.reuse_source_sha256 is not None):
            raise ValueError("invalid_reuse_provenance")
        if self.outcome_status == "missing" and (self.response_text is not None or self.response_ref is not None or self.known_cost_usd is not None):
            raise ValueError("invalid_missing_outcome")
        return self


class SuccessEstimate(Record):
    assigned_count: NonnegativeInt
    observed_count: NonnegativeInt
    success_count: NonnegativeInt
    assigned_rate: Probability | None
    observed_rate: Probability | None
    wilson95_lower: Probability | None
    wilson95_upper: Probability | None
    method: Literal["wilson95"] = "wilson95"
    @model_validator(mode="after")
    def denominator(self):
        if not self.success_count <= self.observed_count <= self.assigned_count:
            raise ValueError("invalid_denominator")
        if (self.assigned_count == 0) != (self.assigned_rate is None) or (self.observed_count == 0) != (self.observed_rate is None):
            raise ValueError("invalid_missing_estimate")
        if (self.wilson95_lower is None) != (self.wilson95_upper is None) or (self.wilson95_lower is not None and self.wilson95_lower > self.wilson95_upper):
            raise ValueError("invalid_interval")
        return self


class PairedDifference(Record):
    family: Family
    paired_count: NonnegativeInt
    missing_pair_count: NonnegativeInt
    point: Difference | None
    lower95: Difference | None
    upper95: Difference | None
    method: Literal["paired_task_bootstrap95"] = "paired_task_bootstrap95"
    resamples: Literal[10000] = 10000
    seed: NonnegativeInt
    noninferiority: Literal["noninferior", "regression", "inconclusive", "incomplete"]
    @model_validator(mode="after")
    def interval(self):
        if self.missing_pair_count > 0 or self.paired_count == 0:
            if self.noninferiority != "incomplete" or any(v is not None for v in (self.point, self.lower95, self.upper95)):
                raise ValueError("incomplete_pair_interval")
        elif any(v is None for v in (self.point, self.lower95, self.upper95)):
            raise ValueError("missing_pair_interval")
        if self.lower95 is not None:
            if self.lower95 > self.upper95:
                raise ValueError("invalid_interval")
            expected = "noninferior" if self.lower95 >= Decimal("-0.05") else "regression" if self.upper95 < Decimal("-0.05") else "inconclusive"
            if self.noninferiority != expected:
                raise ValueError("invalid_noninferiority_claim")
        return self


class RouteEvaluation(Record):
    route: Literal["B0", "B1", "C", "s3_offline"]
    family: Family | None
    success: SuccessEstimate
    cost_known_count: NonnegativeInt
    known_cost_sum_usd: Money | None
    total_cost_usd: Money | None
    cost_per_success_usd: Money | None
    retained_liability_usd: Money
    latency_sample_count: NonnegativeInt
    latency_p50_ms: Annotated[SignedDecimal, Field(ge=0)] | None
    latency_p95_ms: Annotated[SignedDecimal, Field(ge=0)] | None
    latency_method: Literal["nearest_rank"] = "nearest_rank"
    incomplete_reasons: Annotated[Tuple[IncompleteReason, ...], Field(max_length=16)]
    @model_validator(mode="after")
    def missing_coverage(self):
        if self.cost_known_count > self.success.assigned_count or self.latency_sample_count > self.success.observed_count:
            raise ValueError("invalid_coverage")
        if self.cost_known_count < self.success.assigned_count and (self.total_cost_usd is not None or self.cost_per_success_usd is not None):
            raise ValueError("incomplete_cost")
        if self.success.success_count == 0 and self.cost_per_success_usd is not None:
            raise ValueError("zero_success_cost")
        if self.latency_sample_count == 0 and (self.latency_p50_ms is not None or self.latency_p95_ms is not None):
            raise ValueError("missing_latency")
        return self


class EvaluationReport(Record):
    report_id: Identifier
    tuple: EvidenceTuple
    evaluation_spec_sha256: Hash
    corpus_manifest_sha256: Hash
    authorization_sha256: Hash
    artifact_manifest_sha256: Hash
    mode: Mode
    synthetic: bool
    task_count: NonnegativeInt
    attempt_count: NonnegativeInt
    missing_observation_count: NonnegativeInt
    route_rows: Annotated[Tuple[RouteEvaluation, ...], Field(min_length=4, max_length=16)]
    paired_differences: Annotated[Tuple[PairedDifference, ...], Field(max_length=3)]
    authority_invariant_evidence_sha256: Hash | None
    authority_violation_count: NonnegativeInt | None
    compatibility_status: Literal["pass", "fail", "inconclusive"]
    benefit_status: Literal["measured", "unmeasured", "regression", "inconclusive"]
    status: Literal["pass", "fail", "inconclusive"]
    incomplete_reasons: Annotated[Tuple[IncompleteReason, ...], Field(max_length=16)]
    registered_evaluation: EvaluationRecord | None
    frozen_utc: UTC
    expires_utc: UTC
    @model_validator(mode="after")
    def evidence(self):
        if self.synthetic != (self.mode == "simulation") or self.expires_utc <= self.frozen_utc:
            raise ValueError("invalid_report_provenance")
        if self.corpus_manifest_sha256 != self.tuple.corpus_sha256 or self.evaluation_spec_sha256 != self.tuple.eval_spec_sha256:
            raise ValueError("report_tuple_mismatch")
        if len({(r.route, r.family) for r in self.route_rows}) != len(self.route_rows):
            raise ValueError("duplicate_report_row")
        if {r.route for r in self.route_rows if r.family is None} != {"B0", "B1", "C", "s3_offline"}:
            raise ValueError("missing_overall_rows")
        if self.status == "pass" and (self.task_count == 0 or self.missing_observation_count > 0 or self.incomplete_reasons or self.authority_violation_count != 0 or self.authority_invariant_evidence_sha256 is None):
            raise ValueError("incomplete_report")
        if any(p.noninferiority == "noninferior" for p in self.paired_differences) and (self.missing_observation_count > 0 or self.authority_violation_count != 0 or self.authority_invariant_evidence_sha256 is None):
            raise ValueError("unsupported_noninferiority_claim")
        if self.registered_evaluation is not None and (self.registered_evaluation.tuple != self.tuple or self.registered_evaluation.authorization_sha256 != self.authorization_sha256 or self.registered_evaluation.artifact_manifest_sha256 != self.artifact_manifest_sha256 or self.registered_evaluation.mode != self.mode):
            raise ValueError("registered_evaluation_mismatch")
        return self


class OverviewSnapshot(Record):
    authority_id: Identifier
    generation: NonnegativeInt
    active_policy_sha256: Hash | None
    accounting: AccountingTotals
    halt: HaltState
    maximum_credible_late_charge_usd: Money | None
    external_disabled_reason: Literal["external_disabled"] = "external_disabled"
    observed_utc: UTC
    @model_validator(mode="after")
    def identity(self):
        if self.accounting.authority_id != self.authority_id or self.halt.authority_id != self.authority_id:
            raise ValueError("authority_mismatch")
        return self


class OperationSummary(Record):
    authority_id: Identifier
    operation_id: Identifier
    caller_id: Identifier
    policy_bundle_sha256: Hash
    state: OperationState
    accounting: AccountingTotals
    maximum_credible_late_charge_usd: Money | None
    cancelled: bool
    result_expires_utc: UTC | None
    @model_validator(mode="after")
    def authority(self):
        if self.accounting.authority_id != self.authority_id:
            raise ValueError("authority_mismatch")
        return self


class PolicySummary(Record):
    policy_id: Identifier
    version: PositiveInt
    policy_bundle_sha256: Hash
    evaluation_sha256: Hash | None
    approval_sha256: Hash | None
    state: Literal["frozen", "evaluated_pass", "evaluated_fail", "approved", "rejected", "active", "superseded", "revoked"]
    generation: NonnegativeInt | None
    expires_utc: UTC
    eligible: bool
    incomplete_reason: IncompleteReason | None


class QuoteComponent(Record):
    component_id: Identifier
    category: Literal["heldout_generation", "smoke", "development", "controlled_failure", "count", "retry", "reuse"]
    tranche_id: Identifier
    authority_id: Identifier
    target_id: Identifier
    execution_count: NonnegativeInt
    expected_cost_per_execution_usd: Money | None
    maximum_liability_per_execution_usd: Money | None
    original_acquisition_cost_usd: Money | None
    reuse_source_sha256: Hash | None
    price_sha256: Hash | None
    bound_sha256: Hash | None
    incomplete_reasons: Annotated[Tuple[IncompleteReason, ...], Field(max_length=16)]
    @model_validator(mode="after")
    def evidence(self):
        if self.expected_cost_per_execution_usd is not None and self.price_sha256 is None:
            raise ValueError("missing_price")
        if self.maximum_liability_per_execution_usd is not None and (self.price_sha256 is None or self.bound_sha256 is None):
            raise ValueError("missing_bound")
        if self.category == "reuse" and self.reuse_source_sha256 is None:
            raise ValueError("missing_reuse_provenance")
        return self


class QuoteTranche(Record):
    tranche_id: Identifier
    authority_id: Identifier
    ceiling_usd: Money | None


class QuoteRequest(Record):
    quote_id: Identifier
    mode: Mode
    currency: Literal["USD"] = "USD"
    precision: Literal[6] = 6
    planned_task_count: PositiveInt
    planned_static_routes: Literal[2] = 2
    components: Annotated[Tuple[QuoteComponent, ...], Field(min_length=1, max_length=1024)]
    tranches: Annotated[Tuple[QuoteTranche, ...], Field(min_length=1, max_length=32)]
    observed_utc: UTC
    @model_validator(mode="after")
    def references(self):
        ids = {t.tranche_id: t.authority_id for t in self.tranches}
        if len(ids) != len(self.tranches) or len({c.component_id for c in self.components}) != len(self.components):
            raise ValueError("duplicate_quote_identity")
        if any(ids.get(c.tranche_id) != c.authority_id for c in self.components):
            raise ValueError("quote_authority_mismatch")
        return self


class AcquisitionQuote(Record):
    quote_id: Identifier
    request_sha256: Hash
    mode: Mode
    currency: Literal["USD"] = "USD"
    precision: Literal[6] = 6
    components: Annotated[Tuple[QuoteComponent, ...], Field(min_length=1, max_length=1024)]
    tranches: Annotated[Tuple[QuoteTranche, ...], Field(min_length=1, max_length=32)]
    expected_total_usd: Money | None
    maximum_reserved_total_usd: Money | None
    aggregate_authorized_ceiling_usd: Money | None
    unknown_liability_sensitivity_usd: Money | None
    complete: bool
    combined_cap_enforced: Literal[False] = False
    incomplete_reasons: Annotated[Tuple[IncompleteReason, ...], Field(max_length=16)]
    created_utc: UTC
    @model_validator(mode="after")
    def totals(self):
        def total(values):
            return None if any(v is None for v in values) else money_from_micros(sum(values))
        expected = total(tuple(None if c.expected_cost_per_execution_usd is None else usd_micros(c.expected_cost_per_execution_usd) * c.execution_count for c in self.components))
        maximum = total(tuple(None if c.maximum_liability_per_execution_usd is None else usd_micros(c.maximum_liability_per_execution_usd) * c.execution_count for c in self.components))
        ceiling = total(tuple(None if t.ceiling_usd is None else usd_micros(t.ceiling_usd) for t in self.tranches))
        if (self.expected_total_usd, self.maximum_reserved_total_usd, self.aggregate_authorized_ceiling_usd) != (expected, maximum, ceiling):
            raise ValueError("quote_total_mismatch")
        if self.complete and (self.incomplete_reasons or any(c.incomplete_reasons for c in self.components) or expected is None or maximum is None or ceiling is None):
            raise ValueError("incomplete_quote")
        ids = {t.tranche_id: t.authority_id for t in self.tranches}
        if len(ids) != len(self.tranches) or len({c.component_id for c in self.components}) != len(self.components) or any(ids.get(c.tranche_id) != c.authority_id for c in self.components):
            raise ValueError("quote_identity_mismatch")
        if self.complete:
            if sum(c.execution_count for c in self.components if c.category == "heldout_generation") < 240 or sum(c.execution_count for c in self.components if c.category == "smoke") < 20:
                raise ValueError("incomplete_acquisition_plan")
            if any(sum(usd_micros(c.maximum_liability_per_execution_usd) * c.execution_count for c in self.components if c.tranche_id == t.tranche_id) > usd_micros(t.ceiling_usd) for t in self.tranches):
                raise ValueError("insufficient_tranche_budget")
        return self


class CleanupReport(Record):
    authority_id: Identifier
    examined_count: NonnegativeInt
    purged_ciphertext_count: NonnegativeInt
    retained_tombstone_count: NonnegativeInt
    blocked_operation_ids: Annotated[Tuple[Identifier, ...], Field(max_length=4096)]
    next_cursor: Identifier | None
    observed_utc: UTC
    @model_validator(mode="after")
    def counts(self):
        if self.purged_ciphertext_count > self.examined_count or self.retained_tombstone_count < self.purged_ciphertext_count:
            raise ValueError("invalid_cleanup_counts")
        return self

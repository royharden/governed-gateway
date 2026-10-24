"""Thin operator commands over canonical governance ports; no policy authority here."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from gateway.schemas import (
    ActivationRecord, ApprovalRecord, EligibilityContext, ErrorCode,
    EvaluationAuthorization, EvaluationRecord, GatewayError, PolicyBundle, digest,
)
from gateway.schemas.operator import (
    EvaluationReport, OperationSummary, OverviewSnapshot, PolicySummary,
)
from gateway.evaluation.artifacts import EvaluationArtifacts, validate_artifacts


class GovernancePort(Protocol):
    def freeze(self, bundle: PolicyBundle) -> str: ...
    def authorize_evaluation(self, authorization: EvaluationAuthorization) -> str: ...
    def record_evaluation(self, record: EvaluationRecord) -> str: ...
    def verify_approval(self, approval: ApprovalRecord) -> str: ...
    def activate(self, approval_sha256: str, *, expected_generation: int,
                 context: EligibilityContext) -> ActivationRecord: ...
    def rollback(self, approval_sha256: str, *, expected_generation: int,
                 context: EligibilityContext, reason: str) -> ActivationRecord: ...


@dataclass(frozen=True)
class OperatorServices:
    """Trusted composition supplies projections/context; CLI JSON cannot supply them."""
    governance: GovernancePort
    context_for_approval: Callable[[str], EligibilityContext]
    overview: Callable[[], OverviewSnapshot]
    operations: Callable[[int], tuple[OperationSummary, ...]]
    policies: Callable[[int], tuple[PolicySummary, ...]]


def _generation(value: int | None) -> int:
    if value is None:
        return 0  # Canonical genesis CAS; never unconditional activation.
    if type(value) is not int or value < 0:
        raise GatewayError(ErrorCode.GENERATION_CONFLICT)
    return value


def activate(services: OperatorServices, approval_sha256: str, *,
             expected_generation: int | None) -> ActivationRecord:
    context = services.context_for_approval(approval_sha256)
    if context.mode != "simulation":
        raise GatewayError(ErrorCode.EXTERNAL_DISABLED)
    return services.governance.activate(approval_sha256, expected_generation=_generation(expected_generation),
                                        context=context)


def rollback(services: OperatorServices, approval_sha256: str, *,
             expected_generation: int | None, reason: str) -> ActivationRecord:
    context = services.context_for_approval(approval_sha256)
    if context.mode != "simulation":
        raise GatewayError(ErrorCode.EXTERNAL_DISABLED)
    # Eligibility/freshness/revocation and the CAS remain producer transactions.
    return services.governance.rollback(approval_sha256, expected_generation=_generation(expected_generation),
                                        context=context, reason=reason)


def register_evaluation(services: OperatorServices, report: EvaluationReport,
                         authorization: EvaluationAuthorization,
                         record: EvaluationRecord, *, artifacts: EvaluationArtifacts) -> str:
    """Validate explicit detailed-report -> governance-record conversion before insert."""
    validate_artifacts(report, artifacts)
    if report.mode != "simulation" or authorization.mode != "simulation" or record.mode != "simulation":
        raise GatewayError(ErrorCode.EXTERNAL_DISABLED)
    if (report.tuple != record.tuple or report.tuple != authorization.tuple
            or record.authorization_sha256 != digest(authorization)
            or report.authorization_sha256 != record.authorization_sha256
            or report.artifact_manifest_sha256 != record.artifact_manifest_sha256
            or authorization.authority_id != record.authority_id
            or authorization.budget_authority_id != record.budget_authority_id
            or authorization.budget_reference_sha256 != record.budget_reference_sha256
            or report.expires_utc != record.expires_utc or report.frozen_utc != record.frozen_utc
            or record.expires_utc > authorization.expires_utc
            or report.attempt_count != record.attempt_count
            or report.status != record.status):
        raise GatewayError(ErrorCode.INVALID_EVIDENCE)
    # Governance counts represent C's assigned task population, not four offline row copies.
    candidate = {row.family: row for row in report.route_rows if row.route == "C"}
    if set(candidate) != {None, "extraction", "evidence_qa", "transformation"}:
        raise GatewayError(ErrorCode.INVALID_EVIDENCE)
    overall = candidate[None].success
    if (record.task_count != report.task_count or record.task_count != overall.assigned_count
            or record.observed_count != overall.observed_count
            or record.missing_count != overall.assigned_count - overall.observed_count):
        raise GatewayError(ErrorCode.INVALID_EVIDENCE)
    by_family = {family.family_id: family for family in record.families}
    if set(by_family) != {"extraction", "evidence_qa", "transformation"}:
        raise GatewayError(ErrorCode.INVALID_EVIDENCE)
    for name, family in by_family.items():
        row = candidate[name].success
        if (family.task_count != row.assigned_count or family.observed_count != row.observed_count
                or family.missing_count != row.assigned_count - row.observed_count):
            raise GatewayError(ErrorCode.INVALID_EVIDENCE)
        if len(family.metrics) != 1 or family.metrics[0].metric_id != "success":
            raise GatewayError(ErrorCode.INVALID_EVIDENCE)
        success = family.metrics[0]
        if (success.numerator != row.success_count
                or success.denominator != row.assigned_count
                or success.lower != row.wilson95_lower or success.upper != row.wilson95_upper):
            raise GatewayError(ErrorCode.INVALID_EVIDENCE)
    if report.registered_evaluation is not None and report.registered_evaluation != record:
        raise GatewayError(ErrorCode.INVALID_EVIDENCE)
    if report.status == "pass" and (report.compatibility_status != "pass"
                                    or report.authority_violation_count != 0
                                    or report.authority_invariant_evidence_sha256 is None):
        raise GatewayError(ErrorCode.INVALID_EVIDENCE)
    # Signature and persisted authorization are checked by the producer, never a local success stub.
    return services.governance.record_evaluation(record)

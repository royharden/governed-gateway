"""Strict body-free joins for limited developer simulation observations.

These checks establish canonical identity and receipt coverage. Authenticity of
the guarded journal and acquisition authorizations remains with composition;
this module cannot establish execution, independent custody or full acceptance.
"""
from __future__ import annotations

import hashlib
import re
from decimal import Decimal

from gateway.schemas.accounting import AccountingTotals
from gateway.schemas.core import ErrorCode, GatewayError, canonical_bytes, digest, usd_micros
from gateway.schemas.governance import EvidenceTuple


RECEIPT_FIELDS = {
    "acquisition_id", "task_id", "target_id", "receipt_sha256", "request_sha256",
    "parameters_sha256", "exact_model_sha256", "profile_sha256", "adapter_sha256",
    "price_sha256", "bound_sha256", "provider_receipt_sha256", "reused",
    "reuse_source_sha256", "acquired_utc", "fresh_until_utc", "outcome_status",
    "response_ref", "response_text_sha256", "original_acquisition_cost_usd",
    "current_reuse_cost_usd", "known_cost_usd", "retained_liability_usd",
    "attempt_count", "latency_ms", "mode", "synthetic",
}


def receipt_identity(receipt, fresh_until) -> dict:
    """Bind full canonical receipt identity without exporting its response body."""
    fields = RECEIPT_FIELDS - {"receipt_sha256", "exact_model_sha256",
                              "response_text_sha256", "fresh_until_utc"}
    return {**{field: getattr(receipt, field) for field in fields},
            "receipt_sha256": digest(receipt), "exact_model_sha256": digest(receipt.exact_model),
            "response_text_sha256": (None if receipt.response_text is None else
                hashlib.sha256(receipt.response_text.encode("utf-8")).hexdigest()),
            "fresh_until_utc": fresh_until}


def _require(condition: bool) -> None:
    if not condition:
        raise GatewayError(ErrorCode.INVALID_EVIDENCE)


def amount(value, *, nullable: bool = False) -> None:
    if nullable and value is None:
        return
    _require(type(value) is str and re.fullmatch(r"(?:0|[1-9][0-9]*)(?:\.[0-9]{1,6})?", value) is not None)
    usd_micros(Decimal(value))


def validate_observations(document: dict, report, inputs: dict, *, shape, hash_value,
                          identifier, count, utc) -> None:
    """Validate journal011 plus required015 operation totals and original coverage."""
    shape(document, {"schema_version", "domain", "scope", "tuple", "candidate_sha256",
                     "evaluator_code_sha256", "authorization_sha256", "facts", "violation_count"})
    scoring_tuple = EvidenceTuple.model_validate_json(canonical_bytes(document["tuple"]))
    _require(canonical_bytes(document["tuple"]) == canonical_bytes(scoring_tuple)
             and scoring_tuple == report.tuple
             and type(document["schema_version"]) is int and document["schema_version"] == 1
             and document["domain"] == "gateway.simulation-observations.v1"
             and document["scope"] == "developer-owned-limited-observations"
             and document["candidate_sha256"] == scoring_tuple.policy_bundle_sha256
             and document["evaluator_code_sha256"] == scoring_tuple.evaluator_code_sha256
             and document["authorization_sha256"] == report.authorization_sha256)
    count(document["violation_count"])
    _require(document["violation_count"] == report.authority_violation_count)
    facts = document["facts"]
    _require(type(facts) is list and 0 < len(facts) <= 4096)
    dependency_hash = digest(scoring_tuple.model_dump(exclude={"policy_bundle_sha256"}))
    base_checks = {"configured_simulation_authority", "candidate_exact_tuple",
                   "bounded_authority_exposure", "no_observed_breach_or_conflict",
                   "successful_terminal_observed", "committed_policy_and_ledger_observed"}
    staged_checks = {"immutable_request_binding", "actual_committed_join", "single_claim_per_declared_child",
                     "known_staged_original_settlement", "terminal_expiry_is_policy_owned"}
    seen, providers = set(), {}
    violations = 0
    for fact in facts:
        shape(fact, {"schema_version", "scope", "authority_id", "tuple_sha256", "dependency_tuple_sha256",
                     "candidate_sha256", "evaluator_code_sha256", "authorization_sha256", "operation_id",
                     "request_sha256", "reply_http_status", "reply_code", "checks", "policy_snapshot_sha256",
                     "ledger_snapshot_sha256", "provider_receipt_sha256", "target_id", "outcome_status",
                     "response_text_sha256", "known_cost_usd", "attempt_count", "retained_liability_usd",
                     "latency_ms", "accounting", "operation_accounting", "observed_utc"})
        _require(type(fact["schema_version"]) is int and fact["schema_version"] == 1
                 and fact["scope"] == "developer-observed-simulation-only"
                 and fact["authority_id"] == inputs["authority_id"]
                 and fact["evaluator_code_sha256"] == scoring_tuple.evaluator_code_sha256
                 and fact["dependency_tuple_sha256"] == dependency_hash
                 and utc(fact["observed_utc"]) <= report.frozen_utc)
        identifier(fact["authority_id"])
        for field in ("tuple_sha256", "dependency_tuple_sha256", "candidate_sha256",
                      "evaluator_code_sha256", "authorization_sha256", "request_sha256"):
            hash_value(fact[field])
        actual_tuple = EvidenceTuple.model_validate_json(canonical_bytes({
            **scoring_tuple.model_dump(), "policy_bundle_sha256": fact["candidate_sha256"]}))
        _require(fact["tuple_sha256"] == digest(actual_tuple))
        for field in ("policy_snapshot_sha256", "ledger_snapshot_sha256",
                      "provider_receipt_sha256", "response_text_sha256"):
            hash_value(fact[field], nullable=True)
        for field in ("operation_id", "target_id"):
            if fact[field] is not None:
                identifier(fact[field])
        _require(type(fact["reply_http_status"]) is int
                 and fact["reply_http_status"] in (200, 202, 400, 401, 403, 409, 410, 429, 502, 503, 504)
                 and (fact["reply_code"] is None or fact["reply_code"] in {code.value for code in ErrorCode})
                 and (fact["reply_http_status"] < 400 or fact["reply_code"] is not None)
                 and fact["outcome_status"] in ("ok", "refused", "truncated", "provider_error", "cancelled", "timeout", None))
        for field in ("known_cost_usd", "retained_liability_usd", "latency_ms"):
            amount(fact[field], nullable=True)
        if fact["attempt_count"] is not None:
            count(fact["attempt_count"])
        accounting = AccountingTotals.model_validate_json(canonical_bytes(fact["accounting"]))
        _require(canonical_bytes(accounting) == canonical_bytes(fact["accounting"])
                 and accounting.authority_id == fact["authority_id"])
        operation = None
        ledger_present = fact["ledger_snapshot_sha256"] is not None
        if fact["operation_accounting"] is None:
            # Null means no verified ledger operation, never an invented healthy zero.
            _require(not ledger_present and fact["known_cost_usd"] is None
                     and fact["retained_liability_usd"] is None and fact["attempt_count"] is None)
        else:
            operation = AccountingTotals.model_validate_json(canonical_bytes(fact["operation_accounting"]))
            _require(canonical_bytes(operation) == canonical_bytes(fact["operation_accounting"])
                     and ledger_present and fact["operation_id"] is not None
                     and operation.authority_id == accounting.authority_id
                     and operation.cap_usd == accounting.cap_usd
                     and fact["attempt_count"] is not None
                     and fact["retained_liability_usd"] is not None)
            retained = sum(usd_micros(value) for value in (
                operation.future_usd, operation.active_usd, operation.unknown_usd,
                operation.uncovered_excess_usd))
            _require(usd_micros(Decimal(fact["retained_liability_usd"])) == retained)
            # K is still visible in operation_accounting when total cost is unknown.
            if retained:
                _require(fact["known_cost_usd"] is None)
            elif fact["known_cost_usd"] is not None:
                _require(usd_micros(Decimal(fact["known_cost_usd"])) == usd_micros(operation.known_usd))
        committed = fact["policy_snapshot_sha256"] is not None and fact["ledger_snapshot_sha256"] is not None
        checks = fact["checks"]
        shape(checks, base_checks | staged_checks if committed else base_checks)
        _require(all(type(value) is bool for value in checks.values())
                 and checks["successful_terminal_observed"] == (fact["reply_http_status"] == 200)
                 and checks["bounded_authority_exposure"] == (accounting.exposure_usd <= accounting.cap_usd)
                 and checks["no_observed_breach_or_conflict"] == (not accounting.halted and not accounting.conflict
                     and accounting.excess_usd == 0 and accounting.uncovered_excess_usd == 0)
                 and checks["committed_policy_and_ledger_observed"] == committed)
        if fact["known_cost_usd"] is not None:
            # The trusted collector verifies original settlement/staged-receipt
            # proof. A bad public result may itself be an observed violation;
            # do not discard the real committed charge in that failure record.
            _require(operation is not None and committed and checks["actual_committed_join"]
                     and fact["provider_receipt_sha256"] is not None)
        violations += sum(not passed for passed in checks.values())
        key = digest(fact)
        _require(key not in seen)
        seen.add(key)
        provider = fact["provider_receipt_sha256"]
        if provider is not None:
            _require(provider not in providers and committed and fact["operation_id"] is not None
                     and fact["target_id"] is not None and fact["outcome_status"] is not None
                     and fact["attempt_count"] is not None and fact["retained_liability_usd"] is not None)
            providers[provider] = fact
    _require(document["violation_count"] == violations)
    sources = {item["receipt_sha256"]: item for item in inputs["reuse_source_identities"]}
    covered = {}
    for receipt in inputs["acquisition_identities"]:
        original = sources[receipt["reuse_source_sha256"]] if receipt["reused"] else receipt
        provider = original["provider_receipt_sha256"]
        if provider is None:
            _require(report.status != "pass" and report.compatibility_status != "pass"
                     and "missing_evidence" in report.incomplete_reasons)
            continue
        _require(provider not in covered or covered[provider] == original["receipt_sha256"])
        covered[provider] = original["receipt_sha256"]
        fact = providers.get(provider)
        _require(fact is not None)
        fields = {"request_sha256": "request_sha256", "target_id": "target_id",
                  "response_ref": "operation_id", "outcome_status": "outcome_status",
                  "response_text_sha256": "response_text_sha256", "known_cost_usd": "known_cost_usd",
                  "retained_liability_usd": "retained_liability_usd", "attempt_count": "attempt_count",
                  "latency_ms": "latency_ms"}
        _require(all(original[left] == fact[right] for left, right in fields.items())
                 and utc(original["acquired_utc"]) <= utc(fact["observed_utc"]))

"""Policy-side implementation of the ACCOUNT-owned AccountingGate protocol.

No ledger, configuration, signature, or claim authority is duplicated here.
The controller must keep the shared authority lock through claim and handoff.
"""

from datetime import datetime

from gateway.schemas import (
    AccountingIncident, ActivationRecord, EvaluationAuthorization, IncidentEvidence,
    IncidentReceipt, IncidentRecord, IncidentSnapshot, OperationPermit, PermitState,
    PolicyBundle, UnstartedProof, canonical_bytes, digest, money_from_micros, usd_micros,
)

from .eligibility import require, verify_operator
from .store import PolicyStore, decode_record


class AccountingGate:
    def __init__(self, store: PolicyStore) -> None:
        self.store = store

    def validate_funding(self, permit: OperationPermit, *, now: datetime) -> None:
        store = self.store
        require(store._assert_lock_held is not None, "dependency_unavailable")
        store._assert_lock_held()
        with store._transaction(operation_id=permit.operation_id) as (connection, observed, state):
            require(abs((observed - now).total_seconds()) <= 5, "clock_untrusted")
            store._healthy(state)
            row = store._permit_row(connection, permit.operation_id)
            require(canonical_bytes(store._permit_value(row)) == canonical_bytes(permit), "permit_mismatch")
            require(row["state"] in (PermitState.PERMITTED.value, PermitState.FUNDED.value), "invalid_transition")
            operation = store._operation_row(connection, permit.operation_id)
            require(not operation["cancelled"] and observed < permit.expires_utc, "permit_expired")
            context = store._current.get()[2][1]
            require(context is not None, "missing_evidence")
            if permit.purpose == "serve":
                event_row = connection.execute(
                    "SELECT hash,canonical FROM activation_events WHERE authority_id=? AND generation=?",
                    (store.authority_id, permit.policy_generation),
                ).fetchone()
                require(event_row is not None, "invalid_permit")
                event = decode_record(bytes(event_row["canonical"]), ActivationRecord, event_row["hash"])
                require(event.policy_bundle_sha256 == permit.policy_bundle_sha256, "invalid_permit")
                store._eligible(connection, event.approval_sha256, context, observed, grandfathered=True)
            else:
                require(permit.purpose == "eval", "invalid_permit")
                bundle = store._load(connection, "policy_bundles", permit.policy_bundle_sha256, PolicyBundle)
                store._context(connection, bundle, context, observed)
                authorization = store._load(connection, "evaluation_authorizations",
                                            permit.evaluation_authorization_sha256, EvaluationAuthorization)
                verify_operator(authorization, store._key)
                require(authorization.authority_id == permit.authority_id
                        and authorization.budget_authority_id == permit.authority_id
                        and authorization.mode == "simulation" and authorization.tuple == context.tuple
                        and authorization.created_utc <= observed < permit.expires_utc <= authorization.expires_utc,
                        "invalid_authorization")

    def validate_dispatch(self, *, operation_id: str, child_id: str,
                          permit_sha256: str, now: datetime) -> None:
        store = self.store
        require(store._assert_lock_held is not None, "dependency_unavailable")
        store._assert_lock_held()
        with store._transaction(operation_id=operation_id) as (connection, observed, _state):
            require(abs((observed - now).total_seconds()) <= 5, "clock_untrusted")
            permit = store._permit_value(store._permit_row(connection, operation_id))
            require(digest(permit) == permit_sha256, "permit_mismatch")
            ledger = store._ledger(operation_id)
            require(ledger is not None, "invalid_join")
            context = store._current.get()[2][1]
            require(context is not None, "missing_evidence")
            store.assert_dispatch_allowed(operation_id, ledger.join, context=context)
            attempt = next((item for item in ledger.attempts if item.child_id == child_id), None)
            require(attempt is not None and attempt.state == "future" and attempt.attempt_id is None,
                    "already_claimed")
            child = next((item for item in permit.attempt_children if item.child_id == child_id), None)
            require(child is not None, "invalid_permit")
            if child.conditional:
                store._require_retry_event(connection, operation_id, child_id)

    def authorize_unstarted(self, proof: UnstartedProof, *, now: datetime) -> None:
        """Authorize cleanup from actual persisted stopping facts, never DTO flags."""
        store = self.store
        require(proof.authority_id == store.authority_id, "authority_mismatch")
        require(store._assert_lock_held is not None, "dependency_unavailable")
        store._assert_lock_held()
        with store._transaction() as (connection, observed, _state):
            require(abs((observed - now).total_seconds()) <= 5, "clock_untrusted")
            operation = store._operation_row(connection, proof.operation_id)
            permit = store._permit_value(store._permit_row(connection, proof.operation_id))
            ledger = store._ledger(proof.operation_id)
            require(ledger is not None, "invalid_join")
            store._join(connection, permit, ledger.join)
            require(proof.allocation_id == ledger.join.allocation_id
                    and proof.proof_sha256 == digest({"allocation_id": ledger.join.allocation_id,
                        "child_id": proof.child_id, "undispatched": True}), "invalid_evidence")
            child = next((child for child in permit.attempt_children if child.child_id == proof.child_id), None)
            attempt = next((item for item in ledger.attempts if item.child_id == proof.child_id), None)
            require(child is not None and attempt is not None and attempt.attempt_id is None
                    and attempt.state in ("future", "closed_unstarted"), "invalid_evidence")
            if proof.reason == "skipped":
                require(child.conditional, "invalid_evidence")
            if operation["cancelled"] or observed >= permit.expires_utc:
                return
            require(child.conditional and proof.reason == "skipped", "invalid_evidence")
            primary = ledger.attempts[0]
            # Terminal unknown can never authorize a retry, so an unused optional
            # child is unnecessary even while the retained primary U remains.
            if primary.state == "unknown":
                require(primary.settlement_sha256 is not None, "invalid_evidence")
                return
            stage, purged = store._stage_value(connection, operation, permit)
            require(primary.state == "known" and primary.settlement_sha256 is not None
                    and stage is not None and not purged and stage.receipt.attempt_id == primary.attempt_id
                    and stage.receipt.state == "known", "invalid_evidence")
            if stage.receipt.status in ("ok", "refused", "truncated") or stage.receipt.known_usage_cost_usd > 0:
                return
            require(store._retry_reader is not None, "dependency_unavailable")
            result = store._retry_reader(proof.operation_id, primary.child_id)
            require(result is not None and result.provider == stage.receipt.provider
                    and result.model == stage.receipt.model, "invalid_evidence")
            require(not (result.status == "provider_error" and result.dispatch_state == "not_sent"
                         and result.retry_evidence == "pre_send_certain"), "invalid_evidence")

    def incident_snapshot(self, *, authority_id: str) -> IncidentSnapshot:
        return self._snapshot(authority_id=authority_id, operation_id=None)

    def operation_incident_snapshot(self, operation_id: str) -> IncidentSnapshot:
        return self._snapshot(authority_id=self.store.authority_id, operation_id=operation_id)

    def _snapshot(self, *, authority_id: str, operation_id: str | None) -> IncidentSnapshot:
        store = self.store
        require(authority_id == store.authority_id, "authority_mismatch")
        require(store._assert_lock_held is not None, "dependency_unavailable")
        store._assert_lock_held()
        with store._transaction() as (connection, _now, _state):
            if operation_id is not None:
                store._permit_row(connection, operation_id)
            scope = "authority_id=?" + (" AND operation_id=?" if operation_id is not None else "")
            parameters = (authority_id,) if operation_id is None else (authority_id, operation_id)
            rows = connection.execute("SELECT canonical FROM incident_maxima WHERE " + scope
                                      + " ORDER BY operation_id,child_id", parameters).fetchall()
            records = tuple(decode_record(bytes(row[0]), IncidentRecord) for row in rows)
            evidence = connection.execute("SELECT hash,authenticated,conflict FROM incident_evidence WHERE "
                                          + scope + " ORDER BY hash", parameters).fetchall()
            state = store._status(connection)
            credible = [record.maximum_credible_usd for record in records if record.maximum_credible_usd is not None]
            return IncidentSnapshot(
                authority_id=authority_id,
                terminal_unknown_usd=money_from_micros(sum(usd_micros(record.terminal_unknown_usd) for record in records)),
                maximum_credible_usd=(None if not credible else money_from_micros(sum(usd_micros(value) for value in credible))),
                uncovered_excess_usd=money_from_micros(sum(usd_micros(record.uncovered_excess_usd) for record in records)),
                conflict=any(record.conflict for record in records)
                    or any(not row["authenticated"] or row["conflict"] for row in evidence),
                halted=state.emergency_stop or state.incident_halt,
                evidence_sha256=digest({"schema_version": 1, "authority_id": authority_id,
                                        "operation_id": operation_id,
                                        "evidence": tuple(row["hash"] for row in evidence), "maxima": records}),
            )

    def record_accounting_incident(self, incident: AccountingIncident) -> IncidentReceipt:
        store = self.store
        require(store._assert_lock_held is not None, "dependency_unavailable")
        store._assert_lock_held()
        evidence = IncidentEvidence.model_validate(incident.model_dump(mode="python"))
        key = digest(evidence)
        with store._transaction() as (connection, _now, _state):
            duplicate = connection.execute("SELECT 1 FROM incident_evidence WHERE hash=?", (key,)).fetchone() is not None
            record = store.append_incident(evidence)
            state = store._status(connection)
            return IncidentReceipt(authority_id=store.authority_id, incident_sha256=key,
                                    uncovered_excess_usd=record.uncovered_excess_usd,
                                    halted=state.emergency_stop or state.incident_halt,
                                    conflict=record.conflict, duplicate=duplicate)

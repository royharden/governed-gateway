"""Bounded operator recovery; never a lease refund, watcher or ticket reconstruction."""
from __future__ import annotations

from datetime import datetime, timedelta

from gateway.schemas import (
    ErrorCode, GatewayError, OperationState, RecoveryEvidence, RecoverySummary,
    UnknownReason, UnstartedProof, digest,
)


def close_future_children(controller, permit, *, reason: str, now: datetime) -> None:
    controller.guard.assert_held(authority_id=permit.authority_id)
    state = controller.ledger.operation_state(permit.operation_id)
    if state is None:
        raise GatewayError(ErrorCode.INVALID_JOIN)
    controller._join(permit)
    for child in state.attempts:
        if child.state != "future":
            continue
        planned = next(c for c in permit.attempt_children if c.child_id == child.child_id)
        if reason == "skipped" and not planned.conditional:
            # A primary is not optional just because cleanup runs.
            continue
        evidence = RecoveryEvidence(authority_id=permit.authority_id,
            operation_id=permit.operation_id, child_id=child.child_id, attempt_id=None,
            observed_utc=now, expires_utc=permit.expires_utc,
            cancelled=reason == "cancelled_before_dispatch", owner_pid=None,
            owner_process_instance_id=None, owner_exit_evidence_sha256=None,
            staged_settlement_sha256=None)
        proof = UnstartedProof(authority_id=permit.authority_id, operation_id=permit.operation_id,
            child_id=child.child_id, allocation_id=state.join.allocation_id, reason=reason,
            proof_sha256=digest({"allocation_id": state.join.allocation_id,
                                 "child_id": child.child_id, "undispatched": True}),
            recovery_evidence=evidence)
        controller.ledger.close_unstarted(proof)


def recover(controller, authority_id: str, *, now: datetime, ownership=(), cursor=None,
            limit: int = 256) -> RecoverySummary:
    if not 1 <= limit <= 1024 or now.utcoffset() is None or now.utcoffset().total_seconds() != 0:
        raise GatewayError(ErrorCode.INVALID_EVIDENCE)
    closed, retained, blocked, incidents = [], [], [], []
    with controller.guard.hold(authority_id):
        # Enforce trusted wall/monotonic clock through producers, not operator input.
        if abs((controller.now() - now).total_seconds()) > 1:
            raise GatewayError(ErrorCode.CLOCK_UNTRUSTED)
        policy_page = controller.policies.recovery_candidates(authority_id, cursor=cursor, limit=limit)
        ledger_page = controller.ledger.recovery_candidates(authority_id, cursor=cursor, limit=limit)
        if policy_page.authority_id != authority_id:
            raise GatewayError(ErrorCode.AUTHORITY_MISMATCH)
        policies = {row.operation_id: row for row in policy_page.items}
        ledger_rows = {row.operation_id: row for row in ledger_page.items}
        operations = sorted(set(policies) | set(ledger_rows))
        if any(operation <= (cursor or "") for operation in operations):
            raise GatewayError(ErrorCode.INVALID_EVIDENCE)
        # Both producers paginate by immutable lexicographic operation ID. Advance
        # only to the smaller page frontier so neither stream can be skipped.
        more = policy_page.next_cursor is not None or ledger_page.next_cursor is not None
        frontiers = [page.items[-1].operation_id for page in (policy_page, ledger_page) if page.items]
        next_cursor = min(frontiers) if more and frontiers else None
        if more and next_cursor is None:
            raise GatewayError(ErrorCode.INVALID_EVIDENCE)
        for operation in operations:
            try:
                snapshot = policies.get(operation) or controller.policies.operation_snapshot(operation)
                ledger = ledger_rows.get(operation) or controller.ledger.operation_state(operation)
                if snapshot is None:
                    # A bounded policy page may omit a real permit; do not call it an orphan.
                    permit = controller.policies.get_permit(operation)
                    if permit is not None:
                        retained.append(operation)
                        continue
                    fingerprint = digest({"domain": "gateway.orphan-ledger.v1",
                        "authority_id": authority_id, "operation_id": operation,
                        "ledger_context_sha256": ledger.ledger_context_sha256})
                    controller.policies.halt(reason_code="store_unavailable", evidence_sha256=fingerprint)
                    controller._unsafe_authorities.add(authority_id)
                    blocked.append(operation)
                    incidents.append(fingerprint)
                    continue
                permit = snapshot.permit
                if ledger is None:
                    if now >= permit.expires_utc or snapshot.cancelled:
                        if controller.policies.abandon_unfunded(operation, now=now):
                            closed.append(operation)
                        else:
                            retained.append(operation)
                    else:
                        retained.append(operation)
                    continue
                controller._join(permit)
                if ledger.breach or ledger.conflict:
                    controller.policies.halt(reason_code="bound_breach" if ledger.breach else "evidence_conflict",
                        evidence_sha256=digest(ledger))
                    incidents.append(digest(ledger))
                    controller._unsafe_authorities.add(authority_id)
                staged = snapshot.staged_result
                staged_index = next((i for i, child in enumerate(permit.attempt_children)
                    if staged is not None and child.child_id == staged.receipt.child_id), None)
                later_attempt = staged_index is not None and any(
                    child.state in ("active", "known", "unknown")
                    for child in ledger.attempts[staged_index + 1:])
                viable_retry = (staged is not None and staged.receipt.status == "provider_error"
                    and any(child.state == "future" for child in ledger.attempts)
                    and now < permit.expires_utc and not snapshot.cancelled)
                if (staged is not None and snapshot.state != OperationState.TERMINAL
                    and not later_attempt and not viable_retry):
                    if (staged.permit_sha256 != digest(permit)
                        or staged.receipt.serialized_envelope_sha256 != permit.serialized_envelope_sha256):
                        raise GatewayError(ErrorCode.INVALID_JOIN)
                    settled = controller.ledger.settle(staged.receipt)
                    if settled.excess_usd > 0:
                        controller._incident(permit, staged.receipt, conflict=False)
                    controller.replay.cipher.decrypt(staged.encrypted_result, staged.binding)
                    close_future_children(controller, permit, reason="skipped", now=now)
                    controller.policies.mark_terminal(operation, settled, now=now,
                        result_expires_utc=now + timedelta(hours=24) if settled.state == "known" else None)
                    closed.append(operation)
                    continue
                if snapshot.state == OperationState.TERMINAL:
                    retained.append(operation)
                    continue
                # Each attempt needs a deadline or actual owned-process exit proof.
                for child in ledger.attempts:
                    exit_proof = next((proof for proof in ownership if child.owner is not None
                        and proof.process == child.owner and proof.observed_utc <= now), None)
                    expired = now >= child.deadline_utc or now >= permit.expires_utc
                    if not expired and not snapshot.cancelled and exit_proof is None:
                        continue
                    if child.state == "unknown" and child.attempt_id is not None:
                        settlement = controller.ledger.mark_unknown(operation_id=operation,
                            child_id=child.child_id, attempt_id=child.attempt_id,
                            reason=UnknownReason.AMBIGUOUS_DISPATCH)
                        close_future_children(controller, permit, reason="skipped", now=now)
                        controller.policies.mark_terminal(operation, settlement,
                            now=now, result_expires_utc=None)
                    elif child.state == "active" and child.attempt_id is not None:
                        # Cancellation alone does not mean a live in-flight owner is dead.
                        if not expired and exit_proof is None:
                            continue
                        settlement = controller.ledger.mark_unknown(operation_id=operation,
                            child_id=child.child_id, attempt_id=child.attempt_id,
                            reason=UnknownReason.OWNER_TERMINATED if exit_proof else UnknownReason.TIMEOUT)
                        close_future_children(controller, permit,
                            reason="skipped", now=now)
                        controller.policies.mark_terminal(operation, settlement, now=now, result_expires_utc=None)
                    elif child.state == "future":
                        evidence = RecoveryEvidence(authority_id=authority_id, operation_id=operation,
                            child_id=child.child_id, attempt_id=None, observed_utc=now,
                            expires_utc=permit.expires_utc, cancelled=snapshot.cancelled,
                            owner_pid=exit_proof.process.pid if exit_proof else None,
                            owner_process_instance_id=exit_proof.process.process_start_id if exit_proof else None,
                            owner_exit_evidence_sha256=exit_proof.exit_evidence_sha256 if exit_proof else None,
                            staged_settlement_sha256=None)
                        report = controller.ledger.recover(evidence)
                        if report.blocked:
                            raise GatewayError(ErrorCode.INVALID_EVIDENCE)
                refreshed = controller.ledger.operation_state(operation)
                if refreshed is None:
                    raise GatewayError(ErrorCode.INVALID_JOIN)
                if all(child.state == "closed_unstarted" for child in refreshed.attempts):
                    # No settlement is fabricated for an attempt which never began.
                    # Producer bridge re-reads committed closure facts before its
                    # funded->abandoned projection; tombstone survives permanently.
                    controller.policies.close_unstarted_operation(operation, now=now)
                    closed.append(operation)
                else:
                    retained.append(operation)
            except Exception:
                controller._unsafe_authorities.add(authority_id)
                blocked.append(operation)
        controller.policies.purge_expired_results(authority_id, now=now, limit=limit)
    return RecoverySummary(authority_id=authority_id, examined_count=len(operations),
        closed_operation_ids=tuple(closed), retained_operation_ids=tuple(retained),
        blocked_operation_ids=tuple(blocked), incident_sha256s=tuple(incidents),
        next_cursor=next_cursor)

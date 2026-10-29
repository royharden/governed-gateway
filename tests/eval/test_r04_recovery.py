"""Recovery reducer controls with explicit producer doubles, never crash proof.

what_bug_this_catches: unequal producer pages can lose ledger-only operations;
orphan/error handling can accidentally release liability or permit dispatch.
Real native/controller crash/reopen coverage remains a separate matrix.
"""
from contextlib import nullcontext
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace as Row

import pytest

from gateway.controller.recovery import recover
from gateway.schemas import ErrorCode, GatewayError, OperationState


AUTHORITY = "m8-r04-rv4-reducer"
NOW = datetime(2026, 10, 27, tzinfo=timezone.utc)


def controller_case(policy_ids, ledger_ids, *, policy_more=None, ledger_more=None):
    """Only recovery reads/halt/purge exist: no fund/claim/send/refund capability."""
    joined, halted, purged = [], [], []
    snapshots = {key: Row(operation_id=key, permit=Row(operation_id=key,
        expires_utc=NOW + timedelta(minutes=1), attempt_children=()),
        state=OperationState.TERMINAL, staged_result=None, cancelled=False)
        for key in set(policy_ids) | set(ledger_ids)}
    ledger_rows = {key: Row(operation_id=key, breach=False, conflict=False,
        ledger_context_sha256="a" * 64) for key in ledger_ids}
    policy_page = Row(authority_id=AUTHORITY, items=tuple(snapshots[key] for key in policy_ids),
                      next_cursor=policy_more)
    ledger_page = Row(authority_id=AUTHORITY, items=tuple(ledger_rows[key] for key in ledger_ids),
                      next_cursor=ledger_more)
    policies = Row(recovery_candidates=lambda *a, **k: policy_page,
        operation_snapshot=snapshots.get, get_permit=lambda key: None,
        halt=lambda **kwargs: halted.append(kwargs),
        purge_expired_results=lambda *args, **kwargs: purged.append(kwargs))
    controller = Row(guard=Row(hold=lambda _: nullcontext()), now=lambda: NOW,
        policies=policies, ledger=Row(recovery_candidates=lambda *a, **k: ledger_page,
            operation_state=ledger_rows.get), _join=lambda permit: joined.append(permit.operation_id),
        _unsafe_authorities=set())
    return Row(controller=controller, snapshots=snapshots, joined=joined, halted=halted,
               purged=purged, policy_page=policy_page)


@pytest.mark.parametrize("policy_ids,ledger_ids,expected_cursor", [
    (("a", "d"), ("b", "c"), "c"),
    (("b", "c"), ("a", "d"), "c"),
    ((), ("a", "b"), "b"),
    (("a", "b"), (), "b"),
])
def test_unequal_pages_keep_each_operation_visible(policy_ids, ledger_ids, expected_cursor):
    case = controller_case(policy_ids, ledger_ids, policy_more="more", ledger_more="more")
    # Policy-only terminal rows require no money mutation; a missing producer
    # snapshot is retained until its authority-bound evidence can be reconciled.
    report = recover(case.controller, AUTHORITY, now=NOW, limit=2)
    assert report.examined_count == len(set(policy_ids) | set(ledger_ids))
    assert set(report.retained_operation_ids) == set(policy_ids) | set(ledger_ids)
    assert report.next_cursor == expected_cursor
    assert report.closed_operation_ids == report.blocked_operation_ids == ()
    assert not case.halted and not case.controller._unsafe_authorities
    assert len(case.purged) == 1


def test_ledger_orphan_halts_with_stable_body_free_evidence():
    case = controller_case((), ("orphan",))
    case.snapshots.clear()
    report = recover(case.controller, AUTHORITY, now=NOW)
    assert report.blocked_operation_ids == ("orphan",)
    assert report.closed_operation_ids == report.retained_operation_ids == ()
    assert len(report.incident_sha256s) == len(case.halted) == 1
    assert case.halted[0] == {
        "reason_code": "store_unavailable", "evidence_sha256": report.incident_sha256s[0]}
    assert case.controller._unsafe_authorities == {AUTHORITY}
    assert not case.joined


def test_error_reconciling_existing_operation_is_blocked_without_fabricated_closure():
    case = controller_case(("operation",), ("operation",))
    def unreadable(_):
        raise GatewayError(ErrorCode.STORE_UNAVAILABLE)
    case.controller._join = unreadable
    report = recover(case.controller, AUTHORITY, now=NOW)
    assert report.blocked_operation_ids == ("operation",)
    assert report.closed_operation_ids == report.retained_operation_ids == ()
    assert case.controller._unsafe_authorities == {AUTHORITY}
    # Durable halt on generic producer errors is deliberately not inferred here.


def test_foreign_policy_page_denied_before_operation_processing():
    case = controller_case(("operation",), ("operation",))
    case.policy_page.authority_id = "foreign"
    with pytest.raises(GatewayError) as failure:
        recover(case.controller, AUTHORITY, now=NOW)
    assert failure.value.code == ErrorCode.AUTHORITY_MISMATCH
    assert not case.joined and not case.purged


def test_regressing_page_denied_before_any_operation_processing():
    case = controller_case(("a",), ("b",))
    with pytest.raises(GatewayError) as failure:
        recover(case.controller, AUTHORITY, now=NOW, cursor="a")
    assert failure.value.code == ErrorCode.INVALID_EVIDENCE
    assert not case.joined and not case.purged

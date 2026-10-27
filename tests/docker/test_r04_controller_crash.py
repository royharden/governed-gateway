"""Seven single-operation Linux process-death controls, construction-only packet.

what_bug_this_catches: exception cleanup is not process death; a committed claim
with no returned ticket must never become another send, and durable staged/known
results must recover with the exact original memory identity. No campaign,
quality report, activation, serving-policy or real-clock claim is made here.
Execution requires a separately frozen and independently reviewed runtime grant.
"""
import asyncio
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import sqlite3
import threading
import time
import uuid

import pytest

from gateway.bootstrap import _load_demo_configuration, build_mock_context
from gateway.cli.signing import confirmation_digest
from gateway.cli.simulation import create_simulation_signer
from gateway.controller.ports import CancellationToken
from gateway.schemas import (
    EvaluationAuthorizationPayload, GatewayRequest, OperationState,
    OwnerExitEvidence, ProcessInstance, WireMessage, digest, request_digest,
)


pytestmark = pytest.mark.skipif(os.name != "posix", reason="requires separately granted Linux fork matrix")
T0 = datetime(2026, 11, 1, 12, tzinfo=timezone.utc)
CUTS = ("permit", "fund", "claim", "handoff", "stage", "settle", "terminal")
EXIT_AT_CUT = 77
MAXIMUM = Decimal("0.001024")


def integer_micros(amount):
    """Independent exact rational conversion; never production usd_micros."""
    numerator, denominator = amount.as_integer_ratio()
    value, remainder = divmod(numerator * 1_000_000, denominator)
    assert remainder == 0 and value >= 0
    return value


def totals_view(context):
    totals = context.ledger.totals(authority_id=context.authority.authority_id)
    names = ("reserved_usd", "future_usd", "active_usd", "released_usd",
             "known_usd", "unknown_usd", "excess_usd", "uncovered_excess_usd", "exposure_usd")
    values = {name: integer_micros(getattr(totals, name)) for name in names}
    assert values["reserved_usd"] + values["excess_usd"] == sum(values[name] for name in (
        "future_usd", "active_usd", "released_usd", "known_usd", "unknown_usd"))
    assert values["exposure_usd"] == sum(values[name] for name in (
        "known_usd", "future_usd", "active_usd", "unknown_usd", "uncovered_excess_usd"))
    assert values["excess_usd"] == values["uncovered_excess_usd"] == 0
    return values


def opened(spec, signer, clock, *, initialize=False):
    return build_mock_context(spec, initialize=initialize, signer=signer,
        utc_now=lambda: T0 + timedelta(seconds=clock[0]),
        monotonic_source=lambda: clock[0] * 1_000_000_000)


def acknowledge_and_die(sender, cut, marker):
    message = json.dumps({"cut": cut, "pid": os.getpid(), "marker": marker}).encode()
    assert len(message) < 1024
    sender.send_bytes(message)
    sender.close()
    os._exit(EXIT_AT_CUT)


def worker(spec, signer, request, authorization_hash, cut, marker, sends, sender):
    """Fresh composition after quiescent fork. No inherited live parent store."""
    context = opened(spec, signer, [0])
    adapter = context.controller.planner.adapters["B0"]
    begin = adapter.begin_generate

    def spy(*args, **kwargs):
        pending = begin(*args, **kwargs)
        sends.value += 1  # One writer; supervisor reads only after verified exit.
        if cut == "handoff":
            acknowledge_and_die(sender, cut, marker)
        return pending
    adapter.begin_generate = spy
    seams = {
        "permit": (context.policies, "permit_operation"),
        "fund": (context.ledger, "fund_plan"),
        "claim": (context.ledger, "begin_attempt"),
        "stage": (context.policies, "stage_result"),
        "settle": (context.ledger, "settle"),
        "terminal": (context.policies, "mark_terminal"),
    }
    if cut in seams:
        owner, method = seams[cut]
        original = getattr(owner, method)
        def after_commit(*args, **kwargs):
            original(*args, **kwargs)
            acknowledge_and_die(sender, cut, marker)
        setattr(owner, method, after_commit)
    try:
        asyncio.run(context.controller.complete_evaluation(
            request, authorization_hash, cancel=CancellationToken()))
    finally:
        context.close()
    # Reaching here is not the requested crash boundary, even if a reply was OK.
    os._exit(78)


def prepare(root):
    source = Path(os.environ["M8_SOURCE_ROOT"])
    raw = json.loads((source / "fixtures/bootstrap/simulation.example.json").read_text())
    raw.update(runtime_root=str(root), authority_id="m8-r04-crash-" + uuid.uuid4().hex,
        created_utc=(T0 - timedelta(seconds=10)).isoformat(),
        deadline_utc=(T0 + timedelta(minutes=5)).isoformat(),
        cap_usd="0.004500", max_outbound_attempts=1)
    config = root / "synthetic-config.json"
    config.write_text(json.dumps(raw), encoding="utf-8")
    spec, _, _, _, caller = _load_demo_configuration(config)
    signer = create_simulation_signer(allowed_evidence=tuple(record.evidence for record in spec.records))
    context = opened(spec, signer, [0], initialize=True)
    try:
        record = next(row for row in spec.records if row.bundle.policy_id.endswith("acquire-B0"))
        assert record.bundle.max_attempts_total == 1
        context.policies.freeze(record.bundle)
        payload = EvaluationAuthorizationPayload(authorization_id="single-operation-crash-control",
            authority_id=spec.authority_id, mode="simulation", tuple=record.evidence,
            budget_authority_id=spec.authority_id, budget_reference_sha256=context.authority.config_sha256,
            maximum_liability_usd=MAXIMUM, created_utc=T0, expires_utc=spec.deadline_utc,
            nonce="single-operation-" + uuid.uuid4().hex,
            declared_os_account=signer.declared_os_account,
            signer_fingerprint_sha256=signer.fingerprint_sha256)
        authorization = signer.sign_evaluation_authorization(
            payload, confirmed_tuple_sha256=confirmation_digest(payload))
        context.policies.authorize_evaluation(authorization)
        messages = (WireMessage(role="user", content="synthetic bounded crash request"),)
        request = GatewayRequest(authority_id=spec.authority_id, caller_id=caller.caller_id,
            idempotency_key="same-single-operation", route_alias="default", messages=messages,
            max_completion_tokens=128, request_sha256=request_digest(route_alias="default",
                messages=messages, max_completion_tokens=128), deadline_utc=T0 + timedelta(seconds=60))
        # Quote before any request/funding. An unexpected reserve blocks the case.
        with context.guard.hold(spec.authority_id):
            plan, _, _, _ = context.controller.planner.build_evaluation(request, record.bundle,
                authorization, authorization_sha256=digest(authorization), now=T0)
            assert len(plan.attempt_children) == 1 and not plan.attempt_children[0].conditional
            reserved = plan.attempt_children[0].maximum_liability_usd
            assert Decimal(0) < reserved <= MAXIMUM
            assert totals_view(context)["reserved_usd"] == 0
        return spec, signer, request, digest(authorization), reserved
    finally:
        context.close()  # All live parent DB/guard/highwater handles close BEFORE fork.


def observe(context, root, sends, phase, records):
    with context.guard.hold(context.authority.authority_id):
        totals = totals_view(context)
        snapshots = context.policies.list_operation_snapshots(limit=2)
        assert len(snapshots) == 1
        operation = snapshots[0]
        ledger = context.ledger.operation_state(operation.operation_id)
        ledger_children = () if ledger is None else ledger.attempts
        assert len(ledger_children) <= 1
        assert all(child.owner is None for child in ledger_children)
        assert context.policies.active() is None
        assert context.policies.status().generation == 0
    # Independent direct SQLite checks, after child death; no secret/payload reads.
    with sqlite3.connect((root / "policy.sqlite3").as_uri() + "?mode=ro", uri=True) as db:
        counts = {table: db.execute("SELECT COUNT(*) FROM " + table).fetchone()[0]
                  for table in ("operations", "permits", "evaluations", "decisions", "activation_events")}
        assert counts == dict(operations=1, permits=1, evaluations=0, decisions=0, activation_events=0)
        assert db.execute("PRAGMA foreign_key_check").fetchall() == []
    with sqlite3.connect((root / "accounting.sqlite3").as_uri() + "?mode=ro", uri=True) as db:
        claims = db.execute("SELECT COUNT(*) FROM attempts").fetchone()[0]
        funded_operations = db.execute("SELECT COUNT(*) FROM operations").fetchone()[0]
        assert 0 <= sends.value <= claims <= 1 and funded_operations <= 1
    record = dict(phase=phase, totals=totals, sends=sends.value, claims=claims,
        policy_state=operation.state.value, permit_state=operation.permit.state.value,
        funded_operations=funded_operations, ledger_states=[child.state for child in ledger_children])
    records.append(record)
    return record, operation


def forbid_send(context, sends):
    def forbidden(*args, **kwargs):
        sends.value += 1
        raise AssertionError("reopen/duplicate attempted a second provider dispatch")
    for adapter in context.controller.planner.adapters.values():
        adapter.begin_generate = forbidden


def duplicate(context, request, authorization_hash):
    return asyncio.run(context.controller.complete_evaluation(
        request, authorization_hash, cancel=CancellationToken()))


@pytest.mark.parametrize("cut", CUTS)
def test_single_operation_controller_crash_and_reopen(cut):
    parent = Path(os.environ["M8_TEST_RUNTIME_PARENT"])
    root = parent / ("crash-" + cut + "-" + uuid.uuid4().hex)
    root.mkdir(parents=True, exist_ok=False)
    old_root = os.environ.get("GATEWAY_RUNTIME_ROOT")
    os.environ["GATEWAY_RUNTIME_ROOT"] = str(root)
    observations, child = [], None
    receiver = sender = context = None
    started = time.monotonic()
    phase = "prepare"
    completed = False
    try:
        spec, signer, request, authorization_hash, reserved = prepare(root)
        assert len(threading.enumerate()) == 1, "fork requires quiescent supervisor"
        fork = multiprocessing.get_context("fork")
        sends = fork.Value("i", 0, lock=False)
        receiver, sender = fork.Pipe(duplex=False)
        marker = "m8-r04-" + uuid.uuid4().hex
        child = fork.Process(target=worker,
            args=(spec, signer, request, authorization_hash, cut, marker, sends, sender))
        phase = "fork-and-cut"
        child.start()
        sender.close()
        child.join(timeout=10)
        assert not child.is_alive(), "owned worker exceeded ten-second boundary"
        assert child.exitcode == EXIT_AT_CUT, "worker did not reach exact post-commit cut"
        assert receiver.poll(0.5), "missing exact post-commit acknowledgment"
        receipt = json.loads(receiver.recv_bytes(maxlength=1024))
        assert receipt == dict(cut=cut, pid=child.pid, marker=marker)
        assert sends.value == (1 if cut in ("handoff", "stage", "settle", "terminal") else 0)
        clock = [0]
        phase = "reopen"
        context = opened(spec, signer, clock)
        forbid_send(context, sends)
        after_death, operation = observe(context, root, sends, "after-death", observations)
        micros = integer_micros(reserved)
        assert after_death["claims"] == (0 if cut in ("permit", "fund") else 1)
        if cut == "permit":
            assert after_death["funded_operations"] == 0
            assert after_death["totals"]["reserved_usd"] == 0
        elif cut == "fund":
            assert after_death["permit_state"] == "permitted"
            assert after_death["totals"]["future_usd"] == micros
        elif cut in ("claim", "handoff", "stage"):
            assert after_death["totals"]["active_usd"] == micros
        else:
            assert after_death["totals"]["known_usd"] > 0
        if cut in ("permit", "fund", "claim", "handoff"):
            phase = "before-expiry-owner-exit"
            assert duplicate(context, request, authorization_hash).http_status == 202
            # Supervisor exit provenance only; never invent producer ownership.
            provenance = dict(pid=child.pid, marker=marker, cut=cut, exit_code=child.exitcode)
            owned_exit = OwnerExitEvidence(process=ProcessInstance(pid=child.pid,
                process_start_id=marker, started_utc=T0), observed_utc=T0,
                exit_code=EXIT_AT_CUT, owned_process_evidence_sha256=digest(provenance),
                exit_evidence_sha256=digest({"exited": provenance}))
            before = context.controller.recover(spec.authority_id, now=T0, ownership=(owned_exit,))
            assert not before.blocked_operation_ids
            retained, _ = observe(context, root, sends, "before-expiry-owner-exit", observations)
            assert retained["totals"] == after_death["totals"]
            assert retained["claims"] == after_death["claims"]
            # Both injected suppliers advance coherently; no host clock change.
            clock[0] = 61
            phase = "deadline-recovery"
            recovery = context.controller.recover(spec.authority_id, now=T0 + timedelta(seconds=61))
            assert not recovery.blocked_operation_ids
            final, snapshot = observe(context, root, sends, "after-deadline", observations)
            if cut in ("claim", "handoff"):
                assert final["totals"]["unknown_usd"] == micros
                assert final["totals"]["released_usd"] == 0
            else:
                assert snapshot.state == OperationState.ABANDONED
                assert final["totals"]["released_usd"] == (micros if cut == "fund" else 0)
            assert duplicate(context, request, authorization_hash).http_status != 200
        else:
            phase = "staged-or-terminal-replay"
            recovery = context.controller.recover(spec.authority_id, now=T0)
            assert not recovery.blocked_operation_ids
            reply = duplicate(context, request, authorization_hash)
            assert reply.http_status == 200 and reply.result is not None and reply.result.replayed
            final, snapshot = observe(context, root, sends, "recovered-replay", observations)
            assert snapshot.state == OperationState.TERMINAL
            assert final["totals"]["active_usd"] == final["totals"]["future_usd"] == 0
            assert final["totals"]["unknown_usd"] == 0
            assert final["totals"]["known_usd"] + final["totals"]["released_usd"] == micros
            replay_hash = digest(reply.result)
            context.controller.recover(spec.authority_id, now=T0)
            assert digest(duplicate(context, request, authorization_hash).result) == replay_hash
        final_before = observe(context, root, sends, "idempotence-before", observations)[0]
        phase = "repeat-recovery-and-duplicate"
        context.controller.recover(spec.authority_id, now=T0 + timedelta(seconds=clock[0]))
        duplicate(context, request, authorization_hash)
        final_after = observe(context, root, sends, "idempotence-after", observations)[0]
        assert {key: value for key, value in final_before.items() if key != "phase"} == {
            key: value for key, value in final_after.items() if key != "phase"}
        assert sends.value == (1 if cut in ("handoff", "stage", "settle", "terminal") else 0)
        assert time.monotonic() - started < 14, "case exceeded proposed total supervision bound"
        completed = True
    finally:
        # A timeout never becomes a pass; only this direct owned child is killed.
        if child is not None and child.pid is not None and child.is_alive():
            child.kill()
            child.join(timeout=2)
            assert not child.is_alive(), "owned child could not be reaped"
        if context is not None:
            context.close()
        for pipe in (receiver, sender):
            if pipe is not None:
                pipe.close()
        if old_root is None:
            os.environ.pop("GATEWAY_RUNTIME_ROOT", None)
        else:
            os.environ["GATEWAY_RUNTIME_ROOT"] = old_root
        # No bodies, private keys, bearer tokens, or raw exceptions enter evidence.
        (root / "observations.json").write_text(json.dumps({"cut": cut,
            "source_file_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "clock": "synthetic T0 plus coherent UTC/monotonic61s advance",
            "completed": completed, "last_phase": phase,
            "observations": observations, "worker_exit": None if child is None else child.exitcode,
            "limits": "single eval-purpose operation; owner identity gap remains open"}, indent=2), encoding="utf-8")

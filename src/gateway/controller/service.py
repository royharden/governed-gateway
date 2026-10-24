"""Durable mock journey. No fallback store, transport, quote or approval authority."""
from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import secrets
from pydantic import ValidationError

from gateway.schemas import (
    AttemptReceipt, CallerContext, ChatCompletionInput, ErrorCode, EvaluationAuthorization, GatewayError,
    GatewayReply, GatewayRequest, GatewayResult, IncidentEvidence, OperationPermit,
    PermitState, PolicyBundle, ProviderEnvelope, ProviderResult, ReplayBinding, ResultChoice,
    ResultCost, SafeError, SettlementReceipt, UnknownReason, Usage, digest, request_digest,
)
from gateway.api.auth import ClientAuthenticator
from gateway.api.errors import error_reply
from gateway.adapters.errors import AdapterError
from gateway.replay.cipher import ReplayCipher
from gateway.replay.service import ReplayService
from .authority_lock import AuthorityLock
from .planning import PermitPlanner
from .ports import CancellationToken, LedgerPort, PendingGeneration, PolicyPort


class GatewayController:
    def __init__(self, *, policies: PolicyPort, ledger: LedgerPort, planner: PermitPlanner,
                 authority_lock: AuthorityLock, authenticator: ClientAuthenticator,
                 replay_cipher: ReplayCipher, clock: Callable[[], datetime],
                 evaluation_loader: Callable[[str], tuple[PolicyBundle, EvaluationAuthorization]]):
        self.policies, self.ledger, self.planner = policies, ledger, planner
        self.guard, self.authenticator = authority_lock, authenticator
        self.replay = ReplayService(replay_cipher)
        self.clock = clock
        self.evaluation_loader = evaluation_loader
        # A local failure latch adds conservatism, never replaces durable halt state.
        self._unsafe_authorities: set[str] = set()
        self._outcomes: dict[tuple[str, str], tuple[str, ProviderResult]] = {}

    def retry_source(self, operation_id: str, child_id: str) -> ProviderResult | None:
        """Trusted root retry_reader; normalized body-free observation, never a ticket.

        A restart has no observation and returns None; it cannot reconstruct proof
        or dispatch. PolicyStore persists its validated readiness event separately.
        """
        observed = self._outcomes.get((operation_id, child_id))
        if observed is None:
            return None
        authority_id, result = observed
        self.guard.assert_held(authority_id=authority_id)
        return result

    def _remember_outcome(self, permit, ticket, response: ProviderResult) -> None:
        self.guard.assert_held(authority_id=permit.authority_id)
        # Only called after this controller's unique claim/handoff returned an
        # actual normalized result. No caller DTO or client flag populates it.
        if not (response.status == "provider_error" and response.dispatch_state == "not_sent"
                and response.retry_evidence == "pre_send_certain" and response.usage.complete
                and response.usage.input_tokens == 0 and response.usage.output_tokens == 0
                and not response.usage.unknown_components):
            # INT011: do not strip success/refusal bodies into surrogate success
            # models, or retain arbitrary nonretry outcomes as trusted proof.
            return
        safe = ProviderResult.model_validate({**response.model_dump(mode="python"),
            "text": None, "refusal": None, "provider_request_id": None})
        key = (permit.operation_id, ticket.child_id)
        previous = self._outcomes.get(key)
        if previous is not None and previous != (permit.authority_id, safe):
            self._unsafe_authorities.add(permit.authority_id)
            self.policies.halt(reason_code="evidence_conflict", evidence_sha256=digest(safe))
            raise GatewayError(ErrorCode.EVIDENCE_CONFLICT)
        self._outcomes[key] = (permit.authority_id, safe)

    def now(self) -> datetime:
        value = self.clock()
        if value.utcoffset() is None or value.utcoffset().total_seconds() != 0:
            raise GatewayError(ErrorCode.CLOCK_UNTRUSTED)
        return value.astimezone(timezone.utc)

    def _join(self, permit: OperationPermit):
        join = self.ledger.committed_join(operation_id=permit.operation_id)
        if join is None:
            raise GatewayError(ErrorCode.INVALID_JOIN)
        if (join.authority_id, join.operation_id, join.permit_sha256,
            join.policy_bundle_sha256, join.request_sha256, join.serialized_envelope_sha256,
            join.bound_sha256, join.price_sha256, set(join.child_ids)) != (
            permit.authority_id, permit.operation_id, digest(permit),
            permit.policy_bundle_sha256, permit.request_sha256, permit.serialized_envelope_sha256,
            permit.bound_sha256, permit.price_sha256, {c.child_id for c in permit.attempt_children}
        ):
            raise GatewayError(ErrorCode.INVALID_JOIN)
        return join

    def _gates(self, permit: OperationPermit, context) -> None:
        self.guard.assert_held(authority_id=permit.authority_id)
        if permit.authority_id in self._unsafe_authorities:
            raise GatewayError(ErrorCode.HALTED)
        totals = self.ledger.totals(authority_id=permit.authority_id)
        if totals.halted or totals.conflict or totals.excess_usd > 0 or totals.uncovered_excess_usd > 0:
            raise GatewayError(ErrorCode.HALTED)
        if self.now() >= permit.expires_utc:
            raise GatewayError(ErrorCode.DEADLINE_EXCEEDED)
        # A retry can follow a long first attempt. Refresh the trusted reading,
        # retaining the original immutable evidence/clock configuration identity.
        current = self.planner.context_loader(permit.policy_bundle_sha256)
        if digest(current.model_dump(exclude={"observed_utc"})) != digest(
            context.model_dump(exclude={"observed_utc"})
        ):
            raise GatewayError(ErrorCode.INVALID_EVIDENCE)
        self.policies.assert_dispatch_allowed(permit.operation_id, self._join(permit), context=current)

    @staticmethod
    def _adapter_code(error: AdapterError) -> ErrorCode:
        return {
            "unsupported_request": ErrorCode.UNSUPPORTED_REQUEST,
            "invalid_profile": ErrorCode.UNSUPPORTED_PROFILE,
            "invalid_configuration": ErrorCode.UNSUPPORTED_PROFILE,
            "stale_profile": ErrorCode.STALE_EVIDENCE,
            "invalid_envelope": ErrorCode.INVALID_JOIN,
            "external_disabled": ErrorCode.EXTERNAL_DISABLED,
            "invalid_deadline": ErrorCode.DEADLINE_EXCEEDED,
        }.get(error.code, ErrorCode.UNSUPPORTED_PROFILE)

    def _fund(self, permit: OperationPermit, cancel: CancellationToken) -> None:
        self.guard.assert_held(authority_id=permit.authority_id)
        if self.now() >= permit.expires_utc or cancel.is_cancelled():
            raise GatewayError(ErrorCode.CANCELLED if cancel.is_cancelled() else ErrorCode.DEADLINE_EXCEEDED)
        funding = self.ledger.fund_plan(permit)
        if (funding.operation_id != permit.operation_id or funding.authority_id != permit.authority_id
            or funding.permit_sha256 != digest(permit)
            or set(funding.funded_children) != {c.child_id for c in permit.attempt_children}):
            raise GatewayError(ErrorCode.INVALID_JOIN)
        self.policies.transition_permit(permit.operation_id, expected_state=PermitState.PERMITTED,
            target_state=PermitState.FUNDED, join=self._join(permit))

    async def complete(self, caller: CallerContext, body: ChatCompletionInput,
                       idempotency_key: str, *, cancel: CancellationToken) -> GatewayReply:
        operation = None
        try:
            # Revalidate programmatic clients; wire parsing is not the only entrypoint.
            body = ChatCompletionInput.model_validate(body.model_dump(mode="python"))
            key_digest = self.authenticator.key_digest(caller, idempotency_key)
            request_hash = request_digest(route_alias=body.model, messages=body.messages,
                                         max_completion_tokens=body.max_completion_tokens)
            with self.guard.hold(caller.authority_id):
                previous = self.policies.lookup_operation(caller, key_digest)
                if previous is not None:
                    # Old keys work against the original permit even after policy change.
                    return self.replay.reply(previous, caller, request_hash, now=self.now())
                if cancel.is_cancelled():
                    raise GatewayError(ErrorCode.CANCELLED)
                if caller.authority_id in self._unsafe_authorities:
                    raise GatewayError(ErrorCode.HALTED)
                now = self.now()
                snapshot = self.policies.routing_snapshot(caller, body.model, now=now)
                request = GatewayRequest(authority_id=caller.authority_id, caller_id=caller.caller_id,
                    # The persisted key is a scoped keyed digest, never the raw HTTP key.
                    idempotency_key=key_digest, request_sha256=request_hash, route_alias=body.model,
                    messages=body.messages, max_completion_tokens=body.max_completion_tokens,
                    deadline_utc=now + timedelta(seconds=60))
                plan, envelope, adapter, context = self.planner.build(request, snapshot, now=now)
                decision = self.policies.permit_operation(request, plan, key_digest=key_digest,
                    expected_generation=snapshot.generation, context=context)
                if not decision.created:
                    return self.replay.reply(decision.operation, caller, request_hash, now=self.now())
                permit = decision.permit
                if permit is None:
                    raise GatewayError(ErrorCode.INVALID_PERMIT)
                operation = permit.operation_id
                # DL1 validates policy gates and evidence under this same held lock.
                self._fund(permit, cancel)
            return await self._run(caller, permit, envelope, adapter, context, cancel,
                                   snapshot.bundle.attempt_timeout_seconds,
                                   snapshot.bundle.max_backoff_milliseconds)
        except AdapterError as error:
            return error_reply(self._adapter_code(error), operation_id=operation)
        except ValidationError:
            return error_reply(ErrorCode.INVALID_REQUEST, operation_id=operation)
        except GatewayError as error:
            return error_reply(error.code, operation_id=operation)
        except asyncio.CancelledError:
            try:
                cancel.cancel()
                if operation is not None:
                    self.cancel(caller, operation)
            except BaseException:
                self._unsafe_authorities.add(caller.authority_id)
            raise
        except Exception:
            # Raw exception/SQL/provider strings never enter responses or logs.
            self._unsafe_authorities.add(caller.authority_id)
            return error_reply(ErrorCode.STORE_UNAVAILABLE, operation_id=operation)

    async def complete_evaluation(self, request: GatewayRequest, authorization_sha256: str,
                                   *, cancel: CancellationToken) -> GatewayReply:
        """Trusted operator-only acquisition through signed finite evaluation authority.

        No HTTP route exposes this method, no active policy is needed, and no
        evaluation success/approval is minted here. Root supplies persisted inputs.
        """
        operation = None
        caller = None
        try:
            request = GatewayRequest.model_validate(request.model_dump(mode="python"))
            caller = CallerContext(authority_id=request.authority_id, caller_id=request.caller_id)
            key = self.authenticator.key_digest(caller, request.idempotency_key, purpose="eval")
            with self.guard.hold(caller.authority_id):
                previous = self.policies.lookup_operation(caller, key)
                if previous is not None:
                    return self.replay.reply(previous, caller, request.request_sha256, now=self.now())
                if cancel.is_cancelled():
                    raise GatewayError(ErrorCode.CANCELLED)
                if caller.authority_id in self._unsafe_authorities:
                    raise GatewayError(ErrorCode.HALTED)
                now = self.now()
                bundle, authorization = self.evaluation_loader(authorization_sha256)
                normalized = {**request.model_dump(mode="python"), "idempotency_key": key,
                    "deadline_utc": min(request.deadline_utc, now + timedelta(seconds=60))}
                request = GatewayRequest.model_validate(normalized)
                plan, envelope, adapter, context = self.planner.build_evaluation(request, bundle,
                    authorization, authorization_sha256=authorization_sha256, now=now)
                decision = self.policies.permit_operation(request, plan, key_digest=key,
                    expected_generation=0, context=context)
                if not decision.created:
                    return self.replay.reply(decision.operation, caller, request.request_sha256, now=self.now())
                permit = decision.permit
                if permit is None or permit.purpose != "eval":
                    raise GatewayError(ErrorCode.INVALID_PERMIT)
                operation = permit.operation_id
                self._fund(permit, cancel)
            return await self._run(caller, permit, envelope, adapter, context, cancel,
                                   bundle.attempt_timeout_seconds, bundle.max_backoff_milliseconds)
        except AdapterError as error:
            return error_reply(self._adapter_code(error), operation_id=operation)
        except ValidationError:
            return error_reply(ErrorCode.INVALID_REQUEST, operation_id=operation)
        except GatewayError as error:
            return error_reply(error.code, operation_id=operation)
        except asyncio.CancelledError:
            try:
                cancel.cancel()
                if operation is not None and caller is not None:
                    self.cancel(caller, operation)
            except BaseException:
                if caller is not None:
                    self._unsafe_authorities.add(caller.authority_id)
            raise
        except Exception:
            if caller is not None:
                self._unsafe_authorities.add(caller.authority_id)
            return error_reply(ErrorCode.STORE_UNAVAILABLE, operation_id=operation)

    async def _wait(self, pending: PendingGeneration, deadline: datetime,
                    cancel: CancellationToken) -> ProviderResult:
        result = asyncio.ensure_future(pending.result())
        cancellation = asyncio.create_task(cancel.wait_cancelled())
        original_cancellation = None
        try:
            remaining = max(0.0, (deadline - self.now()).total_seconds())
            done, _ = await asyncio.wait((result, cancellation), timeout=remaining,
                                         return_when=asyncio.FIRST_COMPLETED)
            if cancel.is_cancelled():
                pending.cancel()
                raise GatewayError(ErrorCode.CANCELLED)
            if result not in done:
                pending.cancel()
                raise GatewayError(ErrorCode.DEADLINE_EXCEEDED)
            return result.result()
        except asyncio.CancelledError as error:
            # Task cancellation must signal the actual pending transport as well as
            # its result waiter. It is never evidence the provider was uncharged.
            original_cancellation = error
            try:
                cancel.cancel()
                pending.cancel()
            except BaseException:
                # Preserve the original task cancellation; _run still retains
                # conservative liability and attempts durable cleanup under lock.
                pass
            raise
        finally:
            cancellation.cancel()
            if not result.done():
                result.cancel()
            try:
                await asyncio.gather(result, cancellation, return_exceptions=True)
            except BaseException:
                if original_cancellation is None:
                    raise

    def _receipt(self, permit, ticket, envelope, response, started, completed) -> AttemptReceipt:
        if (response.provider, response.model) != (envelope.provider, envelope.model):
            raise GatewayError(ErrorCode.INVALID_JOIN)
        usage = response.usage
        amount = None
        if usage.complete and not usage.unknown_components:
            amount = self.planner.quotes.price_usage(envelope=envelope, usage=usage)
        if amount is not None and (not isinstance(amount, Decimal) or not amount.is_finite() or amount < 0):
            raise GatewayError(ErrorCode.INVALID_EVIDENCE)
        known = amount is not None
        error = None if response.status in ("ok", "refused", "truncated") else (
            ErrorCode.DEADLINE_EXCEEDED if response.status == "timeout" else
            ErrorCode.CANCELLED if response.status == "cancelled" else ErrorCode.UPSTREAM_ERROR)
        return AttemptReceipt(operation_id=permit.operation_id, child_id=ticket.child_id,
            attempt_id=ticket.attempt_id, provider=response.provider, model=response.model,
            provider_request_id=response.provider_request_id,
            policy_bundle_sha256=permit.policy_bundle_sha256, request_sha256=permit.request_sha256,
            dispatch_sha256=envelope.serialized_envelope_sha256,
            permit_sha256=digest(permit), price_sha256=permit.price_sha256,
            bound_sha256=permit.bound_sha256, serialized_envelope_sha256=envelope.serialized_envelope_sha256,
            state="known" if known else "unknown", started_utc=started, completed_utc=completed,
            status=response.status, usage=Usage(input_tokens=usage.input_tokens,
                output_tokens=usage.output_tokens, cache_read_tokens=None, cache_write_tokens=None,
                reasoning_tokens=None), cost_status="known" if known else "unknown",
            known_usage_cost_usd=amount, reserved_usd=ticket.reserved_usd,
            error_code=error, settlement_sha256=None)

    def _incident(self, permit, receipt: AttemptReceipt, *, conflict: bool) -> None:
        self._unsafe_authorities.add(permit.authority_id)
        with self.guard.hold(permit.authority_id):
            # ACCOUNT owns original K/U and the mandatory conflict/late-evidence
            # ingestion before settle returns or raises. Never invent terminal U
            # from an incoming receipt or add a known K charge to D a second time.
            # The full incoming receipt is already durably staged by this caller.
            self.policies.halt(reason_code="settlement_conflict" if conflict else "bound_breach",
                               evidence_sha256=digest(receipt))

    async def _run(self, caller, permit, envelope, adapter, context, cancel,
                   attempt_timeout_seconds: int, max_backoff_milliseconds: int) -> GatewayReply:
        attempts = []
        for index, child in enumerate(permit.attempt_children):
            ticket = None
            staged = False
            receipt = None
            try:
                with self.guard.hold(permit.authority_id):
                    if cancel.is_cancelled():
                        self.cancel(caller, permit.operation_id)
                        raise GatewayError(ErrorCode.CANCELLED)
                    self._gates(permit, context)
                    if index > 0:
                        self.policies.assert_retry_stage_ready(permit.operation_id, child.child_id,
                                                               now=self.now())
                    ticket = self.ledger.begin_attempt(operation_id=permit.operation_id,
                        child_id=child.child_id, permit_sha256=digest(permit))
                    if (ticket.authority_id, ticket.operation_id, ticket.child_id,
                        ticket.permit_sha256, ticket.envelope_sha256, ticket.reserved_usd) != (
                        permit.authority_id, permit.operation_id, child.child_id, digest(permit),
                        envelope.serialized_envelope_sha256, child.maximum_liability_usd
                    ):
                        raise GatewayError(ErrorCode.INVALID_JOIN)
                    self._gates(permit, context)
                    started = self.now()
                    attempt_seconds = min(30, attempt_timeout_seconds)
                    deadline = min(permit.expires_utc, started + timedelta(seconds=attempt_seconds))
                    # Producer must start the mock handoff synchronously, inside this lock.
                    pending = adapter.begin_generate(envelope, ticket=ticket, deadline=deadline,
                                                     cancel_token=cancel)
                response = await self._wait(pending, deadline, cancel)
                completed = self.now()
                with self.guard.hold(permit.authority_id):
                    self._remember_outcome(permit, ticket, response)
                    receipt = self._receipt(permit, ticket, envelope, response, started, completed)
                attempts.append(ticket.attempt_id)
                expiry = completed + timedelta(hours=24)
                safe_error = None if receipt.error_code is None else SafeError(code=receipt.error_code,
                    safe_message=receipt.error_code.value.replace("_", " "))
                result = GatewayResult(operation_id=permit.operation_id, provider=response.provider,
                    model=response.model, policy_bundle_sha256=permit.policy_bundle_sha256,
                    choice=ResultChoice(text=response.text, refusal=response.refusal,
                        finish_reason=response.finish_reason, native_finish_reason=response.native_finish_reason),
                    usage=receipt.usage, cost=ResultCost(status=receipt.cost_status,
                        amount_usd=receipt.known_usage_cost_usd, price_sha256=receipt.price_sha256),
                    attempt_ids=tuple(attempts), replayed=False, result_expires_utc=expiry, error=safe_error)
                binding = ReplayBinding(authority_id=caller.authority_id, caller_id=caller.caller_id,
                    operation_id=permit.operation_id, request_sha256=permit.request_sha256,
                    policy_bundle_sha256=permit.policy_bundle_sha256)
                encrypted = self.replay.cipher.encrypt(result, binding)
                with self.guard.hold(permit.authority_id):
                    self.policies.stage_result(permit.operation_id, encrypted, receipt, now=completed)
                    staged = True
                    try:
                        settled = self.ledger.settle(receipt)
                    except GatewayError as error:
                        if error.code in (ErrorCode.SETTLEMENT_CONFLICT, ErrorCode.EVIDENCE_CONFLICT):
                            self._incident(permit, receipt, conflict=True)
                        raise
                    if settled.excess_usd > 0:
                        self._incident(permit, receipt, conflict=False)
                    retry = (index == 0 and len(permit.attempt_children) == 2
                        and response.status == "provider_error" and response.dispatch_state != "ambiguous"
                        and response.retry_evidence == "pre_send_certain"
                        and response.dispatch_state == "not_sent" and settled.state == "known"
                        and settled.known_usage_cost_usd == 0
                        and not cancel.is_cancelled() and self.now() < permit.expires_utc)
                    if not retry:
                        # Unused children need ledger-verified proof, never an expiry refund.
                        from .recovery import close_future_children
                        close_future_children(self, permit, reason="skipped", now=completed)
                        terminal_now = self.now()
                        terminal = self.policies.mark_terminal(permit.operation_id, settled,
                            now=terminal_now, result_expires_utc=terminal_now + timedelta(hours=24)
                            if settled.state == "known" else None)
                        return self.replay.reply(terminal, caller, permit.request_sha256,
                                                 now=self.now(), replayed=False)
                    self.policies.assert_retry_stage_ready(permit.operation_id,
                        permit.attempt_children[index + 1].child_id, now=self.now())
                if retry:
                    # Source bridge must retain previous staged receipt or safely replace it
                    # only after its immutable no-charge settlement; unresolved seam003.
                    backoff = min(1000, max_backoff_milliseconds)
                    await asyncio.sleep(secrets.randbelow(backoff + 1) / 1000)
            except BaseException:
                if ticket is not None and not staged:
                    try:
                        with self.guard.hold(permit.authority_id):
                            if cancel.is_cancelled():
                                self.policies.cancel_operation(caller, permit.operation_id, now=self.now())
                            settlement = self.ledger.mark_unknown(operation_id=permit.operation_id,
                                child_id=child.child_id, attempt_id=ticket.attempt_id,
                                reason=UnknownReason.CANCELLED_AFTER_DISPATCH if cancel.is_cancelled()
                                else UnknownReason.RESULT_NOT_STAGED)
                            if receipt is not None and receipt.known_usage_cost_usd is not None:
                                # A failed cipher/stage must not discard an observed
                                # higher charge. U comes from committed settlement,
                                # not the incoming result. Quarantine unverified
                                # evidence and halt; never claim it was authenticated.
                                self._unsafe_authorities.add(permit.authority_id)
                                self.policies.append_incident(IncidentEvidence(
                                    authority_id=permit.authority_id, operation_id=permit.operation_id,
                                    child_id=child.child_id, attempt_id=ticket.attempt_id,
                                    provider=receipt.provider, source_sha256=digest(receipt),
                                    observed_cost_usd=receipt.known_usage_cost_usd,
                                    reserved_usd=settlement.reserved_usd,
                                    terminal_unknown_usd=settlement.terminal_unknown_usd,
                                    authenticated=False, conflict=True,
                                    reason_code="unauthenticated_evidence", recorded_utc=self.now()))
                            from .recovery import close_future_children
                            close_future_children(self, permit, reason="skipped", now=self.now())
                            self.policies.mark_terminal(permit.operation_id, settlement,
                                now=self.now(), result_expires_utc=None)
                    except BaseException:
                        self._unsafe_authorities.add(permit.authority_id)
                raise
        raise GatewayError(ErrorCode.UNRESOLVED_LIABILITY)

    def cancel(self, caller: CallerContext, operation_id: str):
        with self.guard.hold(caller.authority_id):
            return self.policies.cancel_operation(caller, operation_id, now=self.now())

    def recover(self, authority_id: str, *, now: datetime, ownership=(), cursor=None, limit: int = 256):
        from .recovery import recover
        return recover(self, authority_id, now=now, ownership=ownership, cursor=cursor, limit=limit)

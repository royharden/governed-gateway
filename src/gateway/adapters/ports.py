"""Async adapter seam. The controller alone owns funded dispatch claims."""

from datetime import datetime
from typing import Protocol

from gateway.schemas import CapabilityProfile, DispatchTicket, GatewayRequest, ProviderEnvelope, ProviderResult


class CancellationToken(Protocol):
    def is_cancelled(self) -> bool: ...


class PendingGeneration(Protocol):
    async def result(self) -> ProviderResult: ...

    def cancel(self) -> None: ...


class ProviderAdapter(Protocol):
    def capability_profile(self) -> CapabilityProfile: ...

    def serialize(self, request: GatewayRequest) -> ProviderEnvelope: ...

    def begin_generate(
        self, envelope: ProviderEnvelope, *, ticket: DispatchTicket,
        deadline: datetime, cancel_token: CancellationToken,
    ) -> PendingGeneration: ...

    async def generate(
        self, envelope: ProviderEnvelope, *, deadline: datetime,
        cancel_token: CancellationToken,
    ) -> ProviderResult: ...

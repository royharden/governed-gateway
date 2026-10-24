"""Pure Decimal indicative pricing; snapshots do not authorize provider access."""

from decimal import Decimal, localcontext
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from .models import (
    BillingPolicy,
    CostObservation,
    Count,
    Digest,
    Identifier,
    Money,
    NormalizedUsage,
    WireModel,
    canonical_digest,
    decode_wire_json,
)


class PriceProvenance(WireModel):
    origin: Literal["synthetic", "verified_primary"]
    source_url: str | None
    retrieved_at: str
    official_verified_at: str | None
    source_commit: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")] | None

    @model_validator(mode="after")
    def provenance(self) -> Self:
        from datetime import datetime
        from urllib.parse import urlsplit

        for value in [self.retrieved_at, self.official_verified_at]:
            if value is not None:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
                if not value.endswith("Z") or parsed.utcoffset().total_seconds() != 0:
                    raise ValueError("price provenance requires UTC timestamps")
        if self.origin == "synthetic":
            if any([self.source_url, self.official_verified_at, self.source_commit]):
                raise ValueError("synthetic fixtures cannot claim official source provenance")
        else:
            url = urlsplit(self.source_url or "")
            if (
                url.scheme != "https"
                or not url.hostname
                or url.username
                or url.password
                or url.query
                or url.fragment
                or self.official_verified_at is None
            ):
                raise ValueError("verified price metadata requires a clean primary URL and time")
        return self


class PricePolicy(WireModel):
    schema_version: Literal[1]
    provider: Identifier
    model: Identifier
    context_sha256: Digest
    cache_mode: Literal["flat_inclusive", "partitioned"]
    input_usd_per_million: Money | None
    cache_read_usd_per_million: Money | None
    cache_write_usd_per_million: Money | None
    output_usd_per_million: Money | None
    fee_usd: Money | None

    @model_validator(mode="after")
    def cache_rates(self) -> Self:
        rates = [self.cache_read_usd_per_million, self.cache_write_usd_per_million]
        if self.cache_mode == "flat_inclusive" and any(rate is not None for rate in rates):
            raise ValueError("flat inclusive pricing cannot add cache subset charges")
        if self.cache_mode == "partitioned" and any(
            rate is None for rate in [self.input_usd_per_million, *rates]
        ):
            raise ValueError("partitioned pricing needs all invoice partition rates")
        return self

    @property
    def policy_sha256(self) -> str:
        return canonical_digest(self.model_dump(mode="json"))

    def billing_policy(self) -> BillingPolicy:
        fields = []
        if self.cache_mode == "partitioned":
            fields.extend(["input_tokens", "cache_read_input_tokens", "cache_write_input_tokens"])
        elif self.input_usd_per_million is not None and Decimal(self.input_usd_per_million) > 0:
            fields.append("input_tokens")
        if self.output_usd_per_million is not None and Decimal(self.output_usd_per_million) > 0:
            fields.append("output_tokens")
        return BillingPolicy(
            schema_version=1,
            policy_sha256=self.policy_sha256,
            required_usage_fields=fields,
            fee_context_known=self.fee_usd is not None,
        )

    def price(self, usage: NormalizedUsage, *, reservation_usd: str) -> CostObservation:
        # Revalidate serialized input; frozen models contain mutable nested objects.
        usage = NormalizedUsage.model_validate(usage.model_dump())
        if any(value is not None and len(str(value)) > 40 for value in usage.model_dump().values()):
            raise ValueError("usage exceeds exact pricing arithmetic bound")
        policy = self.billing_policy()
        known = policy.usage_complete(usage)
        cost = None
        if known:
            with localcontext() as decimal_context:
                decimal_context.prec = 150
                amount = Decimal(self.fee_usd)
                if self.cache_mode == "partitioned":
                    uncached = (
                        usage.input_tokens
                        - usage.cache_read_input_tokens
                        - usage.cache_write_input_tokens
                    )
                    components = [
                        (uncached, self.input_usd_per_million),
                        (usage.cache_read_input_tokens, self.cache_read_usd_per_million),
                        (usage.cache_write_input_tokens, self.cache_write_usd_per_million),
                    ]
                else:
                    components = [(usage.input_tokens, self.input_usd_per_million)]
                components.append((usage.output_tokens, self.output_usd_per_million))
                for count, rate in components:
                    if rate is not None and Decimal(rate) != 0:
                        amount += Decimal(count) * Decimal(rate) / Decimal(1_000_000)
                cost = format(amount, "f")
        return CostObservation(
            schema_version=1,
            usage=usage,
            billing_policy=policy,
            status="known" if known else "unknown",
            computed_cost_usd=cost,
            unresolved_liability_usd="0" if known else reservation_usd,
        )

    def maximum_cost(self, input_maximum: int, output_maximum: int | None) -> str:
        for value in [input_maximum, output_maximum]:
            if value is not None and (type(value) is not int or value < 0 or len(str(value)) > 40):
                raise ValueError("token maximum must be an evidenced bounded integer")
        if self.fee_usd is None:
            raise ValueError("unknown fee context cannot fund a paid operation")
        if self.output_usd_per_million is not None and Decimal(self.output_usd_per_million) > 0:
            if output_maximum is None:
                raise ValueError("billed output needs an evidenced maximum")
        with localcontext() as context:
            context.prec = 150
            # Every inclusive input token is billed once at the worst applicable partition rate.
            rates = [
                Decimal(rate)
                for rate in [
                    self.input_usd_per_million,
                    self.cache_read_usd_per_million,
                    self.cache_write_usd_per_million,
                ]
                if rate is not None
            ]
            amount = Decimal(self.fee_usd) + Decimal(input_maximum) * max(
                rates, default=Decimal(0)
            ) / Decimal(1_000_000)
            if self.output_usd_per_million is not None:
                amount += (
                    Decimal(output_maximum or 0)
                    * Decimal(self.output_usd_per_million)
                    / Decimal(1_000_000)
                )
            return format(amount, "f")


class PriceSnapshot(WireModel):
    schema_version: Literal[1]
    provenance: PriceProvenance
    policies: Annotated[list[PricePolicy], Field(min_length=1, max_length=256)]
    data_sha256: Digest

    @model_validator(mode="after")
    def content(self) -> Self:
        if canonical_digest([p.model_dump(mode="json") for p in self.policies]) != self.data_sha256:
            raise ValueError("price data hash mismatch")
        if len({(p.provider, p.model, p.context_sha256) for p in self.policies}) != len(
            self.policies
        ):
            raise ValueError("duplicate price context")
        return self

    @property
    def snapshot_sha256(self) -> str:
        return canonical_digest(self.model_dump(mode="json"))

    def select(self, *, provider: str, model: str, context_sha256: str) -> PricePolicy:
        for policy in self.policies:
            if (policy.provider, policy.model, policy.context_sha256) == (
                provider,
                model,
                context_sha256,
            ):
                return policy
        raise ValueError("price_unknown")


def load_snapshot(path: Path) -> PriceSnapshot:
    return PriceSnapshot.model_validate(decode_wire_json(path.read_text(encoding="utf-8")))


class FundingEvidence(WireModel):
    """Trusted caller registry entry. Structural validity alone is not live token proof."""

    schema_version: Literal[1]
    snapshot_sha256: Digest
    policy_sha256: Digest
    provider_config_sha256: Digest
    model: Identifier
    request_shape_limit_sha256: Digest
    input_token_maximum: Count
    output_token_maximum: Count | None
    bound_kind: Literal["synthetic_fixture", "trusted_count", "documented_capacity"]
    proof_sha256: Digest

    @property
    def evidence_sha256(self) -> str:
        return canonical_digest(self.model_dump(mode="json"))


class RequestEvidence(WireModel):
    schema_version: Literal[1]
    bound_evidence_sha256: Digest
    request_identity_sha256: Digest
    dispatched_envelope_sha256: Digest
    input_token_count: Count
    output_token_maximum: Count | None
    proof_sha256: Digest

    @property
    def evidence_sha256(self) -> str:
        return canonical_digest(self.model_dump(mode="json"))

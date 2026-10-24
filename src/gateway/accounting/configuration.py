"""Explicit trusted bootstrap configuration. These are upstream types, not wire DTOs."""
from dataclasses import dataclass
from decimal import Decimal
from gateway.schemas import CapabilityProfile, ErrorCode, digest
from gateway.shared.s3.callledger import models as s3
from gateway.shared.s3.callledger.pricing import FundingEvidence, PriceSnapshot, RequestEvidence
from .errors import AccountingError


@dataclass(frozen=True)
class LedgerConfiguration:
    authority: s3.BudgetAuthority
    price_snapshot: PriceSnapshot
    trusted_bounds: tuple[FundingEvidence, ...]
    trusted_requests: tuple[RequestEvidence, ...]
    limits: s3.Limits
    profiles: tuple[CapabilityProfile, ...]

    def projection(self) -> dict:
        limits=self.limits.model_dump(mode="json")
        # S3 uses finite float durations; canonical M8 configuration encodes their
        # exact declared decimal representations as strings, never JSON floats.
        for field in ("operation_deadline_s","attempt_timeout_s"):
            limits[field]=format(Decimal(str(limits[field])),"f")
        return {
            "schema_version": 1,
            "authority": self.authority.model_dump(mode="json"),
            "price_snapshot": self.price_snapshot.model_dump(mode="json"),
            "trusted_bounds": [b.model_dump(mode="json") for b in self.trusted_bounds],
            "trusted_requests": [r.model_dump(mode="json") for r in self.trusted_requests],
            "limits": limits,
            "profiles": self.profiles,
        }

    @property
    def scope_sha256(self) -> str:
        projection=self.projection()
        # Only the durable digest carrier excludes itself; every other immutable
        # authority, profile, policy, bound, seed request and limit is committed.
        projection["authority"].pop("scope_sha256")
        return digest(projection)

    @property
    def config_sha256(self) -> str:
        return digest(self.projection())

    @property
    def bound_bundle_sha256(self) -> str:
        return digest({"schema_version": 1, "synthetic_bounds": [
            b.model_dump(mode="json") for b in sorted(self.trusted_bounds, key=lambda b: b.evidence_sha256)
        ]})

    def validate(self) -> None:
        if self.authority.scope_sha256 != self.scope_sha256:
            raise AccountingError(ErrorCode.AUTHORITY_MISMATCH)
        if self.price_snapshot.provenance.origin != "synthetic" or not self.profiles:
            raise AccountingError(ErrorCode.UNSUPPORTED_PROFILE)
        if len({(p.provider,p.exact_model) for p in self.profiles}) != len(self.profiles):
            raise AccountingError(ErrorCode.INVALID_EVIDENCE)
        if self.limits.max_content_repairs != 0 or self.limits.max_attempts_total > 2:
            raise AccountingError(ErrorCode.INVALID_EVIDENCE)
        if len({r.bound_evidence_sha256 for r in self.trusted_requests}) != len(self.trusted_requests):
            raise AccountingError(ErrorCode.INVALID_EVIDENCE)
        for b in self.trusted_bounds:
            if b.bound_kind != "synthetic_fixture" or b.snapshot_sha256 != self.price_snapshot.snapshot_sha256:
                raise AccountingError(ErrorCode.INVALID_EVIDENCE)
        for r in self.trusted_requests:
            bounds=[b for b in self.trusted_bounds if b.evidence_sha256==r.bound_evidence_sha256]
            if len(bounds)!=1 or r.input_token_count>bounds[0].input_token_maximum or r.output_token_maximum!=bounds[0].output_token_maximum:
                raise AccountingError(ErrorCode.INVALID_EVIDENCE)
        for p in self.profiles:
            if (p.mode != "simulation" or not p.exact_model.startswith("mock-")
                or p.price_sha256 != self.price_snapshot.snapshot_sha256
                or p.bound_sha256 != self.bound_bundle_sha256
                or set(p.supported_billable_components) != {"input_tokens","output_tokens"}):
                raise AccountingError(ErrorCode.UNSUPPORTED_PROFILE)
            matches = [b for b in self.trusted_bounds
                       if b.provider_config_sha256 == p.capability_sha256 and b.model == p.exact_model]
            if len(matches) != 1:
                raise AccountingError(ErrorCode.INVALID_EVIDENCE)
            b = matches[0]
            policies = [x for x in self.price_snapshot.policies if x.policy_sha256 == b.policy_sha256]
            if len(policies) != 1:
                raise AccountingError(ErrorCode.INVALID_EVIDENCE)
            policy = policies[0]
            if (b.bound_kind != "synthetic_fixture" or b.snapshot_sha256 != p.price_sha256
                or policy.provider != p.provider or policy.model != p.exact_model
                or b.output_token_maximum != p.max_output_tokens
                or policy.cache_mode != "flat_inclusive" or policy.fee_usd is None
                or policy.input_usd_per_million is None or policy.output_usd_per_million is None):
                raise AccountingError(ErrorCode.INVALID_EVIDENCE)
            # Restrict this synthetic schedule to integral micro-USD/token rates.
            # Actual charges remain exact; never round a sub-micro charge away.
            for rate in (policy.input_usd_per_million, policy.output_usd_per_million):
                d=Decimal(rate)
                if d != d.to_integral_value():
                    raise AccountingError(ErrorCode.UNSUPPORTED_PROFILE)
            if Decimal(policy.fee_usd).as_tuple().exponent < -6:
                raise AccountingError(ErrorCode.UNSUPPORTED_PROFILE)
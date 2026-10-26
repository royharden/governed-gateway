"""Explicit trusted runtime dependencies; no bootstrap, signing, or import-time I/O.

These helpers accept operator-owned configuration, never HTTP/request dictionaries.
They establish dependency eligibility, not approval or evaluation success.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import re
import stat
import sys
from threading import RLock
from typing import Protocol

from .schemas.core import ErrorCode, GatewayError, digest
from .schemas.governance import (
    DependencyExpiry, EligibilityContext, EvidenceTuple, PolicyBundle,
)
from .schemas.providers import CapabilityProfile


def _require(condition: bool, code: ErrorCode) -> None:
    if not condition:
        raise GatewayError(code)


def _hash(value: str) -> None:
    _require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None,
             ErrorCode.CONFIG_MISMATCH)


def _utc(value: datetime) -> datetime:
    _require(isinstance(value, datetime) and value.utcoffset() == timedelta(0),
             ErrorCode.CLOCK_UNTRUSTED)
    return value.astimezone(timezone.utc)


def _linux_local_mount(root: Path) -> None:
    """Longest matching mount wins; unknown/network/ephemeral filesystems deny."""
    mounts: list[tuple[Path, str]] = []
    with Path("/proc/self/mountinfo").open("r", encoding="utf-8") as source:
        for line in source:
            fields = line.split()
            separator = fields.index("-")
            mount_text = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), fields[4])
            mount = Path(mount_text)
            _require(mount.is_absolute() and separator >= 6, ErrorCode.UNSAFE_RUNTIME_PATH)
            if root.is_relative_to(mount):
                mounts.append((mount, fields[separator + 1]))
    _require(bool(mounts), ErrorCode.UNSAFE_RUNTIME_PATH)
    longest = max(len(mount.parts) for mount, _ in mounts)
    selected = {filesystem for mount, filesystem in mounts if len(mount.parts) == longest}
    _require(len(selected) == 1 and selected <= {"ext4", "xfs", "btrfs"},
             ErrorCode.UNSAFE_RUNTIME_PATH)


def require_local_runtime_root(root: Path) -> Path:
    """Validate an existing Windows/Linux durable local directory without creation.

    Reject symlink/reparse ancestors, UNC/device paths, known sync/export roots,
    and the product tree. Unknown OS/locality refuses rather than guessing.
    Keep DB/WAL/locks/keys together below this returned root. Validation does not
    protect against subsequent local-admin path replacement or prove key ACLs.
    """
    try:
        _require(isinstance(root, Path) and root.is_absolute(), ErrorCode.UNSAFE_RUNTIME_PATH)
        _require(not str(root).startswith(("\\\\", "//")), ErrorCode.UNSAFE_RUNTIME_PATH)
        _require(os.name == "nt" or sys.platform == "linux", ErrorCode.UNSAFE_RUNTIME_PATH)
        if os.name == "nt":
            _require(bool(root.drive), ErrorCode.UNSAFE_RUNTIME_PATH)
        original = root
        root_attributes = original.lstat()
        for ancestor in (original, *original.parents):
            attributes = root_attributes if ancestor == original else ancestor.lstat()
            _require(not stat.S_ISLNK(attributes.st_mode)
                     and not (getattr(attributes, "st_file_attributes", 0) & 0x400),
                     ErrorCode.UNSAFE_RUNTIME_PATH)
        resolved = root.resolve(strict=True)
        # Reuse only metadata already obtained in this validation call. A
        # differently expressed root still checks the resolved directory.
        is_directory = (stat.S_ISDIR(root_attributes.st_mode)
                        if resolved == original else resolved.is_dir())
        _require(is_directory, ErrorCode.UNSAFE_RUNTIME_PATH)
        denied = {"onedrive", ".chatexports", "dropbox", "google drive", "googledrive",
                  "icloud", "icloud drive", "box", "box sync"}
        _require(not any(part.casefold() in denied or part.casefold().startswith("onedrive -")
                         for part in resolved.parts), ErrorCode.UNSAFE_RUNTIME_PATH)
        repository = Path(__file__).resolve(strict=True).parents[2]
        _require(not resolved.is_relative_to(repository), ErrorCode.UNSAFE_RUNTIME_PATH)
        _require(not any((ancestor / ".git").exists()
                         for ancestor in (resolved, *resolved.parents)),
                 ErrorCode.UNSAFE_RUNTIME_PATH)
        for name in ("OneDrive", "OneDriveCommercial", "OneDriveConsumer", "Dropbox",
                     "GoogleDrive", "iCloudDrive"):
            configured = os.environ.get(name)
            if configured:
                _require(not resolved.is_relative_to(Path(configured).resolve(strict=False)),
                         ErrorCode.UNSAFE_RUNTIME_PATH)
        if os.name == "nt":
            # Imported only on an explicit call; GetDriveType performs no writes.
            import ctypes
            get_drive_type = ctypes.windll.kernel32.GetDriveTypeW
            get_drive_type.argtypes = [ctypes.c_wchar_p]
            get_drive_type.restype = ctypes.c_uint
            _require(get_drive_type(resolved.anchor) == 3, ErrorCode.UNSAFE_RUNTIME_PATH)
        else:
            _linux_local_mount(resolved)
        return resolved
    except GatewayError:
        raise
    except Exception:
        raise GatewayError(ErrorCode.UNSAFE_RUNTIME_PATH) from None


class ClockHighWater(Protocol):
    """Trusted durable storage, shared across all processes for one authority.

    read must return an existing aware UTC value (unknown is an error).
    compare_and_advance atomically checks equality with expected, commits observed
    durably, and returns True only after commit; it must never lower high-water.
    Implementations acquire the common authority lock. No implementation or DB
    initialization is supplied here. A new authority needs separate trusted setup.
    """
    def read(self) -> datetime: ...

    def compare_and_advance(self, expected: datetime, observed: datetime) -> bool: ...


class TrustedClock:
    """Fail-closed UTC clock with durable rollback and process drift checks.

    monotonic_ns is an injected integer-nanosecond source, e.g. time.monotonic_ns.
    The explicitly bounded first reading also checks elapsed wall time since the
    existing durable high-water; long offline gaps require trusted operator action.
    Any failure latches this instance closed. Callbacks run only on __call__.
    """
    def __init__(self, *, utc_now: Callable[[], datetime],
                 monotonic_ns: Callable[[], int], high_water: ClockHighWater,
                 clock_identity_sha256: str, max_drift: timedelta,
                 max_startup_advance: timedelta) -> None:
        _hash(clock_identity_sha256)
        _require(isinstance(max_drift, timedelta) and max_drift >= timedelta(0)
                 and isinstance(max_startup_advance, timedelta)
                 and max_startup_advance > timedelta(0), ErrorCode.CONFIG_MISMATCH)
        self._utc_now = utc_now
        self._monotonic_ns = monotonic_ns
        self._high_water = high_water
        self._max_drift = max_drift
        self._max_startup_advance = max_startup_advance
        self._last: tuple[datetime, int] | None = None
        self._failure: ErrorCode | None = None
        self._lock = RLock()
        self._evidence = digest({
            "schema_version": 1, "domain": "gateway.trusted-clock-config.v1",
            "clock_identity_sha256": clock_identity_sha256,
            "max_drift_microseconds": max_drift // timedelta(microseconds=1),
            "max_startup_advance_microseconds": max_startup_advance // timedelta(microseconds=1),
            "high_water_contract": "existing-durable-utc-cas-v1",
            "monotonic_unit": "integer-nanoseconds",
        })

    def __call__(self) -> datetime:
        with self._lock:
            if self._failure is not None:
                raise GatewayError(self._failure)
            try:
                previous = _utc(self._high_water.read())
                observed = _utc(self._utc_now())
                ticks = self._monotonic_ns()
                _require(type(ticks) is int and ticks >= 0, ErrorCode.CLOCK_UNTRUSTED)
                _require(observed >= previous, ErrorCode.CLOCK_ROLLBACK)
                if self._last is None:
                    _require(observed - previous <= self._max_startup_advance,
                             ErrorCode.CLOCK_UNTRUSTED)
                else:
                    last_time, last_ticks = self._last
                    _require(previous >= last_time and observed >= last_time and ticks >= last_ticks,
                             ErrorCode.CLOCK_ROLLBACK)
                    wall_ns = (observed - last_time) // timedelta(microseconds=1) * 1000
                    drift_ns = self._max_drift // timedelta(microseconds=1) * 1000
                    _require(abs(wall_ns - (ticks - last_ticks)) <= drift_ns,
                             ErrorCode.CLOCK_UNTRUSTED)
                _require(self._high_water.compare_and_advance(previous, observed) is True,
                         ErrorCode.CLOCK_UNTRUSTED)
                self._last = (observed, ticks)
                return observed
            except GatewayError as error:
                self._failure = error.code
                raise
            except Exception:
                self._failure = ErrorCode.CLOCK_UNTRUSTED
                raise GatewayError(ErrorCode.CLOCK_UNTRUSTED) from None

    def evidence_sha256(self) -> str:
        """Stable configuration identity, available only after a validated reading.

        This digest is not signed proof of time. Fresh observed_utc plus every
        clock call's gates establish the runtime check; clients cannot set it.
        """
        with self._lock:
            _require(self._last is not None and self._failure is None, ErrorCode.CLOCK_UNTRUSTED)
            return self._evidence


def clock_evidence(clock: TrustedClock) -> str:
    """Return the stable evidence identity after clock() has validated time."""
    return clock.evidence_sha256()


def _identity(profile: CapabilityProfile) -> tuple[str, ...]:
    return (profile.provider, profile.exact_model, profile.api_version,
            profile.capability_sha256, profile.adapter_sha256)


def _profiles(profiles: tuple[CapabilityProfile, ...]) -> tuple[CapabilityProfile, ...]:
    _require(type(profiles) is tuple and len(profiles) > 0, ErrorCode.MISSING_EVIDENCE)
    try:
        checked = tuple(CapabilityProfile.model_validate(p.model_dump(mode="python")) for p in profiles)
    except Exception:
        raise GatewayError(ErrorCode.INVALID_EVIDENCE) from None
    _require(len({_identity(p) for p in checked}) == len(checked), ErrorCode.EVIDENCE_CONFLICT)
    return tuple(sorted(checked, key=_identity))


def profile_manifest_digest(profiles: tuple[CapabilityProfile, ...]) -> str:
    """Exact INT-SEAMS-004 composite, not a single capability profile digest."""
    rows = [{"provider": p.provider, "exact_model": p.exact_model,
             "api_version": p.api_version, "capability_sha256": p.capability_sha256,
             "adapter_sha256": p.adapter_sha256, "price_sha256": p.price_sha256,
             "bound_sha256": p.bound_sha256} for p in _profiles(profiles)]
    return digest({"schema_version": 1, "profiles": rows})


def adapter_manifest_digest(profiles: tuple[CapabilityProfile, ...]) -> str:
    """Exact sorted distinct adapter-hash composite from INT-SEAMS-004."""
    return digest({"schema_version": 1,
                   "adapter_sha256": sorted({p.adapter_sha256 for p in _profiles(profiles)})})


@dataclass(frozen=True)
class RuntimeEvidenceRecord:
    """Trusted configured dependency record; never an approval or pass assertion."""
    bundle: PolicyBundle
    evidence: EvidenceTuple
    dependency_expiries: tuple[DependencyExpiry, ...]
    evaluation_max_age_seconds: int


class ApprovedProfileRegistry:
    """Immutable configured manifest sets, addressed only by exact composite hash."""
    def __init__(self, *, manifests: tuple[tuple[CapabilityProfile, ...], ...],
                 clock: TrustedClock) -> None:
        _require(type(manifests) is tuple, ErrorCode.CONFIG_MISMATCH)
        entries = tuple(_profiles(profiles) for profiles in manifests)
        keys = tuple(profile_manifest_digest(profiles) for profiles in entries)
        _require(len(set(keys)) == len(keys), ErrorCode.EVIDENCE_CONFLICT)
        self._entries = tuple(zip(keys, entries))
        self._clock = clock

    def __call__(self, manifest_digest: str) -> tuple[CapabilityProfile, ...]:
        _hash(manifest_digest)
        now = self._clock()
        for key, profiles in self._entries:
            if key == manifest_digest:
                _require(profile_manifest_digest(profiles) == key, ErrorCode.INVALID_EVIDENCE)
                _require(all(p.mode == "simulation" for p in profiles), ErrorCode.EXTERNAL_DISABLED)
                _require(all(now < p.expires_utc for p in profiles), ErrorCode.STALE_EVIDENCE)
                return profiles
        raise GatewayError(ErrorCode.MISSING_EVIDENCE)


class EvidenceContextLoader:
    """Trusted context_loader(policy_bundle_sha256) for the DL3/DL4 ports.

    Configuration must come from the local trusted bootstrap, never a request.
    There is no default registry, unsigned active policy, or eligibility flag.
    Approval/signature/evaluation/revocation/CAS checks remain PolicyStore duties.
    """
    def __init__(self, *, authority_id: str, records: tuple[RuntimeEvidenceRecord, ...],
                 profile_loader: ApprovedProfileRegistry, clock: TrustedClock) -> None:
        _require(type(records) is tuple, ErrorCode.CONFIG_MISMATCH)
        copied = []
        for record in records:
            _require(isinstance(record, RuntimeEvidenceRecord)
                     and type(record.dependency_expiries) is tuple
                     and type(record.evaluation_max_age_seconds) is int
                     and 0 < record.evaluation_max_age_seconds <= 86400,
                     ErrorCode.CONFIG_MISMATCH)
            copied.append(RuntimeEvidenceRecord(
                bundle=PolicyBundle.model_validate(record.bundle.model_dump(mode="python")),
                evidence=EvidenceTuple.model_validate(record.evidence.model_dump(mode="python")),
                dependency_expiries=tuple(DependencyExpiry.model_validate(d.model_dump(mode="python"))
                                          for d in record.dependency_expiries),
                evaluation_max_age_seconds=record.evaluation_max_age_seconds,
            ))
        _require(len({digest(r.bundle) for r in copied}) == len(copied), ErrorCode.EVIDENCE_CONFLICT)
        self._authority_id = authority_id
        self._records = tuple(copied)
        self._profile_loader = profile_loader
        self._clock = clock

    def __call__(self, policy_bundle_sha256: str) -> EligibilityContext:
        _hash(policy_bundle_sha256)
        try:
            record = next((r for r in self._records if digest(r.bundle) == policy_bundle_sha256), None)
            _require(record is not None, ErrorCode.MISSING_EVIDENCE)
            bundle, evidence = record.bundle, record.evidence
            _require(evidence.policy_bundle_sha256 == policy_bundle_sha256
                     and evidence.eval_spec_sha256 == bundle.eval_spec_sha256
                     and evidence.feature_schema_sha256 == bundle.feature_schema_sha256
                     and evidence.price_sha256 == bundle.price_sha256
                     and evidence.bound_sha256 == bundle.bound_bundle_sha256,
                     ErrorCode.INVALID_EVIDENCE)
            profiles = self._profile_loader(evidence.adapter_capability_sha256)
            _require(profile_manifest_digest(profiles) == evidence.adapter_capability_sha256
                     and adapter_manifest_digest(profiles) == evidence.adapter_sha256,
                     ErrorCode.INVALID_EVIDENCE)
            profile_by_identity = {_identity(p): p for p in profiles}
            for target in bundle.targets:
                identity = (target.provider, target.exact_model, target.api_version,
                            target.capability_sha256, target.adapter_sha256)
                _require(identity in profile_by_identity, ErrorCode.MISSING_EVIDENCE)
            # Current synthetic bundle uses the same frozen table/bound identities.
            # A future aggregate-to-member mapping needs its own pinned contract.
            _require(all(p.price_sha256 == evidence.price_sha256
                         and p.bound_sha256 == evidence.bound_sha256 for p in profiles),
                     ErrorCode.INVALID_EVIDENCE)
            now = self._clock()
            context = EligibilityContext(
                authority_id=self._authority_id, mode="simulation", tuple=evidence,
                dependency_expiries=record.dependency_expiries,
                evaluation_max_age_seconds=record.evaluation_max_age_seconds,
                observed_utc=now, clock_evidence_sha256=clock_evidence(self._clock),
            )
            _require(now < bundle.expires_utc
                     and all(now < item.expires_utc for item in context.dependency_expiries)
                     and all(now < profile.expires_utc for profile in profiles),
                     ErrorCode.STALE_EVIDENCE)
            return context
        except GatewayError:
            raise
        except Exception:
            raise GatewayError(ErrorCode.INVALID_EVIDENCE) from None

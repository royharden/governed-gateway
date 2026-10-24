"""One reentrant thread/process lock per finite authority; never a send ticket."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
import hashlib
import math
import os
from pathlib import Path
import threading
import time

from gateway.schemas import ErrorCode, GatewayError
from gateway.runtime import require_local_runtime_root


@dataclass
class _Entry:
    mutex: threading.RLock = field(default_factory=threading.RLock)
    depth: int = 0
    owner: int | None = None
    descriptor: int | None = None


_entries: dict[tuple[int, str], _Entry] = {}
_entries_mutex = threading.Lock()


def validate_runtime_root(root: Path) -> Path:
    # One shared trusted locality rule, supplied by INT; never a parallel policy.
    return require_local_runtime_root(root)


class AuthorityLock:
    def __init__(self, runtime_root: Path):
        self.runtime_root = validate_runtime_root(runtime_root)

    def _entry(self, authority_id: str) -> tuple[Path, _Entry]:
        if not authority_id or len(authority_id) > 128:
            raise GatewayError(ErrorCode.AUTHORITY_MISMATCH)
        name = hashlib.sha256(authority_id.encode("utf-8")).hexdigest() + ".lock"
        path = self.runtime_root / "authority-locks" / name
        key = (os.getpid(), os.path.normcase(str(path)))
        with _entries_mutex:
            return path, _entries.setdefault(key, _Entry())

    def assert_held(self, *, authority_id: str) -> None:
        _, entry = self._entry(authority_id)
        if entry.depth <= 0 or entry.owner != threading.get_ident() or entry.descriptor is None:
            raise GatewayError(ErrorCode.LOCK_UNAVAILABLE)

    @contextmanager
    def hold(self, authority_id: str, *, timeout_seconds: float = 5.0):
        if not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 60:
            raise GatewayError(ErrorCode.LOCK_UNAVAILABLE)
        path, entry = self._entry(authority_id)
        end = time.monotonic() + timeout_seconds
        if not entry.mutex.acquire(timeout=timeout_seconds):
            raise GatewayError(ErrorCode.LOCK_UNAVAILABLE)
        descriptor = None
        acquired = False
        try:
            if entry.depth == 0:
                path.parent.mkdir(parents=True, exist_ok=True)
                flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
                descriptor = os.open(path, flags, 0o600)
                if os.fstat(descriptor).st_size == 0:
                    os.write(descriptor, b"\0")
                while True:
                    try:
                        if os.name == "nt":
                            import msvcrt
                            os.lseek(descriptor, 0, os.SEEK_SET)
                            msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
                        else:
                            import fcntl
                            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        acquired = True
                        break
                    except OSError:
                        if time.monotonic() >= end:
                            raise GatewayError(ErrorCode.LOCK_UNAVAILABLE) from None
                        time.sleep(min(0.01, max(end - time.monotonic(), 0)))
                entry.descriptor, entry.owner = descriptor, threading.get_ident()
            entry.depth += 1
            try:
                yield
            finally:
                entry.depth -= 1
                if entry.depth == 0:
                    fd = entry.descriptor
                    entry.descriptor, entry.owner = None, None
                    try:
                        if os.name == "nt":
                            import msvcrt
                            os.lseek(fd, 0, os.SEEK_SET)
                            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                        else:
                            import fcntl
                            fcntl.flock(fd, fcntl.LOCK_UN)
                    finally:
                        os.close(fd)
                        descriptor = None
        except OSError:
            raise GatewayError(ErrorCode.LOCK_UNAVAILABLE) from None
        finally:
            if descriptor is not None and not acquired:
                os.close(descriptor)
            entry.mutex.release()

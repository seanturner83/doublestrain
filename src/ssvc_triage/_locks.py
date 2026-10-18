"""Per-key locks for `ssvc-run --workers`: rows are judged on threads, and two rows can
want the same expensive thing at once (a trigger spec for the same advisory, a
govulncheck scan of the same checkout, the same package tarball, the same cache entry).
The first builds it while the others wait, then they find it cached."""
from __future__ import annotations

import contextlib
import threading

_GUARD = threading.Lock()
_LOCKS: dict[object, threading.Lock] = {}


@contextlib.contextmanager
def keylock(key):
    with _GUARD:
        lock = _LOCKS.setdefault(key, threading.Lock())
    with lock:
        yield

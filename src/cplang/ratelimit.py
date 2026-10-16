"""Sliding-window rate limiter used by `max_calls_per_window` by default; hosts can supply their own `RateLimiter`."""

from __future__ import annotations

import threading
from collections import deque
from typing import Protocol


class RateLimiter(Protocol):
    """Counts calls per key within a sliding window."""

    def check(self, key: str, limit: int, window_seconds: int, *, now_us: int) -> bool:
        """Admit-and-record: True if the call is within `limit` per `window_seconds`."""
        ...

    def peek(self, key: str, limit: int, window_seconds: int, *, now_us: int) -> bool:
        """Like `check` but records nothing (tests, explain, replay, monitor mode)."""
        ...


class InMemoryRateLimiter:
    """Keys with no call left in their window are dropped, so memory follows the number of active keys."""

    def __init__(self) -> None:
        self._calls: dict[str, deque[int]] = {}
        self._lock = threading.Lock()

    def _live(self, key: str, window_seconds: int, now_us: int) -> deque[int]:
        q = self._calls.get(key)
        if q is None:
            return deque()
        cutoff = now_us - window_seconds * 1_000_000
        while q and q[0] <= cutoff:
            q.popleft()
        if not q:
            del self._calls[key]
        return q

    def check(self, key: str, limit: int, window_seconds: int, *, now_us: int) -> bool:
        """Record a call and return whether it is within the limit."""
        with self._lock:
            q = self._live(key, window_seconds, now_us)
            if len(q) >= limit:
                return False
            q.append(now_us)
            self._calls[key] = q
            return True

    def peek(self, key: str, limit: int, window_seconds: int, *, now_us: int) -> bool:
        """Return whether a call would be within the limit, recording nothing."""
        with self._lock:
            return len(self._live(key, window_seconds, now_us)) < limit

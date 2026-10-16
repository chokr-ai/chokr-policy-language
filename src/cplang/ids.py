"""Prefixed, time-sortable ids (ULIDs) for verdicts. Thread-safe; the time and random sources can be replaced."""

from __future__ import annotations

import os
import threading
import time
from collections.abc import Callable

_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"  # Crockford base32 alphabet


def _enc(n: int, length: int) -> str:
    out = []
    for _ in range(length):
        out.append(_ALPHABET[n & 31])
        n >>= 5
    return "".join(reversed(out))


class IdGenerator:
    """A 26-character ULID: 48 bits of millisecond time plus 80 random bits. Ids from one generator never decrease."""

    def __init__(self, now_ms: Callable[[], int] | None = None, randbytes: Callable[[int], bytes] = os.urandom) -> None:
        self._now_ms = now_ms or (lambda: int(time.time() * 1000))
        self._randbytes = randbytes
        self._lock = threading.Lock()
        self._last_ms = -1
        self._last_rand = 0

    def ulid(self) -> str:
        """The next ULID."""
        with self._lock:
            ms = self._now_ms()
            if ms <= self._last_ms:  # same millisecond, or the clock stepped back
                ms = self._last_ms
                self._last_rand += 1
            else:
                self._last_rand = int.from_bytes(self._randbytes(10), "big")
            self._last_ms = ms
            return _enc(ms, 10) + _enc(self._last_rand, 16)

    def new_id(self, prefix: str) -> str:
        """The next id with the given prefix, such as `ver_01J...`."""
        return f"{prefix}_{self.ulid()}"


default_ids = IdGenerator()

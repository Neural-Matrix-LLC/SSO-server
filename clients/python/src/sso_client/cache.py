"""In-process TTL cache for ACTIVE results only (decision 15): key sha256(token):ip, TTL min(30 s, exp)."""
from __future__ import annotations

import hashlib
import threading
import time
from collections import OrderedDict

from .models import CheckResult


def cache_key(token: str, ip: str | None) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest() + ":" + (ip or "")


class TTLCache:
    def __init__(self, ttl: float = 30.0, maxsize: int = 10_000, clock=time.time):
        self.ttl, self.maxsize, self.clock = ttl, maxsize, clock
        self._data: OrderedDict[str, tuple[float, CheckResult]] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: str) -> CheckResult | None:
        with self._lock:
            item = self._data.get(key)
            if item is None:
                return None
            if item[0] <= self.clock():
                del self._data[key]
                return None
            self._data.move_to_end(key)
            return item[1]

    def set(self, key: str, result: CheckResult) -> None:
        if self.ttl <= 0 or not result.active:
            return  # never cache inactive answers
        until = self.clock() + self.ttl
        if result.expires_at is not None:
            until = min(until, result.expires_at.timestamp())
        if until <= self.clock():
            return
        with self._lock:
            self._data[key] = (until, result)
            self._data.move_to_end(key)
            while len(self._data) > self.maxsize:
                self._data.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()

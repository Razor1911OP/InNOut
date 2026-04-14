"""Host/time correlation — Splunk-style density + Falcon-style burst hints."""

from __future__ import annotations

import time
from collections import defaultdict, deque

from narip.schemas.security import CanonicalSecurityEvent


class HostCorrelator:
    def __init__(self, window_sec: float = 300.0, max_hosts: int = 5000) -> None:
        self._window = window_sec
        self._max_hosts = max_hosts
        self._events: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=256))

    def _prune(self, host: str, now: float) -> None:
        dq = self._events[host]
        while dq and now - dq[0] > self._window:
            dq.popleft()

    def observe(self, c: CanonicalSecurityEvent) -> dict[str, float]:
        now = time.time()
        host = c.host or c.source_host or c.user_principal or "unknown"
        if len(self._events) > self._max_hosts and host not in self._events:
            return {"recent_count": 0.0, "boost": 0.0}
        dq = self._events[host]
        dq.append(now)
        self._prune(host, now)
        n = len(dq)
        boost = 0.0
        if n >= 25:
            boost = 0.2
        elif n >= 12:
            boost = 0.12
        elif n >= 6:
            boost = 0.06
        return {"recent_count": float(n), "boost": boost, "host": host}

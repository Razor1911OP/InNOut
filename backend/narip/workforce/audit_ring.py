"""Ring buffer of structured events for dashboards, SIEM forwarders, and UI activity feeds."""

from __future__ import annotations

import asyncio
import time
import uuid
from collections import deque
from typing import Any

from pydantic import BaseModel, Field


class AuditEvent(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    ts: float = Field(default_factory=time.time)
    category: str
    action: str
    employee_id: str | None = None
    detail: dict[str, Any] = Field(default_factory=dict)


class AuditRingBuffer:
    def __init__(self, maxlen: int = 2000) -> None:
        self._q: deque[AuditEvent] = deque(maxlen=maxlen)
        self._lock = asyncio.Lock()

    async def append(self, ev: AuditEvent) -> None:
        async with self._lock:
            self._q.append(ev)

    def append_sync(self, ev: AuditEvent) -> None:
        self._q.append(ev)

    async def recent(self, limit: int = 100, category: str | None = None) -> list[AuditEvent]:
        async with self._lock:
            rows = list(self._q)
        rows.reverse()
        if category:
            rows = [r for r in rows if r.category == category]
        return rows[:limit]

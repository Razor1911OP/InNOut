from __future__ import annotations

import asyncio
import json
from collections import deque
from collections.abc import AsyncIterator
from typing import Any


class IncidentBroker:
    """In-process pub/sub with REST-pollable history; swap for Redis/Kafka in production."""

    def __init__(self, history_maxlen: int = 1000) -> None:
        self._subs: list[asyncio.Queue[str]] = []
        self._lock = asyncio.Lock()
        self._history: deque[str] = deque(maxlen=history_maxlen)

    async def publish(self, topic: str, payload: dict[str, Any]) -> None:
        msg = json.dumps({"topic": topic, "payload": payload}, default=str)
        async with self._lock:
            self._history.append(msg)
            for q in self._subs:
                await q.put(msg)

    async def recent_messages(self, limit: int = 100, topic_prefix: str | None = None) -> list[dict[str, Any]]:
        async with self._lock:
            items = list(self._history)
        items.reverse()
        out: list[dict[str, Any]] = []
        for raw in items:
            if len(out) >= limit:
                break
            try:
                row = json.loads(raw)
            except json.JSONDecodeError:
                continue
            t = str(row.get("topic") or "")
            if topic_prefix and not t.startswith(topic_prefix):
                continue
            out.append(row)
        return out

    async def subscribe(self) -> AsyncIterator[str]:
        q: asyncio.Queue[str] = asyncio.Queue(maxsize=256)
        async with self._lock:
            self._subs.append(q)
        try:
            while True:
                yield await q.get()
        finally:
            async with self._lock:
                if q in self._subs:
                    self._subs.remove(q)

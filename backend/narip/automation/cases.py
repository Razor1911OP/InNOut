from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class CaseRecord(BaseModel):
    case_id: str
    status: Literal["open", "in_progress", "resolved", "auto_closed"] = "open"
    priority: Literal["P1", "P2", "P3", "P4"] = "P3"
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)
    fingerprint: str | None = None
    vendor: str = ""
    risk_score: int = 0
    title: str = ""
    summary: dict[str, Any] = Field(default_factory=dict)


class CaseStore:
    def __init__(self) -> None:
        self._cases: dict[str, CaseRecord] = {}
        self._by_print: dict[str, str] = {}
        self._lock = asyncio.Lock()

    async def upsert_by_fingerprint(
        self,
        fp: str,
        *,
        vendor: str,
        risk_score: int,
        title: str,
        summary: dict[str, Any],
    ) -> CaseRecord:
        async with self._lock:
            if fp in self._by_print:
                cid = self._by_print[fp]
                cur = self._cases[cid]
                cur.updated_at = _utcnow()
                cur.risk_score = max(cur.risk_score, risk_score)
                if cur.priority == "P4" and risk_score >= 70:
                    cur.priority = "P2"
                return cur
            cid = str(uuid.uuid4())
            rec = CaseRecord(
                case_id=cid,
                fingerprint=fp,
                vendor=vendor,
                risk_score=risk_score,
                title=title,
                summary=summary,
                priority="P1" if risk_score >= 85 else ("P2" if risk_score >= 65 else ("P3" if risk_score >= 40 else "P4")),
            )
            self._cases[cid] = rec
            self._by_print[fp] = cid
            return rec

    async def list_open(self, limit: int = 50) -> list[CaseRecord]:
        async with self._lock:
            rows = [c for c in self._cases.values() if c.status == "open"]
            rows.sort(key=lambda x: x.updated_at, reverse=True)
            return rows[:limit]

    async def get(self, case_id: str) -> CaseRecord | None:
        async with self._lock:
            return self._cases.get(case_id)

    async def set_status(self, case_id: str, status: str) -> CaseRecord | None:
        async with self._lock:
            c = self._cases.get(case_id)
            if not c:
                return None
            c.status = status  # type: ignore[assignment]
            c.updated_at = _utcnow()
            return c

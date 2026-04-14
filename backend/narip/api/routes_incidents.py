"""REST polling for published incidents (replaces WebSocket subscribe)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query

from narip.api.deps import get_broker
from narip.pubsub.bus import IncidentBroker

router = APIRouter(prefix="/v1/incidents", tags=["incidents-rest"])


@router.get("/recent", response_model=list[dict[str, Any]])
async def incidents_recent(
    limit: int = Query(default=50, ge=1, le=500),
    topic_prefix: str | None = Query(
        default=None,
        description="If set, only topics starting with this string (e.g. workforce. or incident.)",
    ),
    broker: IncidentBroker = Depends(get_broker),
) -> list[dict[str, Any]]:
    return await broker.recent_messages(limit=limit, topic_prefix=topic_prefix)

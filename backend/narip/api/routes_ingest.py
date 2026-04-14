"""Production-style ingestion: Falcon + Splunk HEC → score + automation."""

from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException

from narip.api.deps import get_orchestrator, get_settings
from narip.config import Settings
from narip.observability.metrics import Metrics
from narip.schemas.security import CanonicalSecurityEvent, IngestScoreResponse
from narip.security.cim import splunk_hec_to_canonical
from narip.security.falcon import falcon_event_to_canonical
from narip.services.ingest_orchestrator import IngestOrchestrator

router = APIRouter(prefix="/v1/ingest", tags=["ingest-falcon-splunk"])


@router.post("/falcon/event", response_model=IngestScoreResponse)
async def ingest_falcon_event(
    body: dict[str, Any],
    orchestrator: IngestOrchestrator = Depends(get_orchestrator),
) -> IngestScoreResponse:
    t0 = time.perf_counter()
    try:
        c = falcon_event_to_canonical(body)
        res = await orchestrator.score_canonical(c)
        Metrics.ingest("falcon", True)
        return res
    except Exception:
        Metrics.ingest("falcon", False)
        raise
    finally:
        Metrics.observe_latency("ingest_falcon", time.perf_counter() - t0)


@router.post("/splunk/hec", response_model=IngestScoreResponse)
async def ingest_splunk_hec(
    body: dict[str, Any],
    orchestrator: IngestOrchestrator = Depends(get_orchestrator),
    settings: Settings = Depends(get_settings),
    authorization: str | None = Header(default=None),
) -> IngestScoreResponse:
    if settings.splunk_hec_token:
        expected = f"Splunk {settings.splunk_hec_token}"
        if authorization != expected:
            raise HTTPException(status_code=401, detail="invalid or missing HEC token")
    t0 = time.perf_counter()
    try:
        c = splunk_hec_to_canonical(body)
        res = await orchestrator.score_canonical(c)
        Metrics.ingest("splunk", True)
        return res
    except Exception:
        Metrics.ingest("splunk", False)
        raise
    finally:
        Metrics.observe_latency("ingest_splunk", time.perf_counter() - t0)


@router.post("/normalize/falcon", response_model=CanonicalSecurityEvent)
def normalize_falcon_only(body: dict[str, Any]) -> CanonicalSecurityEvent:
    return falcon_event_to_canonical(body)


@router.post("/normalize/splunk", response_model=CanonicalSecurityEvent)
def normalize_splunk_only(body: dict[str, Any]) -> CanonicalSecurityEvent:
    return splunk_hec_to_canonical(body)

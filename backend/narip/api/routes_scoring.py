import time

from fastapi import APIRouter, Depends

from narip.api.deps import get_broker, get_pipeline
from narip.observability.metrics import Metrics
from narip.pubsub.bus import IncidentBroker
from narip.schemas.requests import UnifiedScoreBatchRequest, UnifiedScoreRequest
from narip.schemas.risk import UnifiedRiskResponse
from narip.services.pipeline import DetectionPipeline

router = APIRouter(prefix="/v1/risk", tags=["unified-risk"])


@router.post("/score", response_model=UnifiedRiskResponse)
async def unified_score(
    body: UnifiedScoreRequest,
    pipe: DetectionPipeline = Depends(get_pipeline),
) -> UnifiedRiskResponse:
    t0 = time.perf_counter()
    try:
        res = pipe.run_unified(
            email=body.email,
            transaction=body.transaction,
            flows=body.flows,
            otp=body.otp,
            account=body.account,
            supply=body.supply,
        )
        Metrics.event_result(True)
        return res
    except Exception:
        Metrics.event_result(False)
        raise
    finally:
        Metrics.observe_latency("unified_score", time.perf_counter() - t0)


@router.post("/score/batch", response_model=list[UnifiedRiskResponse])
async def unified_score_batch(
    body: UnifiedScoreBatchRequest,
    pipe: DetectionPipeline = Depends(get_pipeline),
) -> list[UnifiedRiskResponse]:
    """Score many events in one HTTP request (REST alternative to streaming)."""
    t0 = time.perf_counter()
    out: list[UnifiedRiskResponse] = []
    try:
        for item in body.items:
            out.append(
                pipe.run_unified(
                    email=item.email,
                    transaction=item.transaction,
                    flows=item.flows,
                    otp=item.otp,
                    account=item.account,
                    supply=item.supply,
                )
            )
        Metrics.event_result(True)
        return out
    except Exception:
        Metrics.event_result(False)
        raise
    finally:
        Metrics.observe_latency("unified_score_batch", time.perf_counter() - t0)


@router.get("/snapshot", response_model=UnifiedRiskResponse)
def unified_risk_snapshot(pipe: DetectionPipeline = Depends(get_pipeline)) -> UnifiedRiskResponse:
    """Dashboard-friendly default unified score (replaces GraphQL risk_snapshot)."""
    return pipe.run_unified()


@router.post("/score/publish-incident")
async def score_and_publish(
    body: UnifiedScoreRequest,
    pipe: DetectionPipeline = Depends(get_pipeline),
    broker: IncidentBroker = Depends(get_broker),
) -> dict:
    res = pipe.run_unified(
        email=body.email,
        transaction=body.transaction,
        flows=body.flows,
        otp=body.otp,
        account=body.account,
        supply=body.supply,
    )
    if res.enterprise_risk_score >= 60:
        await broker.publish(
            "incident.high_risk",
            {"score": res.enterprise_risk_score, "audit_reference": res.audit_reference},
        )
    return {"unified": res.model_dump(), "published": res.enterprise_risk_score >= 60}

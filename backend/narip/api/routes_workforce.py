"""Role-aware phishing assessments, simulations, profiles, and UI-facing audit logs."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query

from narip.api.deps import get_broker, get_workforce_service
from narip.pubsub.bus import IncidentBroker
from narip.schemas.workforce import (
    AssessPhishingRequest,
    EmployeeProfile,
    PhishingSimulationOutcome,
    RoleAwarePhishingAssessment,
    WorkforceDashboardSummary,
)
from narip.services.workforce_service import WorkforceService
from narip.workforce.audit_ring import AuditEvent

router = APIRouter(prefix="/v1/workforce", tags=["workforce-phishing-ai"])


@router.post("/profiles", response_model=EmployeeProfile)
def upsert_profile(
    body: EmployeeProfile,
    svc: WorkforceService = Depends(get_workforce_service),
) -> EmployeeProfile:
    return svc.upsert_profile(body)


@router.get("/profiles/{employee_id}", response_model=EmployeeProfile)
def get_profile(
    employee_id: str,
    svc: WorkforceService = Depends(get_workforce_service),
) -> EmployeeProfile:
    p = svc.get_profile(employee_id)
    if not p:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="employee not found")
    return p


@router.post("/phishing/assess", response_model=RoleAwarePhishingAssessment)
async def assess_role_phishing(
    body: AssessPhishingRequest,
    svc: WorkforceService = Depends(get_workforce_service),
    broker: IncidentBroker = Depends(get_broker),
) -> RoleAwarePhishingAssessment:
    res = svc.assess_phishing(body.employee_id, body.email)
    await broker.publish(
        "workforce.phishing_assessment",
        {
            "employee_id": res.employee_id,
            "training_gap_score": res.training_gap_score,
            "role_cluster": res.role_cluster,
            "phishing_probability": res.phishing_probability,
            "automation_flags": res.automation_flags,
        },
    )
    return res


@router.post("/phishing/simulation", response_model=PhishingSimulationOutcome)
async def record_simulation(
    body: PhishingSimulationOutcome,
    svc: WorkforceService = Depends(get_workforce_service),
    broker: IncidentBroker = Depends(get_broker),
) -> PhishingSimulationOutcome:
    o = svc.record_simulation(body)
    await broker.publish("workforce.simulation_outcome", o.model_dump(mode="json"))
    return o


@router.get("/dashboard/summary", response_model=WorkforceDashboardSummary)
def workforce_dashboard(
    svc: WorkforceService = Depends(get_workforce_service),
) -> WorkforceDashboardSummary:
    s = svc.dashboard_summary()
    return WorkforceDashboardSummary(**s)


@router.get("/roles/taxonomy")
def roles_taxonomy(svc: WorkforceService = Depends(get_workforce_service)) -> dict[str, Any]:
    return {"clusters": svc.taxonomy_public()}


@router.get("/audit/logs", response_model=list[AuditEvent])
async def audit_logs(
    limit: int = Query(default=100, ge=1, le=500),
    category: str | None = None,
    svc: WorkforceService = Depends(get_workforce_service),
) -> list[AuditEvent]:
    return await svc.audit.recent(limit=limit, category=category)


@router.get("/events/recent", response_model=list[dict[str, Any]])
async def workforce_events_recent(
    limit: int = Query(default=50, ge=1, le=200),
    broker: IncidentBroker = Depends(get_broker),
) -> list[dict[str, Any]]:
    """REST poll for workforce.* pub/sub messages (replaces WebSocket audit stream)."""
    return await broker.recent_messages(limit=limit, topic_prefix="workforce.")

"""Workforce-aware phishing risk, training gaps, and simulation outcomes."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field

from narip.schemas.events import EmailEvent


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class EmployeeProfile(BaseModel):
    employee_id: str
    email: str
    display_name: str = ""
    department: str = ""
    role_title: str = ""
    manager_id: str | None = None
    # Last completed generic training (ISO); large gap increases training_gap_score
    last_training_completed_at: datetime | None = None
    # Optional HRIS / IdP group hints
    groups: list[str] = Field(default_factory=list)
    updated_at: datetime = Field(default_factory=_utcnow)


class PhishingSimulationOutcome(BaseModel):
    employee_id: str
    campaign_id: str
    scenario_tags: list[str] = Field(default_factory=list)
    clicked_link: bool = False
    submitted_credentials: bool = False
    reported_phish: bool = False
    recorded_at: datetime = Field(default_factory=_utcnow)


class RoleAwarePhishingAssessment(BaseModel):
    employee_id: str
    role_cluster: str
    role_cluster_display: str
    phishing_probability: float = Field(ge=0.0, le=1.0)
    role_exposure_alignment: float = Field(
        ge=0.0,
        le=1.0,
        description="How well the message matches this role's real-world lure patterns",
    )
    training_gap_score: float = Field(
        ge=0.0,
        le=100.0,
        description="Higher = more urgent need for role-specific micro-training",
    )
    estimated_residual_click_risk: float = Field(
        ge=0.0,
        le=1.0,
        description="ML-adjusted probability employee would engage after generic training",
    )
    recommended_modules: list[str] = Field(default_factory=list)
    recommended_simulations: list[str] = Field(default_factory=list)
    automation_flags: list[str] = Field(default_factory=list)
    models_used: list[str] = Field(default_factory=list)
    feature_vector: list[float] = Field(default_factory=list)
    explain_snippets: list[str] = Field(default_factory=list)


class AssessPhishingRequest(BaseModel):
    employee_id: str
    email: EmailEvent


class WorkforceDashboardSummary(BaseModel):
    total_profiles: int
    high_gap_employees: int
    avg_training_gap: float
    top_clusters_at_risk: list[dict[str, Any]]

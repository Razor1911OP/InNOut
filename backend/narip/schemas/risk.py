from pydantic import BaseModel, Field


class ModuleBreakdown(BaseModel):
    module: str
    normalized_contribution: float = Field(ge=0.0, le=1.0)
    weight: float
    raw_score: float


class UnifiedRiskResponse(BaseModel):
    enterprise_risk_score: int = Field(ge=0, le=100)
    posterior_risk_0_1: float = Field(ge=0.0, le=1.0)
    breakdown: list[ModuleBreakdown]
    shap_feature_names: list[str] = Field(default_factory=list)
    shap_values: list[float] = Field(default_factory=list)
    audit_reference: str
    lime_available: bool = True

from pydantic import BaseModel, Field


class PhishingResult(BaseModel):
    phishing_probability: float = Field(ge=0.0, le=1.0)
    models_used: list[str] = Field(default_factory=list)
    feature_vector: list[float] = Field(default_factory=list)


class BECResult(BaseModel):
    bec_risk_score: float = Field(ge=0.0, le=1.0)
    attack_pattern_id: str | None = None
    models_used: list[str] = Field(default_factory=list)
    feature_vector: list[float] = Field(default_factory=list)


class WireFraudResult(BaseModel):
    wire_fraud_probability: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    models_used: list[str] = Field(default_factory=list)
    feature_vector: list[float] = Field(default_factory=list)


class SupplyChainResult(BaseModel):
    compromise_risk: float = Field(ge=0.0, le=1.0)
    affected_components: list[str] = Field(default_factory=list)
    models_used: list[str] = Field(default_factory=list)
    feature_vector: list[float] = Field(default_factory=list)


class OTPTakeoverResult(BaseModel):
    otp_takeover_probability: float = Field(ge=0.0, le=1.0)
    behavioral_anomaly_score: float = Field(ge=0.0, le=1.0)
    models_used: list[str] = Field(default_factory=list)
    feature_vector: list[float] = Field(default_factory=list)


class ATOResult(BaseModel):
    ato_risk: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    models_used: list[str] = Field(default_factory=list)
    feature_vector: list[float] = Field(default_factory=list)


class LateralMovementResult(BaseModel):
    breach_likelihood: float = Field(ge=0.0, le=1.0)
    exfiltration_rate_estimate_bytes_per_sec: float = Field(ge=0.0)
    models_used: list[str] = Field(default_factory=list)
    feature_vector: list[float] = Field(default_factory=list)

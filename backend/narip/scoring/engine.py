"""Weighted ensemble + Bayesian network layer + audit reference."""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass

from narip.config import Settings, get_settings
from narip.schemas.detection import (
    ATOResult,
    BECResult,
    LateralMovementResult,
    OTPTakeoverResult,
    PhishingResult,
    SupplyChainResult,
    WireFraudResult,
)
from narip.schemas.risk import ModuleBreakdown, UnifiedRiskResponse
from narip.scoring.bayesian import posterior_risk
from narip.scoring.explainability import explain_with_shap


@dataclass
class ModuleOutputs:
    phishing: PhishingResult
    bec: BECResult
    wire: WireFraudResult
    supply_chain: SupplyChainResult
    otp: OTPTakeoverResult
    ato: ATOResult
    lateral: LateralMovementResult


class UnifiedRiskEngine:
    def __init__(self, settings: Settings | None = None) -> None:
        self._s = settings or get_settings()

    def aggregate(self, m: ModuleOutputs, unified_names: list[str], unified_vector: list[float]) -> UnifiedRiskResponse:
        w = [
            (self._s.weight_phishing, m.phishing.phishing_probability, "phishing"),
            (self._s.weight_bec, m.bec.bec_risk_score, "bec"),
            (self._s.weight_wire, m.wire.wire_fraud_probability, "wire_fraud"),
            (self._s.weight_supply_chain, m.supply_chain.compromise_risk, "supply_chain"),
            (self._s.weight_otp, m.otp.otp_takeover_probability, "otp_fraud"),
            (self._s.weight_ato, m.ato.ato_risk, "account_takeover"),
            (self._s.weight_lateral, m.lateral.breach_likelihood, "lateral_exfil"),
        ]
        w_sum = sum(x[0] for x in w) or 1.0
        breakdown: list[ModuleBreakdown] = []
        ensemble = 0.0
        for weight, raw, name in w:
            nw = weight / w_sum
            ensemble += nw * raw
            breakdown.append(
                ModuleBreakdown(
                    module=name,
                    normalized_contribution=float(nw * raw),
                    weight=float(weight),
                    raw_score=float(raw),
                )
            )

        post = posterior_risk(self._s.risk_prior, ensemble)
        score_100 = int(round(100 * post))
        shap_names, shap_vals = explain_with_shap(unified_names, unified_vector)

        audit_reference = self._audit_blob(m, post, ensemble)

        return UnifiedRiskResponse(
            enterprise_risk_score=score_100,
            posterior_risk_0_1=post,
            breakdown=breakdown,
            shap_feature_names=shap_names,
            shap_values=shap_vals,
            audit_reference=audit_reference,
            lime_available=True,
        )

    def _audit_blob(self, m: ModuleOutputs, posterior: float, ensemble: float) -> str:
        payload = {
            "ts": time.time(),
            "id": str(uuid.uuid4()),
            "posterior": posterior,
            "ensemble": ensemble,
            "modules": {
                "phishing": m.phishing.model_dump(),
                "bec": m.bec.model_dump(),
                "wire": m.wire.model_dump(),
                "supply_chain": m.supply_chain.model_dump(),
                "otp": m.otp.model_dump(),
                "ato": m.ato.model_dump(),
                "lateral": m.lateral.model_dump(),
            },
        }
        return json.dumps(payload, separators=(",", ":"), default=str)[:8192]

"""Supply chain: One-Class SVM proxy (IF + margin) + Isolation Forest."""

from __future__ import annotations

import numpy as np
from sklearn.svm import OneClassSVM

from narip.detection.base import isolation_scores
from narip.schemas.detection import SupplyChainResult
from narip.schemas.events import SupplyChainSignal


class SupplyChainDetector:
    def __init__(self) -> None:
        rng = np.random.RandomState(41)
        self._ref = rng.randn(120, 3) * 0.2
        self._ocsvm = OneClassSVM(nu=0.12, kernel="rbf", gamma="scale")
        self._ocsvm.fit(self._ref)
        self._models_used = ["one_class_svm", "isolation_forest"]

    def score(self, features: list[float], signal: SupplyChainSignal | None = None) -> SupplyChainResult:
        x = np.array([features], dtype=np.float64)
        iso = float(isolation_scores(x, seed=42)[0])
        oc = float(self._ocsvm.score_samples(x)[0])
        oc_n = float(1.0 / (1.0 + np.exp(oc)))  # lower score = more outlier
        risk = float(np.clip(0.5 * iso + 0.5 * oc_n, 0.0, 1.0))
        affected: list[str] = []
        if signal and signal.version_old != signal.version_new:
            affected.append(signal.component_id)
        if risk > 0.55:
            affected.append(f"vendor_egress_anomaly:{signal.component_id if signal else 'unknown'}")
        return SupplyChainResult(
            compromise_risk=risk,
            affected_components=list(dict.fromkeys(affected)),
            models_used=self._models_used,
            feature_vector=list(features),
        )

"""ATO: LSTM autoencoder proxy + Isolation Forest."""

from __future__ import annotations

import numpy as np

from narip.detection.base import isolation_scores, train_placeholder_binary
from narip.schemas.detection import ATOResult


class ATODetector:
    def __init__(self) -> None:
        self._lstm_ae_proxy = train_placeholder_binary(3, seed=61)
        self._models_used = ["lstm_autoencoder_proxy", "isolation_forest"]

    def score(self, features: list[float]) -> ATOResult:
        x = np.array([features], dtype=np.float64)
        seq_proxy = float(self._lstm_ae_proxy.predict_proba(x)[0, 1])
        iso = float(isolation_scores(x, seed=62)[0])
        ato_risk = float(np.clip(0.5 * seq_proxy + 0.5 * iso, 0.0, 1.0))
        confidence = float(np.clip(0.55 + abs(ato_risk - 0.5), 0.0, 1.0))
        return ATOResult(
            ato_risk=ato_risk,
            confidence=confidence,
            models_used=self._models_used,
            feature_vector=list(features),
        )

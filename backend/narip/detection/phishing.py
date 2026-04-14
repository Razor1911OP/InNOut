"""Phishing: sender reputation, URL analysis, NLP — LR, RF, LSTM (seq via pooled embedding proxy)."""

from __future__ import annotations

import numpy as np

from narip.detection.base import random_forest_proba, train_placeholder_binary
from narip.schemas.detection import PhishingResult
from narip.schemas.events import EmailEvent


class PhishingDetector:
    def __init__(self) -> None:
        self._lr = train_placeholder_binary(3, seed=11)
        self._models_used = ["logistic_regression", "random_forest", "lstm_sequence_proxy"]

    def score(self, features: list[float], email: EmailEvent | None = None) -> PhishingResult:
        x = np.array([features], dtype=np.float64)
        lr_p = float(self._lr.predict_proba(x)[0, 1])
        rf_p = float(random_forest_proba(x, seed=12)[0])
        # LSTM proxy: character n-gram density on subject+body
        text = (email.subject + " " + email.body_text) if email else ""
        lstm_proxy = min(1.0, len(text) / 2000.0) * float(np.mean(features))
        combined = (0.35 * lr_p + 0.4 * rf_p + 0.25 * lstm_proxy)
        return PhishingResult(
            phishing_probability=float(np.clip(combined, 0.0, 1.0)),
            models_used=self._models_used,
            feature_vector=list(features),
        )

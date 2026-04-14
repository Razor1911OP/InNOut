"""OTP fraud: autoencoder proxy (reconstruction error) + KNN."""

from __future__ import annotations

import numpy as np

from narip.detection.base import knn_anomaly_score, train_placeholder_binary
from narip.schemas.detection import OTPTakeoverResult


class OTPFraudDetector:
    def __init__(self) -> None:
        self._ae_proxy = train_placeholder_binary(4, seed=51)
        self._models_used = ["autoencoder_reconstruction_proxy", "knn"]

    def score(self, features: list[float]) -> OTPTakeoverResult:
        x = np.array([features], dtype=np.float64)
        recon_err = float(np.mean((x - 0.0) ** 2))
        ae_score = float(np.clip(recon_err * 2.0 + self._ae_proxy.predict_proba(x)[0, 1] * 0.3, 0.0, 1.0))
        knn_s = float(knn_anomaly_score(x, seed=52)[0])
        takeover_p = float(np.clip(0.45 * ae_score + 0.55 * knn_s, 0.0, 1.0))
        return OTPTakeoverResult(
            otp_takeover_probability=takeover_p,
            behavioral_anomaly_score=float(np.clip(0.6 * ae_score + 0.4 * knn_s, 0.0, 1.0)),
            models_used=self._models_used,
            feature_vector=list(features),
        )

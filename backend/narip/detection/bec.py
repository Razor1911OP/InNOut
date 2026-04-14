"""BEC: Isolation Forest + DBSCAN-style cluster id from feature quantization."""

from __future__ import annotations

import hashlib

import numpy as np
from sklearn.cluster import DBSCAN

from narip.detection.base import isolation_scores
from narip.schemas.detection import BECResult


class BECDetector:
    def __init__(self) -> None:
        self._models_used = ["isolation_forest", "dbscan"]

    def score(self, features: list[float]) -> BECResult:
        x = np.array([features], dtype=np.float64)
        iso_risk = float(isolation_scores(x, seed=21)[0])
        # DBSCAN on small reference + sample to assign pattern id
        ref = np.random.RandomState(21).randn(50, len(features)) * 0.3
        X = np.vstack([ref, x])
        db = DBSCAN(eps=0.45, min_samples=3).fit(X)
        label = int(db.labels_[-1])
        pattern = f"BEC-PAT-{label}" if label >= 0 else "BEC-PAT-NOISE"
        # stable id from features
        h = hashlib.sha256(np.array(features).tobytes()).hexdigest()[:8].upper()
        attack_pattern_id = f"{pattern}-{h}"
        bec_score = float(np.clip(0.55 * iso_risk + 0.45 * np.mean(features), 0.0, 1.0))
        return BECResult(
            bec_risk_score=bec_score,
            attack_pattern_id=attack_pattern_id,
            models_used=self._models_used,
            feature_vector=list(features),
        )

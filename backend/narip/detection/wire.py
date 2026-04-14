"""Wire fraud: XGBoost + simple graph risk (NetworkX ego proxy)."""

from __future__ import annotations

import numpy as np
import networkx as nx
from sklearn.ensemble import GradientBoostingClassifier

from narip.schemas.detection import WireFraudResult

try:
    import xgboost as xgb

    _HAS_XGB = True
except ImportError:
    _HAS_XGB = False


class WireFraudDetector:
    def __init__(self) -> None:
        rng = np.random.RandomState(31)
        X = rng.randn(300, 3)
        y = ((X[:, 0] + X[:, 1] * 0.5) > 0.3).astype(int)
        if _HAS_XGB:
            self._xgb = xgb.XGBClassifier(
                n_estimators=60,
                max_depth=4,
                learning_rate=0.08,
                random_state=31,
                verbosity=0,
            )
            self._models_used = ["xgboost", "gnn_graph_proxy"]
        else:
            self._xgb = GradientBoostingClassifier(random_state=31, max_depth=3, n_estimators=40)
            self._models_used = ["sklearn_gradient_boosting", "gnn_graph_proxy"]
        self._xgb.fit(X, y)

    def _gnn_proxy(self, sender: str, recipient: str) -> float:
        g = nx.Graph()
        g.add_edge(sender, "hub")
        g.add_edge(recipient, "hub")
        # risk higher if same hub concentration (simplified)
        return min(1.0, g.degree(sender) * 0.2 + g.degree(recipient) * 0.2)

    def score(self, features: list[float], sender: str = "a", recipient: str = "b") -> WireFraudResult:
        x = np.array([features], dtype=np.float64)
        p = float(self._xgb.predict_proba(x)[0, 1])
        gnn = self._gnn_proxy(sender, recipient)
        combined = 0.72 * p + 0.28 * gnn
        confidence = float(np.clip(0.5 + abs(p - 0.5) * 1.2, 0.0, 1.0))
        return WireFraudResult(
            wire_fraud_probability=float(np.clip(combined, 0.0, 1.0)),
            confidence=confidence,
            models_used=self._models_used,
            feature_vector=list(features),
        )

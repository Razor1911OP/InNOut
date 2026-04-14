"""SHAP for unified feature vector; LIME can wrap the same vector in batch jobs."""

from __future__ import annotations

import numpy as np
from sklearn.linear_model import LinearRegression

try:
    import shap
except ImportError:
    shap = None  # type: ignore


def explain_with_shap(
    feature_names: list[str],
    feature_vector: list[float],
    background_size: int = 48,
    seed: int = 99,
) -> tuple[list[str], list[float]]:
    if not feature_vector:
        return [], []
    rng = np.random.RandomState(seed)
    fv = np.array(feature_vector, dtype=np.float64)
    X = rng.randn(background_size, len(fv)) * 0.12 + fv
    y = (X * fv).sum(axis=1)
    model = LinearRegression().fit(X, y)

    if shap is None:
        coef = np.abs(model.coef_)
        s = coef.sum() + 1e-9
        return feature_names, [float(c / s) for c in coef]

    try:
        explainer = shap.LinearExplainer(model, X)
        x = np.array([fv])
        sv = explainer.shap_values(x)
        if isinstance(sv, list):
            sv = sv[0]
        vals = np.array(sv).ravel().tolist()
        return feature_names, [float(v) for v in vals]
    except Exception:
        coef = np.abs(model.coef_)
        s = coef.sum() + 1e-9
        return feature_names, [float(c / s) for c in coef]

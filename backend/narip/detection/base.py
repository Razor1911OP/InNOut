from __future__ import annotations

import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import KNeighborsClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


def train_placeholder_binary(n_features: int, seed: int = 42) -> Pipeline:
    rng = np.random.RandomState(seed)
    X = rng.randn(400, n_features)
    y = ((X**2).sum(axis=1) > np.median((X**2).sum(axis=1))).astype(int)
    clf = Pipeline(
        [
            ("scaler", StandardScaler()),
            (
                "model",
                LogisticRegression(max_iter=200, random_state=seed),
            ),
        ]
    )
    clf.fit(X, y)
    return clf


def isolation_scores(X: np.ndarray, seed: int = 42) -> np.ndarray:
    iso = IsolationForest(random_state=seed, n_estimators=50)
    iso.fit(X)
    raw = iso.score_samples(X)
    # map to 0–1 risk (higher = more anomalous)
    mn, mx = raw.min(), raw.max()
    if mx - mn < 1e-9:
        return np.zeros(len(X))
    return 1.0 - (raw - mn) / (mx - mn)


def random_forest_proba(X: np.ndarray, seed: int = 42) -> np.ndarray:
    rng = np.random.RandomState(seed)
    Xb = np.vstack([X, rng.randn(200, X.shape[1]) * 0.5])
    yb = np.array([1] * len(X) + [0] * 200)
    clf = RandomForestClassifier(n_estimators=30, max_depth=6, random_state=seed)
    clf.fit(Xb, yb)
    return clf.predict_proba(X)[:, 1]


def knn_anomaly_score(X: np.ndarray, seed: int = 42) -> np.ndarray:
    rng = np.random.RandomState(seed)
    ref = rng.randn(300, X.shape[1])
    y = np.array([0] * len(ref))
    knn = KNeighborsClassifier(n_neighbors=5)
    knn.fit(ref, y)
    # distance to neighbors as proxy
    dist, _ = knn.kneighbors(X, n_neighbors=5, return_distance=True)
    d = dist.mean(axis=1)
    d = (d - d.min()) / (d.max() - d.min() + 1e-9)
    return d

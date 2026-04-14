"""Role-conditioned phishing risk: extends content ML with HR context and behavior priors."""

from __future__ import annotations

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from narip.detection.base import random_forest_proba
from narip.schemas.events import EmailEvent
from narip.schemas.workforce import RoleAwarePhishingAssessment
from narip.workforce.role_profiles import RoleCluster


def _train_role_model(seed: int = 77) -> Pipeline:
    rng = np.random.RandomState(seed)
    X = rng.randn(500, 8)
    # Synthetic: high alignment + bad content flags -> positive
    y = ((X[:, 3] + X[:, 4] + X[:, 0]) > 0.8).astype(int)
    clf = Pipeline(
        [
            ("scaler", StandardScaler()),
            ("lr", LogisticRegression(max_iter=300, random_state=seed)),
        ]
    )
    clf.fit(X, y)
    return clf


class RoleAwarePhishingDetector:
    def __init__(self) -> None:
        self._model = _train_role_model()
        self._models_used = [
            "logistic_regression_role_conditioned",
            "random_forest_content",
            "role_lure_alignment",
            "behavior_prior",
        ]

    def build_features(
        self,
        base_phish: list[float],
        email: EmailEvent,
        cluster: RoleCluster,
        alignment: float,
        days_since_training: float,
        sim_fail_rate: float,
        cluster_index_norm: float,
    ) -> list[float]:
        text = (email.subject + " " + email.body_text).lower()
        urgency = min(1.0, text.count("urgent") * 0.15 + text.count("immediately") * 0.15)
        return [
            float(base_phish[0]),
            float(base_phish[1]),
            float(base_phish[2]),
            float(alignment),
            float(cluster.baseline_click_risk),
            float(min(1.0, days_since_training / 365.0)),
            float(sim_fail_rate),
            float(cluster_index_norm * 0.5 + urgency * 0.5),
        ]

    def score_residual_click_risk(self, features: list[float]) -> float:
        x = np.array([features], dtype=np.float64)
        p_lr = float(self._model.predict_proba(x)[0, 1])
        p_rf = float(random_forest_proba(x[:, :3], seed=78)[0])
        return float(np.clip(0.45 * p_lr + 0.55 * p_rf, 0.0, 1.0))

    def training_gap_score(
        self,
        phishing_p: float,
        alignment: float,
        residual: float,
        days_since_training: float,
        sim_fail_rate: float,
        cluster: RoleCluster,
    ) -> float:
        # Higher when attack is role-plausible and human still likely to fail despite generic training
        generic_training_failure = min(1.0, sim_fail_rate * 1.1 + cluster.baseline_click_risk * 0.35)
        recency_penalty = min(1.0, days_since_training / 540.0)
        raw = (
            0.28 * phishing_p
            + 0.22 * alignment
            + 0.22 * residual
            + 0.16 * generic_training_failure
            + 0.12 * recency_penalty
        )
        return float(np.clip(raw * 100.0, 0.0, 100.0))

    def assess(
        self,
        *,
        employee_id: str,
        email: EmailEvent,
        cluster: RoleCluster,
        base_phish_features: list[float],
        base_phish_probability: float,
        alignment: float,
        days_since_training: float,
        sim_fail_rate: float,
        cluster_index_norm: float,
    ) -> RoleAwarePhishingAssessment:
        feats = self.build_features(
            base_phish_features,
            email,
            cluster,
            alignment,
            days_since_training,
            sim_fail_rate,
            cluster_index_norm,
        )
        residual = self.score_residual_click_risk(feats)
        gap = self.training_gap_score(
            base_phish_probability,
            alignment,
            residual,
            days_since_training,
            sim_fail_rate,
            cluster,
        )
        mods = list(cluster.priority_modules)
        sims = [
            f"Micro-sim: {cluster.display_name} themed lure",
            "Just-in-time nudge on first match to role keywords",
        ]
        flags: list[str] = []
        if gap >= 65:
            flags.append("auto_assign_role_module")
        if alignment >= 0.55 and base_phish_probability >= 0.45:
            flags.append("quarantine_recommended")
        if sim_fail_rate >= 0.35:
            flags.append("human_coaching_queue")

        explain = [
            f"Role cluster '{cluster.display_name}' baseline engagement prior: {cluster.baseline_click_risk:.2f}",
            f"Content-to-role alignment: {alignment:.2f}",
            f"Residual click risk (role-conditioned ML): {residual:.2f}",
        ]
        return RoleAwarePhishingAssessment(
            employee_id=employee_id,
            role_cluster=cluster.key,
            role_cluster_display=cluster.display_name,
            phishing_probability=float(base_phish_probability),
            role_exposure_alignment=float(alignment),
            training_gap_score=gap,
            estimated_residual_click_risk=residual,
            recommended_modules=mods,
            recommended_simulations=sims,
            automation_flags=flags,
            models_used=self._models_used,
            feature_vector=feats,
            explain_snippets=explain,
        )

"""Employee profiles, simulation history, and automated training-gap orchestration."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from narip.detection.role_aware_phishing import RoleAwarePhishingDetector
from narip.schemas.events import EmailEvent
from narip.schemas.workforce import (
    EmployeeProfile,
    PhishingSimulationOutcome,
    RoleAwarePhishingAssessment,
)
from narip.services.pipeline import DetectionPipeline
from narip.workforce.audit_ring import AuditEvent, AuditRingBuffer
from narip.workforce.role_profiles import RoleTaxonomy, load_role_taxonomy


def _days_since(dt: datetime | None) -> float:
    if dt is None:
        return 400.0
    now = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return max(0.0, (now - dt).total_seconds() / 86400.0)


class WorkforceService:
    def __init__(
        self,
        pipeline: DetectionPipeline,
        taxonomy: RoleTaxonomy | None = None,
        audit: AuditRingBuffer | None = None,
    ) -> None:
        self._pipe = pipeline
        self._tax = taxonomy or load_role_taxonomy()
        self._audit = audit or AuditRingBuffer()
        self._profiles: dict[str, EmployeeProfile] = {}
        self._outcomes: list[PhishingSimulationOutcome] = []
        self._role_detector = RoleAwarePhishingDetector()

    @property
    def audit(self) -> AuditRingBuffer:
        return self._audit

    def upsert_profile(self, p: EmployeeProfile) -> EmployeeProfile:
        p.updated_at = datetime.now(timezone.utc)
        self._profiles[p.employee_id] = p
        self._audit.append_sync(
            AuditEvent(
                category="workforce",
                action="profile_upsert",
                employee_id=p.employee_id,
                detail={"email": p.email, "department": p.department, "role_title": p.role_title},
            )
        )
        return p

    def get_profile(self, employee_id: str) -> EmployeeProfile | None:
        return self._profiles.get(employee_id)

    def record_simulation(self, o: PhishingSimulationOutcome) -> PhishingSimulationOutcome:
        self._outcomes.append(o)
        self._audit.append_sync(
            AuditEvent(
                category="simulation",
                action="phishing_outcome",
                employee_id=o.employee_id,
                detail={
                    "clicked": o.clicked_link,
                    "submitted": o.submitted_credentials,
                    "reported": o.reported_phish,
                    "campaign_id": o.campaign_id,
                },
            )
        )
        return o

    def _sim_fail_rate(self, employee_id: str, window: int = 12) -> float:
        rows = [x for x in self._outcomes if x.employee_id == employee_id][-window:]
        if not rows:
            return 0.0
        fails = sum(1 for r in rows if r.clicked_link or r.submitted_credentials)
        return fails / len(rows)

    def assess_phishing(
        self,
        employee_id: str,
        email: EmailEvent,
    ) -> RoleAwarePhishingAssessment:
        prof = self._profiles.get(employee_id)
        if not prof:
            prof = EmployeeProfile(
                employee_id=employee_id,
                email=email.sender,
                display_name="",
                department="",
                role_title="",
            )
        cluster_key = self._tax.resolve_cluster(prof.department, prof.role_title)
        cluster = self._tax.clusters.get(cluster_key) or self._tax.clusters["general"]
        keys = sorted(self._tax.clusters.keys())
        idx_norm = keys.index(cluster.key) / max(1, (len(keys) - 1))

        base_f = self._pipe.features.phishing_from_email(email)
        base_p = self._pipe.phishing_d.score(base_f, email=email).phishing_probability
        text = email.subject + " " + email.body_text
        from narip.workforce.role_profiles import role_content_alignment_score

        alignment = role_content_alignment_score(text, cluster)
        days = _days_since(prof.last_training_completed_at)
        fail_rate = self._sim_fail_rate(employee_id)

        res = self._role_detector.assess(
            employee_id=employee_id,
            email=email,
            cluster=cluster,
            base_phish_features=base_f,
            base_phish_probability=base_p,
            alignment=alignment,
            days_since_training=days,
            sim_fail_rate=fail_rate,
            cluster_index_norm=idx_norm,
        )
        self._audit.append_sync(
            AuditEvent(
                category="phishing",
                action="role_aware_assessment",
                employee_id=employee_id,
                detail={
                    "training_gap_score": res.training_gap_score,
                    "role_cluster": res.role_cluster,
                    "phishing_probability": res.phishing_probability,
                },
            )
        )
        return res

    def taxonomy_public(self) -> dict[str, Any]:
        return {
            k: {
                "display_name": v.display_name,
                "typical_lures": v.typical_lures,
                "baseline_click_risk": v.baseline_click_risk,
                "priority_modules": v.priority_modules,
            }
            for k, v in self._tax.clusters.items()
        }

    def dashboard_summary(self) -> dict[str, Any]:
        if not self._profiles:
            return {
                "total_profiles": 0,
                "high_gap_employees": 0,
                "avg_training_gap": 0.0,
                "top_clusters_at_risk": [],
            }
        gaps: list[tuple[str, float]] = []
        cluster_scores: dict[str, list[float]] = {}
        for eid, prof in self._profiles.items():
            cluster_key = self._tax.resolve_cluster(prof.department, prof.role_title)
            # Proxy gap without a live message: blend cluster prior, simulations, and training recency
            c = self._tax.clusters.get(cluster_key) or self._tax.clusters["general"]
            days = _days_since(prof.last_training_completed_at)
            fr = self._sim_fail_rate(eid)
            residual_proxy = float(min(1.0, c.baseline_click_risk * 0.55 + fr * 0.55))
            gap = self._role_detector.training_gap_score(
                0.35,
                0.25,
                residual_proxy,
                days,
                fr,
                c,
            )
            gaps.append((eid, gap))
            cluster_scores.setdefault(cluster_key, []).append(gap)
        high = sum(1 for _, g in gaps if g >= 60)
        avg = sum(g for _, g in gaps) / len(gaps)
        top_c = sorted(
            (
                {"cluster": k, "avg_gap": sum(v) / len(v), "count": len(v)}
                for k, v in cluster_scores.items()
            ),
            key=lambda x: x["avg_gap"],
            reverse=True,
        )[:5]
        return {
            "total_profiles": len(self._profiles),
            "high_gap_employees": high,
            "avg_training_gap": round(avg, 2),
            "top_clusters_at_risk": top_c,
        }

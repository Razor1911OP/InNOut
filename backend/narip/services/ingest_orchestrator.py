"""End-to-end: Falcon/Splunk → IOC → correlate → score → playbooks → cases."""

from __future__ import annotations

from typing import Any

from narip.automation.cases import CaseStore
from narip.automation.dedupe import fingerprint_event
from narip.automation.playbooks import PlaybookEngine
from narip.pubsub.bus import IncidentBroker
from narip.schemas.risk import UnifiedRiskResponse
from narip.schemas.security import CanonicalSecurityEvent, IngestScoreResponse
from narip.security.bridge import apply_vendor_severity_boost, canonical_to_narip_inputs
from narip.security.correlator import HostCorrelator
from narip.services.pipeline import DetectionPipeline
from narip.threat_intel.ioc_store import IOCStore


class IngestOrchestrator:
    def __init__(
        self,
        pipeline: DetectionPipeline,
        ioc: IOCStore,
        correlator: HostCorrelator,
        playbooks: PlaybookEngine,
        cases: CaseStore,
        broker: IncidentBroker,
    ) -> None:
        self._pipe = pipeline
        self._ioc = ioc
        self._correlator = correlator
        self._playbooks = playbooks
        self._cases = cases
        self._broker = broker

    async def score_canonical(self, c: CanonicalSecurityEvent) -> IngestScoreResponse:
        ioc_hits = self._ioc.enrich(c)
        corr = self._correlator.observe(c)
        boost = float(corr.get("boost") or 0.0)
        if ioc_hits:
            boost = min(0.25, boost + 0.08 * min(len(ioc_hits), 3))

        email, txn, flows, account, supply = canonical_to_narip_inputs(c)
        unified: UnifiedRiskResponse = self._pipe.run_unified(
            email=email,
            transaction=txn,
            flows=flows,
            account=account,
            supply=supply,
        )

        adj = apply_vendor_severity_boost(unified.enterprise_risk_score, c, correlation_boost=boost)
        unified.enterprise_risk_score = adj
        unified.posterior_risk_0_1 = adj / 100.0

        ctx = {
            "risk_score": adj,
            "vendor": c.vendor,
            "tactics": c.mitre_tactics,
            "techniques": c.mitre_techniques,
            "host": c.host,
        }
        actions = self._playbooks.evaluate(ctx)

        fp = fingerprint_event(c)
        title = c.detection_name or c.event_type or "Security telemetry"
        summary: dict[str, Any] = {
            "event_type": c.event_type,
            "severity_vendor": c.severity_0_100,
            "mitre_tactics": c.mitre_tactics,
            "ioc_hits": ioc_hits,
            "correlation": corr,
        }
        case_rec = await self._cases.upsert_by_fingerprint(
            fp,
            vendor=c.vendor,
            risk_score=adj,
            title=title[:200],
            summary=summary,
        )

        executed: list[dict[str, Any]] = []
        for step in actions:
            act = step.get("action")
            if act == "publish":
                topic = str(step.get("topic") or "incident.generic")
                await self._broker.publish(
                    topic,
                    {
                        "case_id": case_rec.case_id,
                        "risk": adj,
                        "vendor": c.vendor,
                        "playbook": step.get("playbook"),
                    },
                )
                executed.append(step)
            elif act == "create_case":
                executed.append({**step, "case_id": case_rec.case_id})
            elif act == "tag":
                executed.append(step)
            elif act == "suggest_close":
                executed.append(step)

        return IngestScoreResponse(
            canonical=c,
            unified=unified.model_dump(),
            ioc_hits=ioc_hits,
            correlation=corr,
            case_id=case_rec.case_id,
            playbook_actions=executed,
            audit_reference=unified.audit_reference,
        )

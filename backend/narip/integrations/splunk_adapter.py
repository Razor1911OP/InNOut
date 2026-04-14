from __future__ import annotations

from typing import Any

from narip.integrations.base import IntegrationAdapter
from narip.security.cim import splunk_hec_to_canonical


class SplunkSIEMAdapter(IntegrationAdapter):
    """Splunk: HEC/CIM-shaped events → canonical telemetry (Authentication, Endpoint, Network)."""

    name = "splunk_siem"
    category = "ingestion"

    async def health(self) -> dict[str, Any]:
        return {
            "adapter": self.name,
            "status": "ready",
            "category": self.category,
            "capabilities": [
                "hec_json_normalize",
                "cim_field_mapping",
                "mitre_inference",
            ],
        }

    async def push_event(self, payload: dict[str, Any]) -> dict[str, Any]:
        c = splunk_hec_to_canonical(payload)
        return {
            "accepted": True,
            "adapter": self.name,
            "canonical": c.model_dump(mode="json"),
        }

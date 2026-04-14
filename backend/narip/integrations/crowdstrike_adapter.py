from __future__ import annotations

from typing import Any

from narip.integrations.base import IntegrationAdapter
from narip.security.falcon import falcon_event_to_canonical


class CrowdStrikeFalconAdapter(IntegrationAdapter):
    """CrowdStrike Falcon: normalize streaming detections to NARIP canonical form."""

    name = "crowdstrike_falcon"
    category = "ingestion"

    async def health(self) -> dict[str, Any]:
        return {
            "adapter": self.name,
            "status": "ready",
            "category": self.category,
            "capabilities": [
                "falcon_streaming_normalize",
                "mitre_inference",
                "process_network_mapping",
            ],
        }

    async def push_event(self, payload: dict[str, Any]) -> dict[str, Any]:
        c = falcon_event_to_canonical(payload)
        return {
            "accepted": True,
            "adapter": self.name,
            "canonical": c.model_dump(mode="json"),
        }

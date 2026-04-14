from __future__ import annotations

from typing import Any

from narip.integrations.base import IntegrationAdapter


class StubAdapter(IntegrationAdapter):
    def __init__(self, name: str, category: str) -> None:
        self.name = name
        self.category = category

    async def health(self) -> dict[str, Any]:
        return {"adapter": self.name, "status": "stub", "category": self.category}

    async def push_event(self, payload: dict[str, Any]) -> dict[str, Any]:
        return {"accepted": True, "adapter": self.name, "echo_keys": list(payload.keys())}


def build_stubs() -> list[StubAdapter]:
    ingestion = [
        ("microsoft_exchange", "ingestion"),
        ("google_workspace", "ingestion"),
        ("microsoft_defender", "ingestion"),
        ("elasticsearch_siem", "ingestion"),
        ("alienvault_otx", "ingestion"),
        ("shodan", "ingestion"),
        ("swift_mt", "ingestion"),
        ("ach_gateway", "ingestion"),
        ("payment_gateway_generic", "ingestion"),
    ]
    response = [
        ("splunk_soar", "response"),
        ("cortex_xsoar", "response"),
        ("email_gateway_quarantine", "response"),
        ("azure_ad", "response"),
        ("okta", "response"),
        ("crowdstrike_rtr", "response"),
        ("servicenow", "response"),
        ("jira", "response"),
    ]
    return [StubAdapter(n, c) for n, c in ingestion + response]

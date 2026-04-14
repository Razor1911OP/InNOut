"""Vendor-neutral security telemetry (Falcon / Splunk CIM converged)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class CanonicalSecurityEvent(BaseModel):
    """Normalized record analogous to Falcon streaming + Splunk CIM Endpoint/Network/Auth."""

    vendor: Literal["crowdstrike_falcon", "splunk_cim", "generic"] = "generic"
    event_type: str = ""
    event_time: datetime | None = None
    ingested_at: datetime = Field(default_factory=_utcnow)

    host: str | None = None
    user_principal: str | None = None
    user_sid: str | None = None

    process_name: str | None = None
    command_line: str | None = None
    parent_process: str | None = None
    process_hash_sha256: str | None = None

    detection_id: str | None = None
    detection_name: str | None = None
    description: str | None = None
    severity_0_100: int = Field(default=0, ge=0, le=100)

    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)

    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    bytes_out: int = 0
    protocol: str | None = None

    index: str | None = None
    sourcetype: str | None = None
    source_host: str | None = None

    raw_excerpt: dict[str, Any] = Field(default_factory=dict)

    def summary_text(self) -> str:
        parts = [
            self.detection_name or "",
            self.description or "",
            self.command_line or "",
            self.process_name or "",
        ]
        return " ".join(p for p in parts if p).strip()


class IngestScoreResponse(BaseModel):
    canonical: CanonicalSecurityEvent
    unified: dict[str, Any]
    ioc_hits: list[dict[str, Any]] = Field(default_factory=list)
    correlation: dict[str, Any] = Field(default_factory=dict)
    case_id: str | None = None
    playbook_actions: list[dict[str, Any]] = Field(default_factory=list)
    audit_reference: str | None = None

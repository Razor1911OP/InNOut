"""Map canonical telemetry into NARIP domain events for the seven-module pipeline."""

from __future__ import annotations

from datetime import datetime, timezone

from narip.schemas.events import (
    AccountTelemetryEvent,
    EmailEvent,
    NetworkFlowEvent,
    SupplyChainSignal,
    TransactionEvent,
)
from narip.schemas.security import CanonicalSecurityEvent
from narip.security.enrichment import elevation_score_from_command_line, supply_chain_hint_from_command_line


def _flow_id(c: CanonicalSecurityEvent) -> str:
    base = f"{c.src_ip or ''}:{c.dst_ip or ''}:{c.dst_port or 0}"
    return f"flow-{hash(base) & 0xFFFFFFFF:x}"


def canonical_to_narip_inputs(
    c: CanonicalSecurityEvent,
    *,
    default_email: EmailEvent | None = None,
    default_transaction: TransactionEvent | None = None,
) -> tuple[
    EmailEvent | None,
    TransactionEvent | None,
    list[NetworkFlowEvent],
    AccountTelemetryEvent | None,
    SupplyChainSignal | None,
]:
    flows: list[NetworkFlowEvent] = []
    if c.dst_ip and c.src_ip:
        flows.append(
            NetworkFlowEvent(
                flow_id=_flow_id(c),
                src_ip=c.src_ip,
                dst_ip=c.dst_ip,
                dst_port=int(c.dst_port or 0),
                bytes_out=c.bytes_out,
                process_name=c.process_name,
                user_id=c.user_principal,
            )
        )

    priv = int(round(elevation_score_from_command_line(c.command_line) * 10))
    resources: list[str] = []
    if c.detection_name:
        resources.append(c.detection_name)
    if c.mitre_techniques:
        resources.extend(c.mitre_techniques[:3])
    if c.process_name:
        resources.append(c.process_name)

    ts = (c.event_time or datetime.now(timezone.utc)).isoformat()
    account = AccountTelemetryEvent(
        user_id=c.user_principal or "unknown_principal",
        login_ip=c.src_ip or c.user_principal or "0.0.0.0",
        device_id=c.host or c.source_host or "unknown_host",
        resource_access=resources or ["telemetry_only"],
        privilege_level=priv,
        timestamp_iso=ts,
    )

    eco, pkg = supply_chain_hint_from_command_line(c.command_line)
    supply: SupplyChainSignal | None = None
    if eco and pkg:
        supply = SupplyChainSignal(
            component_id=f"{eco}:{pkg}",
            version_old=None,
            version_new=pkg,
            vendor_egress_bytes_per_hour=float(c.bytes_out) if c.bytes_out else 0.0,
            baseline_egress_bytes_per_hour=1.0,
        )

    return (
        default_email,
        default_transaction,
        flows,
        account,
        supply,
    )


def apply_vendor_severity_boost(
    base_score_0_100: int,
    c: CanonicalSecurityEvent,
    *,
    correlation_boost: float = 0.0,
) -> int:
    """Fuse Falcon/Splunk severities and host correlation into enterprise score."""
    v = base_score_0_100 / 100.0
    vendor = (c.severity_0_100 / 100.0) * 0.35
    lateral_hint = 0.15 if "lateral_movement" in c.mitre_tactics else 0.0
    exfil_hint = 0.12 if "exfiltration" in c.mitre_tactics else 0.0
    merged = min(1.0, v * 0.55 + vendor + lateral_hint + exfil_hint + min(0.2, correlation_boost))
    return int(round(merged * 100))

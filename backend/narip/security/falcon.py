"""
CrowdStrike Falcon streaming-style normalization.

Supports common shapes: metadata.eventType + event.{...}, or flat process/network objects.
Field names follow Falcon public samples (ComputerName, UserName, CommandLine, etc.).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from narip.schemas.security import CanonicalSecurityEvent
from narip.security.enrichment import infer_mitre_from_text


def _ms_to_dt(ms: Any) -> datetime | None:
    try:
        if ms is None:
            return None
        v = float(ms)
        if v > 1e12:
            v /= 1000.0
        return datetime.fromtimestamp(v, tz=timezone.utc)
    except (TypeError, ValueError, OSError):
        return None


def _pick(d: dict[str, Any], *keys: str, default: Any = None) -> Any:
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    return default


def falcon_event_to_canonical(payload: dict[str, Any]) -> CanonicalSecurityEvent:
    md = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
    ev = payload.get("event") if isinstance(payload.get("event"), dict) else payload

    event_type = str(_pick(md, "eventType", "event_type", default="") or _pick(ev, "event_simpleName", "EventType", default=""))
    event_time = _ms_to_dt(_pick(md, "eventCreationTime", "timestamp", default=None))
    if event_time is None:
        event_time = _ms_to_dt(_pick(ev, "ProcessStartTime", "Timestamp", default=None))

    host = str(_pick(ev, "ComputerName", "Hostname", "hostname", default=None) or "") or None
    user = str(_pick(ev, "UserName", "UserIdentifier", "UserSid", default=None) or "") or None

    proc = str(_pick(ev, "FileName", "ImageFileName", "process_name", default=None) or "") or None
    cmd = str(_pick(ev, "CommandLine", "command_line", default=None) or "") or None
    parent = str(_pick(ev, "ParentBaseFileName", "ParentProcessImageFileName", default=None) or "") or None
    sha = str(_pick(ev, "SHA256HashData", "SHA256Hash", default=None) or "") or None

    det_name = str(_pick(ev, "DetectName", "PatternDispositionDescription", "name", default=None) or "") or None
    desc = str(_pick(ev, "DetectDescription", "Description", "description", default=None) or "") or None
    det_id = str(_pick(ev, "DetectId", "DetectionId", "detection_id", default=None) or "") or None

    sev = _pick(ev, "Severity", "SeverityName", default=0)
    try:
        if isinstance(sev, str) and sev.isdigit():
            severity = int(sev)
        elif isinstance(sev, (int, float)):
            severity = int(sev)
        else:
            severity = 0
    except (TypeError, ValueError):
        severity = 0
    severity = max(0, min(100, severity))

    src_ip = str(_pick(ev, "LocalIP", "ConnectionIP", "ClientIP", "src_ip", default=None) or "") or None
    dst_ip = str(_pick(ev, "RemoteAddress", "RemoteIP", "DestinationIp", "dst_ip", default=None) or "") or None
    dst_port = _pick(ev, "RemotePort", "DestinationPort", "dst_port", default=None)
    try:
        port = int(dst_port) if dst_port is not None else None
    except (TypeError, ValueError):
        port = None

    bytes_out = int(_pick(ev, "BytesSent", "BytesWritten", "bytes_out", default=0) or 0)

    text = " ".join(x for x in (det_name, desc, cmd, proc) if x)
    tactics, techniques = infer_mitre_from_text(text)

    excerpt = {k: payload[k] for k in list(payload.keys())[:8] if k in payload}
    return CanonicalSecurityEvent(
        vendor="crowdstrike_falcon",
        event_type=event_type or "UnknownFalconEvent",
        event_time=event_time,
        host=host,
        user_principal=user,
        process_name=proc,
        command_line=cmd,
        parent_process=parent,
        process_hash_sha256=sha,
        detection_id=det_id,
        detection_name=det_name,
        description=desc,
        severity_0_100=severity,
        mitre_tactics=tactics,
        mitre_techniques=techniques,
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=port,
        bytes_out=max(0, bytes_out),
        raw_excerpt=excerpt,
    )

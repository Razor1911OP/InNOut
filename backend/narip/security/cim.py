"""
Splunk CIM-oriented normalization (Authentication, Network Traffic, Endpoint.Process).

Accepts HEC-shaped payloads: {"event": {...}, "sourcetype": "...", ...} or flat events.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from narip.schemas.security import CanonicalSecurityEvent
from narip.security.enrichment import infer_mitre_from_text, splunk_risk_tags


def _parse_time(v: Any) -> datetime | None:
    if v is None:
        return None
    if isinstance(v, (int, float)):
        ts = float(v)
        if ts > 1e12:
            ts /= 1000.0
        try:
            return datetime.fromtimestamp(ts, tz=timezone.utc)
        except (OSError, ValueError):
            return None
    if isinstance(v, str):
        try:
            return datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


def _pick(d: dict[str, Any], *keys: str, default: Any = None) -> Any:
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    return default


def splunk_hec_to_canonical(payload: dict[str, Any]) -> CanonicalSecurityEvent:
    outer = payload
    raw = outer.get("event") if isinstance(outer.get("event"), dict) else outer
    if not isinstance(raw, dict):
        raw = {}

    sourcetype = str(_pick(outer, "sourcetype", default="") or _pick(raw, "sourcetype", default="") or "")
    index = str(_pick(outer, "index", default="") or _pick(raw, "index", default="") or "") or None
    source_host = str(_pick(outer, "host", default="") or _pick(raw, "host", default="") or "") or None

    # CIM Authentication
    user = _pick(raw, "user", "user_name", "src_user", "User", default=None)
    src = _pick(raw, "src", "src_ip", "ip", "ClientIP", default=None)
    dest = _pick(raw, "dest", "dest_ip", "dst", "dvc_ip", default=None)
    action = str(_pick(raw, "action", "status", default="") or "")

    # CIM Endpoint / Sysmon-style
    host = _pick(raw, "dest_nt_host", "ComputerName", "hostname", "dvc", "host", default=None)
    proc = _pick(raw, "process", "process_name", "Image", "ImageFileName", default=None)
    cmd = _pick(raw, "process_path", "CommandLine", "command_line", default=None)
    parent = _pick(raw, "parent_process", "ParentImage", "ParentProcessName", default=None)

    # CIM Network
    dst_ip = _pick(raw, "dst_ip", "dest_ip", "RemoteAddress", default=None)
    src_ip = _pick(raw, "src_ip", "src", default=None)
    dst_port = _pick(raw, "dst_port", "dest_port", "RemotePort", default=None)
    try:
        port = int(dst_port) if dst_port is not None else None
    except (TypeError, ValueError):
        port = None

    bytes_out = int(_pick(raw, "bytes_out", "bytes_sent", default=0) or 0)

    et = _parse_time(_pick(raw, "_time", "timestamp", "event_time", default=None))

    det_name = str(_pick(raw, "signature", "rule_name", "search_name", default="") or "") or None
    desc = str(_pick(raw, "message", "raw", "description", default="") or "") or None
    if isinstance(desc, str) and len(desc) > 400:
        desc = desc[:400]

    text = " ".join(str(x) for x in (det_name, desc, cmd, proc, action, sourcetype) if x)
    tactics, techniques = infer_mitre_from_text(text)

    sev = 25
    if "fail" in action.lower() or "denied" in action.lower():
        sev += 15
    if any(t in ("lateral_movement", "credential_access", "command_and_control") for t in tactics):
        sev += 35
    if "endpoint_telemetry" in splunk_risk_tags({**raw, "sourcetype": sourcetype}):
        sev += 10
    sev = max(0, min(100, sev))

    excerpt: dict[str, Any] = {}
    for k in ("sourcetype", "index", "signature", "user", "src", "dest"):
        if k in raw:
            excerpt[k] = raw[k]

    return CanonicalSecurityEvent(
        vendor="splunk_cim",
        event_type=sourcetype or "splunk:event",
        event_time=et,
        host=str(host) if host else source_host,
        user_principal=str(user) if user else None,
        process_name=str(proc) if proc else None,
        command_line=str(cmd) if cmd else None,
        parent_process=str(parent) if parent else None,
        detection_name=det_name,
        description=desc,
        severity_0_100=sev,
        mitre_tactics=tactics,
        mitre_techniques=techniques,
        src_ip=str(src_ip or src) if (src_ip or src) else None,
        dst_ip=str(dst_ip or dest) if (dst_ip or dest) else None,
        dst_port=port,
        bytes_out=max(0, bytes_out),
        index=index,
        sourcetype=sourcetype or None,
        source_host=source_host,
        raw_excerpt=excerpt,
    )

"""Fingerprint alerts to suppress analyst duplicate work (SOAR dedupe pattern)."""

from __future__ import annotations

import hashlib

from narip.schemas.security import CanonicalSecurityEvent


def fingerprint_event(c: CanonicalSecurityEvent) -> str:
    key = "|".join(
        [
            c.vendor,
            c.host or "",
            c.user_principal or "",
            c.detection_id or c.detection_name or "",
            c.dst_ip or "",
            str(c.dst_port or ""),
        ]
    )
    return hashlib.sha256(key.encode()).hexdigest()[:20]

"""Feature extraction, normalization, and enrichment hooks for NARIP."""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from narip.schemas.events import (
    AccountTelemetryEvent,
    EmailEvent,
    NetworkFlowEvent,
    OTPSessionEvent,
    SupplyChainSignal,
    TransactionEvent,
)


def _clamp01(x: float) -> float:
    return max(0.0, min(1.0, x))


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for c in text.lower():
        freq[c] = freq.get(c, 0) + 1
    n = len(text)
    h = 0.0
    for c in freq.values():
        p = c / n
        h -= p * math.log2(p)
    return h / 8.0 if h else 0.0


@dataclass
class FeatureBundle:
    """Named feature groups for downstream ML and explainability."""

    phishing: list[float] = field(default_factory=list)
    bec: list[float] = field(default_factory=list)
    wire: list[float] = field(default_factory=list)
    supply_chain: list[float] = field(default_factory=list)
    otp: list[float] = field(default_factory=list)
    ato: list[float] = field(default_factory=list)
    lateral: list[float] = field(default_factory=list)
    unified_names: list[str] = field(default_factory=list)
    unified_vector: list[float] = field(default_factory=list)


class FeatureExtractor:
    """Stateful enrichment: domain reputation hash buckets, text stats, graph placeholders."""

    def __init__(self) -> None:
        self._domain_bad_hashes: set[str] = set()

    def seed_bad_domain(self, domain: str) -> None:
        self._domain_bad_hashes.add(hashlib.sha256(domain.lower().encode()).hexdigest()[:12])

    def phishing_from_email(self, e: EmailEvent) -> list[float]:
        domain = e.sender.split("@")[-1].lower() if "@" in e.sender else ""
        dom_hash = hashlib.sha256(domain.encode()).hexdigest()[:12]
        domain_rep = 1.0 if dom_hash in self._domain_bad_hashes else 0.2

        suspicious_tlds = sum(1 for u in e.urls if urlparse(u).netloc.endswith((".tk", ".ml", ".gq")))
        url_risk = _clamp01(0.15 * len(e.urls) + 0.25 * suspicious_tlds)

        urgency = len(re.findall(r"\b(urgent|immediately|wire|confidential)\b", e.body_text, re.I))
        nlp_score = _clamp01(_entropy(e.body_text) * 0.35 + urgency * 0.08)

        return [domain_rep, url_risk, nlp_score]

    def bec_from_email(self, e: EmailEvent) -> list[float]:
        wire_kw = len(re.findall(r"\b(wire transfer|routing number|swift|iban)\b", e.body_text, re.I))
        urgency = len(re.findall(r"\b(urgent|ceo|cfo|do not tell|secret)\b", e.body_text, re.I))
        reply_mismatch = 1.0 if e.reply_to and e.reply_to.lower() != e.sender.lower() else 0.0
        return [_clamp01(reply_mismatch), _clamp01(urgency * 0.15), _clamp01(wire_kw * 0.2)]

    def wire_from_transaction(self, t: TransactionEvent, historical_mean: float = 5000.0) -> list[float]:
        amt = abs(t.amount)
        z = abs(amt - historical_mean) / (historical_mean + 1e-6)
        amount_dev = _clamp01(z / 5.0)
        # Recipient history placeholder: hash stability as proxy
        rec_hist = _clamp01(int(hashlib.md5(t.recipient_account.encode()).hexdigest()[:8], 16) / 0xFFFFFFFF)
        hour = 12.0
        try:
            from datetime import datetime

            hour = datetime.fromisoformat(t.initiated_at_iso.replace("Z", "+00:00")).hour
        except Exception:
            pass
        timing = _clamp01(abs(hour - 14) / 12.0)
        return [amount_dev, rec_hist, timing]

    def supply_chain(self, s: SupplyChainSignal) -> list[float]:
        version_changed = 1.0 if (s.version_old and s.version_new and s.version_old != s.version_new) else 0.0
        egress_ratio = s.vendor_egress_bytes_per_hour / (s.baseline_egress_bytes_per_hour + 1e-6)
        traffic_anomaly = _clamp01(math.log1p(egress_ratio) / 4.0)
        return [version_changed, traffic_anomaly, _clamp01(egress_ratio / 10.0)]

    def otp_session(self, o: OTPSessionEvent) -> list[float]:
        dwell = sum(o.keystroke_dwell_ms) / (len(o.keystroke_dwell_ms) + 1e-6)
        flight = sum(o.keystroke_flight_ms) / (len(o.keystroke_flight_ms) + 1e-6)
        dwell_n = _clamp01(dwell / 200.0)
        flight_n = _clamp01(flight / 150.0)
        geo = 0.0
        if o.geo_lat is not None and o.geo_lon is not None:
            geo = _clamp01((abs(o.geo_lat) + abs(o.geo_lon)) / 360.0)
        fp_entropy = _entropy(o.device_fingerprint) if o.device_fingerprint else 0.0
        return [dwell_n, flight_n, geo, fp_entropy]

    def ato_telemetry(self, cur: AccountTelemetryEvent, baseline_resource_count: int = 3) -> list[float]:
        access_spike = _clamp01(len(cur.resource_access) / float(baseline_resource_count + 1))
        priv = _clamp01(cur.privilege_level / 10.0)
        dev_change_proxy = _clamp01(_entropy(cur.device_id) * 0.5)
        return [access_spike, priv, dev_change_proxy]

    def lateral_from_flows(self, flows: list[NetworkFlowEvent]) -> list[float]:
        if not flows:
            return [0.0, 0.0, 0.0]
        total_bytes = sum(f.bytes_out for f in flows)
        unique_dst = len({f.dst_ip for f in flows})
        priv_ports = sum(1 for f in flows if f.dst_port in (445, 135, 3389, 22))
        return [
            _clamp01(math.log1p(total_bytes) / 20.0),
            _clamp01(unique_dst / 20.0),
            _clamp01(priv_ports / max(len(flows), 1)),
        ]

    def build_unified(self, bundle: FeatureBundle) -> FeatureBundle:
        names = []
        vec: list[float] = []
        groups = [
            ("phishing", bundle.phishing),
            ("bec", bundle.bec),
            ("wire", bundle.wire),
            ("supply_chain", bundle.supply_chain),
            ("otp", bundle.otp),
            ("ato", bundle.ato),
            ("lateral", bundle.lateral),
        ]
        for gname, feats in groups:
            for i, v in enumerate(feats):
                names.append(f"{gname}_{i}")
                vec.append(float(v))
        bundle.unified_names = names
        bundle.unified_vector = vec
        return bundle

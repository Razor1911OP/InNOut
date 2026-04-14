"""IOC matching (AlienVault OTX / threat-feed style) for automatic enrichment."""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from narip.schemas.security import CanonicalSecurityEvent


_DOMAIN_RE = re.compile(r"(?:[a-z0-9-]+\.)+[a-z]{2,}", re.I)


class IOCStore:
    def __init__(self) -> None:
        self._ips: set[str] = set()
        self._cidrs: list[Any] = []
        self._domains: set[str] = set()
        self._hashes: set[str] = set()

    def seed_defaults(self) -> None:
        """Synthetic IOCs for integration tests — replace via feed sync in production."""
        self.add_ip("198.51.100.1")
        self.add_domain("malware.example.invalid")
        self.add_hash("deadbeef" * 8)

    def add_ip(self, ip: str) -> None:
        self._ips.add(ip.strip())

    def add_cidr(self, cidr: str) -> None:
        self._cidrs.append(ipaddress.ip_network(cidr, strict=False))

    def add_domain(self, d: str) -> None:
        self._domains.add(d.lower().strip())

    def add_hash(self, h: str) -> None:
        self._hashes.add(h.lower().strip())

    def load_otx_style_pulse(self, indicators: list[dict[str, Any]]) -> int:
        """Accept simplified OTX indicator list: {type, indicator}."""
        n = 0
        for row in indicators:
            it = str(row.get("type") or "").lower()
            ind = str(row.get("indicator") or "").strip()
            if not ind:
                continue
            if it in ("ipv4", "ip", "IPv4"):
                self.add_ip(ind)
                n += 1
            elif it in ("domain", "hostname"):
                self.add_domain(ind)
                n += 1
            elif it in ("filehash-sha256", "sha256"):
                self.add_hash(ind)
                n += 1
        return n

    def _ip_hit(self, ip: str | None) -> bool:
        if not ip:
            return False
        if ip in self._ips:
            return True
        try:
            addr = ipaddress.ip_address(ip)
            for net in self._cidrs:
                if addr in net:
                    return True
        except ValueError:
            pass
        return False

    def _domain_hits(self, text: str) -> list[str]:
        if not text:
            return []
        found = []
        for m in _DOMAIN_RE.findall(text):
            ml = m.lower()
            if ml in self._domains:
                found.append(ml)
        return found

    def enrich(self, c: CanonicalSecurityEvent) -> list[dict[str, Any]]:
        hits: list[dict[str, Any]] = []
        for ip in (c.src_ip, c.dst_ip):
            if self._ip_hit(ip):
                hits.append({"kind": "ip", "value": ip, "source": "ioc_store"})
        if c.process_hash_sha256 and c.process_hash_sha256.lower() in self._hashes:
            hits.append({"kind": "sha256", "value": c.process_hash_sha256, "source": "ioc_store"})
        for d in self._domain_hits(c.summary_text()):
            hits.append({"kind": "domain", "value": d, "source": "ioc_store"})
        return hits

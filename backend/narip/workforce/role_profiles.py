from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class RoleCluster:
    key: str
    display_name: str
    typical_lures: list[str] = field(default_factory=list)
    baseline_click_risk: float = 0.4
    priority_modules: list[str] = field(default_factory=list)


@dataclass
class RoleTaxonomy:
    clusters: dict[str, RoleCluster] = field(default_factory=dict)

    def resolve_cluster(self, department: str, role_title: str) -> str:
        text = f"{department} {role_title}".lower()
        if any(
            k in text
            for k in ("finance", "account", "payable", "receivable", "controller", "treasury", "accounting")
        ):
            return "finance"
        if any(k in text for k in ("logistics", "warehouse", "shipping", "fleet", "supply chain", "operations")):
            return "logistics"
        if any(k in text for k in ("ceo", "cfo", "coo", "cto", "vp", "director", "board", "chief")):
            return "executive"
        if any(k in text for k in ("hr", "human resource", "people ", "talent")):
            return "hr"
        if any(k in text for k in ("engineer", "developer", "devops", "sre", "it ", "security", "infra")):
            return "engineering"
        return "general"


def load_role_taxonomy(path: Path | None = None) -> RoleTaxonomy:
    base = path or (Path(__file__).resolve().parent.parent / "data" / "roles" / "taxonomy.yaml")
    tax = RoleTaxonomy()
    if not base.is_file():
        tax.clusters["general"] = RoleCluster(key="general", display_name="General Staff")
        return tax
    raw = yaml.safe_load(base.read_text(encoding="utf-8")) or {}
    clusters = (raw.get("clusters") or {}) if isinstance(raw, dict) else {}
    for key, row in clusters.items():
        if not isinstance(row, dict):
            continue
        tax.clusters[str(key)] = RoleCluster(
            key=str(key),
            display_name=str(row.get("display_name") or key),
            typical_lures=[str(x) for x in (row.get("typical_lures") or [])],
            baseline_click_risk=float(row.get("baseline_click_risk") or 0.4),
            priority_modules=[str(x) for x in (row.get("priority_modules") or [])],
        )
    if "general" not in tax.clusters:
        tax.clusters["general"] = RoleCluster(key="general", display_name="General Staff")
    return tax


def role_content_alignment_score(email_text: str, cluster: RoleCluster) -> float:
    if not email_text or not cluster.typical_lures:
        return 0.0
    t = email_text.lower()
    hits = sum(1 for lure in cluster.typical_lures if lure.lower() in t)
    return min(1.0, hits * 0.22 + (0.15 if hits else 0.0))

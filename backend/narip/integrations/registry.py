from __future__ import annotations

from narip.integrations.crowdstrike_adapter import CrowdStrikeFalconAdapter
from narip.integrations.splunk_adapter import SplunkSIEMAdapter
from narip.integrations.stubs import build_stubs

ADAPTER_REGISTRY: dict[str, object] = {}
for a in build_stubs():
    ADAPTER_REGISTRY[a.name] = a
ADAPTER_REGISTRY["crowdstrike_falcon"] = CrowdStrikeFalconAdapter()
ADAPTER_REGISTRY["splunk_siem"] = SplunkSIEMAdapter()


def list_adapters() -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for a in ADAPTER_REGISTRY.values():
        name = getattr(a, "name", "unknown")
        cat = getattr(a, "category", "unknown")
        out.append({"name": str(name), "category": str(cat)})
    out.sort(key=lambda x: x["name"])
    return out

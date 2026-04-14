from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from narip.api.deps import get_ioc_store
from narip.threat_intel.ioc_store import IOCStore

router = APIRouter(prefix="/v1/threat-intel", tags=["threat-intel"])


@router.post("/indicators")
def load_indicators(body: dict[str, Any], store: IOCStore = Depends(get_ioc_store)) -> dict[str, int]:
    """Load simplified OTX-style indicators: {\"indicators\": [{\"type\",\"indicator\"}, ...]}."""
    rows = body.get("indicators")
    if not isinstance(rows, list):
        return {"loaded": 0}
    n = store.load_otx_style_pulse(rows)
    return {"loaded": n}

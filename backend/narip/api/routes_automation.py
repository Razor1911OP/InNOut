from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from narip.api.deps import get_case_store, get_playbook_engine
from narip.automation.cases import CaseRecord, CaseStore
from narip.automation.playbooks import PlaybookEngine

router = APIRouter(prefix="/v1/automation", tags=["automation-soar"])


@router.get("/cases", response_model=list[CaseRecord])
async def list_cases(store: CaseStore = Depends(get_case_store)) -> list[CaseRecord]:
    return await store.list_open()


@router.get("/cases/{case_id}", response_model=CaseRecord)
async def get_case(case_id: str, store: CaseStore = Depends(get_case_store)) -> CaseRecord:
    c = await store.get(case_id)
    if not c:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="case not found")
    return c


@router.post("/cases/{case_id}/status")
async def set_case_status(
    case_id: str,
    body: dict[str, Any],
    store: CaseStore = Depends(get_case_store),
) -> dict[str, Any]:
    st = str(body.get("status") or "")
    if st not in ("open", "in_progress", "resolved", "auto_closed"):
        from fastapi import HTTPException

        raise HTTPException(status_code=400, detail="invalid status")
    c = await store.set_status(case_id, st)
    if not c:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="case not found")
    return {"case_id": case_id, "status": c.status}


@router.get("/playbooks")
def list_playbooks(engine: PlaybookEngine = Depends(get_playbook_engine)) -> list[dict[str, Any]]:
    return [
        {"id": p.pb_id, "name": p.name, "enabled": p.enabled, "match": p.match, "steps": p.steps}
        for p in engine.playbooks
    ]


@router.post("/playbooks/reload")
def reload_playbooks(engine: PlaybookEngine = Depends(get_playbook_engine)) -> dict[str, str]:
    engine.reload()
    return {"status": "reloaded"}

from fastapi import APIRouter

from narip.integrations.registry import ADAPTER_REGISTRY, list_adapters

router = APIRouter(prefix="/v1/integrations", tags=["integrations"])


@router.get("/adapters")
def adapters() -> list[dict[str, str]]:
    return list_adapters()


@router.get("/adapters/{name}/health")
async def adapter_health(name: str) -> dict:
    a = ADAPTER_REGISTRY.get(name)
    if not a:
        return {"error": "unknown_adapter", "name": name}
    return await a.health()


@router.post("/adapters/{name}/ingest")
async def adapter_ingest(name: str, payload: dict) -> dict:
    a = ADAPTER_REGISTRY.get(name)
    if not a:
        return {"error": "unknown_adapter", "name": name}
    return await a.push_event(payload)

"""NARIP — REST API entrypoint (OpenAPI) + Prometheus metrics."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import make_asgi_app

from narip import __version__
from narip.api.routes_automation import router as automation_router
from narip.api.routes_incidents import router as incidents_router
from narip.api.routes_ingest import router as ingest_router
from narip.api.routes_integrations import router as integrations_router
from narip.api.routes_intel import router as intel_router
from narip.api.routes_modules import router as modules_router
from narip.api.routes_scoring import router as scoring_router
from narip.api.routes_workforce import router as workforce_router

app = FastAPI(
    title="Nexus AI Risk Intelligence Platform (NARIP)",
    version=__version__,
    description=(
        "REST-only AI/ML risk scoring, Falcon/Splunk ingest, SOAR-style automation, "
        "and role-aware phishing intelligence."
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(modules_router)
app.include_router(scoring_router)
app.include_router(incidents_router)
app.include_router(ingest_router)
app.include_router(automation_router)
app.include_router(intel_router)
app.include_router(workforce_router)
app.include_router(integrations_router)

app.mount("/metrics", make_asgi_app())


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "narip", "version": __version__, "api": "rest"}

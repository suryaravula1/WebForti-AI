from __future__ import annotations

from fastapi import FastAPI

from services.llm_core.service import create_generation_plan_from_settings
from webforti_common.models import CVERecord
from webforti_common.settings import load_settings

app = FastAPI(title="WebForti LLM Core", version="0.1.0")
settings = load_settings()


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "llm_core", "model_provider": settings.model_provider}


@app.post("/plan")
def plan(payload: dict) -> dict:
    cve = CVERecord(**payload["cve"])
    context = payload.get("context", [])
    generation_plan = create_generation_plan_from_settings(cve, context, settings)
    return {"plan": generation_plan.to_dict()}

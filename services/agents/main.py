from __future__ import annotations

from fastapi import FastAPI

from services.agents.service import generate_artifacts
from webforti_common.models import GenerationPlan
from webforti_common.settings import load_settings

app = FastAPI(title="WebForti Artifact Agents", version="0.1.0")
settings = load_settings()


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "agents"}


@app.post("/generate")
def generate(payload: dict) -> dict:
    plan = GenerationPlan.from_mapping(payload["plan"])
    bundle = generate_artifacts(plan, allow_egress=settings.sandbox_allow_egress)
    return {"bundle": bundle.to_dict()}

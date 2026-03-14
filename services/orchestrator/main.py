from __future__ import annotations

from fastapi import FastAPI

from services.orchestrator.service import verify_bundle
from webforti_common.models import ArtifactBundle
from webforti_common.settings import load_settings

app = FastAPI(title="WebForti Verification Orchestrator", version="0.1.0")
settings = load_settings()


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "orchestrator", "verification_mode": settings.verification_mode}


@app.post("/verify")
def verify(payload: dict) -> dict:
    bundle = ArtifactBundle.from_mapping(payload["bundle"])
    result = verify_bundle(
        bundle,
        mode=settings.verification_mode,
        timeout_seconds=settings.verification_timeout_seconds,
    )
    return {"result": result.to_dict()}

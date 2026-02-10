from __future__ import annotations

from fastapi import FastAPI

from services.rag_service.service import build_store, retrieve_context
from webforti_common.models import CVERecord
from webforti_common.settings import load_settings

app = FastAPI(title="WebForti RAG Service", version="0.1.0")
settings = load_settings()
store = build_store(settings)


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "rag_service"}


@app.post("/retrieve")
def retrieve(payload: dict) -> dict:
    cve = CVERecord(**payload["cve"])
    context = retrieve_context(cve, store, top_k=int(payload.get("top_k", 5)))
    return {"context": context}

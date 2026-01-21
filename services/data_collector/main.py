from __future__ import annotations

from fastapi import FastAPI

from services.data_collector.service import fetch_cve

app = FastAPI(title="WebForti Data Collector", version="0.1.0")


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "data_collector"}


@app.get("/cves/{cve_id}")
def get_cve(cve_id: str, prefer_seed: bool = False) -> dict:
    return fetch_cve(cve_id, prefer_seed=prefer_seed).to_dict()

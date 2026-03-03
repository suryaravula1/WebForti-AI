from __future__ import annotations

from typing import Annotated

from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from services.gateway.auth import API_KEY_HEADER, verify_gateway_api_key
from services.gateway.pipeline import run_job
from services.gateway.postgres_repository import PostgresJobRepository
from services.gateway.queue import QueuedJob, RedisJobQueue
from services.gateway.state import InMemoryJobStore
from webforti_common.settings import load_settings

app = FastAPI(title="WebForti API Gateway", version="0.1.0")
settings = load_settings()
job_store = InMemoryJobStore()
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.cors_origins),
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


def require_auth(x_webforti_api_key: Annotated[str | None, Header(alias=API_KEY_HEADER)] = None) -> None:
    verify_gateway_api_key(settings, x_webforti_api_key)


def postgres_repo() -> PostgresJobRepository:
    return PostgresJobRepository(settings.postgres_dsn)


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "gateway"}


@app.post("/jobs", dependencies=[Depends(require_auth)])
def create_job(payload: dict, background_tasks: BackgroundTasks) -> dict:
    cve_id = payload["cve_id"]
    submitted_by = payload.get("submitted_by", "local")
    prefer_seed = bool(payload.get("prefer_seed", False))
    record = job_store.create(cve_id, submitted_by=submitted_by)
    if settings.queue_backend == "redis":
        if settings.persistence_backend == "postgres":
            postgres_repo().persist_queued_record(record)
        RedisJobQueue(settings.redis_url).enqueue(
            QueuedJob(
                job_id=record.job.job_id,
                cve_id=cve_id,
                submitted_by=submitted_by,
                prefer_seed=prefer_seed,
            )
        )
    else:
        if settings.persistence_backend == "postgres":
            postgres_repo().persist_queued_record(record)
        background_tasks.add_task(run_job, record.job.job_id, job_store, settings, prefer_seed=prefer_seed)
    return record.to_summary()


@app.get("/jobs", dependencies=[Depends(require_auth)])
def list_jobs() -> dict:
    if settings.persistence_backend == "postgres":
        return {"jobs": postgres_repo().list_jobs()}
    return {"jobs": [record.to_summary() for record in job_store.list()]}


@app.get("/jobs/{job_id}", dependencies=[Depends(require_auth)])
def get_job(job_id: str) -> dict:
    if settings.persistence_backend == "postgres":
        job = postgres_repo().get_job(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="job not found")
        return job
    try:
        return job_store.get(job_id).to_summary()
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="job not found") from exc


@app.get("/jobs/{job_id}/events", dependencies=[Depends(require_auth)])
def get_events(job_id: str) -> dict:
    if settings.persistence_backend == "postgres":
        if not postgres_repo().get_job(job_id):
            raise HTTPException(status_code=404, detail="job not found")
        return {"events": postgres_repo().get_events(job_id)}
    try:
        record = job_store.get(job_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="job not found") from exc
    return {"events": [event.to_dict() for event in record.events]}


@app.get("/jobs/{job_id}/artifacts", dependencies=[Depends(require_auth)])
def get_artifacts(job_id: str) -> dict:
    if settings.persistence_backend == "postgres":
        artifacts = postgres_repo().get_artifacts(job_id)
        if not artifacts:
            raise HTTPException(status_code=404, detail="artifacts not available")
        return artifacts
    try:
        record = job_store.get(job_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="job not found") from exc
    if not record.bundle:
        raise HTTPException(status_code=404, detail="artifacts not available")
    return {"bundle": record.bundle.to_dict()}


@app.get("/jobs/{job_id}/report", dependencies=[Depends(require_auth)])
def get_report(job_id: str) -> dict:
    if settings.persistence_backend == "postgres":
        report = postgres_repo().get_report(job_id)
        if not report:
            raise HTTPException(status_code=404, detail="job not found")
        if not report["verification"]:
            raise HTTPException(status_code=404, detail="report not available")
        return report
    try:
        record = job_store.get(job_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="job not found") from exc
    if not record.result:
        raise HTTPException(status_code=404, detail="report not available")
    return {
        "job": record.job.to_dict(),
        "cve": record.cve.to_dict() if record.cve else None,
        "plan": record.plan.to_dict() if record.plan else None,
        "verification": record.result.to_dict(),
    }


@app.get("/llm-experimentation", dependencies=[Depends(require_auth)])
def list_llm_experimentation() -> dict:
    try:
        return {"experiments": postgres_repo().list_llm_experimentation()}
    except Exception as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

from __future__ import annotations

from services.gateway.state import InMemoryJobStore, JobRecord
from services.gateway.postgres_repository import PostgresJobRepository
from services.agents.service import generate_artifacts
from services.data_collector.service import fetch_cve
from services.llm_core.service import create_generation_plan_from_settings
from services.orchestrator.service import verify_bundle
from services.rag_service.service import build_store, retrieve_context
from webforti_common.http_helpers import get_json, post_json
from webforti_common.models import ArtifactBundle, CVERecord, GenerationPlan, JobStatus, VerificationResult, VerificationStatus
from webforti_common.settings import Settings


def run_job(job_id: str, store: InMemoryJobStore, settings: Settings, *, prefer_seed: bool = False) -> JobRecord:
    if settings.pipeline_mode == "http":
        return run_job_http(job_id, store, settings, prefer_seed=prefer_seed)
    return run_job_local(job_id, store, settings, prefer_seed=prefer_seed)


def run_job_local(job_id: str, store: InMemoryJobStore, settings: Settings, *, prefer_seed: bool = False) -> JobRecord:
    record = store.get(job_id)
    def transition(status: JobStatus, message: str, payload: dict | None = None) -> None:
        store.transition(job_id, status, message, payload)
        persist_if_configured(record, settings)

    try:
        transition(JobStatus.INGESTING, "Fetching and normalizing CVE metadata")
        record.cve = fetch_cve(record.job.cve_id, prefer_seed=prefer_seed)

        transition(JobStatus.RETRIEVING_CONTEXT, "Retrieving relevant knowledge context")
        knowledge_store = build_store(settings)
        record.context = retrieve_context(record.cve, knowledge_store, top_k=5)

        transition(JobStatus.PLANNING, "Creating schema-validated generation plan")
        record.plan = create_generation_plan_from_settings(record.cve, record.context, settings)

        transition(JobStatus.GENERATING_ARTIFACTS, "Generating exploit, Snort, and Docker artifacts")
        record.bundle = generate_artifacts(record.plan, allow_egress=settings.sandbox_allow_egress)

        transition(JobStatus.VALIDATING_ARTIFACTS, "Validating generated artifacts")
        if not record.bundle.is_complete():
            raise ValueError(f"artifact validation failed: {record.bundle.to_dict()}")

        transition(JobStatus.VERIFYING, "Running isolated verification workflow")
        record.result = verify_bundle(
            record.bundle,
            mode=settings.verification_mode,
            timeout_seconds=settings.verification_timeout_seconds,
        )

        transition(
            JobStatus.COMPLETED,
            "Verification completed",
            {"status": record.result.status.value, "effectiveness_score": record.result.effectiveness_score},
        )
    except Exception as exc:
        store.fail(job_id, str(exc))
    persist_if_configured(record, settings)
    return record


def run_job_http(job_id: str, store: InMemoryJobStore, settings: Settings, *, prefer_seed: bool = False) -> JobRecord:
    record = store.get(job_id)
    def transition(status: JobStatus, message: str, payload: dict | None = None) -> None:
        store.transition(job_id, status, message, payload)
        persist_if_configured(record, settings)

    try:
        transition(JobStatus.INGESTING, "Fetching and normalizing CVE metadata")
        cve_payload = get_json(f"{settings.ingestion_url}/cves/{record.job.cve_id}?prefer_seed={str(prefer_seed).lower()}")
        record.cve = CVERecord(**cve_payload)

        transition(JobStatus.RETRIEVING_CONTEXT, "Retrieving relevant knowledge context")
        context_payload = post_json(f"{settings.rag_url}/retrieve", {"cve": record.cve.to_dict(), "top_k": 5})
        record.context = context_payload["context"]

        transition(JobStatus.PLANNING, "Creating schema-validated generation plan")
        plan_payload = post_json(f"{settings.llm_core_url}/plan", {"cve": record.cve.to_dict(), "context": record.context}, timeout=180)
        record.plan = GenerationPlan.from_mapping(plan_payload["plan"])

        transition(JobStatus.GENERATING_ARTIFACTS, "Generating exploit, Snort, and Docker artifacts")
        bundle_payload = post_json(f"{settings.agents_url}/generate", {"plan": record.plan.to_dict()})
        record.bundle = ArtifactBundle.from_mapping(bundle_payload["bundle"])

        transition(JobStatus.VALIDATING_ARTIFACTS, "Validating generated artifacts")
        if not record.bundle.is_complete():
            raise ValueError(f"artifact validation failed: {record.bundle.to_dict()}")

        transition(JobStatus.VERIFYING, "Running isolated verification workflow")
        result_payload = post_json(f"{settings.orchestrator_url}/verify", {"bundle": record.bundle.to_dict()})
        raw_result = result_payload["result"]
        record.result = VerificationResult(
            cve_id=raw_result["cve_id"],
            status=VerificationStatus(raw_result["status"]),
            exploit_executed=raw_result["exploit_executed"],
            exploit_succeeded=raw_result["exploit_succeeded"],
            rule_alerted=raw_result["rule_alerted"],
            blocked=raw_result["blocked"],
            effectiveness_score=raw_result["effectiveness_score"],
            confidence_score=raw_result["confidence_score"],
            evidence=raw_result.get("evidence", {}),
        )

        transition(
            JobStatus.COMPLETED,
            "Verification completed",
            {"status": record.result.status.value, "effectiveness_score": record.result.effectiveness_score},
        )
    except Exception as exc:
        store.fail(job_id, str(exc))
    persist_if_configured(record, settings)
    return record


def persist_if_configured(record: JobRecord, settings: Settings) -> None:
    if settings.persistence_backend != "postgres":
        return
    PostgresJobRepository(settings.postgres_dsn).persist_record(record, settings)

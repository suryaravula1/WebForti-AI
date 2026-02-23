from __future__ import annotations

from dataclasses import dataclass, field

from webforti_common.models import ArtifactBundle, CVERecord, GenerationPlan, Job, JobEvent, JobStatus, VerificationResult, utc_now


@dataclass(slots=True)
class JobRecord:
    job: Job
    events: list[JobEvent] = field(default_factory=list)
    cve: CVERecord | None = None
    context: list[dict] = field(default_factory=list)
    plan: GenerationPlan | None = None
    bundle: ArtifactBundle | None = None
    result: VerificationResult | None = None
    error: str | None = None

    def to_summary(self) -> dict:
        data = self.job.to_dict()
        data["error"] = self.error
        data["has_report"] = self.result is not None
        return data


class InMemoryJobStore:
    def __init__(self) -> None:
        self._records: dict[str, JobRecord] = {}

    def create(self, cve_id: str, submitted_by: str = "local", job_id: str | None = None) -> JobRecord:
        job = Job.create(cve_id, submitted_by=submitted_by)
        if job_id:
            job.job_id = job_id
        record = JobRecord(job=job)
        self._records[job.job_id] = record
        self.add_event(job.job_id, JobStatus.QUEUED, "Job queued")
        return record

    def get(self, job_id: str) -> JobRecord:
        if job_id not in self._records:
            raise KeyError(job_id)
        return self._records[job_id]

    def list(self) -> list[JobRecord]:
        return list(self._records.values())

    def transition(self, job_id: str, status: JobStatus, message: str, payload: dict | None = None) -> None:
        record = self.get(job_id)
        record.job.status = status
        record.job.current_stage = status.value
        record.job.updated_at = utc_now()
        self.add_event(job_id, status, message, payload or {})

    def fail(self, job_id: str, error: str) -> None:
        record = self.get(job_id)
        record.error = error
        self.transition(job_id, JobStatus.FAILED, error)

    def add_event(self, job_id: str, status: JobStatus, message: str, payload: dict | None = None) -> None:
        self.get(job_id).events.append(JobEvent(job_id=job_id, stage=status, message=message, payload=payload or {}))

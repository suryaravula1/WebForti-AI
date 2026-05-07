from __future__ import annotations

from services.gateway.pipeline import run_job
from services.gateway.state import InMemoryJobStore
from webforti_common.settings import Settings


def test_seeded_pipeline_completes() -> None:
    settings = Settings(model_provider="mock", verification_mode="mock", mongo_uri="memory://test")
    store = InMemoryJobStore()
    record = store.create("CVE-2021-41773", submitted_by="test")

    completed = run_job(record.job.job_id, store, settings, prefer_seed=True)

    assert completed.job.status.value == "completed"
    assert completed.plan is not None
    assert completed.bundle is not None
    assert completed.bundle.is_complete()
    assert completed.result is not None
    assert completed.result.status.value == "pass"

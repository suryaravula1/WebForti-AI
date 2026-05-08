from __future__ import annotations

from services.gateway.postgres_repository import PostgresJobRepository


def test_job_summary_serializes_datetimes() -> None:
    repo = PostgresJobRepository.__new__(PostgresJobRepository)
    row = (
        "job-1",
        "CVE-2099-0001",
        "completed",
        "tester",
        __import__("datetime").datetime(2026, 1, 1),
        __import__("datetime").datetime(2026, 1, 2),
        True,
    )

    summary = repo._job_summary(row)

    assert summary["job_id"] == "job-1"
    assert summary["has_report"] is True
    assert summary["created_at"].startswith("2026-01-01")

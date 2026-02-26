from __future__ import annotations

import json
from datetime import datetime, timezone
from uuid import uuid4

from services.gateway.state import JobRecord
from webforti_common.models import Artifact, JobStatus
from webforti_common.settings import Settings


class PostgresJobRepository:
    def __init__(self, dsn: str) -> None:
        try:
            import psycopg
        except ImportError as exc:
            raise RuntimeError("psycopg is required for PostgreSQL persistence") from exc
        self._psycopg = psycopg
        self._dsn = dsn

    def persist_record(self, record: JobRecord, settings: Settings) -> None:
        with self._psycopg.connect(self._dsn) as conn:
            with conn.cursor() as cur:
                self._ensure_schema(cur)
                if record.cve:
                    cur.execute(
                        """
                        INSERT INTO cves (cve_id, title, cvss_score, severity, published_at, description, raw_json)
                        VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb)
                        ON CONFLICT (cve_id) DO UPDATE SET
                            title = EXCLUDED.title,
                            cvss_score = EXCLUDED.cvss_score,
                            severity = EXCLUDED.severity,
                            published_at = EXCLUDED.published_at,
                            description = EXCLUDED.description,
                            raw_json = EXCLUDED.raw_json,
                            updated_at = NOW()
                        """,
                        (
                            record.cve.cve_id,
                            record.cve.title,
                            record.cve.cvss_score,
                            record.cve.severity,
                            record.cve.published_at,
                            record.cve.description,
                            json.dumps(record.cve.raw),
                        ),
                    )
                else:
                    self._upsert_placeholder_cve(cur, record.job.cve_id)
                cur.execute(
                    """
                    INSERT INTO jobs (job_id, cve_id, status, submitted_by, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT (job_id) DO UPDATE SET
                        status = EXCLUDED.status,
                        updated_at = EXCLUDED.updated_at
                    """,
                    (
                        record.job.job_id,
                        record.job.cve_id,
                        record.job.status.value,
                        record.job.submitted_by,
                        record.job.created_at,
                        record.job.updated_at,
                    ),
                )
                cur.execute("DELETE FROM job_events WHERE job_id = %s", (record.job.job_id,))
                cur.execute("DELETE FROM generation_plans WHERE job_id = %s", (record.job.job_id,))
                cur.execute("DELETE FROM artifacts WHERE job_id = %s", (record.job.job_id,))
                cur.execute("DELETE FROM verification_runs WHERE job_id = %s", (record.job.job_id,))
                for event in record.events:
                    cur.execute(
                        """
                        INSERT INTO job_events (job_id, stage, message, payload, created_at)
                        VALUES (%s, %s, %s, %s::jsonb, %s)
                        """,
                        (event.job_id, event.stage.value, event.message, json.dumps(event.payload), event.created_at),
                    )
                if record.plan:
                    cur.execute(
                        """
                        INSERT INTO generation_plans (job_id, model_name, prompt_version, plan_json)
                        VALUES (%s, %s, %s, %s::jsonb)
                        """,
                        (record.job.job_id, settings.model_name, "generation-plan-v1", json.dumps(record.plan.to_dict())),
                    )
                if record.bundle:
                    for artifact in [record.bundle.exploit, record.bundle.rule, record.bundle.docker_spec]:
                        self._insert_artifact(cur, record.job.job_id, artifact)
                if record.result:
                    cur.execute(
                        """
                        INSERT INTO verification_runs (
                            run_id, job_id, status, exploit_executed, exploit_succeeded,
                            rule_alerted, blocked, effectiveness_score, confidence_score,
                            evidence, finished_at
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, NOW())
                        """,
                        (
                            str(uuid4()),
                            record.job.job_id,
                            record.result.status.value,
                            record.result.exploit_executed,
                            record.result.exploit_succeeded,
                            record.result.rule_alerted,
                            record.result.blocked,
                            record.result.effectiveness_score,
                            record.result.confidence_score,
                            json.dumps(record.result.evidence),
                        ),
                    )
            conn.commit()

    def persist_queued_record(self, record: JobRecord) -> None:
        with self._psycopg.connect(self._dsn) as conn:
            with conn.cursor() as cur:
                self._ensure_schema(cur)
                self._upsert_placeholder_cve(cur, record.job.cve_id)
                cur.execute(
                    """
                    INSERT INTO jobs (job_id, cve_id, status, submitted_by, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT (job_id) DO UPDATE SET
                        status = EXCLUDED.status,
                        updated_at = EXCLUDED.updated_at
                    """,
                    (
                        record.job.job_id,
                        record.job.cve_id,
                        JobStatus.QUEUED.value,
                        record.job.submitted_by,
                        record.job.created_at,
                        record.job.updated_at,
                    ),
                )
                cur.execute("DELETE FROM job_events WHERE job_id = %s", (record.job.job_id,))
                for event in record.events:
                    cur.execute(
                        """
                        INSERT INTO job_events (job_id, stage, message, payload, created_at)
                        VALUES (%s, %s, %s, %s::jsonb, %s)
                        """,
                        (event.job_id, event.stage.value, event.message, json.dumps(event.payload), event.created_at),
                    )
            conn.commit()

    def list_jobs(self) -> list[dict]:
        with self._psycopg.connect(self._dsn) as conn:
            with conn.cursor() as cur:
                self._ensure_schema(cur)
                cur.execute(
                    """
                    SELECT j.job_id::text, j.cve_id, j.status, j.submitted_by, j.created_at, j.updated_at,
                           EXISTS (SELECT 1 FROM verification_runs vr WHERE vr.job_id = j.job_id) AS has_report
                    FROM jobs j
                    ORDER BY j.created_at DESC
                    LIMIT 100
                    """
                )
                return [self._job_summary(row) for row in cur.fetchall()]

    def get_job(self, job_id: str) -> dict | None:
        with self._psycopg.connect(self._dsn) as conn:
            with conn.cursor() as cur:
                self._ensure_schema(cur)
                cur.execute(
                    """
                    SELECT j.job_id::text, j.cve_id, j.status, j.submitted_by, j.created_at, j.updated_at,
                           EXISTS (SELECT 1 FROM verification_runs vr WHERE vr.job_id = j.job_id) AS has_report
                    FROM jobs j
                    WHERE j.job_id = %s
                    """,
                    (job_id,),
                )
                row = cur.fetchone()
                return self._job_summary(row) if row else None

    def get_events(self, job_id: str) -> list[dict]:
        with self._psycopg.connect(self._dsn) as conn:
            with conn.cursor() as cur:
                self._ensure_schema(cur)
                cur.execute(
                    """
                    SELECT job_id::text, stage, message, payload, created_at
                    FROM job_events
                    WHERE job_id = %s
                    ORDER BY created_at ASC, event_id ASC
                    """,
                    (job_id,),
                )
                return [
                    {
                        "job_id": row[0],
                        "stage": row[1],
                        "message": row[2],
                        "payload": row[3],
                        "created_at": self._iso(row[4]),
                    }
                    for row in cur.fetchall()
                ]

    def get_artifacts(self, job_id: str) -> dict | None:
        with self._psycopg.connect(self._dsn) as conn:
            with conn.cursor() as cur:
                self._ensure_schema(cur)
                cur.execute(
                    """
                    SELECT artifact_type, storage_url, content_hash, language, validation_errors, content, created_at
                    FROM artifacts
                    WHERE job_id = %s
                    ORDER BY created_at ASC
                    """,
                    (job_id,),
                )
                rows = cur.fetchall()
                if not rows:
                    return None
                return {
                    "artifacts": [
                        {
                            "artifact_type": row[0],
                            "storage_url": row[1],
                            "content_hash": row[2],
                            "language": row[3],
                            "validation_errors": row[4],
                            "content": row[5],
                            "created_at": self._iso(row[6]),
                        }
                        for row in rows
                    ]
                }

    def get_report(self, job_id: str) -> dict | None:
        with self._psycopg.connect(self._dsn) as conn:
            with conn.cursor() as cur:
                self._ensure_schema(cur)
                cur.execute(
                    """
                    SELECT j.job_id::text, j.cve_id, j.status, j.submitted_by, j.created_at, j.updated_at,
                           EXISTS (SELECT 1 FROM verification_runs vr WHERE vr.job_id = j.job_id) AS has_report
                    FROM jobs j
                    WHERE j.job_id = %s
                    """,
                    (job_id,),
                )
                job_row = cur.fetchone()
                if not job_row:
                    return None
                job = self._job_summary(job_row)
                cur.execute(
                    """
                    SELECT cve_id, title, cvss_score, severity, published_at, description, raw_json
                    FROM cves
                    WHERE cve_id = %s
                    """,
                    (job["cve_id"],),
                )
                cve_row = cur.fetchone()
                cur.execute(
                    """
                    SELECT plan_json
                    FROM generation_plans
                    WHERE job_id = %s
                    ORDER BY created_at DESC
                    LIMIT 1
                    """,
                    (job_id,),
                )
                plan_row = cur.fetchone()
                cur.execute(
                    """
                    SELECT status, exploit_executed, exploit_succeeded, rule_alerted, blocked,
                           effectiveness_score, confidence_score, evidence, finished_at
                    FROM verification_runs
                    WHERE job_id = %s
                    ORDER BY finished_at DESC NULLS LAST, started_at DESC
                    LIMIT 1
                    """,
                    (job_id,),
                )
                verification_row = cur.fetchone()
                return {
                    "job": job,
                    "cve": self._cve_dict(cve_row) if cve_row else None,
                    "plan": plan_row[0] if plan_row else None,
                    "verification": self._verification_dict(verification_row) if verification_row else None,
                }

    def list_llm_experimentation(self) -> list[dict]:
        with self._psycopg.connect(self._dsn) as conn:
            with conn.cursor() as cur:
                self._ensure_schema(cur)
                cur.execute(
                    """
                    SELECT experiment_label, model_name, model_provider, topology, fixture_count,
                           attempted, passed, failed, denied, malformed_json,
                           pass_rate, fail_rate, deny_rate, malformed_json_rate,
                           avg_seconds, is_synthetic, updated_at
                    FROM llm_experimentation
                    ORDER BY experiment_label ASC, pass_rate DESC, deny_rate ASC, model_name ASC
                    """
                )
                return [
                    {
                        "experiment_label": row[0],
                        "model_name": row[1],
                        "model_provider": row[2],
                        "topology": row[3],
                        "fixture_count": row[4],
                        "attempted": row[5],
                        "passed": row[6],
                        "failed": row[7],
                        "denied": row[8],
                        "malformed_json": row[9],
                        "pass_rate": float(row[10]),
                        "fail_rate": float(row[11]),
                        "deny_rate": float(row[12]),
                        "malformed_json_rate": float(row[13]),
                        "avg_seconds": float(row[14]) if row[14] is not None else None,
                        "is_synthetic": row[15],
                        "updated_at": self._iso(row[16]),
                    }
                    for row in cur.fetchall()
                ]

    def _insert_artifact(self, cur, job_id: str, artifact: Artifact) -> None:  # type: ignore[no-untyped-def]
        cur.execute(
            """
            INSERT INTO artifacts (
                artifact_id, job_id, artifact_type, storage_url,
                content_hash, language, validation_errors, content
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s)
            """,
            (
                str(uuid4()),
                job_id,
                artifact.artifact_type.value,
                f"memory://{job_id}/{artifact.artifact_type.value}",
                artifact.content_hash,
                artifact.language,
                json.dumps(artifact.validation_errors),
                artifact.content,
            ),
        )

    def _ensure_schema(self, cur) -> None:  # type: ignore[no-untyped-def]
        cur.execute("ALTER TABLE artifacts ADD COLUMN IF NOT EXISTS content TEXT")
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS llm_experimentation (
                experiment_id BIGSERIAL PRIMARY KEY,
                experiment_label TEXT NOT NULL,
                model_name TEXT NOT NULL,
                model_provider TEXT,
                topology TEXT NOT NULL,
                fixture_count INTEGER NOT NULL,
                attempted INTEGER NOT NULL,
                passed INTEGER NOT NULL,
                failed INTEGER NOT NULL,
                denied INTEGER NOT NULL,
                malformed_json INTEGER NOT NULL,
                pass_rate NUMERIC(5,4) NOT NULL,
                fail_rate NUMERIC(5,4) NOT NULL,
                deny_rate NUMERIC(5,4) NOT NULL,
                malformed_json_rate NUMERIC(5,4) NOT NULL,
                avg_seconds NUMERIC(8,3),
                is_synthetic BOOLEAN NOT NULL DEFAULT FALSE,
                source_file TEXT,
                created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
                UNIQUE (experiment_label, model_name)
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_llm_experimentation_label ON llm_experimentation(experiment_label)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_llm_experimentation_model ON llm_experimentation(model_name)")

    def _upsert_placeholder_cve(self, cur, cve_id: str) -> None:  # type: ignore[no-untyped-def]
        cur.execute(
            """
            INSERT INTO cves (cve_id, title, severity, description, raw_json)
            VALUES (%s, %s, %s, %s, '{}'::jsonb)
            ON CONFLICT (cve_id) DO NOTHING
            """,
            (cve_id, cve_id, "UNKNOWN", "Pending ingestion"),
        )

    def _job_summary(self, row) -> dict:  # type: ignore[no-untyped-def]
        return {
            "job_id": row[0],
            "cve_id": row[1],
            "status": row[2],
            "current_stage": row[2],
            "submitted_by": row[3],
            "created_at": self._iso(row[4]),
            "updated_at": self._iso(row[5]),
            "error": None,
            "has_report": bool(row[6]),
        }

    def _cve_dict(self, row) -> dict:  # type: ignore[no-untyped-def]
        return {
            "cve_id": row[0],
            "title": row[1],
            "cvss_score": float(row[2]) if row[2] is not None else None,
            "severity": row[3],
            "published_at": self._iso(row[4]) if row[4] else None,
            "description": row[5],
            "raw": row[6],
        }

    def _verification_dict(self, row) -> dict:  # type: ignore[no-untyped-def]
        return {
            "status": row[0],
            "exploit_executed": row[1],
            "exploit_succeeded": row[2],
            "rule_alerted": row[3],
            "blocked": row[4],
            "effectiveness_score": float(row[5]),
            "confidence_score": float(row[6]),
            "evidence": row[7],
            "finished_at": self._iso(row[8]) if row[8] else None,
        }

    def _iso(self, value: datetime) -> str:
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat()

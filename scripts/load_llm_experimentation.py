from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from webforti_common.settings import load_settings


def main() -> None:
    parser = argparse.ArgumentParser(description="Load LLM experimentation metrics into PostgreSQL.")
    parser.add_argument("--input", default="benchmarks/model_comparison_synthetic.json")
    parser.add_argument("--experiment-label", default=None)
    args = parser.parse_args()

    input_path = Path(args.input)
    payload = json.loads(input_path.read_text(encoding="utf-8"))
    experiment_label = args.experiment_label or str(payload.get("label") or input_path.stem)
    settings = load_settings()
    inserted = upsert_experimentation_rows(
        settings.postgres_dsn,
        payload,
        experiment_label=experiment_label,
        source_file=str(input_path),
    )
    print(json.dumps({"table": "llm_experimentation", "upserted": inserted, "experiment_label": experiment_label}, indent=2))


def upsert_experimentation_rows(
    dsn: str,
    payload: dict[str, Any],
    *,
    experiment_label: str,
    source_file: str,
) -> int:
    try:
        import psycopg
    except ImportError as exc:
        raise RuntimeError("psycopg is required to load PostgreSQL experimentation data") from exc

    rows = payload.get("rows") or []
    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            ensure_schema(cur)
            for row in rows:
                cur.execute(
                    """
                    INSERT INTO llm_experimentation (
                        experiment_label, model_name, model_provider, topology, fixture_count,
                        attempted, passed, failed, denied, malformed_json,
                        pass_rate, fail_rate, deny_rate, malformed_json_rate,
                        avg_seconds, is_synthetic, source_file
                    )
                    VALUES (
                        %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s,
                        %s, %s, %s, %s,
                        %s, %s, %s
                    )
                    ON CONFLICT (experiment_label, model_name) DO UPDATE SET
                        model_provider = EXCLUDED.model_provider,
                        topology = EXCLUDED.topology,
                        fixture_count = EXCLUDED.fixture_count,
                        attempted = EXCLUDED.attempted,
                        passed = EXCLUDED.passed,
                        failed = EXCLUDED.failed,
                        denied = EXCLUDED.denied,
                        malformed_json = EXCLUDED.malformed_json,
                        pass_rate = EXCLUDED.pass_rate,
                        fail_rate = EXCLUDED.fail_rate,
                        deny_rate = EXCLUDED.deny_rate,
                        malformed_json_rate = EXCLUDED.malformed_json_rate,
                        avg_seconds = EXCLUDED.avg_seconds,
                        is_synthetic = EXCLUDED.is_synthetic,
                        source_file = EXCLUDED.source_file,
                        updated_at = NOW()
                    """,
                    (
                        experiment_label,
                        row["model"],
                        provider_for_model(row["model"]),
                        payload["topology"],
                        int(payload["fixture_count"]),
                        int(row["attempted"]),
                        int(row["passed"]),
                        int(row["failed"]),
                        int(row["denied"]),
                        int(row["malformed_json"]),
                        float(row["pass_rate"]),
                        float(row["fail_rate"]),
                        float(row["deny_rate"]),
                        float(row["malformed_json_rate"]),
                        float(row["synthetic_avg_seconds"]) if row.get("synthetic_avg_seconds") is not None else None,
                        "synthetic" in experiment_label.lower() or "synthetic" in str(payload.get("label", "")).lower(),
                        source_file,
                    ),
                )
        conn.commit()
    return len(rows)


def ensure_schema(cur) -> None:  # type: ignore[no-untyped-def]
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


def provider_for_model(model_name: str) -> str:
    lowered = model_name.lower()
    if "openai" in lowered or "gpt" in lowered:
        return "openai"
    if "claude" in lowered:
        return "anthropic"
    if "qwen" in lowered:
        return "openrouter"
    if "kimi" in lowered:
        return "moonshot/openrouter"
    if "gemini" in lowered:
        return "google"
    if "deepseek" in lowered:
        return "deepseek/openrouter"
    if "llama" in lowered:
        return "local"
    return "unknown"


if __name__ == "__main__":
    main()

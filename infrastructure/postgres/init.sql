CREATE TABLE IF NOT EXISTS cves (
    cve_id VARCHAR(32) PRIMARY KEY,
    title TEXT NOT NULL,
    cvss_score NUMERIC(3,1),
    severity VARCHAR(16),
    published_at TIMESTAMP,
    description TEXT NOT NULL,
    raw_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS jobs (
    job_id UUID PRIMARY KEY,
    cve_id VARCHAR(32) NOT NULL REFERENCES cves(cve_id),
    status VARCHAR(32) NOT NULL,
    submitted_by TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS job_events (
    event_id BIGSERIAL PRIMARY KEY,
    job_id UUID NOT NULL REFERENCES jobs(job_id),
    stage VARCHAR(64) NOT NULL,
    message TEXT NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS generation_plans (
    plan_id BIGSERIAL PRIMARY KEY,
    job_id UUID NOT NULL REFERENCES jobs(job_id),
    model_name TEXT NOT NULL,
    prompt_version TEXT NOT NULL,
    plan_json JSONB NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS artifacts (
    artifact_id UUID PRIMARY KEY,
    job_id UUID NOT NULL REFERENCES jobs(job_id),
    artifact_type VARCHAR(32) NOT NULL,
    storage_url TEXT,
    content_hash TEXT NOT NULL,
    language TEXT,
    validation_errors JSONB NOT NULL DEFAULT '[]'::jsonb,
    content TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS verification_runs (
    run_id UUID PRIMARY KEY,
    job_id UUID NOT NULL REFERENCES jobs(job_id),
    status VARCHAR(16) NOT NULL,
    exploit_executed BOOLEAN NOT NULL,
    exploit_succeeded BOOLEAN NOT NULL,
    rule_alerted BOOLEAN NOT NULL,
    blocked BOOLEAN NOT NULL,
    effectiveness_score NUMERIC(4,2) NOT NULL,
    confidence_score NUMERIC(4,2) NOT NULL,
    evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
    started_at TIMESTAMP NOT NULL DEFAULT NOW(),
    finished_at TIMESTAMP
);

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
);

CREATE INDEX IF NOT EXISTS idx_jobs_cve_id ON jobs(cve_id);
CREATE INDEX IF NOT EXISTS idx_job_events_job_id ON job_events(job_id);
CREATE INDEX IF NOT EXISTS idx_artifacts_job_id ON artifacts(job_id);
CREATE INDEX IF NOT EXISTS idx_verification_runs_job_id ON verification_runs(job_id);
CREATE INDEX IF NOT EXISTS idx_llm_experimentation_label ON llm_experimentation(experiment_label);
CREATE INDEX IF NOT EXISTS idx_llm_experimentation_model ON llm_experimentation(model_name);

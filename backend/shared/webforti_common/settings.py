from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Settings:
    environment: str = "local"
    pipeline_mode: str = "local"
    persistence_backend: str = "memory"
    queue_backend: str = "inline"
    model_provider: str = "mock"
    model_name: str = "qwen/qwen3.6-35b-a3b:nitro"
    openai_compatible_url: str = "https://api.openai.com/v1"
    openai_api_key: str = ""
    openrouter_site_url: str = "http://localhost"
    openrouter_app_title: str = "WebForti"
    mongo_uri: str = "mongodb://localhost:27017"
    mongo_database: str = "webforti"
    mongo_vector_index: str = "knowledge_vector_index"
    embedding_provider: str = "hashing"
    embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2"
    embedding_dimensions: int = 64
    postgres_dsn: str = "postgresql://webforti:webforti@localhost:5432/webforti"
    redis_url: str = "redis://localhost:6379/0"
    gateway_url: str = "http://localhost:8000"
    cors_origins: tuple[str, ...] = ("http://localhost:5173", "http://127.0.0.1:5173")
    gateway_api_key: str = ""
    ingestion_url: str = "http://localhost:8001"
    rag_url: str = "http://localhost:8002"
    llm_core_url: str = "http://localhost:8003"
    agents_url: str = "http://localhost:8004"
    orchestrator_url: str = "http://localhost:8005"
    verification_mode: str = "mock"
    verification_timeout_seconds: int = 60
    sandbox_allow_egress: bool = False


def load_settings() -> Settings:
    env = {**_load_dotenv(Path.cwd() / ".env"), **os.environ}
    embedding_provider = env.get("WEBFORTI_EMBEDDING_PROVIDER", "hashing")
    default_embedding_dimensions = "384" if embedding_provider.lower() in {
        "sentence_transformers",
        "sentence-transformers",
        "sbert",
    } else "64"
    return Settings(
        environment=env.get("WEBFORTI_ENV", "local"),
        pipeline_mode=env.get("WEBFORTI_PIPELINE_MODE", "local"),
        persistence_backend=env.get("WEBFORTI_PERSISTENCE_BACKEND", "memory"),
        queue_backend=env.get("WEBFORTI_QUEUE_BACKEND", "inline"),
        model_provider=env.get("WEBFORTI_MODEL_PROVIDER", "mock"),
        model_name=env.get("WEBFORTI_MODEL_NAME", "qwen/qwen3.6-35b-a3b:nitro"),
        openai_compatible_url=env.get("OPENAI_COMPATIBLE_URL", "https://api.openai.com/v1"),
        openai_api_key=env.get("OPENAI_API_KEY", ""),
        openrouter_site_url=env.get("OPENROUTER_SITE_URL", "http://localhost"),
        openrouter_app_title=env.get("OPENROUTER_APP_TITLE", "WebForti"),
        mongo_uri=env.get("MONGO_URI", "mongodb://localhost:27017"),
        mongo_database=env.get("MONGO_DATABASE", "webforti"),
        mongo_vector_index=env.get("MONGO_VECTOR_INDEX", "knowledge_vector_index"),
        embedding_provider=embedding_provider,
        embedding_model=env.get("WEBFORTI_EMBEDDING_MODEL", "sentence-transformers/all-MiniLM-L6-v2"),
        embedding_dimensions=int(env.get("WEBFORTI_EMBEDDING_DIMENSIONS", default_embedding_dimensions)),
        postgres_dsn=env.get("POSTGRES_DSN", "postgresql://webforti:webforti@localhost:5432/webforti"),
        redis_url=env.get("REDIS_URL", "redis://localhost:6379/0"),
        gateway_url=env.get("GATEWAY_URL", "http://localhost:8000"),
        cors_origins=_split_csv(env.get("WEBFORTI_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")),
        gateway_api_key=env.get("WEBFORTI_API_KEY", ""),
        ingestion_url=env.get("INGESTION_URL", "http://localhost:8001"),
        rag_url=env.get("RAG_URL", "http://localhost:8002"),
        llm_core_url=env.get("LLM_CORE_URL", "http://localhost:8003"),
        agents_url=env.get("AGENTS_URL", "http://localhost:8004"),
        orchestrator_url=env.get("ORCHESTRATOR_URL", "http://localhost:8005"),
        verification_mode=env.get("WEBFORTI_VERIFICATION_MODE", "mock"),
        verification_timeout_seconds=int(env.get("WEBFORTI_VERIFICATION_TIMEOUT_SECONDS", "60")),
        sandbox_allow_egress=env.get("SANDBOX_ALLOW_EGRESS", "false").lower() == "true",
    )


def _split_csv(value: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in value.split(",") if item.strip())


def _load_dotenv(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            values[key] = value
    return values

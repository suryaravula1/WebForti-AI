from __future__ import annotations

from pathlib import Path

from fastapi import HTTPException

from services.gateway.auth import verify_gateway_api_key
from services.gateway.queue import QueuedJob
from webforti_common.knowledge_store import (
    HashingEmbeddingModel,
    InMemoryKnowledgeStore,
    build_embedder,
    embed_text,
    extract_cve_ids,
    with_embedding,
)
from webforti_common.settings import Settings, _load_dotenv, _split_csv


def test_load_dotenv_parses_simple_values(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("A=1\nB='two'\n# ignored\nC=\"three\"\n", encoding="utf-8")

    assert _load_dotenv(env_file) == {"A": "1", "B": "two", "C": "three"}


def test_split_csv_trims_empty_values() -> None:
    assert _split_csv("http://localhost:5173, ,http://127.0.0.1:5173") == (
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    )


def test_hash_embedding_is_stable() -> None:
    first = embed_text("Apache traversal payload")
    second = embed_text("Apache traversal payload")

    assert first == second
    assert len(first) == 64
    embedded = with_embedding({"id": "x", "text": "payload"})
    assert embedded["embedding_model"] == "webforti-hashing-64"
    assert embedded["embedding_dimensions"] == 64


def test_embedding_provider_is_configurable() -> None:
    hashing = build_embedder(Settings(embedding_provider="hashing", embedding_dimensions=128))
    assert isinstance(hashing, HashingEmbeddingModel)
    assert hashing.name == "webforti-hashing-128"
    assert len(hashing.embed("Apache traversal payload")) == 128


def test_knowledge_store_boosts_exact_cve_context() -> None:
    store = InMemoryKnowledgeStore()
    store.upsert_document({"id": "generic", "title": "Generic Apache", "text": "Apache web request"})
    store.upsert_document({"id": "f5", "title": "F5 payload", "text": "iControl REST", "cve_id": "CVE-2022-1388"})

    results = store.search("CVE-2022-1388 Apache web request", top_k=2)

    assert extract_cve_ids("test CVE-2022-1388") == ["CVE-2022-1388"]
    assert results[0]["id"] == "f5"
    assert results[0]["retrieval_mode"] == "cve_exact"


def test_queued_job_roundtrip() -> None:
    queued = QueuedJob(job_id="job-1", cve_id="CVE-2099-0001", submitted_by="test", prefer_seed=True)
    assert QueuedJob.from_json(queued.to_json()) == queued


def test_gateway_api_key_auth_is_optional() -> None:
    verify_gateway_api_key(Settings(), None)


def test_gateway_api_key_auth_rejects_invalid_key() -> None:
    try:
        verify_gateway_api_key(Settings(gateway_api_key="expected"), "wrong")
    except HTTPException as exc:
        assert exc.status_code == 401
    else:
        raise AssertionError("invalid API key should raise HTTPException")


def test_gateway_api_key_auth_accepts_matching_key() -> None:
    verify_gateway_api_key(Settings(gateway_api_key="expected"), "expected")

from __future__ import annotations

from webforti_common.knowledge_store import InMemoryKnowledgeStore, KnowledgeStore, build_embedder, build_knowledge_store
from webforti_common.models import CVERecord
from webforti_common.seed_data import SEED_KNOWLEDGE
from webforti_common.settings import Settings


def build_seeded_memory_store(settings: Settings | None = None) -> InMemoryKnowledgeStore:
    store = InMemoryKnowledgeStore(embedder=build_embedder(settings)) if settings else InMemoryKnowledgeStore()
    for document in SEED_KNOWLEDGE:
        store.upsert_document(document)
    return store


def build_store(settings: Settings) -> KnowledgeStore:
    store = build_knowledge_store(settings)
    for document in SEED_KNOWLEDGE:
        store.upsert_document(document)
    return store


def retrieve_context(cve: CVERecord, store: KnowledgeStore, top_k: int = 5) -> list[dict]:
    query = f"{cve.cve_id} {cve.title} {cve.description}"
    return store.search(query, top_k=top_k)

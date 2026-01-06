from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Protocol

from webforti_common.settings import Settings


TOKEN_RE = re.compile(r"[a-zA-Z0-9_.:-]+")
CVE_ID_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
EMBEDDING_DIMENSIONS = 64
DEFAULT_SENTENCE_BERT_DIMENSIONS = 384


def tokenize(text: str) -> set[str]:
    return {token.lower() for token in TOKEN_RE.findall(text)}


def lexical_score(query: str, text: str) -> float:
    q = tokenize(query)
    t = tokenize(text)
    if not q or not t:
        return 0.0
    return len(q & t) / math.sqrt(len(q) * len(t))


def extract_cve_ids(text: str) -> list[str]:
    return sorted({match.group(0).upper() for match in CVE_ID_RE.finditer(text)})


def embed_text(text: str, dimensions: int = EMBEDDING_DIMENSIONS) -> list[float]:
    vector = [0.0] * dimensions
    for token in tokenize(text):
        digest = hashlib.sha256(token.encode("utf-8")).digest()
        index = int.from_bytes(digest[:4], "big") % dimensions
        sign = 1.0 if digest[4] % 2 == 0 else -1.0
        vector[index] += sign
    norm = math.sqrt(sum(value * value for value in vector))
    if norm == 0:
        return vector
    return [round(value / norm, 6) for value in vector]


class EmbeddingModel(Protocol):
    name: str
    dimensions: int

    def embed(self, text: str) -> list[float]:
        ...


@dataclass(frozen=True, slots=True)
class HashingEmbeddingModel:
    dimensions: int = EMBEDDING_DIMENSIONS
    name: str = "webforti-hashing-64"

    def embed(self, text: str) -> list[float]:
        return embed_text(text, self.dimensions)


@dataclass(frozen=True, slots=True)
class SentenceBertEmbeddingModel:
    model_name: str = "sentence-transformers/all-MiniLM-L6-v2"
    dimensions: int = DEFAULT_SENTENCE_BERT_DIMENSIONS

    @property
    def name(self) -> str:
        return self.model_name

    def embed(self, text: str) -> list[float]:
        model = _load_sentence_transformer(self.model_name)
        vector = model.encode(
            [text],
            normalize_embeddings=True,
            show_progress_bar=False,
        )[0]
        values = [round(float(value), 6) for value in vector]
        if len(values) != self.dimensions:
            raise ValueError(
                f"Sentence-BERT model '{self.model_name}' returned {len(values)} dimensions; "
                f"WEBFORTI_EMBEDDING_DIMENSIONS is {self.dimensions}"
            )
        return values


@lru_cache(maxsize=4)
def _load_sentence_transformer(model_name: str):
    try:
        from sentence_transformers import SentenceTransformer
    except ImportError as exc:
        raise RuntimeError(
            "sentence-transformers is required for WEBFORTI_EMBEDDING_PROVIDER=sentence_transformers"
        ) from exc
    return SentenceTransformer(model_name)


def build_embedder(settings: Settings) -> EmbeddingModel:
    provider = settings.embedding_provider.lower().replace("-", "_")
    if provider in {"sentence_transformers", "sbert"}:
        return SentenceBertEmbeddingModel(settings.embedding_model, settings.embedding_dimensions)
    return HashingEmbeddingModel(settings.embedding_dimensions, f"webforti-hashing-{settings.embedding_dimensions}")


class KnowledgeStore(Protocol):
    def upsert_document(self, document: dict) -> None:
        ...

    def search(self, query: str, top_k: int = 5) -> list[dict]:
        ...


@dataclass(slots=True)
class InMemoryKnowledgeStore:
    documents: list[dict] = field(default_factory=list)
    embedder: EmbeddingModel = field(default_factory=HashingEmbeddingModel)

    def upsert_document(self, document: dict) -> None:
        document = with_embedding(document, self.embedder)
        existing = next((item for item in self.documents if item.get("id") == document.get("id")), None)
        if existing:
            existing.update(document)
        else:
            self.documents.append(document)

    def search(self, query: str, top_k: int = 5) -> list[dict]:
        exact = self._exact_cve_matches(query)
        ranked = []
        for doc in self.documents:
            text = " ".join(str(doc.get(key, "")) for key in ["title", "text", "cve_id"])
            ranked.append((lexical_score(query, text), doc))
        ranked.sort(key=lambda item: item[0], reverse=True)
        lexical = [{**doc, "score": round(score, 4), "retrieval_mode": "lexical"} for score, doc in ranked if score > 0]
        return merge_ranked_results(exact, lexical, top_k=top_k)

    def _exact_cve_matches(self, query: str) -> list[dict]:
        cve_ids = set(extract_cve_ids(query))
        if not cve_ids:
            return []
        return [
            {**doc, "score": 1.0, "retrieval_mode": "cve_exact"}
            for doc in self.documents
            if str(doc.get("cve_id", "")).upper() in cve_ids
        ]


class MongoKnowledgeStore:
    def __init__(self, settings: Settings) -> None:
        try:
            from pymongo import MongoClient
        except ImportError as exc:
            raise RuntimeError("pymongo is required for MongoKnowledgeStore") from exc
        self.client = MongoClient(settings.mongo_uri)
        self.collection = self.client[settings.mongo_database]["knowledge_documents"]
        self.embedder = build_embedder(settings)
        self.vector_index = settings.mongo_vector_index

    def upsert_document(self, document: dict) -> None:
        document = with_embedding(document, self.embedder)
        self.collection.update_one({"id": document["id"]}, {"$set": document}, upsert=True)

    def search(self, query: str, top_k: int = 5) -> list[dict]:
        exact_results = self._exact_cve_matches(query)
        vector_results = self._vector_search(query, top_k=top_k)
        if vector_results:
            return merge_ranked_results(exact_results, vector_results, top_k=top_k)
        candidates = list(self.collection.find({}, {"_id": 0}).limit(500))
        ranked = []
        for doc in candidates:
            text = " ".join(str(doc.get(key, "")) for key in ["title", "text", "cve_id"])
            ranked.append((lexical_score(query, text), doc))
        ranked.sort(key=lambda item: item[0], reverse=True)
        lexical_results = [{**doc, "score": round(score, 4), "retrieval_mode": "lexical"} for score, doc in ranked if score > 0]
        return merge_ranked_results(exact_results, lexical_results, top_k=top_k)

    def _exact_cve_matches(self, query: str) -> list[dict]:
        cve_ids = extract_cve_ids(query)
        if not cve_ids:
            return []
        return [
            {**doc, "score": 1.0, "retrieval_mode": "cve_exact"}
            for doc in self.collection.find({"cve_id": {"$in": cve_ids}}, {"_id": 0})
        ]

    def _vector_search(self, query: str, top_k: int) -> list[dict]:
        query_vector = self.embedder.embed(query)
        try:
            results = list(
                self.collection.aggregate(
                    [
                        {
                            "$vectorSearch": {
                                "index": self.vector_index,
                                "path": "embedding",
                                "queryVector": query_vector,
                                "numCandidates": max(top_k * 10, 20),
                                "limit": top_k,
                                "filter": {"embedding_model": self.embedder.name},
                            }
                        },
                        {
                            "$project": {
                                "_id": 0,
                                "id": 1,
                                "title": 1,
                                "text": 1,
                                "source": 1,
                                "cve_id": 1,
                                "embedding_model": 1,
                                "score": {"$meta": "vectorSearchScore"},
                            }
                        },
                    ]
                )
            )
        except Exception:
            return []
        return [{**doc, "retrieval_mode": "vector"} for doc in results]


def with_embedding(document: dict, embedder: EmbeddingModel | None = None) -> dict:
    embedder = embedder or HashingEmbeddingModel()
    text = " ".join(str(document.get(key, "")) for key in ["title", "text", "cve_id"])
    return {
        **document,
        "embedding": embedder.embed(text),
        "embedding_model": embedder.name,
        "embedding_dimensions": embedder.dimensions,
    }


def merge_ranked_results(primary: list[dict], secondary: list[dict], *, top_k: int) -> list[dict]:
    merged: list[dict] = []
    seen: set[str] = set()
    for item in [*primary, *secondary]:
        key = str(item.get("id") or item.get("title") or item)
        if key in seen:
            continue
        seen.add(key)
        merged.append(item)
        if len(merged) >= top_k:
            break
    return merged


def build_knowledge_store(settings: Settings) -> KnowledgeStore:
    if settings.mongo_uri.startswith("memory://"):
        return InMemoryKnowledgeStore(embedder=build_embedder(settings))
    return MongoKnowledgeStore(settings)

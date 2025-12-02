# WebForti Backend Architecture

WebForti is implemented as a monorepo with independent microservice entry points:

- `services/gateway`: analyst-facing API gateway and job lifecycle endpoints.
- `services/data_collector`: CVE ingestion and normalization.
- `services/rag_service`: MongoDB-backed knowledge retrieval.
- `services/llm_core`: provider-neutral model planning.
- `services/agents`: controlled artifact generation.
- `services/orchestrator`: verification scoring and Docker sandbox execution.
- `services/worker`: Redis-backed asynchronous job worker.
- `frontend`: local React dashboard for job submission, polling, reports, and artifact inspection.
- `backend/shared/webforti_common`: shared contracts, validation, scoring, settings, and provider clients.

The demo implementation uses OpenRouter Qwen for model planning and keeps `WEBFORTI_MODEL_PROVIDER=mock` only as a deterministic test fallback. MongoDB Atlas, PostgreSQL, Redis, and Docker verification can be enabled independently through environment settings.

The gateway supports two orchestration modes:

- `WEBFORTI_PIPELINE_MODE=local`: direct in-process calls for fast tests and benchmarks.
- `WEBFORTI_PIPELINE_MODE=http`: service-to-service HTTP calls for a Docker Compose service run.

State and orchestration are also configurable:

- `WEBFORTI_PERSISTENCE_BACKEND=memory`: default in-memory state.
- `WEBFORTI_PERSISTENCE_BACKEND=postgres`: write completed job records to PostgreSQL.
- `WEBFORTI_QUEUE_BACKEND=inline`: default gateway background task execution.
- `WEBFORTI_QUEUE_BACKEND=redis`: enqueue work for the `worker` service.
- `WEBFORTI_CORS_ORIGINS`: comma-separated browser origins allowed to call the gateway; defaults to Vite dev origins.
- `WEBFORTI_API_KEY`: optional shared gateway key; when set, job/report/artifact routes require `X-WebForti-API-Key`.

PostgreSQL also includes `llm_experimentation`, an aggregate comparison table for model-level benchmark/demo metrics such as attempted jobs, pass/fail/deny counts, malformed JSON counts, rates, and average latency. It is loaded from `benchmarks/model_comparison_synthetic.json` by `scripts/load_llm_experimentation.py`.

## MongoDB Atlas Retrieval

RAG documents are stored in MongoDB in the `knowledge_documents` collection. The final demo path uses Sentence-BERT embeddings through `sentence-transformers/all-MiniLM-L6-v2` with 384-dimensional vectors, stored in MongoDB Atlas and queried with Atlas Vector Search. The deterministic hashing embedder remains available only as a lightweight test fallback.

Retrieval first includes exact `CVE-*` document matches when present, then fills the remaining context with Atlas Vector Search results filtered to the active embedding model. The index definition lives at `infrastructure/mongo/atlas_vector_index.json` and can be applied with:

```bash
PYTHONPATH=.:backend/shared python scripts/create_atlas_vector_index.py --wait
```

When the Atlas Vector Search index is unavailable, retrieval falls back to lexical scoring so local development and tests continue to work.

The curated web-CVE ingestion script lives at `scripts/ingest_curated_web_cves.py`. It validates user-curated CVE IDs against NVD before insertion, stores normalized source records in `cve_corpus`, and stores the embedded RAG documents in `knowledge_documents`. The broader expansion script, `scripts/expand_web_cve_corpus.py`, searches NVD keyword families for web-security CVEs and selects high-relevance records by CWE, severity, and recency. The current Atlas RAG corpus contains 430 CVE-tagged documents.

## Model Provider

Set `WEBFORTI_MODEL_PROVIDER=openrouter` to use Qwen through OpenRouter:

```bash
WEBFORTI_MODEL_PROVIDER=openrouter \
WEBFORTI_MODEL_NAME=qwen/qwen3.6-35b-a3b:nitro \
OPENAI_COMPATIBLE_URL=https://openrouter.ai/api/v1 \
OPENAI_API_KEY=... \
python benchmarks/run_benchmark.py
```

The code still has a mock provider for reproducible tests, but the final demo path should use OpenRouter.

## Verification Semantics

Verification separates:

- `exploit_executed`: the verification script ran.
- `exploit_succeeded`: the simulated exploit objective succeeded.
- `rule_alerted`: Snort detected the expected indicator.
- `blocked`: mitigation prevented the exploit objective.

A pass requires execution, detection, and either blocking or failure of the exploit objective. This avoids the report's original ambiguity where Snort detection mode was described as blocking.

## Docker Verification

`WEBFORTI_VERIFICATION_MODE=docker` provisions:

- a Kali Linux attacker container running the generated Python verification script,
- a Snort inline IPS bridge container,
- an Ubuntu-based target container built from the generated Docker spec,
- two internal Docker networks with no external egress: attacker-to-IPS and IPS-to-target.

Before execution, the orchestrator validates the generated rule with Snort 3 using `snort -T -R webforti.rules` and records the validation result in the verification evidence. It also generates a deterministic HTTP probe pcap and replays it through Snort 3 with the generated rule, producing `snort3_pcap_alerted` benchmark evidence.

During the live attacker run, the Kali container can reach only the Snort bridge. The bridge converts the live HTTP request into a packet capture, evaluates it with Snort 3 and the generated rule, and blocks the request before forwarding when Snort alerts. Benchmarks report this as `snort3_inline_alert_rate` and `snort3_inline_block_rate`. The bridge also records the actual request path and replays it through Snort 3 as a second pcap, reported as `snort3_live_request_alert_rate`.

This is now Snort-gated inline enforcement at the HTTP bridge layer, not the older content-term proxy decision. A lower-level AFPacket or NFQUEUE bridge would still be needed before claiming kernel packet-path IPS behavior.

For Apache-oriented CVEs such as `CVE-2021-41773`, the environment agent emits an Ubuntu-based Apache target image instead of the generic Ubuntu Python HTTP target.

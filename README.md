# WebForti

WebForti is an AI-powered web security platform that turns a CVE into a verified defense workflow. The system retrieves vulnerability context, plans mitigation with an OpenAI-compatible LLM, generates exploit and defense artifacts, and validates them in an isolated Docker + Snort environment before presenting the results in a dashboard.

## At a glance

- CVE-driven workflow from analyst submission to verified defense report
- RAG-backed planning with MongoDB Atlas Vector Search and Sentence-BERT embeddings
- Structured JSON generation plans instead of free-form model output
- Automated artifact generation for exploit scripts, Snort rules, and Docker target specs
- Closed-loop verification using Kali attacker, Snort inline IPS bridge, and Ubuntu target containers
- React dashboard for submission, job tracking, reports, artifacts, analytics, and model benchmarks

## Tech stack

- `Frontend`: React, TypeScript, Vite
- `Backend`: FastAPI, Python
- `LLM`: OpenRouter Qwen via OpenAI-compatible API
- `Retrieval`: MongoDB Atlas Vector Search, Sentence-BERT
- `Operational Data`: PostgreSQL, Redis
- `Verification`: Docker, Snort 3, Kali Linux, Ubuntu targets

## System architecture

![WebForti architecture](docs/images/webforti_architecture.png)

WebForti is organized as a microservice-style pipeline. The gateway receives CVE jobs, the retrieval layer assembles vulnerability context, the LLM core produces a schema-validated generation plan, the agents layer turns that plan into concrete artifacts, and the orchestrator verifies the artifacts inside an isolated Docker topology.

For a deeper backend breakdown, see [docs/backend_architecture.md](docs/backend_architecture.md).

## End-to-end workflow

1. An analyst submits a CVE from the dashboard or API.
2. The data collection layer normalizes CVE details from seed data or external sources.
3. The RAG service retrieves related CVE documents, rules, and security context from MongoDB Atlas.
4. The LLM core generates a structured defense plan using Qwen through an OpenAI-compatible interface.
5. The agents service converts that plan into an exploit verification script, a Snort rule, and a Docker target specification.
6. The orchestrator runs verification inside Docker using a Kali attacker, Snort inline bridge, and Ubuntu target.
7. Evidence, scores, and reports are stored and surfaced back to the dashboard.

## Core components

| Component | Responsibility |
| --- | --- |
| `services/gateway` | Analyst-facing API, job lifecycle, report endpoints |
| `services/data_collector` | CVE ingestion and normalization |
| `services/rag_service` | MongoDB-backed retrieval and context assembly |
| `services/llm_core` | Provider-neutral structured planning |
| `services/agents` | Artifact generation for exploit, Snort, and Docker outputs |
| `services/orchestrator` | Docker verification, scoring, evidence collection |
| `services/worker` | Redis-backed asynchronous execution |
| `frontend` | Dashboard for CVE submission, tracking, reports, analytics |
| `backend/shared/webforti_common` | Shared contracts, settings, validation, provider clients |

## Benchmark snapshot

### Final demo path: OpenRouter Qwen + MongoDB Atlas + Docker

Measured benchmark summary from `docs/benchmark_results.md`:

| Metric | Result |
| --- | ---: |
| Seeded benchmark CVEs | 8 |
| Completed jobs | 8 / 8 |
| Average response time | 22.06s |
| Total elapsed time | 176.46s |
| Snort rule syntactic correctness | 100% |
| Exploit script validation rate | 100% |
| Docker spec validation rate | 100% |
| Snort 3 syntax validation rate | 100% |
| Snort 3 deterministic PCAP alert rate | 100% |
| Snort 3 live request alert rate | 100% |
| Proxy / inline bridge alert-block rate | 100% |
| Purple-team verification pass rate | 100% |

### Corpus and benchmark visuals

<p align="center">
  <img src="benchmarks/dataset.png" alt="CWE dataset distribution" width="32%" />
  <img src="benchmarks/latency.png" alt="Latency benchmark" width="32%" />
  <img src="benchmarks/metrics_failvssucces.png" alt="Benchmark pass fail distribution" width="32%" />
</p>

- `dataset.png`: CWE frequency distribution for the curated vulnerability corpus
- `latency.png`: latency benchmark visual used in the project benchmarking/reporting flow
- `metrics_failvssucces.png`: benchmark outcome comparison visual used in the dashboard/report assets

Full benchmark notes and metric tables are in [docs/benchmark_results.md](docs/benchmark_results.md).

## Repository layout

```text
frontend/                  React dashboard
services/gateway/          FastAPI gateway and job lifecycle
services/data_collector/   CVE normalization and ingestion
services/rag_service/      Retrieval and context assembly
services/llm_core/         Structured model planning
services/agents/           Artifact generation
services/orchestrator/     Docker verification and scoring
services/worker/           Redis-backed async execution
backend/shared/            Shared models, settings, validation, provider clients
infrastructure/            Docker, Mongo, Postgres assets
benchmarks/                Benchmark scripts, fixtures, visual outputs
docs/                      Architecture and benchmark documentation
```

## Quick start: final demo app

These commands start the local final-demo path: PostgreSQL, Redis queue, FastAPI gateway, five workers, Docker verification, and the React dashboard. Keep OpenRouter and MongoDB Atlas secrets in `.env`; do not paste secrets into shell commands.

### 1. First-time setup

```bash
cd /path/to/WebForti
export WEBFORTI_ROOT="$PWD"

python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt

cd "$WEBFORTI_ROOT/frontend"
npm install
cd "$WEBFORTI_ROOT"

test -f .env || cp .env.example .env
```

Edit `.env` with your local settings:

```bash
WEBFORTI_MODEL_PROVIDER=openrouter
WEBFORTI_MODEL_NAME=qwen/qwen3.6-35b-a3b:nitro
OPENAI_COMPATIBLE_URL=https://openrouter.ai/api/v1
OPENAI_API_KEY=your-openrouter-key

MONGO_URI=your-mongodb-atlas-uri
MONGO_DATABASE=webforti

WEBFORTI_EMBEDDING_PROVIDER=sentence_transformers
WEBFORTI_EMBEDDING_MODEL=sentence-transformers/all-MiniLM-L6-v2
WEBFORTI_EMBEDDING_DIMENSIONS=384
```

### 2. Start infrastructure

```bash
docker compose up -d postgres redis
docker compose ps postgres redis
```

Optional but useful before a demo:

```bash
docker build -q -f infrastructure/docker/Dockerfile.sandbox-target -t webforti/sandbox-target:latest .
docker build -q -f infrastructure/docker/Dockerfile.sandbox-apache-ubuntu -t webforti/sandbox-apache-ubuntu:latest .
docker build -q -f infrastructure/docker/Dockerfile.snort-runtime-sensor -t webforti/snort-inline-ips:latest .
```

### 3. Load model benchmark table

```bash
set -a
source .env
set +a

PYTHONPATH=.:backend/shared \
POSTGRES_DSN=postgresql://webforti:webforti@localhost:5432/webforti \
.venv/bin/python scripts/load_llm_experimentation.py
```

### 4. Start backend gateway

```bash
tmux new-session -d -s webforti-gateway "cd \"$WEBFORTI_ROOT\" && set -a && source .env && set +a && PYTHONPATH=.:backend/shared WEBFORTI_QUEUE_BACKEND=redis WEBFORTI_PERSISTENCE_BACKEND=postgres WEBFORTI_VERIFICATION_MODE=docker POSTGRES_DSN=postgresql://webforti:webforti@localhost:5432/webforti REDIS_URL=redis://localhost:6379/0 .venv/bin/uvicorn services.gateway.main:app --host 127.0.0.1 --port 8000"
```

### 5. Start five workers

```bash
for i in 1 2 3 4 5; do
  tmux new-session -d -s "webforti-worker-$i" "cd \"$WEBFORTI_ROOT\" && set -a && source .env && set +a && PYTHONPATH=.:backend/shared WEBFORTI_QUEUE_BACKEND=redis WEBFORTI_PERSISTENCE_BACKEND=postgres WEBFORTI_VERIFICATION_MODE=docker POSTGRES_DSN=postgresql://webforti:webforti@localhost:5432/webforti REDIS_URL=redis://localhost:6379/0 .venv/bin/python -m services.worker.main"
done
```

### 6. Start frontend

```bash
tmux new-session -d -s webforti-ui "cd \"$WEBFORTI_ROOT/frontend\" && npm run dev -- --host 127.0.0.1 --port 5173"
```

Open the dashboard:

```text
http://127.0.0.1:5173/
```

### 7. Verify the app is up

```bash
curl -s http://127.0.0.1:8000/health
curl -I http://127.0.0.1:5173
tmux ls
```

Submit a sample CVE from the API:

```bash
curl -s -X POST http://127.0.0.1:8000/jobs \
  -H 'Content-Type: application/json' \
  -d '{"cve_id":"CVE-2021-41773","submitted_by":"dashboard","prefer_seed":true}' \
  | python3 -m json.tool
```

### 8. Stop everything

```bash
tmux kill-session -t webforti-gateway 2>/dev/null || true
tmux kill-session -t webforti-ui 2>/dev/null || true
for i in 1 2 3 4 5; do tmux kill-session -t "webforti-worker-$i" 2>/dev/null || true; done
docker compose stop postgres redis
```

## OpenRouter demo benchmark

```bash
PYTHONPATH=.:backend/shared \
WEBFORTI_MODEL_PROVIDER=openrouter \
WEBFORTI_MODEL_NAME=qwen/qwen3.6-35b-a3b:nitro \
OPENAI_COMPATIBLE_URL=https://openrouter.ai/api/v1 \
WEBFORTI_VERIFICATION_MODE=docker \
python3 benchmarks/run_benchmark.py
```

This runs the final demo path: OpenRouter Qwen planning, MongoDB Atlas RAG with Sentence-BERT embeddings, generated artifacts, Docker verification, and Snort evidence across 8 seeded CVEs.

Mock baseline for fast local testing:

```bash
PYTHONPATH=.:backend/shared \
WEBFORTI_MODEL_PROVIDER=mock \
WEBFORTI_VERIFICATION_MODE=mock \
python3 benchmarks/run_benchmark.py
```

Docker verification validates generated rules with Snort 3 before running the Kali attacker, Snort inline IPS bridge, and Ubuntu target topology. It records deterministic PCAP Snort alerts, live-request Snort replay alerts, and inline Snort block status. Apache-oriented CVEs use an Ubuntu-based Apache target image.

## Run services

```bash
cp .env.example .env
docker compose --env-file .env up --build
```

Gateway API: `http://localhost:8000`

```bash
curl -X POST http://localhost:8000/jobs \
  -H 'Content-Type: application/json' \
  -d '{"cve_id":"CVE-2021-41773","prefer_seed":true}'
```

## Dashboard

```bash
cd frontend
npm install
npm run dev -- --host 127.0.0.1 --port 5173
```

Dashboard URL: `http://127.0.0.1:5173`

The dashboard calls the gateway at `http://localhost:8000` by default. Override that with:

```bash
VITE_WEBFORTI_API_BASE=http://localhost:8000 npm run dev
```

Allowed browser origins are controlled by `WEBFORTI_CORS_ORIGINS`, defaulting to `http://localhost:5173,http://127.0.0.1:5173`.

Set `WEBFORTI_API_KEY` to require `X-WebForti-API-Key` on all job/report/artifact routes. For the local dashboard, provide the same value through `VITE_WEBFORTI_API_KEY` when starting Vite.

## MongoDB Atlas vector search

Create the Atlas Vector Search index for RAG retrieval:

```bash
PYTHONPATH=.:backend/shared python scripts/create_atlas_vector_index.py --wait
```

The script reads `MONGO_URI`, `MONGO_DATABASE`, and the embedding settings from `.env`, then creates or updates `knowledge_vector_index` on `knowledge_documents`.

Final report embedding settings:

```bash
WEBFORTI_EMBEDDING_PROVIDER=sentence_transformers
WEBFORTI_EMBEDDING_MODEL=sentence-transformers/all-MiniLM-L6-v2
WEBFORTI_EMBEDDING_DIMENSIONS=384
```

Ingest the curated web-CVE corpus into MongoDB Atlas:

```bash
PYTHONPATH=.:backend/shared python scripts/ingest_curated_web_cves.py
```

The ingestion script validates each curated CVE against NVD before insertion, stores normalized source records in `cve_corpus`, and stores the embedded RAG documents in `knowledge_documents`.

Expand the Atlas RAG corpus to roughly 430 CVE-tagged documents:

```bash
PYTHONPATH=.:backend/shared python scripts/expand_web_cve_corpus.py --target-total 430
```

The expansion script searches NVD keyword families for web-security CVEs, filters for web-relevant CWE IDs and product text, ranks candidates by severity and recency, then inserts the selected records into the same MongoDB collections.

Load LLM comparison metrics into PostgreSQL:

```bash
PYTHONPATH=.:backend/shared python scripts/load_llm_experimentation.py
```

This upserts `benchmarks/model_comparison_synthetic.json` into the `llm_experimentation` table. The table stores aggregate metrics only; narrative notes are intentionally omitted.

## Service ports

- Gateway: `8000`
- Data collector: `8001`
- RAG service: `8002`
- LLM core: `8003`
- Artifact agents: `8004`
- Verification orchestrator: `8005`

## Next implementation work

- Replace the current Snort-gated HTTP bridge with a lower-level AFPacket or NFQUEUE bridge if the final claim needs kernel packet-path IPS behavior instead of application-layer inline enforcement.

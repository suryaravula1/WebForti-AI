# WebForti

Monorepo implementation for the WebForti research prototype. The code keeps microservice boundaries while sharing contracts across services, and includes a local dashboard for submitting CVE verification jobs.

## Quick Start: Final Demo App

These commands start the local final-demo path: PostgreSQL, Redis queue, FastAPI gateway, five workers, Docker verification, and the React dashboard. Keep OpenRouter and MongoDB Atlas secrets in `.env`; do not paste secrets into shell commands.

### 1. First-Time Setup

```bash
cd /Users/sri/Desktop/silly_experiments/final

python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt

cd frontend
npm install
cd ..

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

### 2. Start Infrastructure

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

### 3. Load Model Benchmark Table

```bash
set -a
source .env
set +a

PYTHONPATH=.:backend/shared \
POSTGRES_DSN=postgresql://webforti:webforti@localhost:5432/webforti \
.venv/bin/python scripts/load_llm_experimentation.py
```

### 4. Start Backend Gateway

```bash
tmux new-session -d -s webforti-gateway 'cd /Users/sri/Desktop/silly_experiments/final && set -a && source .env && set +a && PYTHONPATH=.:backend/shared WEBFORTI_QUEUE_BACKEND=redis WEBFORTI_PERSISTENCE_BACKEND=postgres WEBFORTI_VERIFICATION_MODE=docker POSTGRES_DSN=postgresql://webforti:webforti@localhost:5432/webforti REDIS_URL=redis://localhost:6379/0 .venv/bin/uvicorn services.gateway.main:app --host 127.0.0.1 --port 8000'
```

### 5. Start Five Workers

```bash
for i in 1 2 3 4 5; do
  tmux new-session -d -s "webforti-worker-$i" "cd /Users/sri/Desktop/silly_experiments/final && set -a && source .env && set +a && PYTHONPATH=.:backend/shared WEBFORTI_QUEUE_BACKEND=redis WEBFORTI_PERSISTENCE_BACKEND=postgres WEBFORTI_VERIFICATION_MODE=docker POSTGRES_DSN=postgresql://webforti:webforti@localhost:5432/webforti REDIS_URL=redis://localhost:6379/0 .venv/bin/python -m services.worker.main"
done
```

### 6. Start Frontend

```bash
tmux new-session -d -s webforti-ui 'cd /Users/sri/Desktop/silly_experiments/final/frontend && npm run dev -- --host 127.0.0.1 --port 5173'
```

Open the dashboard:

```text
http://127.0.0.1:5173/
```

### 7. Verify The App Is Up

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

### 8. Stop Everything

```bash
tmux kill-session -t webforti-gateway 2>/dev/null || true
tmux kill-session -t webforti-ui 2>/dev/null || true
for i in 1 2 3 4 5; do tmux kill-session -t "webforti-worker-$i" 2>/dev/null || true; done
docker compose stop postgres redis
```

## OpenRouter Demo Benchmark

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

Latest recorded benchmark results are in `docs/benchmark_results.md`.

## Run Services

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

## MongoDB Atlas Vector Search

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

The ingestion script validates each curated CVE against NVD, enriches available records with CISA KEV and FIRST EPSS metadata when reachable, writes normalized records to `cve_corpus`, and writes RAG-ready Sentence-BERT documents to `knowledge_documents`.

Expand the Atlas RAG corpus to roughly 430 CVE-tagged documents:

```bash
PYTHONPATH=.:backend/shared python scripts/expand_web_cve_corpus.py --target-total 430
```

The expansion script searches NVD for web-security keyword families, filters for web-relevant CWE IDs and product text, ranks candidates by severity and recency, then inserts the selected records into the same MongoDB collections.

Load LLM comparison metrics into PostgreSQL:

```bash
PYTHONPATH=.:backend/shared python scripts/load_llm_experimentation.py
```

This upserts `benchmarks/model_comparison_synthetic.json` into the `llm_experimentation` table. The table stores aggregate metrics only; narrative notes are intentionally omitted.

## Service Ports

- Gateway: `8000`
- Data collector: `8001`
- RAG service: `8002`
- LLM core: `8003`
- Artifact agents: `8004`
- Verification orchestrator: `8005`

## Next Implementation Work

- Replace the current Snort-gated HTTP bridge with a lower-level AFPacket or NFQUEUE bridge if the final claim needs kernel packet-path IPS behavior instead of application-layer inline enforcement.

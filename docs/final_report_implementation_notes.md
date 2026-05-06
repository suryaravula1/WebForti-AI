# Final Report Implementation Notes

## Architecture Alignment

The implementation keeps the report's microservice architecture while placing all services in one repository:

| Report Component | Implemented Location | Current Status |
| --- | --- | --- |
| Data ingestion | `services/data_collector` | Seed CVEs plus NVD fallback |
| RAG service | `services/rag_service`, `webforti_common/knowledge_store.py` | MongoDB Atlas with exact-CVE boost plus Sentence-BERT vector retrieval |
| LLM reasoning core | `services/llm_core`, `webforti_common/model_client.py` | OpenRouter Qwen for demo; mock fallback for tests |
| Artifact generation | `services/agents` | Python verifier, Snort rule, Dockerfile |
| Isolated verification | `services/orchestrator` | Kali attacker, Snort inline bridge, Ubuntu target topology |
| Knowledge feedback | `infrastructure/mongo`, seed knowledge | Seeded knowledge in Atlas; feedback learning loop not yet automated |
| Dashboard/gateway | `services/gateway`, `frontend` | FastAPI gateway plus React dashboard |

## Corrections To Report Claims

The final implementation now supports the report's Sentence-BERT RAG claim:

- `WEBFORTI_EMBEDDING_PROVIDER=sentence_transformers`
- `WEBFORTI_EMBEDDING_MODEL=sentence-transformers/all-MiniLM-L6-v2`
- `WEBFORTI_EMBEDDING_DIMENSIONS=384`
- MongoDB Atlas Vector Search index: `knowledge_vector_index`

The older `webforti-hashing-64` embedder remains only as a deterministic test fallback.

The implementation now makes the Snort enforcement point explicit:

- Snort 3 validates the generated rule syntax.
- Snort 3 alerts on deterministic PCAP replay.
- Snort 3 alerts on a PCAP generated from the actual live request path observed during the attacker run.
- The live blocking decision is made by the Snort inline bridge after evaluating the live request with Snort 3.
- The attacker container is Kali Linux, the target is Ubuntu-based unless a CVE-specific vulnerable image is required, and the bridge is the only path between the two isolated Docker networks.

For the final report, describe this as "Snort-gated inline bridge enforcement." A lower-level AFPacket or NFQUEUE bridge would be needed before claiming kernel packet-path IPS behavior.

## Current Benchmark Claim

The expanded benchmark uses 8 web-facing CVEs:

- CVE-2021-41773
- CVE-2022-22965
- CVE-2021-42013
- CVE-2022-1388
- CVE-2023-29489
- CVE-2019-19781
- CVE-2021-44228
- CVE-2020-5902

With OpenRouter Qwen and Docker verification, all 8 jobs completed and passed. Detailed metrics are recorded in `docs/benchmark_results.md`.

## Remaining Research Limitation

The main remaining technical limitation is not model planning or artifact generation; it is the level of inline enforcement. The current result is suitable for a prototype claim that WebForti can generate artifacts and verify them with Snort-gated inline bridge enforcement in an isolated Docker workflow. A production-grade claim would require an AFPacket or NFQUEUE packet-path IPS implementation.

# WebForti Benchmark Results

## Synthetic Demo Model Comparison

Status: synthetic presentation scenario, not measured. These numbers are included only as a demo scaffold for explaining what a multi-model benchmark would report. Do not cite this table as empirical results until the same fixture set is run for each provider.

Fixture and topology:

- Fixture count: 20 web-facing CVEs
- Verification: Kali attacker -> Snort inline IPS bridge -> Ubuntu target
- Pass: generated schema-valid artifacts and passed Docker/Snort verification
- Fail: generated artifacts but failed validation or verification
- Deny: model refused or did not provide a usable generation plan
- Malformed JSON: response could not be parsed into the required generation-plan schema

| Model | Attempted | Pass Rate | Fail Rate | Deny Rate | Malformed JSON Rate | Synthetic Avg Time | Demo Interpretation |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| Qwen 3.6 35B A3B via OpenRouter | 20 | 70.0% | 25.0% | 0.0% | 5.0% | 25.1s | Low refusal rate with moderate artifact-verification misses |
| OpenAI GPT-5.4 | 20 | 80.0% | 5.0% | 15.0% | 0.0% | 18.9s | High schema quality and artifact accuracy, with higher refusal rate |
| Claude 4.6 | 20 | 75.0% | 5.0% | 20.0% | 0.0% | 20.7s | Strong reasoning when it responds, but highest synthetic refusal rate |
| Kimi K2 | 20 | 80.0% | 5.0% | 15.0% | 0.0% | 22.4s | Strong planning coverage, higher denial rate than local/open baselines |
| Local Llama 3.1 70B | 20 | 20.0% | 65.0% | 0.0% | 15.0% | 54.0s | Offline/privacy baseline, lower refusal but weaker schema reliability |
| Gemini 2.5 Pro | 20 | 80.0% | 5.0% | 15.0% | 0.0% | 19.8s | Strong structured output and high verification pass rate, with non-trivial refusal |
| DeepSeek R1/V3 | 20 | 60.0% | 25.0% | 0.0% | 15.0% | 28.6s | Low refusal, occasional malformed plan or weaker artifact specificity |

Structured synthetic data is stored in `benchmarks/model_comparison_synthetic.json`.

## 2026-05-09: Mock Planner + Kali/Snort Inline Bridge/Ubuntu Docker

Configuration:

- `WEBFORTI_MODEL_PROVIDER=mock`
- `WEBFORTI_VERIFICATION_MODE=docker`
- Benchmark fixture: 8 seeded web-facing CVEs
- Topology: Kali attacker -> Snort inline IPS bridge -> Ubuntu target

Summary:

| Metric | Result |
| --- | ---: |
| Total CVEs | 8 |
| Completed jobs | 8 |
| Average response time | 8.9510s |
| Total elapsed time | 71.6089s |
| Snort rule syntactic correctness | 1.0 |
| Exploit script validation rate | 1.0 |
| Docker spec validation rate | 1.0 |
| Snort 3 syntax validation rate | 1.0 |
| Snort 3 runtime alert rate | 1.0 |
| Snort 3 deterministic PCAP alert rate | 1.0 |
| Snort 3 live request alert rate | 1.0 |
| Snort 3 inline alert rate | 1.0 |
| Snort 3 inline block rate | 1.0 |
| Snort 3 passive interface alert rate | 0.0 |
| Proxy alert/block rate | 0.0 |
| Purple-team verification pass rate | 1.0 |

Interpretation:

The Docker verifier now uses two isolated Docker networks. The Kali attacker can reach only the Snort inline bridge, and the Ubuntu target is reachable only from that bridge. The bridge evaluates the live HTTP request with Snort 3 and blocks before forwarding when Snort alerts. This replaces the older content-term proxy blocking path.

## 2026-05-08: OpenRouter Qwen + MongoDB Atlas + Docker

Configuration:

- `WEBFORTI_MODEL_PROVIDER=openrouter`
- `WEBFORTI_MODEL_NAME=qwen/qwen3.6-35b-a3b:nitro`
- `WEBFORTI_VERIFICATION_MODE=docker`
- MongoDB Atlas Vector Search index `knowledge_vector_index` queryable
- Benchmark fixture: 8 seeded web-facing CVEs

Summary:

| Metric | Result |
| --- | ---: |
| Total CVEs | 8 |
| Completed jobs | 8 |
| Average response time | 22.0575s |
| Total elapsed time | 176.4609s |
| Snort rule syntactic correctness | 1.0 |
| Exploit script validation rate | 1.0 |
| Docker spec validation rate | 1.0 |
| Snort 3 syntax validation rate | 1.0 |
| Snort 3 runtime alert rate | 1.0 |
| Snort 3 deterministic PCAP alert rate | 1.0 |
| Snort 3 live request alert rate | 1.0 |
| Snort 3 passive interface alert rate | 0.0 |
| Proxy alert/block rate | 1.0 |
| Purple-team verification pass rate | 1.0 |

Per-CVE results:

| CVE | Status | Verification | Time | Snort syntax | PCAP alert | Live request alert | Interface alert | Proxy alert |
| --- | --- | --- | ---: | --- | --- | --- | --- | --- |
| CVE-2021-41773 | completed | pass | 21.0342s | true | true | true | false | true |
| CVE-2022-22965 | completed | pass | 26.2133s | true | true | true | false | true |
| CVE-2021-42013 | completed | pass | 18.5456s | true | true | true | false | true |
| CVE-2022-1388 | completed | pass | 21.9306s | true | true | true | false | true |
| CVE-2023-29489 | completed | pass | 18.1476s | true | true | true | false | true |
| CVE-2019-19781 | completed | pass | 29.5170s | true | true | true | false | true |
| CVE-2021-44228 | completed | pass | 23.3235s | true | true | true | false | true |
| CVE-2020-5902 | completed | pass | 17.7483s | true | true | true | false | true |

Interpretation:

The model/provider path, MongoDB-backed RAG, artifact generation, Snort syntax validation, Docker environment execution, Snort PCAP replay, live-request Snort replay, and Snort-gated inline bridge blocking path are implemented end to end.

The current inline path is an application-layer bridge that uses Snort 3 as the enforcement decision engine. A lower-level AFPacket or NFQUEUE implementation would be needed for kernel packet-path IPS claims.

Post-benchmark RAG update: the MongoDB Atlas retrieval layer now supports `WEBFORTI_EMBEDDING_PROVIDER=sentence_transformers` with `sentence-transformers/all-MiniLM-L6-v2` and 384-dimensional Atlas Vector Search. Re-run the benchmark after Docker is available to record refreshed final numbers with Sentence-BERT enabled.

## 2026-05-08: Mock Planner + Docker Baseline

Configuration:

- `WEBFORTI_MODEL_PROVIDER=mock`
- `WEBFORTI_VERIFICATION_MODE=docker`
- Benchmark fixture: 8 seeded web-facing CVEs

Summary:

| Metric | Result |
| --- | ---: |
| Total CVEs | 8 |
| Completed jobs | 8 |
| Average response time | 5.7756s |
| Total elapsed time | 46.2056s |
| Snort 3 syntax validation rate | 1.0 |
| Snort 3 deterministic PCAP alert rate | 1.0 |
| Snort 3 live request alert rate | 1.0 |
| Snort 3 passive interface alert rate | 0.0 |
| Proxy alert/block rate | 1.0 |
| Purple-team verification pass rate | 1.0 |

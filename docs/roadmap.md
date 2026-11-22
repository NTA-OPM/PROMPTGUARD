# Roadmap status (vs spec §15)

| Milestone | Status |
|---|---|
| M0 Research & design | ✅ `validation-report.md`, ADRs, threat model |
| M1 Core contracts | ✅ |
| M2 Rule engine, structural, normalization | ✅ (English) |
| M3 Policy | ✅ (hash checksum; cryptographic signing pending) |
| M4 SDK & CLI | ✅ |
| M5 API & deployment | ✅ code + tests; ⚠ Docker image unbuilt in sandbox |
| M6 Evaluation | ✅ harness, leakage, reports; baseline corpus is small |
| M7 Model adapter | 🟡 adapter + tests with a fake model; **no real model benchmarked** |
| M8 Beta release | 🟡 needs: external review, CI run on GitHub, name decision, real-model + external dataset results |
| M9 Integrations | 🟡 FastAPI + RAG helpers; LangChain/LlamaIndex/MCP pending |
| M10 Dashboard | ⬜ (explicitly Phase 2) |
| M11 Research release | ⬜ multilingual, multimodal extraction, drift/robustness studies |

## Highest-value next steps
1. Held-out evaluation on external datasets (verify licences) and a larger, multi-author corpus.
2. Benchmark one local classifier (e.g. Prompt Guard 2 after accepting its licence) and report the
   rules+model combination honestly, including latency.
3. Multilingual rule packs reviewed by native speakers; report per-language recall.
4. Policy signing; process-level isolation for model inference.
5. Adversarial/bypass regression suite with transformations (spec §5.1 "detector bypass testing").

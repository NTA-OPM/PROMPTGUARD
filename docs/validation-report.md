# Validation report: requirements spec v1.0 → implementation v0.1

This documents what was checked in the specification, what was verified externally, what the
implementation does about each finding, and what is still open. Dated 2026-11-22.

## 1. External claims verified (web research this session)

| Spec claim / assumption | Finding | Consequence |
|---|---|---|
| Name "PromptGuard" is provisional; check conflicts (§24, §25) | **Confirmed conflict.** PyPI already has `promptguard` (a client for a different service), plus `promptguard-ai`, `promptguard-ml`, `promptguard-mcp-server`, and `llm-pg` which *imports* as `promptguard`. | Distribution is named **`promptguard-oss`**; import name stays `promptguard` (spec §16) but may collide with `llm-pg`/`promptguard` if installed in the same environment. **Decision needed from the owner before release:** rename the import package, or accept the collision. Trademark search not performed. |
| Meta Prompt Guard is a baseline/adapter, not the architecture (§24) | Prompt Guard 2 ships in 86M and 22M sizes (22M is DeBERTa-xsmall based, English-focused; 86M includes non-English training). Weights are **gated** on Hugging Face under the **Llama 4 Community License**; v1 (86M) is under the Llama 3.1 community licence. | The classifier adapter never downloads or bundles weights (`allow_download=False`, offline by default). The user must accept the licence themselves. Not packaged as an MIT dependency. |
| deepset prompt-injections dataset: "verify licence" (§10.3) | HF metadata lists **Apache-2.0** (licence added after initial upload; the card itself has no licence text). | Safe to use as an *external* benchmark by reference, but **not vendored** in this repo; contributors must record provenance in a manifest. Re-verify the LICENSE file before any redistribution. |
| PINT benchmark: "use methodology, respect terms" (§10.3) | Repo is public (MIT per a third-party index); README says inputs come from public datasets and public documents. I could **not** verify whether the compiled dataset is distributed or only the harness. | Treated as methodology reference only. No PINT data used. Open item: confirm terms directly. |
| BIPIA, NotInject, XSTest, Gandalf datasets | **Not verified** (not researched in this pass). | Listed as future work; no data from them is used. |
| OWASP LLM01:2025, Microsoft/MSRC layered-defence guidance, NIST AI RMF | Cited as framing only; I did not re-read each page this session. | Mitigation guidance is reflected in `docs/integration-guides.md` and `docs/limitations.md`. Re-verify citations before publishing. |

## 2. Spec internal issues and how they were resolved

1. **Detector interface** (§6.4 `Detector.run(input_envelope)`). Detectors need derived views
   (normalized text, decoded payloads) with offset maps, so `run` receives a `ScanContext`
   (envelope + original + views). Same intent, richer argument.
2. **"Policies signed/validated"** (§5.4). Implemented as schema validation, structural
   safety checks (monotonic thresholds, critical may not map below *review*, required profiles)
   and an optional canonical-hash `checksum`. **Cryptographic signing is not implemented**
   (needs a key-management decision) → roadmap.
3. **Risk "Critical = high-confidence + sensitive context"** (§8.3) was under-specified.
   Implemented explicitly in `core/aggregation.py` and documented in `detection-and-scoring.md`.
4. **ERROR/INDETERMINATE as an action** (§5.4) conflicts with "fail-open or fail-closed
   according to policy". Implemented as `decision.action` = the *resolved* action plus an
   `indeterminate: true` flag and `DETECTOR_ERROR:*` reason codes.
5. **"Context reduces false positives"** (research question 1, §10.7). Measured on the
   baseline corpus: labels **improved recall but did not reduce FPR** (see
   `docs/benchmark-methodology.md`). The spec's framing is a hypothesis, not a result.
6. **Acceptance criterion numbering** in §14.3 starts at 11 (document artefact); treated as 1–13.
7. **Python 3.12+** is the floor; development used 3.13.
8. **Benign security discussion** must be a negative class (§5.2) but must not become an
   attacker-controlled bypass. Implemented as an *informational marker that never suppresses
   findings*; only quoted/code context may downgrade severity by one level, and only in the
   `user-input` profile, and never to "allow".

## 3. MVP acceptance criteria (§14.3) status

| # | Criterion | Status | Evidence |
|---|---|---|---|
| 1 | Install in clean env and scan from SDK | ✅ | clean-venv install + scan verified; `tests/` |
| 2 | CLI stdin/files/JSON + documented exit codes | ✅ | `tests/integration/test_cli.py`; `docs/cli.md` |
| 3 | Findings: category, detector, evidence, explanation, version | ✅ | `core/schema.py`, `test_engine.py` |
| 4 | Policy returns allow/monitor/review/sanitize/block | ✅ | `policy/engine.py`, `test_policy.py` |
| 5 | Profiles and fail mode validated and versioned | ✅ | policy tests, hash/checksum |
| 6 | Core works without network | ✅ | `no_network` fixture test (socket connect patched to fail) |
| 7 | Raw prompt logging off by default | ✅ | `test_logs_are_content_free`, API tests assert no echo |
| 8 | API rejects oversize with structured error | ✅ | 413 for Content-Length, chunked and per-field limits |
| 9 | Evaluation: precision/recall/FPR/FNR/F1 + per-category | ✅ | `evaluation/`, benchmark cards |
| 10 | Reproducible with pinned config + dataset version | ✅ | dataset sha256 verification, deterministic `run_id`, test |
| 11 | CI: tests, lint, types, dependency scanning | ✅ written, ⚠ not executed on GitHub yet | `.github/workflows/ci.yml` ran locally except `pip-audit` |
| 12 | Docs state limitations / layered defence | ✅ | `docs/limitations.md`, README |
| 13 | Docker service starts from documented steps | ⚠ **not verified**: no Docker daemon in the build sandbox. The same `uvicorn --factory` command was verified in a clean venv. |

## 4. Open items for the owner

- Choose the final project/package name after a trademark and namespace search.
- Decide MIT vs Apache-2.0 (repo currently MIT; Apache-2.0 adds an explicit patent grant).
- Confirm Docker build and the CI workflow on GitHub (neither could be executed here).
- Review and approve any third-party datasets before ingestion (licence + provenance manifest).
- Add multilingual rule packs and community-reviewed data before claiming any non-English support.

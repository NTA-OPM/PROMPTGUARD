# Dataset card: promptguard-baseline v0.1.0

| | |
|---|---|
| Files | `examples.jsonl` (sha256 pinned in `manifest.json`), generator `build_corpus.py` |
| Size | 173 examples: dev 47 attack / 33 benign; test (locked) 61 attack / 32 benign |
| Licence | MIT (repository licence). All text written by the project; no scraping, no third-party text |
| Collected | 2026-11-22 |
| Intended use | Regression testing and honest baseline measurement of rule-based detection |
| Not intended for | Training production models, leaderboard claims, estimating real-world prevalence |

## Composition
Attacks over all 10 risk categories (instruction override, impersonation, disclosure, tool/action,
exfiltration, trust-boundary, jailbreak framing, obfuscation, context injection, multi-step coercion),
with source types user/retrieved/tool/document/agent-plan. Obfuscations (zero-width, homoglyph, fullwidth,
dotted/spaced letters, leetspeak, base64, Unicode tags) are generated programmatically from base phrases.
Benign: ordinary prompts, ordinary documents/tool output, *benign security discussion*, *benign trigger
words* ("ignore the typo", "send the report to…"), code and shell snippets, non-English ordinary text.
Six non-English attacks (es, fr, de, pt, hi, ne) exist to *measure the absence* of support.

## Splits and governance
Split by **family** (attack template/topic). Leakage check (family, exact, near-duplicate) must report 0
cross-split issues (enforced by `tests/unit/test_evaluation.py`). `test` is locked: rules were frozen before it
was evaluated; one later engine fix is recorded in `docs/benchmark-methodology.md` as post-hoc.
Fields: `id, text, label, category, source_type, language, family, split, content_type, notes`.

## Limitations and biases
Small; single author for both rules and data (optimistic); phrasing reflects publicly known attack styles;
adaptive attackers, long documents, real traffic and most languages are not represented; the benign set is not
a sample of production traffic. Attack strings are generic and non-operational. Report issues or contribute
data via the *dataset proposal* issue template (licence + provenance required).

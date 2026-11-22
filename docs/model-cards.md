# Model cards

## Built-in "model": rule pack `promptguard-default` v0.1.0
Not a learned model. 47 regular-expression rules plus structural/Unicode heuristics. English only.
Intended use: transparent signals for review/monitoring. Not for: sole defence, other languages.
Measured (locked test, n = 93): recall 67.2% [55–78], FPR 6.2% [2–20]. See `benchmark-methodology.md`.

## Optional classifier adapter (no model is bundled or benchmarked)
`ClassifierDetector` wraps any adapter implementing `classify(texts) -> [ClassifierOutput]` and exposing a
`ModelCard` (model id, version, licence, languages, max tokens, confidence semantics). `HFTextClassifierAdapter`
loads a local Hugging Face sequence classifier with `local_files_only=True` by default.

Before using a third-party guard model:
1. Read and accept its licence yourself (e.g. Meta's Llama Prompt Guard 2 is gated under the Llama 4 Community
   License; it is **not** MIT-licensed).
2. Set `label_category` to the model's label names (defaults handle `INJECTION`/`JAILBREAK`/`LABEL_1`;
   verify against the model card).
3. Benchmark it with `promptguard evaluate` on your own data; scores are treated as **uncalibrated**.
4. Remember context-window limits: input is chunked (default 1500 chars, 150 overlap, ≤ 32 chunks).

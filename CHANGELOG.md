# Changelog

## 0.1.0-dev (unreleased)
- Core: envelope/finding/decision schemas, representation views with offset maps, rule/structural/Unicode
  detectors, transparent aggregation, policy engine with validation, hashing and explicit failure modes.
- SDK, CLI (documented exit codes), FastAPI service with size/rate/auth guardrails, FastAPI dependency,
  RAG chunk gate, content-free logging and metrics.
- Evaluation: manifests with sha256 verification, leakage detection, metrics with Wilson intervals,
  reproducible runs, Markdown/HTML benchmark cards. Baseline corpus v0.1.0 (original, synthetic).
- Optional classifier adapter (offline by default; no weights bundled).
- Post-hoc (after locked-test run 1): relaxed view now deletes separators in dotted single-letter runs.

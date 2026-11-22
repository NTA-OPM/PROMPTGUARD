# Contributing

Thanks for helping make prompt-injection risk more testable and honest.

## Setup
```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
ruff check src tests datasets && ruff format --check src tests datasets
mypy && pytest --cov=promptguard
promptguard evaluate --dataset datasets/baseline --split dev --min-recall 0.9 --max-fpr 0.1
```

## Principles
- **Honest claims.** Never write "prevents" or "secures". Report measured numbers with intervals and failures.
- **Detection ≠ policy.** Detectors return evidence; policies decide.
- **Privacy.** Never log raw content. Tests assert this.
- **Don't tune on the locked test split.** If you changed behaviour after seeing it, say so.
- **Safety.** No operational harmful payloads in tests or datasets; generic injection phrasing only.

## Good first contributions
Rules with benign near-miss tests · non-English rule packs reviewed by native speakers · datasets with clear
licence/provenance (use the dataset-proposal template) · integration adapters (LangChain, LlamaIndex, MCP) ·
bypass transformations for the regression suite.

## Pull requests
Small and focused; tests + docs; update `CHANGELOG.md`; describe false-positive risk for new rules;
security-sensitive changes (parsers, API, policy loading) get extra review. By contributing you agree your
work is licensed under the repository's MIT licence.

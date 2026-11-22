# Architecture

```
InputEnvelope (text, source_type, trust, profile, language, source_id, content_type)
   │  size / type validation (hard limit → reject; scan limit → truncate + report)
   ▼
Representations (original is never modified; every view maps back to original offsets)
   normalized · invis_space · relaxed · leet · tags · b64:* · pct:* · html
   ▼
Detectors (independent; return findings, never decisions)
   rules (YAML pack) · structural · unicode · discussion-marker · [optional classifier]
   ▼
Context enrichment (quoted/code spans, hidden HTML spans → finding.metadata)
   ▼
Aggregation (transparent ordinal level + ranking score; NOT a probability)
   ▼
Policy (profile thresholds · category overrides · failure mode · truncation)
   ▼
ScanResult { findings, risk, decision, coverage, errors, limitations, versions }
   ▼
Application enforces (allow / monitor / sanitize / review / block) + its own authorization
```

## Packages (`src/promptguard/`)
| Package | Role |
|---|---|
| `core/schema.py` | Pydantic contracts: `InputEnvelope`, `Finding`, `ScanResult`, `PolicyDecision`… |
| `core/engine.py` | `Scanner` (sync/async/batch), failure isolation, hooks |
| `core/aggregation.py` | Effective severity, corroboration, critical rule, ranking score |
| `normalization/` | Views, offset maps, decoding, HTML view, sanitisation |
| `detectors/` | `Detector` ABC + registry; rule/structural/unicode/discussion detectors |
| `policy/` | Policy schema, validation, hashing, evaluation |
| `models/` | Optional classifier adapter (lazy, offline by default) |
| `evaluation/` | Datasets, leakage, metrics, runner, reports |
| `api/` | FastAPI service + ASGI guardrail middleware |
| `cli/` | Typer CLI |
| `sdk/` | `gate_chunks`, `wrap_untrusted`, FastAPI dependency |
| `telemetry/` | Content-free logs, HMAC correlation, Prometheus-text metrics |

## Key design decisions
See `docs/adr/`. In short: detection ≠ policy; findings carry evidence not verdicts; original
text preserved; stateless core; optional model; explicit failure modes; no dynamic code loading.

## Concurrency
`Scanner` is read-only after construction and safe to share across threads. `ascan` offloads to
a thread (`asyncio.to_thread`). The classifier adapter serialises calls through a single worker.

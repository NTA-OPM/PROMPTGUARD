# REST API

Run: `uvicorn promptguard.api.app:app_factory --factory` (needs `pip install 'promptguard-oss[api]'`).
OpenAPI at `/openapi.json`; `/docs` UI only if `PROMPTGUARD_ENABLE_DOCS=true` (the UI loads assets
from a CDN, so it is off by default).

| Endpoint | Purpose |
|---|---|
| `POST /api/v1/scan` | Scan one input envelope (`detail`: `standard` \| `analyst`) |
| `POST /api/v1/scan/batch` | Bounded batch |
| `POST /api/v1/policy/evaluate` | Re-evaluate caller-supplied findings under a profile (flags that change severity are recomputed, not trusted) |
| `GET /api/v1/detectors`, `/api/v1/policies` | Registry and profiles |
| `POST /api/v1/evaluate` | Benchmark an approved dataset (analyst key; dataset dir must be configured; no dataset text returned) |
| `GET /health`, `/ready`, `/metrics` | Liveness, readiness (+ auth mode), Prometheus text |

## Errors
`{"error": {"code": "...", "message": "...", "request_id": "...", "details": [...]}}` with codes
`invalid_request` (422), `unauthorized` (401), `forbidden` (403), `not_found` (404),
`payload_too_large` (413), `rate_limited` (429 + `Retry-After`), `internal_error` (500).
Validation errors never echo the offending input. `X-Request-ID` is accepted if it matches
`[A-Za-z0-9._-]{1,64}`, otherwise generated.

## Configuration (environment)
`PROMPTGUARD_API_KEYS`, `PROMPTGUARD_ANALYST_KEYS` (comma-separated; none = open development mode,
shown by `/ready`), `PROMPTGUARD_MAX_BODY_BYTES` (1 MB), `PROMPTGUARD_MAX_TEXT_CHARS` (200k),
`PROMPTGUARD_MAX_BATCH_ITEMS` (100), `PROMPTGUARD_RATE_LIMIT_PER_MINUTE` (120, 0 = off),
`PROMPTGUARD_POLICY`, `PROMPTGUARD_DATASET_DIR`, `PROMPTGUARD_CORS_ORIGINS` (default none),
`PROMPTGUARD_METRICS`, `PROMPTGUARD_ENABLE_DOCS`, `PROMPTGUARD_LOG_SALT`.

## Deployment notes
Terminate TLS in front (reverse proxy). The rate limiter is in-process (per replica); use a gateway
for global limits. Keys are compared in constant time but are bearer secrets: rotate them, and
prefer OIDC at the gateway for production. Request/response bodies are never logged by the app;
keep proxy access logs free of bodies as well.

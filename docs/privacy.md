# Privacy and data handling

- **Stateless core.** `Scanner.scan` keeps nothing; no database, files or caches of input.
- **Offline.** No network calls in the core scanner (enforced by a test that makes sockets fail).
  The optional model adapter loads local files only unless `allow_download=True`.
- **No raw content in logs, metrics or errors.** `logging_hook` emits category, severity, action,
  reason codes, timings, versions and an HMAC correlation id. The HMAC salt is random per process
  unless `PROMPTGUARD_LOG_SALT` is set (set it only if you need cross-process correlation; anyone
  with the salt can confirm guesses of short inputs).
- **Results contain evidence.** `ScanResult` includes short snippets of the scanned text for the
  *caller*. The API's default `standard` detail removes snippets, rule ids and explanations.
- **No telemetry.** Nothing is sent anywhere. There is no opt-in telemetry in v0.1.
- **Retention.** None implemented (nothing is retained). If you add retention, encrypt it, set a
  TTL and document it for your users.
- **Datasets.** Benchmark data may contain attack text; do not add personal or confidential content.

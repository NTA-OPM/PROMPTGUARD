# Threat model

## Assets
Application instructions and secrets in context; user data; downstream tool authority;
integrity of the scan verdict; availability of the scanner; privacy of scanned text.

## Actors
Malicious users; attacker-authored third-party content (web, email, documents, tool output,
OCR); compromised connectors; misconfiguring developers/operators; adaptive attackers probing
thresholds and detector behaviour.

## In scope (detect / explain / recommend)
Direct and indirect injection, jailbreak framing, instruction-hierarchy and authority claims,
prompt disclosure, exfiltration steering (incl. markdown-image channels), tool/action
manipulation, obfuscation, hidden HTML content, context poisoning. Each maps to a `Category`
(`detection-and-scoring.md`).

## Out of scope
Guaranteeing prevention; sandboxing; authorisation; DLP; malware scanning; attribution;
automatic remediation; generating attack payloads.

## Attacks *against PromptGuard itself* and mitigations

| # | Attack | Mitigation (where) |
|---|---|---|
| 1 | Scanned text tries to instruct the scanner | Scanner is deterministic code, never an LLM; text is inert data. No eval/exec/URL fetch anywhere in `src/`. |
| 2 | ReDoS via crafted input | Bounded quantifiers in all rules; timing tests on 10 adversarial payloads (`test_rules_safety.py`); input cap `max_chars`. |
| 3 | Decompression/decoding bombs | Decode depth ≤ 2, ≤16 candidates, ≤200 kB decoded budget, decoded text analysed only. |
| 4 | Resource exhaustion via API | Body cap (also chunked), text/batch caps, token-bucket rate limit, thread offload. |
| 5 | Malicious rule/policy/plugin upload | No dynamic loading from requests. Rule packs/policies load only from files with strict schemas (`extra=forbid`); no code fields. |
| 6 | Policy weakening by insiders | Policy validator rejects non-monotonic thresholds and `critical → allow`; canonical hash/checksum detects tampering. |
| 7 | Log/telemetry leakage | No content in logs; HMAC correlation; metrics have no content; errors never echo input (tested). |
| 8 | HTML/XSS in reports | Reports escape all dataset text, ship a CSP, contain no script (tested). |
| 9 | Detector probing by adaptive attacker | API `standard` detail hides rule ids, explanations, snippets; rate limiting; analyst detail needs an analyst key. This raises cost; it does not stop a patient attacker. |
| 10 | Dataset tampering / leakage | Manifest sha256 verification; path-traversal rejection; family/near-duplicate leakage checks. |
| 11 | Bypass via "benign discussion" framing | The discussion marker never suppresses findings; only quoted/code context downgrades one level and never to allow. |
| 12 | Findings consumed by other systems | Findings are untrusted data; `/policy/evaluate` recomputes severity-altering flags instead of trusting caller metadata (tested). |
| 13 | Model adapter risks | Optional, offline by default, timeout, thread-isolated, graceful degradation; weights never bundled. In-process only: stronger isolation (separate process/sandbox) is roadmap. |

## Residual risks
Evasion by paraphrase/translation; novel obfuscation; in-process model adapters; no
cryptographic policy signing; in-memory rate limiter is per process.

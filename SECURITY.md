# Security policy

PromptGuard is a security tool; reports are welcome and handled seriously.

## Reporting a vulnerability
Use GitHub **private vulnerability reporting** (Security → Report a vulnerability) on this repository.
Please do not open public issues for exploitable bugs. Include affected version/commit, impact, and a
minimal reproduction. Do not include real user data.

Targets (best effort for a volunteer project): acknowledgement within 5 business days, triage within 10,
fix or mitigation plan for confirmed high/critical issues within 30 days, coordinated disclosure with credit
if you wish.

## In scope
Scanner crashes/hangs/ReDoS on crafted input; memory or CPU exhaustion; API auth/rate-limit/size-limit
bypass; information disclosure (raw input in logs/errors); path traversal in dataset/rule/policy loading;
XSS in generated reports; unsafe deserialisation; supply-chain issues in released artefacts.

## Not a vulnerability
A prompt that evades detection. Evasion is expected (see `docs/limitations.md`); please report bypasses as
a *benchmark report* issue (or privately if you prefer) with the transformation class, so they can become
regression tests. Do not submit operational harmful payloads.

## Supported versions
Pre-release (0.x): only the latest commit/tag receives fixes.

## Hardening checklist for operators
Run behind TLS; set API keys; keep the container read-only/non-root (see `docker-compose.yml`); keep proxy
logs body-free; pin dependencies via `deployment/constraints-api.txt`; verify `pip-audit` in CI.

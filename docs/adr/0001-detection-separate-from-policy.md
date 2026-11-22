# ADR 0001: Detectors return findings; policy decides

**Status:** accepted. Detectors emit evidence with category/severity/confidence. A separate policy maps
aggregated risk + context to a *recommendation*. Reason: the same signal deserves different handling in
a chat box vs. a tool-output pipeline; mixing them hides trade-offs and prevents per-profile tuning.
Consequence: every decision is traceable (`reason_codes`, `finding_ids`) and policies can be validated
and versioned independently of detector code.

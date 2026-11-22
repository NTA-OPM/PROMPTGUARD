# Detection taxonomy and scoring

## Categories (`core/schema.Category`)
`instruction_override`, `system_impersonation`, `prompt_disclosure`,
`tool_invocation_manipulation`, `data_exfiltration`, `trust_boundary_manipulation`,
`jailbreak_framing`, `obfuscation_evasion`, `context_injection`, `multi_step_coercion`,
`benign_security_discussion` (informational, never raises risk), `ambiguous_low_confidence`
(classifier uncertainty).

## Findings
`finding_id` (deterministic) · `detector_id/version` · `category` · `severity` · `confidence`
(author-assigned weight or raw model score; **uncalibrated**) · `rule_id` · `evidence[]`
(original-text span, escaped snippet, normalized snippet, view) · `explanation` ·
`normalization_notes` · `metadata` · `timestamp`.

Spans are Unicode code-point offsets into the **original** text. Decoded views (base64/percent/
tag-smuggled) map to the span of the encoded region.

## Third-party severity
Rules may declare `severity_third_party`. It applies when `source_type` is retrieved content,
tool output, third-party document, OCR/transcript, agent plan or unknown, because the same words
are far more suspicious inside data the user did not author.

## Aggregation (`core/aggregation.py`)
1. **Effective severity** = base; +1 (cap *high*) when the evidence is in visually hidden HTML;
   −1 when inside quoted/code content **and** the profile enables `quoted_downgrade`
   (user-input only by default; applies only to medium/high; never to obfuscation findings).
2. **Level** = max effective severity among risk-bearing findings.
3. **Corroboration:** ≥ 2 distinct categories at ≥ medium raise the level by one (cap *high*).
4. **Critical:** a *high* action-intent finding (exfiltration / tool manipulation) together with
   another *high* hierarchy finding, or in a profile with `critical_on_action_intent`.
5. **Ranking score** (`risk.score`, 0–1): noisy-OR over per-category maxima of
   `severity_weight × confidence` with weights 0.02/0.10/0.35/0.70/1.00. Used for ROC/PR curves
   only; **not a probability**.

## Risk level → default recommendation
See `policies` (`policy-guide.md`). Defaults are conservative starting points; tune per app.

## Normalization notes
NFKC is applied per code point (so offsets stay exact) and therefore does not compose
multi-character sequences. Homoglyph folding happens only inside tokens that already contain
ASCII letters, so genuine Cyrillic/Greek prose is untouched. The normalization pipeline is
versioned (`NORMALIZATION_VERSION`).

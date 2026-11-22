# Writing detectors and rules

## Rules (YAML)
Add to `src/promptguard/data/rules/default.yaml` (or a custom pack passed to `RuleDetector`).
Required: `id` (`PG-XX-NNN`), `category`, `severity`, `confidence`, `explanation`, `pattern`.
Optional: `severity_third_party`, `flags`. Use `pattern: |-` block scalars so backslashes stay literal
and **quote explanations** that contain `:`.

Checklist for a PR:
1. Bounded quantifiers only (no nested unbounded groups); `tests/unit/test_rules_safety.py` must pass.
2. At least 2 positive and 2 *benign-near-miss* examples added to `datasets/` (dev split) and a unit test.
3. State the false-positive risk in `explanation`; prefer lower severity + corroboration over broad rules.
4. Do **not** tune on the locked `test` split. If you must, say so in the PR.
5. Run `promptguard evaluate --dataset datasets/baseline --split dev --min-recall 0.9 --max-fpr 0.1`.

## Python detectors
```python
class MyDetector(Detector):
    id = "my-detector"; version = "0.1.0"; categories = (Category.JAILBREAK_FRAMING,)
    required = False            # optional layers must never make a scan indeterminate
    def run(self, ctx: ScanContext) -> list[Finding]:
        return [self.make(ctx, category=..., severity=..., explanation=..., spans=[(s, e)], confidence=0.5)]
```
Rules for detectors: pure function of the context; no network, files, subprocesses or global state;
treat text as inert data; never raise on hostile input (the engine isolates failures, but a failing
required detector forces the policy's failure mode); return original-text spans.
Register with `Scanner(detectors=[...])`. Detectors are **not** loadable from API requests.

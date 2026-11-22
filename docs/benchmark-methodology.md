# Benchmark methodology and results

## Method
1. Taxonomy fixed first (`detection-and-scoring.md`).
2. Corpus: `datasets/baseline` v0.1.0, **original and synthetic**, with attacks across all categories,
   ordinary prompts, benign security discussion, benign trigger words, code, non-English text
   and agent/tool/document source types. Generator: `datasets/baseline/build_corpus.py`.
3. **Splits by family**, never by row. A family (attack template/topic) lives in exactly one split.
   `promptguard.evaluation.dataset.leakage_report` checks family leakage, exact duplicates and
   MinHash-LSH near-duplicates (Jaccard ≥ 0.8) across splits; the test suite fails if any exists.
4. `dev` was used to design rules and thresholds. `test` is **locked**: written after the rule pack
   was frozen and evaluated once before any further change.
5. Pinned config: engine, rules sha256, policy hash, dataset sha256, split, positive-at, context
   mode → deterministic `run_id`. Re-running yields identical metrics (tested); only latency varies.
6. Positive = recommended action ≥ `review` (or `block` with `--positive-at block`).
7. Wilson 95% intervals for recall and FPR. ROC/PR use the ordinal score (uncalibrated).
8. Report: confusion matrix, precision/recall/FPR/FNR/F1, threshold sweep, per-category,
   per-benign-type, per-language, per-source, per-length, failure examples, latency, leakage.

## Results (rule-only, CPU, engine 0.1.0.dev0)

### Official: locked test split, run 1 (frozen rules) — `benchmarks/baseline-v0.1.0-test-run1.*`
n = 93 (61 attacks / 32 benign). **Recall 67.2% [55–78]**, precision 95.3%, **FPR 6.2% [2–20]**,
F1 78.8%, ROC-AUC 0.81, PR-AUC 0.88.

| Group | Recall |
|---|---|
| instruction_override | 23% (13) — paraphrases and 6 non-English samples |
| jailbreak_framing | 56% (9) |
| data_exfiltration | 67% (6) |
| obfuscation_evasion | 88% (8) |
| all others | 75–100% (n = 4–5 each; CIs very wide) |
| English / non-English | 75% / **0%** (6 attacks) |

False alarms: a code block containing a chat-role JSON snippet and `git rm -rf --cached`, both
inside a "third-party document". Misses are listed in the benchmark card.

### Post-hoc run 2 — `…test-run2-posthoc.*` (**contaminated**: not a clean estimate)
After run 1, one engine gap was fixed (separator-delimited single letters such as
`f.o.r.g.e.t y.o.u.r`). Recall 68.8%, FPR 6.2%. Reported only for transparency; the test split
should now be considered *used*, and new held-out data is needed to evaluate further changes.

### Dev split (in-sample, tuned): recall 100%, FPR 3.0%. Shown only as a regression floor (CI gate:
recall ≥ 0.90, FPR ≤ 0.10); it says nothing about generalisation.

### Research question 1 — does trust-boundary context help?
| Split | Context mode | Recall | FPR |
|---|---|---|---|
| test (post-hoc engine) | labeled | 68.9% | 6.3% |
| test | ignore (all as user input) | 62.3% | 0.0% |
| dev | labeled | 100% | 3.0% |
| dev | ignore | 93.6% | 3.0% |

Context labels **raised recall** (+6.6 pts on test) because third-party content gets stricter
severities, but **did not reduce false positives**: the two test false alarms exist *because*
the content was labelled third-party. With n = 93 the difference is within noise; treat it as a
hypothesis to test on larger data, not a finding.

### Latency (this sandbox: 4 vCPU x86_64, CPython 3.13, rules-only)
| Input | p50 | p95 |
|---|---|---|
| 200 chars | 0.7 ms | 0.9 ms |
| 2 000 chars | 5.4 ms | 6.9 ms |
| 20 000 chars | 51 ms | 56 ms |
| 200 000 chars (cap) | 519 ms | 532 ms |

Cost is linear (~2.6 ms/KB): the spec's "P95 < 100 ms for short text" holds up to roughly 30 kB.
Classifier latency is not measured (no model weights in this environment).

## Honest caveats
- The corpus is small, author-written, and the author also wrote the rules; both biases inflate
  recall relative to unseen attackers. Intervals are wide.
- No external benchmark (deepset, PINT, BIPIA…) was run. Doing so, with licences verified, is the
  next credibility step. Do not compare these numbers to published leaderboards.
- No claim is made about superiority over any other detector.

## Reproduce
```bash
pip install -e .
python datasets/baseline/build_corpus.py       # regenerates the identical JSONL + manifest
promptguard evaluate --dataset datasets/baseline --split test --output run.json
promptguard report run.json --format html --output report.html
```

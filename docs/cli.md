# CLI manual

```
promptguard scan [FILES...] [--stdin] [--file F] [--context SOURCE_TYPE] [--profile P] [--policy YAML]
                 [--format json|jsonl|text] [--input-format text|jsonl] [--html]
                 [--fail-on review|block|never] [--max-bytes N] [--max-chars N]
promptguard evaluate --dataset DIR [--split dev|test|all] [--positive-at review|block]
                     [--context-mode labeled|ignore] [--policy YAML] [--output run.json]
                     [--min-recall X] [--max-fpr Y]
promptguard report RUN.json [--format html|md] [--output FILE]
promptguard policy validate FILE | policy hash FILE
promptguard detectors | version
```

## Exit codes
| code | meaning |
|---|---|
| 0 | allow / monitor / sanitize (or `--fail-on never`) |
| 10 | review |
| 20 | block |
| 1 | `evaluate` regression gate failed |
| 2 | usage error |
| 3 | input error (unreadable, binary, too large, malformed JSONL, bad dataset) |
| 4 | policy/config error |

Input is read as text only (NUL bytes → rejected as binary), size-limited (`--max-bytes`, default
5 MB) and never executed. JSONL input: `{"text": "...", "source_type": "...", "id": "..."}` per line.

Examples:
```bash
promptguard scan --file document.txt --context retrieved_content --format text
cat page.html | promptguard scan --stdin --html --context retrieved_content
promptguard evaluate --dataset datasets/baseline --split dev --min-recall 0.9 --max-fpr 0.1
```

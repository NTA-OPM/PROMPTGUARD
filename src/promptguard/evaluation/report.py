"""Benchmark card (Markdown) and self-contained HTML report.

All dataset-derived strings are HTML-escaped; the page contains no scripts and ships a
restrictive Content-Security-Policy. Attack text is shown as inert escaped text.
"""

from __future__ import annotations

import html
from typing import Any


def _pct(x: float | None) -> str:
    return "n/a" if x is None else f"{100 * x:.1f}%"


def _ci(ci: Any) -> str:
    return "" if not ci else f" [{100 * ci[0]:.0f}–{100 * ci[1]:.0f}]"


def _md_group(title: str, groups: dict[str, Any]) -> str:
    if not groups:
        return ""
    lines = [
        f"### {title}",
        "",
        "| group | n | recall (95% CI) | FPR (95% CI) |",
        "|---|---|---|---|",
    ]
    for name, g in groups.items():
        rec = f"{_pct(g.get('recall'))}{_ci(g.get('recall_ci95'))}" if "recall" in g else "–"
        fpr = f"{_pct(g.get('fpr'))}{_ci(g.get('fpr_ci95'))}" if "fpr" in g else "–"
        lines.append(f"| {name} | {g['n']} | {rec} | {fpr} |")
    return "\n".join(lines) + "\n"


def to_markdown(run: dict[str, Any]) -> str:
    m, o = run["metrics"], run["metrics"]["overall"]
    d, cfg = run["dataset"], run["config"]
    out = [
        f"# Benchmark card — {run['run_id']}",
        "",
        "> Measured on a small, project-authored corpus. These numbers describe *this dataset under this configuration* "
        "and are **not** a general accuracy claim. PromptGuard does not guarantee prevention of prompt injection.",
        "",
        "## Configuration",
        "",
        f"- Engine `{run['engine_version']}`; policy `{run['versions'].get('policy')}`; rules sha256 `{str(run['versions'].get('rules_sha256'))[:16]}…`",
        f"- Dataset `{d['id']}` v{d['version']} (sha256 `{d['sha256'][:16]}…`, licence {d['license']}), split **{d['split']}**, n={d['n']}",
        f"- Positive = policy action ≥ **{cfg['positive_at']}**; context mode **{cfg['context_mode']}**",
        f"- Locked splits (not for tuning): {', '.join(d['locked_splits']) or 'none'}",
        f"- Reproduce: `{run['reproduce']}`",
        "",
        "## Operating point",
        "",
        "| TP | FP | TN | FN | precision | recall (95% CI) | FPR (95% CI) | FNR | F1 |",
        "|---|---|---|---|---|---|---|---|---|",
        f"| {o['tp']} | {o['fp']} | {o['tn']} | {o['fn']} | {_pct(o['precision'])} | {_pct(o['recall'])}{_ci(o['recall_ci95'])} | {_pct(o['fpr'])}{_ci(o['fpr_ci95'])} | {_pct(o['fnr'])} | {_pct(o['f1'])} |",
        "",
        f"Ranking (ordinal score, uncalibrated): ROC-AUC {m['ranking'].get('roc_auc')}, PR-AUC {m['ranking'].get('pr_auc')}. "
        f"Review burden: {m['review_burden']['flagged_per_1000_benign']} benign inputs flagged per 1000.",
        "",
        "## Threshold sweep (risk level)",
        "",
        "| positive if level ≥ | precision | recall | FPR | TP | FP | FN |",
        "|---|---|---|---|---|---|---|",
    ]
    for s in m["threshold_sweep"]:
        out.append(
            f"| {s['positive_if_risk_level_at_least']} | {_pct(s['precision'])} | {_pct(s['recall'])} | {_pct(s['fpr'])} | {s['tp']} | {s['fp']} | {s['fn']} |"
        )
    out.append("")
    for title, key in (
        ("By attack category", "by_attack_category"),
        ("By benign type", "by_benign_type"),
        ("By language", "by_language"),
        ("By source type", "by_source_type"),
        ("By length", "by_length"),
    ):
        out.append(_md_group(title, m[key]))
    t = run["timing"]["end_to_end"]
    out += [
        "## Latency (rule-only, this machine)",
        "",
        f"p50 {t['p50_ms']} ms · p95 {t['p95_ms']} ms · p99 {t['p99_ms']} ms · max {t['max_ms']} ms (n={t['n']}). {run['timing']['note']}",
        "",
        "## Dataset hygiene",
        "",
        f"Cross-split leakage issues: **{run['leakage']['cross_split_leakage']}** "
        f"(of {len(run['leakage']['issues'])} duplicate/near-duplicate findings, {run['leakage']['checked']} examples checked).",
        "",
        "## Failure examples",
        "",
    ]
    for kind, label in (("false_negatives", "Missed attacks"), ("false_positives", "False alarms")):
        items = run["failures"][kind]
        out.append(f"**{label} ({len(items)} shown)**")
        out.append("")
        for it in items:
            txt = it.get("text", "").replace("\n", " ")[:160]
            out.append(f"- `{it['id']}` [{it['category']}] → {it['action']}: `{txt!r}`")
        out.append("")
    out += [
        "## Calibration",
        "",
        "Not assessed. Scores and risk levels are policy labels / ordinal aids, not probabilities.",
        "",
    ]
    return "\n".join(out)


def _svg_pr(curve: list[dict[str, float]]) -> str:
    if not curve:
        return ""
    w = h = 220
    pts = " ".join(
        f"{20 + c['recall'] * (w - 30):.1f},{h - 20 - c['precision'] * (h - 30):.1f}" for c in curve
    )
    return (
        f'<svg role="img" aria-label="Precision-recall curve" viewBox="0 0 {w} {h}" width="{w}" height="{h}">'
        f'<rect x="20" y="10" width="{w - 30}" height="{h - 30}" fill="none" stroke="currentColor" opacity=".3"/>'
        f'<polyline points="{pts}" fill="none" stroke="currentColor" stroke-width="2"/>'
        f'<text x="{w / 2}" y="{h - 4}" font-size="10" text-anchor="middle">recall</text>'
        f'<text x="8" y="{h / 2}" font-size="10" transform="rotate(-90 8 {h / 2})" text-anchor="middle">precision</text></svg>'
    )


def to_html(run: dict[str, Any]) -> str:
    md = to_markdown(run)
    body: list[str] = []
    in_table = False
    for line in md.splitlines():
        e = html.escape(line)
        if line.startswith("|"):
            cells = [c.strip() for c in line.strip("|").split("|")]
            if set("".join(cells)) <= set("-: "):
                continue
            tag = "th" if not in_table else "td"
            if not in_table:
                body.append("<table>")
                in_table = True
            body.append(
                "<tr>" + "".join(f"<{tag}>{html.escape(c)}</{tag}>" for c in cells) + "</tr>"
            )
            continue
        if in_table:
            body.append("</table>")
            in_table = False
        if line.startswith("# "):
            body.append(f"<h1>{html.escape(line[2:])}</h1>")
        elif line.startswith("## "):
            body.append(f"<h2>{html.escape(line[3:])}</h2>")
        elif line.startswith("### "):
            body.append(f"<h3>{html.escape(line[4:])}</h3>")
        elif line.startswith("> "):
            body.append(f"<blockquote>{html.escape(line[2:])}</blockquote>")
        elif line.startswith("- "):
            body.append(f"<p>• {html.escape(line[2:])}</p>")
        elif line.strip():
            body.append(f"<p>{e}</p>")
    if in_table:
        body.append("</table>")
    svg = _svg_pr(run["metrics"]["ranking"].get("curve", []))
    return (
        "<!doctype html><html lang=en><head><meta charset=utf-8>"
        "<meta http-equiv=Content-Security-Policy content=\"default-src 'none'; style-src 'unsafe-inline'\">"
        "<meta name=viewport content='width=device-width,initial-scale=1'>"
        f"<title>PromptGuard benchmark {html.escape(run['run_id'])}</title>"
        "<style>body{font:15px/1.5 system-ui,sans-serif;max-width:60rem;margin:2rem auto;padding:0 1rem;color:#1b1f23;background:#fff}"
        "table{border-collapse:collapse;margin:.5rem 0}td,th{border:1px solid #bbb;padding:.2rem .5rem;text-align:left}"
        "blockquote{border-left:4px solid #c60;padding-left:.8rem;margin:1rem 0}"
        "@media(prefers-color-scheme:dark){body{background:#111;color:#eee}td,th{border-color:#555}}</style></head><body>"
        + "\n".join(body)
        + f"<h2>Precision-recall (ranking score)</h2>{svg}</body></html>"
    )

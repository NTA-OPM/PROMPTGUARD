"""Reproducible evaluation runner."""

from __future__ import annotations

import hashlib
import json
import platform
import sys
import time
from collections import defaultdict
from typing import Any, Literal

from promptguard._version import __version__
from promptguard.core.engine import Scanner
from promptguard.core.schema import Action, InputEnvelope, Severity, SourceType
from promptguard.evaluation.dataset import Dataset, Example, leakage_report
from promptguard.evaluation.metrics import confusion, latency_summary, roc_pr

PositiveAt = Literal["review", "block"]
ContextMode = Literal["labeled", "ignore"]
_LEN_BUCKETS = ((200, "<200"), (1000, "200-999"), (5000, "1000-4999"))


def _bucket(n: int) -> str:
    for lim, name in _LEN_BUCKETS:
        if n < lim:
            return name
    return ">=5000"


def _group(rows: list[dict[str, Any]], key: str, *, by_attack: bool) -> dict[str, Any]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in rows:
        groups[str(r[key])].append(r)
    out: dict[str, Any] = {}
    for name, rs in sorted(groups.items()):
        c = confusion([r["is_attack"] for r in rs], [r["pred"] for r in rs])
        entry = {"n": len(rs), "attacks": c["support_attack"], "benign": c["support_benign"]}
        if c["support_attack"]:
            entry.update(recall=c["recall"], recall_ci95=c["recall_ci95"])
        if c["support_benign"]:
            entry.update(fpr=c["fpr"], fpr_ci95=c["fpr_ci95"])
        out[name] = entry
    return out


def evaluate(
    dataset: Dataset,
    scanner: Scanner,
    *,
    split: str | None = "dev",
    positive_at: PositiveAt = "review",
    context_mode: ContextMode = "labeled",
    max_failures: int = 25,
    include_texts: bool = True,
) -> dict[str, Any]:
    examples = dataset.split(split)
    if not examples:
        raise ValueError(f"no examples in split {split!r}")
    threshold = Action.REVIEW if positive_at == "review" else Action.BLOCK
    rows: list[dict[str, Any]] = []
    lat: list[float] = []
    det_ms: dict[str, list[float]] = defaultdict(list)
    for ex in examples:
        env = InputEnvelope(
            text=ex.text,
            input_id=ex.id,
            source_type=ex.source_type if context_mode == "labeled" else SourceType.USER_INPUT,
            content_type=ex.content_type,
        )
        t0 = time.perf_counter()
        res = scanner.scan(env)
        lat.append((time.perf_counter() - t0) * 1000)
        for k, v in res.detector_timings_ms.items():
            det_ms[k].append(v)
        rows.append(
            {
                "id": ex.id,
                "is_attack": ex.label == "attack",
                "category": ex.category,
                "language": ex.language,
                "source_type": ex.source_type.value,
                "length": _bucket(len(ex.text)),
                "pred": res.decision.action >= threshold,
                "action": res.decision.action.value,
                "level": res.risk.level.value,
                "score": res.risk.score,
                "rules": sorted({f.rule_id or f.detector_id for f in res.findings}),
            }
        )
    y = [r["is_attack"] for r in rows]
    overall = confusion(y, [r["pred"] for r in rows])
    ranking = roc_pr(y, [r["score"] for r in rows])
    sweep = []
    for lvl in Severity:
        c = confusion(y, [Severity(r["level"]) >= lvl and r["score"] > 0 for r in rows])
        sweep.append(
            {
                "positive_if_risk_level_at_least": lvl.value,
                **{k: c[k] for k in ("tp", "fp", "tn", "fn", "precision", "recall", "f1", "fpr")},
            }
        )
    ex_by_id: dict[str, Example] = {e.id: e for e in examples}
    failures = {
        "false_negatives": [
            {"id": r["id"], "category": r["category"], "action": r["action"], **({"text": ex_by_id[r["id"]].text} if include_texts else {})}
            for r in rows if r["is_attack"] and not r["pred"]
        ][:max_failures],
        "false_positives": [
            {"id": r["id"], "category": r["category"], "action": r["action"], "rules": r["rules"], **({"text": ex_by_id[r["id"]].text} if include_texts else {})}
            for r in rows if (not r["is_attack"]) and r["pred"]
        ][:max_failures],
    }  # fmt: skip
    versions = scanner.versions()
    config = {
        "split": split,
        "positive_at": positive_at,
        "context_mode": context_mode,
    }
    fingerprint = json.dumps(
        {
            "versions": versions,
            "dataset": [dataset.manifest.dataset_id, dataset.manifest.version, dataset.sha256],
            "config": config,
        },
        sort_keys=True,
    )
    return {
        "run_id": "run_" + hashlib.sha256(fingerprint.encode()).hexdigest()[:16],
        "kind": "promptguard.evaluation",
        "schema_version": "1",
        "engine_version": __version__,
        "versions": versions,
        "dataset": {
            "id": dataset.manifest.dataset_id,
            "version": dataset.manifest.version,
            "sha256": dataset.sha256,
            "license": dataset.manifest.license,
            "split": split,
            "locked_splits": dataset.manifest.locked_splits,
            "n": len(rows),
        },
        "config": config,
        "metrics": {
            "overall": overall,
            "ranking": ranking,
            "threshold_sweep": sweep,
            "by_attack_category": _group(
                [r for r in rows if r["is_attack"]], "category", by_attack=True
            ),
            "by_benign_type": _group(
                [r for r in rows if not r["is_attack"]], "category", by_attack=False
            ),
            "by_language": _group(rows, "language", by_attack=True),
            "by_source_type": _group(rows, "source_type", by_attack=True),
            "by_length": _group(rows, "length", by_attack=True),
            "calibration": {
                "status": "not_assessed",
                "note": "Scores are ordinal; no calibration is claimed.",
            },
            "review_burden": {
                "flagged_per_1000_benign": round(
                    1000 * overall["fp"] / max(overall["support_benign"], 1), 1
                ),
            },
        },
        "failures": failures,
        "leakage": leakage_report(dataset.examples),
        "timing": {
            "end_to_end": latency_summary(lat),
            "per_detector_mean_ms": {k: round(sum(v) / len(v), 3) for k, v in det_ms.items()},
            "note": "Wall-clock; hardware-dependent and excluded from run_id/reproducibility checks.",
        },
        "environment": {"python": sys.version.split()[0], "platform": platform.platform()},
        "reproduce": (
            f"promptguard evaluate --dataset <dir> --split {split} --positive-at {positive_at} --context-mode {context_mode}"
        ),
    }


def deterministic_view(run: dict[str, Any]) -> dict[str, Any]:
    """Subset of a run that must be identical across re-runs on the same inputs."""
    return {
        k: run[k]
        for k in ("run_id", "versions", "dataset", "config", "metrics", "failures", "leakage")
    }

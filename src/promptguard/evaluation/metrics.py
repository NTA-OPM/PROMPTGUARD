"""Metric primitives (dependency-free, deterministic)."""

from __future__ import annotations

import math
from collections.abc import Sequence
from typing import Any


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (round(max(0.0, centre - half), 4), round(min(1.0, centre + half), 4))


def _r(x: float) -> float:
    return round(x, 4)


def confusion(y_true: Sequence[bool], y_pred: Sequence[bool]) -> dict[str, Any]:
    tp = sum(t and p for t, p in zip(y_true, y_pred, strict=True))
    fp = sum((not t) and p for t, p in zip(y_true, y_pred, strict=True))
    fn = sum(t and (not p) for t, p in zip(y_true, y_pred, strict=True))
    tn = sum((not t) and (not p) for t, p in zip(y_true, y_pred, strict=True))
    pos, neg = tp + fn, fp + tn
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / pos if pos else None
    f1 = (
        (2 * precision * recall / (precision + recall))
        if precision and recall
        else (0.0 if pos and tp + fp else None)
    )
    fpr = fp / neg if neg else None
    fnr = fn / pos if pos else None
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "support_attack": pos, "support_benign": neg,
        "precision": None if precision is None else _r(precision),
        "recall": None if recall is None else _r(recall),
        "f1": None if f1 is None else _r(f1),
        "fpr": None if fpr is None else _r(fpr),
        "fnr": None if fnr is None else _r(fnr),
        "accuracy": _r((tp + tn) / max(len(y_true), 1)),
        "recall_ci95": wilson(tp, pos) if pos else None,
        "fpr_ci95": wilson(fp, neg) if neg else None,
    }  # fmt: skip


def roc_pr(y_true: Sequence[bool], scores: Sequence[float]) -> dict[str, Any]:
    """ROC-AUC (trapezoid) and PR-AUC (average precision) with tie grouping."""
    pos = sum(y_true)
    neg = len(y_true) - pos
    if pos == 0 or neg == 0:
        return {"roc_auc": None, "pr_auc": None, "note": "needs both classes", "curve": []}
    order = sorted(range(len(scores)), key=lambda i: -scores[i])
    tp = fp = 0
    roc = [(0.0, 0.0)]
    pr: list[tuple[float, float]] = []
    i = 0
    ap = 0.0
    prev_recall = 0.0
    while i < len(order):
        j = i
        while j < len(order) and scores[order[j]] == scores[order[i]]:
            tp += bool(y_true[order[j]])
            fp += not y_true[order[j]]
            j += 1
        recall = tp / pos
        precision = tp / (tp + fp)
        roc.append((fp / neg, recall))
        pr.append((recall, precision))
        ap += (recall - prev_recall) * precision
        prev_recall = recall
        i = j
    auc = sum((x2 - x1) * (y1 + y2) / 2 for (x1, y1), (x2, y2) in zip(roc, roc[1:], strict=False))
    step = max(1, len(pr) // 100)
    return {
        "roc_auc": _r(auc),
        "pr_auc": _r(ap),
        "curve": [{"recall": _r(r), "precision": _r(p)} for r, p in pr[::step]],
        "note": "scores are ordinal ranking aids, not calibrated probabilities",
    }


def percentile(values: Sequence[float], q: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    k = (len(s) - 1) * q
    lo, hi = math.floor(k), math.ceil(k)
    return round(s[lo] + (s[hi] - s[lo]) * (k - lo), 3)


def latency_summary(ms: Sequence[float]) -> dict[str, float]:
    return {
        "n": len(ms),
        "mean_ms": round(sum(ms) / len(ms), 3) if ms else 0.0,
        "p50_ms": percentile(ms, 0.50),
        "p95_ms": percentile(ms, 0.95),
        "p99_ms": percentile(ms, 0.99),
        "max_ms": round(max(ms), 3) if ms else 0.0,
    }

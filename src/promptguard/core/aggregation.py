"""Transparent finding aggregation.

The aggregate is an *ordinal* risk level plus a ranking score. It is intentionally not a
probability and is never described as one.

Algorithm (documented in docs/detection-and-scoring.md)
    1. Effective severity per finding: base severity; +1 (cap HIGH) if the evidence sits
       in visually hidden HTML; -1 if it is inside quoted/code content and the profile
       enables ``quoted_downgrade`` (never below LOW, never applied to CRITICAL).
    2. Level = max effective severity of risk-bearing findings.
    3. Corroboration: >= 2 distinct categories at >= MEDIUM raise the level by one (cap HIGH).
    4. CRITICAL = a HIGH action-intent finding (exfiltration / tool manipulation) together
       with another HIGH hierarchy finding, or with ``critical_on_action_intent``.
"""

from __future__ import annotations

from dataclasses import dataclass

from promptguard.core.schema import (
    ACTION_INTENT_CATEGORIES,
    HIERARCHY_CATEGORIES,
    NON_RISK_CATEGORIES,
    Category,
    Finding,
    RiskAssessment,
    Severity,
)

_WEIGHT = {
    Severity.INFORMATIONAL: 0.02,
    Severity.LOW: 0.10,
    Severity.MEDIUM: 0.35,
    Severity.HIGH: 0.70,
    Severity.CRITICAL: 1.00,
}


@dataclass(frozen=True)
class AggregationOptions:
    quoted_downgrade: bool = False
    critical_on_action_intent: bool = False


def effective_severity(f: Finding, opts: AggregationOptions) -> tuple[Severity, list[str]]:
    sev = f.severity
    notes: list[str] = []
    if f.metadata.get("hidden") and sev >= Severity.LOW:
        sev = sev.bump(1, cap=Severity.HIGH) if sev < Severity.HIGH else sev
        notes.append("HIDDEN_CONTENT_ESCALATION")
    if (
        opts.quoted_downgrade
        and f.metadata.get("quoted")
        and Severity.MEDIUM <= sev <= Severity.HIGH
        and f.category is not Category.OBFUSCATION_EVASION
    ):
        sev = sev.bump(-1)
        notes.append("QUOTED_CONTENT_DOWNGRADE")
    return sev, notes


def aggregate(findings: list[Finding], opts: AggregationOptions | None = None) -> RiskAssessment:
    opts = opts or AggregationOptions()
    risk = [f for f in findings if f.category not in NON_RISK_CATEGORIES]
    if not risk:
        return RiskAssessment(
            level=Severity.INFORMATIONAL,
            score=0.0,
            reasons=[],
            contributing_finding_ids=[],
        )
    eff: dict[str, Severity] = {}
    reasons: list[str] = []
    for f in risk:
        sev, notes = effective_severity(f, opts)
        eff[f.finding_id] = sev
        reasons.extend(notes)

    level = max(eff.values())
    # corroboration across distinct categories
    strong_cats = {f.category for f in risk if eff[f.finding_id] >= Severity.MEDIUM}
    if len(strong_cats) >= 2 and level < Severity.HIGH:
        level = level.bump(1, cap=Severity.HIGH)
        reasons.append("MULTI_CATEGORY_CORROBORATION")

    high_action = {
        f.category
        for f in risk
        if f.category in ACTION_INTENT_CATEGORIES and eff[f.finding_id] >= Severity.HIGH
    }
    high_hier = {
        f.category
        for f in risk
        if f.category in HIERARCHY_CATEGORIES and eff[f.finding_id] >= Severity.HIGH
    }
    if high_action and (high_hier or opts.critical_on_action_intent):
        level = Severity.CRITICAL
        reasons.append(
            "ACTION_INTENT_WITH_HIERARCHY_ATTACK"
            if high_hier
            else "ACTION_INTENT_IN_SENSITIVE_PROFILE"
        )

    # ranking score: noisy-OR over per-category maxima of weight*confidence
    per_cat: dict[Category, float] = {}
    for f in risk:
        w = _WEIGHT[eff[f.finding_id]] * (f.confidence if f.confidence is not None else 0.5)
        per_cat[f.category] = max(per_cat.get(f.category, 0.0), w)
    miss = 1.0
    for w in per_cat.values():
        miss *= 1.0 - min(w, 0.999)
    score = round(1.0 - miss, 6)
    if level is Severity.CRITICAL:
        score = max(score, 0.95)
    return RiskAssessment(
        level=level,
        score=score,
        contributing_finding_ids=[f.finding_id for f in risk],
        reasons=list(dict.fromkeys(reasons)),
        categories=sorted({f.category for f in risk}, key=lambda c: c.value),
        effective_severities=eff,
    )

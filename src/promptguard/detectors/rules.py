"""Versioned YAML rule-pack detector."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from promptguard.core.schema import Category, Finding, Severity
from promptguard.detectors.base import Detector, ScanContext

MAX_MATCHES_PER_RULE_VIEW = 5
#: Views whose matches count as evidence of deliberate obfuscation.
_OBFUSCATING_PREFIXES = ("invis_space", "relaxed", "leet", "tags", "b64", "pct")


class RuleSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(pattern=r"^PG-[A-Z]{2}-\d{3}$|^[A-Z][A-Z0-9_-]{2,31}$")
    category: Category
    severity: Severity
    severity_third_party: Severity | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    explanation: str
    pattern: str
    flags: str = "i"


class RulePack(BaseModel):
    model_config = ConfigDict(extra="forbid")
    pack_id: str
    version: str
    language: str = "en"
    rules: list[RuleSpec]


@dataclass(frozen=True)
class CompiledRule:
    spec: RuleSpec
    regex: re.Pattern[str]


class RulePackError(ValueError):
    pass


def load_rule_pack(path: Path | None = None) -> tuple[RulePack, str]:
    """Load + validate a rule pack. Returns (pack, sha256-of-bytes)."""
    if path is None:
        data = resources.files("promptguard.data.rules").joinpath("default.yaml").read_bytes()
    else:
        data = Path(path).read_bytes()
    try:
        raw = yaml.safe_load(data)
        pack = RulePack.model_validate(raw)
    except (yaml.YAMLError, ValidationError) as exc:
        raise RulePackError(f"invalid rule pack: {exc}") from exc
    ids = [r.id for r in pack.rules]
    if len(ids) != len(set(ids)):
        raise RulePackError("duplicate rule ids in pack")
    return pack, hashlib.sha256(data).hexdigest()


def compile_rules(pack: RulePack) -> list[CompiledRule]:
    out: list[CompiledRule] = []
    for spec in pack.rules:
        flags = 0
        for f in spec.flags:
            flags |= {"i": re.IGNORECASE, "s": re.DOTALL, "m": re.MULTILINE}.get(f, 0)
        try:
            out.append(CompiledRule(spec, re.compile(spec.pattern, flags)))
        except re.error as exc:
            raise RulePackError(f"rule {spec.id}: bad pattern: {exc}") from exc
    return out


def _view_kind(name: str) -> str | None:
    for p in _OBFUSCATING_PREFIXES:
        if name.startswith(p):
            return p
    return None


_KIND_TEXT = {
    "invis_space": ("invisible characters used as separators", Severity.MEDIUM),
    "relaxed": ("separator/letter-spacing tricks (e.g. 'i g n o r e')", Severity.MEDIUM),
    "leet": ("leetspeak substitutions", Severity.MEDIUM),
    "tags": ("Unicode tag characters (invisible ASCII smuggling)", Severity.HIGH),
    "b64": ("base64-encoded text", Severity.HIGH),
    "pct": ("percent-encoded text", Severity.MEDIUM),
}


class RuleDetector(Detector):
    id = "rules"
    name = "Rule-pack pattern detector"
    description = "Matches the versioned YAML rule pack against normalized and decoded views."
    capabilities = ("pattern", "multi-view")
    categories = tuple(c for c in Category if c is not Category.BENIGN_SECURITY_DISCUSSION)

    def __init__(self, pack_path: Path | None = None) -> None:
        self.pack, self.pack_sha256 = load_rule_pack(pack_path)
        self.rules = compile_rules(self.pack)
        self.version = self.pack.version

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        seen: dict[str, list[tuple[int, int]]] = {}
        obf: dict[str, list[tuple[int, int]]] = {}
        third = ctx.third_party
        original = ctx.text
        for view in ctx.reps.views:
            kind = _view_kind(view.name)
            for rule in self.rules:
                for n, m in enumerate(rule.regex.finditer(view.text)):
                    if n >= MAX_MATCHES_PER_RULE_VIEW:
                        break
                    s, e = view.to_original(m.start(), m.end())
                    prior = seen.setdefault(rule.spec.id, [])
                    if any(s < pe and ps < e for ps, pe in prior):
                        continue  # same rule already matched here in an earlier view
                    prior.append((s, e))
                    matched = m.group()
                    notes: list[str] = []
                    obfuscated_kind = kind
                    if kind is None and view.name != "html":
                        raw = re.sub(r"\s+", " ", original[s:e]).casefold()
                        if raw != re.sub(r"\s+", " ", matched).casefold():
                            obfuscated_kind = "normalization"
                    if view.note and view.name != "normalized":
                        notes.append(view.note)
                    if obfuscated_kind is not None:
                        obf.setdefault(obfuscated_kind, []).append((s, e))
                        if obfuscated_kind == "normalization":
                            notes.append("match only visible after Unicode normalization")
                    sev = (
                        rule.spec.severity_third_party
                        if third and rule.spec.severity_third_party
                        else rule.spec.severity
                    )
                    findings.append(
                        self.make(
                            ctx,
                            category=rule.spec.category,
                            severity=sev,
                            explanation=rule.spec.explanation,
                            spans=[(s, e)],
                            rule_id=rule.spec.id,
                            confidence=rule.spec.confidence,
                            view=view.name,
                            normalized_snippets=[matched],
                            notes=notes,
                            metadata={
                                "view": view.name,
                                "third_party_severity_applied": bool(
                                    third and rule.spec.severity_third_party
                                ),
                            },
                        )
                    )
        for kind, spans in obf.items():
            desc, sev = _KIND_TEXT.get(
                kind, ("Unicode normalization (compatibility forms / homoglyphs)", Severity.MEDIUM)
            )
            findings.append(
                self.make(
                    ctx,
                    category=Category.OBFUSCATION_EVASION,
                    severity=sev,
                    explanation=(
                        f"{len(spans)} rule match(es) became visible only after undoing {desc}. "
                        "Deliberate disguise of instruction-like text is itself a risk signal."
                    ),
                    spans=spans[:5],
                    rule_id=f"PG-OBA-{kind.upper()}",
                    confidence=0.75,
                    view=kind,
                    metadata={"match_count": len(spans), "obfuscation_kind": kind},
                )
            )
        return findings

    def manifest_extra(self) -> dict[str, Any]:
        return {
            "pack_id": self.pack.pack_id,
            "pack_version": self.pack.version,
            "sha256": self.pack_sha256,
        }

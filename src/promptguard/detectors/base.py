"""Detector interface, scan context and registry."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, ClassVar

from promptguard.core.schema import (
    Category,
    DetectorManifest,
    Evidence,
    Finding,
    InputEnvelope,
    Severity,
    Span,
    make_finding_id,
)
from promptguard.normalization.pipeline import Representations

_MAX_SNIPPET = 160


def safe_snippet(text: str, limit: int = _MAX_SNIPPET) -> str:
    """Render text for display: control/invisible characters shown as escapes, truncated."""
    out: list[str] = []
    for ch in text[:limit]:
        if ch.isprintable() or ch == " ":
            out.append(ch)
        else:
            out.append(f"\\u{ord(ch):04x}" if ord(ch) <= 0xFFFF else f"\\U{ord(ch):08x}")
    s = "".join(out)
    return s + ("…" if len(text) > limit else "")


@dataclass
class ScanContext:
    """Everything a detector may look at. Detectors must treat ``text`` as inert data."""

    envelope: InputEnvelope
    text: str  # original text (possibly truncated to the scan limit)
    reps: Representations
    config: dict[str, Any] = field(default_factory=dict)

    @property
    def third_party(self) -> bool:
        return self.envelope.source_type.is_third_party


class Detector(ABC):
    id: ClassVar[str]
    version: str = "1.0.0"
    name: ClassVar[str] = ""
    description: ClassVar[str] = ""
    categories: tuple[Category, ...] = ()
    required: ClassVar[bool] = True
    capabilities: ClassVar[tuple[str, ...]] = ()
    dependencies: ClassVar[tuple[str, ...]] = ()
    languages: ClassVar[tuple[str, ...]] = ("en",)

    @abstractmethod
    def run(self, ctx: ScanContext) -> list[Finding]:
        """Return findings. Must not raise on hostile input and must not do I/O."""

    def manifest(self) -> DetectorManifest:
        return DetectorManifest(
            id=self.id,
            version=self.version,
            name=self.name or self.id,
            description=self.description,
            capabilities=list(self.capabilities),
            categories=list(self.categories),
            supported_contexts=["all"],
            dependencies=list(self.dependencies),
            required=self.required,
            languages=list(self.languages),
        )

    # helpers ------------------------------------------------------------------------
    def make(
        self,
        ctx: ScanContext,
        *,
        category: Category,
        severity: Severity,
        explanation: str,
        spans: list[tuple[int, int]],
        rule_id: str | None = None,
        confidence: float | None = None,
        score: float | None = None,
        view: str = "original",
        normalized_snippets: list[str | None] | None = None,
        notes: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Finding:
        ev: list[Evidence] = []
        for i, (s, e) in enumerate(spans):
            ns = normalized_snippets[i] if normalized_snippets else None
            raw = ctx.text[s:e]
            ev.append(
                Evidence(
                    span=Span(start=s, end=e),
                    view=view,
                    snippet=safe_snippet(raw),
                    normalized_snippet=(safe_snippet(ns) if ns is not None and ns != raw else None),
                )
            )
        first = spans[0] if spans else (0, 0)
        return Finding(
            finding_id=make_finding_id(ctx.envelope.input_id, self.id, rule_id, *first),
            detector_id=self.id,
            detector_version=self.version,
            category=category,
            severity=severity,
            confidence=confidence,
            score=score,
            rule_id=rule_id,
            evidence=ev,
            explanation=explanation,
            normalization_notes=notes or [],
            metadata=metadata or {},
        )


class DetectorRegistry:
    def __init__(self) -> None:
        self._detectors: dict[str, Detector] = {}

    def register(self, detector: Detector) -> None:
        if detector.id in self._detectors:
            raise ValueError(f"detector already registered: {detector.id}")
        self._detectors[detector.id] = detector

    def unregister(self, detector_id: str) -> None:
        self._detectors.pop(detector_id, None)

    def all(self) -> list[Detector]:
        return list(self._detectors.values())

    def get(self, detector_id: str) -> Detector | None:
        return self._detectors.get(detector_id)

    def manifests(self) -> list[DetectorManifest]:
        return [d.manifest() for d in self._detectors.values()]

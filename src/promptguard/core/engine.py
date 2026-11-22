"""The scanner: envelope -> views -> detectors -> aggregation -> policy recommendation."""

from __future__ import annotations

import asyncio
import contextlib
import time
import unicodedata
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from promptguard._version import __version__
from promptguard.core.aggregation import AggregationOptions, aggregate
from promptguard.core.schema import (
    Coverage,
    DetectorError,
    DetectorManifest,
    Finding,
    InputEnvelope,
    ScanResult,
    Severity,
    SourceType,
)
from promptguard.detectors.base import Detector, DetectorRegistry, ScanContext
from promptguard.detectors.rules import RuleDetector
from promptguard.detectors.structural import DiscussionDetector, StructuralDetector, UnicodeDetector
from promptguard.normalization.pipeline import (
    NORMALIZATION_VERSION,
    build_representations,
    html_hidden_spans,
    quoted_spans,
    sanitize_text,
    span_inside,
    span_overlaps,
)
from promptguard.policy.engine import Policy, evaluate_policy, load_policy, resolve_profile

Hook = Callable[[ScanResult], None]


class InputRejected(ValueError):
    """Input failed validation (e.g. not text, NUL bytes, over the hard limit)."""


@dataclass
class ScannerConfig:
    #: Text beyond this many characters is not scanned and the result is marked truncated.
    max_chars: int = 200_000
    #: Hard limit; larger inputs are rejected (``InputRejected``) rather than truncated.
    reject_over_chars: int = 5_000_000
    max_decode_depth: int = 2
    reject_nul: bool = False


@dataclass
class _Timing:
    per_detector: dict[str, float] = field(default_factory=dict)


class Scanner:
    """Stateless, offline scanner. Thread-safe once constructed (detectors are read-only)."""

    def __init__(
        self,
        policy: Policy | None = None,
        *,
        detectors: Sequence[Detector] | None = None,
        config: ScannerConfig | None = None,
        hooks: Sequence[Hook] = (),
    ) -> None:
        self.policy = policy or load_policy()
        self.config = config or ScannerConfig()
        self.registry = DetectorRegistry()
        if detectors is None:
            detectors = [
                RuleDetector(),
                StructuralDetector(),
                UnicodeDetector(),
                DiscussionDetector(),
            ]
        for d in detectors:
            self.registry.register(d)
        self._hooks = list(hooks)

    # ----------------------------------------------------------------- introspection
    @property
    def detectors(self) -> list[Detector]:
        return self.registry.all()

    def manifests(self) -> list[DetectorManifest]:
        return self.registry.manifests()

    def add_hook(self, hook: Hook) -> None:
        self._hooks.append(hook)

    def versions(self) -> dict[str, str]:
        v = {
            "engine": __version__,
            "normalization": NORMALIZATION_VERSION,
            "policy": f"{self.policy.policy_id}@{self.policy.version}",
            "policy_hash": self.policy.canonical_hash(),
        }
        for d in self.registry.all():
            v[f"detector:{d.id}"] = d.version
            if isinstance(d, RuleDetector):
                v["rules_sha256"] = d.pack_sha256
        return v

    # ----------------------------------------------------------------- scanning
    def _coerce(self, item: str | InputEnvelope, env_kwargs: dict[str, Any]) -> InputEnvelope:
        if isinstance(item, InputEnvelope):
            if env_kwargs:
                return item.model_copy(update=env_kwargs)
            return item
        if not isinstance(item, str):
            raise InputRejected("input must be text (str) or an InputEnvelope")
        return InputEnvelope(text=item, **env_kwargs)

    def scan(self, item: str | InputEnvelope, **env_kwargs: Any) -> ScanResult:
        """Scan one input. ``env_kwargs`` populate an ``InputEnvelope`` for plain strings."""
        t0 = time.perf_counter()
        env = self._coerce(item, env_kwargs)
        text = env.text
        if len(text) > self.config.reject_over_chars:
            raise InputRejected(
                f"input exceeds hard limit of {self.config.reject_over_chars} characters"
            )
        if self.config.reject_nul and "\x00" in text:
            raise InputRejected("input contains NUL characters")
        truncated = len(text) > self.config.max_chars
        scan_text = text[: self.config.max_chars]

        reps = build_representations(
            scan_text, content_type=env.content_type, max_decode_depth=self.config.max_decode_depth
        )
        ctx = ScanContext(envelope=env, text=scan_text, reps=reps, config={"limitations": []})

        findings: list[Finding] = []
        errors: list[DetectorError] = []
        timing = _Timing()
        for det in self.registry.all():
            ts = time.perf_counter()
            try:
                findings.extend(det.run(ctx))
            except Exception as exc:  # noqa: BLE001 - isolation boundary: never leak input via message
                errors.append(
                    DetectorError(
                        detector_id=det.id,
                        error_type=type(exc).__name__,
                        message="detector failed; see error_type",
                        required=det.required,
                    )
                )
            timing.per_detector[det.id] = round((time.perf_counter() - ts) * 1000, 3)

        self._enrich(findings, scan_text, env)
        findings.sort(
            key=lambda f: (
                -f.severity.rank,
                f.evidence[0].span.start if f.evidence else 0,
                f.finding_id,
            )
        )

        profile_name = resolve_profile(self.policy, env)
        prof = self.policy.profile(profile_name)
        opts = AggregationOptions(
            quoted_downgrade=prof.quoted_downgrade,
            critical_on_action_intent=prof.critical_on_action_intent,
        )
        assessment = aggregate(findings, opts)
        limitations = self._limitations(
            env, scan_text, truncated, ctx.config.get("limitations", [])
        )
        decision = evaluate_policy(
            self.policy,
            profile_name,
            assessment,
            findings,
            errors=errors,
            truncated=truncated,
            limitations=limitations,
            effective=assessment.effective_severities,
        )
        result = ScanResult(
            input_id=env.input_id,
            engine_version=__version__,
            findings=findings,
            risk=assessment,
            decision=decision,
            coverage=Coverage(
                chars_total=len(text),
                chars_scanned=len(scan_text),
                truncated=truncated,
                views=[v.name for v in reps.views],
                classifier_chunks=int(ctx.config.get("classifier_chunks", 0)),
            ),
            errors=errors,
            limitations=limitations,
            duration_ms=round((time.perf_counter() - t0) * 1000, 3),
            detector_timings_ms=timing.per_detector,
            versions=self.versions(),
        )
        for hook in self._hooks:
            with contextlib.suppress(Exception):  # instrumentation must never break scanning
                hook(result)
        return result

    async def ascan(self, item: str | InputEnvelope, **env_kwargs: Any) -> ScanResult:
        return await asyncio.to_thread(self.scan, item, **env_kwargs)

    def scan_batch(
        self, items: Sequence[str | InputEnvelope], **env_kwargs: Any
    ) -> list[ScanResult]:
        return [self.scan(i, **env_kwargs) for i in items]

    def sanitize(self, text: str) -> tuple[str, list[str]]:
        """Apply the documented minimal sanitisation (invisible/control characters only)."""
        return sanitize_text(text)

    # ----------------------------------------------------------------- internals
    @staticmethod
    def _enrich(findings: list[Finding], text: str, env: InputEnvelope) -> None:
        """Attach context flags (quoted / hidden) from evidence positions."""
        q = quoted_spans(text)
        hidden = html_hidden_spans(text) if env.content_type == "text/html" else []
        for f in findings:
            if not f.evidence:
                continue
            sp = (f.evidence[0].span.start, f.evidence[0].span.end)
            if q and span_inside(sp, q):
                f.metadata["quoted"] = True
            if hidden and span_overlaps(sp, hidden):
                f.metadata["hidden"] = True

    @staticmethod
    def _limitations(env: InputEnvelope, text: str, truncated: bool, extra: list[str]) -> list[str]:
        lim = [
            "Detection is a risk signal, not proof of maliciousness; absence of findings is not proof of safety.",
            "Built-in rules are English-only and are not evaluated for other languages.",
        ]
        letters = [c for c in text[:5000] if c.isalpha()]
        if letters:
            non_latin = sum(1 for c in letters if not unicodedata.name(c, "").startswith("LATIN"))
            if non_latin / len(letters) > 0.3:
                lim.append(
                    "Text is mostly non-Latin script: rule coverage for this language is not evaluated."
                )
        if env.language_hint and env.language_hint.lower().split("-")[0] != "en":
            lim.append(
                f"language_hint={env.language_hint!r}: no evaluated detector support for this language."
            )
        if env.source_type is SourceType.UNKNOWN:
            lim.append("source_type is unknown; treated as third-party content.")
        if truncated:
            lim.append("Input exceeded the scan limit; the remainder was not analysed.")
        lim.extend(extra)
        return lim


_default_scanner: Scanner | None = None


def scan(text: str | InputEnvelope, **env_kwargs: Any) -> ScanResult:
    """Convenience: scan with a lazily created default scanner."""
    global _default_scanner  # noqa: PLW0603
    if _default_scanner is None:
        _default_scanner = Scanner()
    return _default_scanner.scan(text, **env_kwargs)


__all__ = ["InputRejected", "Scanner", "ScannerConfig", "Severity", "scan"]

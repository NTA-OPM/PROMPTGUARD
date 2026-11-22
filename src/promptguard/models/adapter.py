"""Optional local classifier adapters.

* Nothing here is imported or downloaded unless the user configures it.
* Weights are never bundled. Many guard models are gated or carry non-OSI licences
  (e.g. Meta Llama Prompt Guard 2 uses the Llama 4 Community License): the user must accept
  the model's terms and supply the model id/path themselves.
* Model scores are treated as *uncalibrated* signals.
"""

from __future__ import annotations

import concurrent.futures as cf
from dataclasses import dataclass
from typing import Any, Protocol

from pydantic import BaseModel, Field

from promptguard.core.chunking import chunk_spans
from promptguard.core.schema import Category, Finding, Severity
from promptguard.detectors.base import Detector, ScanContext


class ModelCard(BaseModel):
    model_id: str
    version: str = "unspecified"
    license: str = "unspecified (user must verify)"
    languages: list[str] = Field(default_factory=lambda: ["en"])
    max_tokens: int = 512
    confidence_semantics: str = "uncalibrated model score; not a probability of attack"
    notes: str = ""


@dataclass(frozen=True)
class ClassifierOutput:
    label: str
    score: float  # score of ``label``


class ClassifierAdapter(Protocol):
    card: ModelCard

    def classify(self, texts: list[str]) -> list[ClassifierOutput]: ...


class HFTextClassifierAdapter:
    """Hugging Face sequence-classification adapter (lazy imports, offline by default)."""

    def __init__(
        self,
        model_id_or_path: str,
        *,
        license: str = "unspecified (user must verify)",  # noqa: A002
        allow_download: bool = False,
        device: str = "cpu",
        max_tokens: int = 512,
        label_names: dict[int, str] | None = None,
    ) -> None:
        try:
            import torch  # type: ignore[import-not-found]  # noqa: F401
            from transformers import (  # type: ignore[import-not-found]
                AutoModelForSequenceClassification,
                AutoTokenizer,
            )
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise RuntimeError(
                "Optional model support requires: pip install 'promptguard-oss[model]'"
            ) from exc
        local_only = not allow_download
        self._tok = AutoTokenizer.from_pretrained(model_id_or_path, local_files_only=local_only)
        self._model = AutoModelForSequenceClassification.from_pretrained(
            model_id_or_path, local_files_only=local_only
        ).to(device)
        self._model.eval()
        self._device = device
        self._max_tokens = max_tokens
        self._labels = label_names or {int(k): v for k, v in self._model.config.id2label.items()}
        self.card = ModelCard(
            model_id=str(model_id_or_path), license=license, max_tokens=max_tokens
        )

    def classify(
        self, texts: list[str]
    ) -> list[ClassifierOutput]:  # pragma: no cover - needs weights
        import torch

        enc = self._tok(
            texts, return_tensors="pt", truncation=True, max_length=self._max_tokens, padding=True
        )
        enc = {k: v.to(self._device) for k, v in enc.items()}
        with torch.no_grad():
            probs = torch.softmax(self._model(**enc).logits, dim=-1)
        out = []
        for row in probs:
            idx = int(row.argmax())
            out.append(ClassifierOutput(self._labels.get(idx, str(idx)), float(row[idx])))
        return out


DEFAULT_LABEL_CATEGORY: dict[str, Category] = {
    "injection": Category.CONTEXT_INJECTION,
    "label_1": Category.CONTEXT_INJECTION,
    "malicious": Category.CONTEXT_INJECTION,
    "jailbreak": Category.JAILBREAK_FRAMING,
}
BENIGN_LABELS = frozenset({"benign", "label_0", "safe", "legit", "legitimate"})


class ClassifierDetector(Detector):
    """Runs an adapter over overlapping chunks. Optional, never required."""

    id = "classifier"
    name = "Optional local classifier"
    description = "Wraps a user-supplied local model; scores are uncalibrated signals."
    required = False
    capabilities = ("semantic", "model")

    def __init__(
        self,
        adapter: ClassifierAdapter,
        *,
        chunk_chars: int = 1500,
        overlap_chars: int = 150,
        max_chunks: int = 32,
        timeout_s: float = 10.0,
        medium_threshold: float = 0.5,
        high_threshold: float = 0.9,
        label_category: dict[str, Category] | None = None,
    ) -> None:
        self.adapter = adapter
        self.chunk_chars, self.overlap_chars = chunk_chars, overlap_chars
        self.max_chunks, self.timeout_s = max_chunks, timeout_s
        self.medium_threshold, self.high_threshold = medium_threshold, high_threshold
        self.label_category = {**DEFAULT_LABEL_CATEGORY, **(label_category or {})}
        self.version = adapter.card.version
        self.categories = tuple(
            set(self.label_category.values()) | {Category.AMBIGUOUS_LOW_CONFIDENCE}
        )
        self._pool = cf.ThreadPoolExecutor(max_workers=1, thread_name_prefix="pg-classifier")

    def run(self, ctx: ScanContext) -> list[Finding]:
        spans = chunk_spans(len(ctx.text), self.chunk_chars, self.overlap_chars)
        truncated = len(spans) > self.max_chunks
        spans = spans[: self.max_chunks]
        ctx.config["classifier_chunks"] = len(spans)
        if truncated:
            ctx.config.setdefault("limitations", []).append(
                f"classifier scanned only the first {self.max_chunks} chunks"
            )
        fut = self._pool.submit(self.adapter.classify, [ctx.text[s:e] for s, e in spans])
        outputs = fut.result(timeout=self.timeout_s)  # TimeoutError -> DetectorError upstream
        findings: list[Finding] = []
        for i, ((s, e), out) in enumerate(zip(spans, outputs, strict=True)):
            label = out.label.lower()
            if label in BENIGN_LABELS or out.score < self.medium_threshold:
                continue
            cat = self.label_category.get(label, Category.AMBIGUOUS_LOW_CONFIDENCE)
            sev = Severity.HIGH if out.score >= self.high_threshold else Severity.MEDIUM
            findings.append(
                self.make(
                    ctx,
                    category=cat,
                    severity=sev,
                    explanation=(
                        f"Local model '{self.adapter.card.model_id}' labelled this chunk '{out.label}' "
                        f"(raw score {out.score:.2f}; uncalibrated)."
                    ),
                    spans=[(s, e)],
                    rule_id=f"MODEL-{label}",
                    score=out.score,
                    confidence=min(out.score, 1.0),
                    metadata={
                        "chunk_index": i,
                        "label": out.label,
                        "model": self.adapter.card.model_dump(),
                    },
                )
            )
        return findings

    def manifest_extra(self) -> dict[str, Any]:
        return self.adapter.card.model_dump()

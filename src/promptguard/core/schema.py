"""Typed data contracts shared by every PromptGuard component.

Design notes
------------
* ``Finding`` is *evidence*, not a verdict. ``PolicyDecision`` is a *recommendation*
  that the host application must enforce itself.
* ``confidence`` is an author-assigned heuristic weight (rules) or a raw model score
  (classifiers). Neither is a calibrated probability.
* Offsets are Unicode code-point offsets into the **original** input text.
"""

from __future__ import annotations

import datetime as dt
import enum
import hashlib
import uuid
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

SCHEMA_VERSION = "1.0"


_SEVERITY_ORDER = ("informational", "low", "medium", "high", "critical")
_ACTION_ORDER = ("allow", "allow_with_monitoring", "sanitize", "review", "block")


class _OrderedMixin:
    """Total order by position in ``_order_names`` (defined by each enum)."""

    value: str

    @property
    def rank(self) -> int:
        return self._order_names().index(self.value)

    @classmethod
    def _order_names(cls) -> tuple[str, ...]:
        raise NotImplementedError

    def __lt__(self, other: object) -> bool:
        return isinstance(other, type(self)) and self.rank < other.rank

    def __le__(self, other: object) -> bool:
        return isinstance(other, type(self)) and self.rank <= other.rank

    def __gt__(self, other: object) -> bool:
        return isinstance(other, type(self)) and self.rank > other.rank

    def __ge__(self, other: object) -> bool:
        return isinstance(other, type(self)) and self.rank >= other.rank


class Severity(_OrderedMixin, str, enum.Enum):
    """Severity of a finding and risk level of an aggregate assessment."""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def _order_names(cls) -> tuple[str, ...]:
        return _SEVERITY_ORDER

    def bump(self, steps: int = 1, cap: Severity | None = None) -> Severity:
        idx = min(max(self.rank + steps, 0), len(_SEVERITY_ORDER) - 1)
        out = Severity(_SEVERITY_ORDER[idx])
        return min(out, cap) if cap is not None else out


class Action(_OrderedMixin, str, enum.Enum):
    """Policy recommendation. Higher rank = more restrictive."""

    ALLOW = "allow"
    ALLOW_WITH_MONITORING = "allow_with_monitoring"
    SANITIZE = "sanitize"
    REVIEW = "review"
    BLOCK = "block"

    @classmethod
    def _order_names(cls) -> tuple[str, ...]:
        return _ACTION_ORDER


class Category(str, enum.Enum):
    INSTRUCTION_OVERRIDE = "instruction_override"
    SYSTEM_IMPERSONATION = "system_impersonation"
    PROMPT_DISCLOSURE = "prompt_disclosure"
    TOOL_INVOCATION_MANIPULATION = "tool_invocation_manipulation"
    DATA_EXFILTRATION = "data_exfiltration"
    TRUST_BOUNDARY_MANIPULATION = "trust_boundary_manipulation"
    JAILBREAK_FRAMING = "jailbreak_framing"
    OBFUSCATION_EVASION = "obfuscation_evasion"
    CONTEXT_INJECTION = "context_injection"
    MULTI_STEP_COERCION = "multi_step_coercion"
    BENIGN_SECURITY_DISCUSSION = "benign_security_discussion"
    AMBIGUOUS_LOW_CONFIDENCE = "ambiguous_low_confidence"


#: Categories that express intent to *act* on or move data (used for critical escalation).
ACTION_INTENT_CATEGORIES = frozenset(
    {Category.DATA_EXFILTRATION, Category.TOOL_INVOCATION_MANIPULATION}
)
#: Categories describing attempts to take over the instruction hierarchy.
HIERARCHY_CATEGORIES = frozenset(
    {
        Category.INSTRUCTION_OVERRIDE,
        Category.SYSTEM_IMPERSONATION,
        Category.TRUST_BOUNDARY_MANIPULATION,
        Category.JAILBREAK_FRAMING,
        Category.CONTEXT_INJECTION,
        Category.MULTI_STEP_COERCION,
    }
)
#: Categories that never contribute to risk level (analyst context only).
NON_RISK_CATEGORIES = frozenset({Category.BENIGN_SECURITY_DISCUSSION})


class SourceType(str, enum.Enum):
    TRUSTED_INSTRUCTION = "trusted_instruction"
    USER_INPUT = "user_input"
    RETRIEVED_CONTENT = "retrieved_content"
    TOOL_OUTPUT = "tool_output"
    THIRD_PARTY_DOCUMENT = "third_party_document"
    OCR_TRANSCRIPT = "ocr_transcript"
    AGENT_PLAN = "agent_plan"
    UNKNOWN = "unknown"

    @property
    def is_third_party(self) -> bool:
        """True for content not typed by the end user: an attacker can influence it indirectly.

        Agent plans are included because they are model-generated from untrusted context.
        """
        return self in _THIRD_PARTY


_THIRD_PARTY = frozenset(
    {
        SourceType.RETRIEVED_CONTENT,
        SourceType.TOOL_OUTPUT,
        SourceType.THIRD_PARTY_DOCUMENT,
        SourceType.OCR_TRANSCRIPT,
        SourceType.AGENT_PLAN,
        SourceType.UNKNOWN,
    }
)


class TrustLevel(str, enum.Enum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    UNKNOWN = "unknown"


DEFAULT_PROFILE_FOR_SOURCE: dict[SourceType, str] = {
    SourceType.TRUSTED_INSTRUCTION: "trusted-instruction",
    SourceType.USER_INPUT: "user-input",
    SourceType.RETRIEVED_CONTENT: "retrieved-document",
    SourceType.THIRD_PARTY_DOCUMENT: "retrieved-document",
    SourceType.TOOL_OUTPUT: "tool-output",
    SourceType.AGENT_PLAN: "agent-plan",
    SourceType.OCR_TRANSCRIPT: "multimodal-transcript",
    SourceType.UNKNOWN: "retrieved-document",
}


class InputEnvelope(BaseModel):
    """Text plus the trust context it arrived in.

    Trust labels are *metadata*: they select analysis/policy behaviour but do not by
    themselves isolate anything from the model.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    text: str
    source_type: SourceType = SourceType.USER_INPUT
    trust_level: TrustLevel | None = None
    context_profile: str | None = Field(default=None, max_length=64)
    language_hint: str | None = Field(default=None, max_length=16)
    source_id: str | None = Field(default=None, max_length=256)
    content_type: str = Field(default="text/plain", pattern=r"^text/(plain|html)$")
    metadata: dict[str, Any] = Field(default_factory=dict)
    input_id: str = Field(default_factory=lambda: uuid.uuid4().hex, max_length=64)

    @field_validator("metadata")
    @classmethod
    def _bounded_metadata(cls, v: dict[str, Any]) -> dict[str, Any]:
        if len(v) > 32:
            raise ValueError("metadata may contain at most 32 keys")
        return v

    @property
    def effective_trust(self) -> TrustLevel:
        if self.trust_level is not None:
            return self.trust_level
        if self.source_type is SourceType.TRUSTED_INSTRUCTION:
            return TrustLevel.TRUSTED
        if self.source_type is SourceType.UNKNOWN:
            return TrustLevel.UNKNOWN
        return TrustLevel.UNTRUSTED


class Span(BaseModel):
    model_config = ConfigDict(frozen=True)
    start: int = Field(ge=0)
    end: int = Field(ge=0)


class Evidence(BaseModel):
    span: Span
    view: str = "original"
    snippet: str = ""
    normalized_snippet: str | None = None


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


class Finding(BaseModel):
    finding_id: str
    detector_id: str
    detector_version: str
    category: Category
    severity: Severity
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    score: float | None = None
    rule_id: str | None = None
    evidence: list[Evidence] = Field(default_factory=list)
    explanation: str
    normalization_notes: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    timestamp: dt.datetime = Field(default_factory=utcnow)

    @property
    def spans(self) -> list[Span]:
        return [e.span for e in self.evidence]


def make_finding_id(
    input_id: str, detector_id: str, rule_id: str | None, start: int, end: int
) -> str:
    """Deterministic id: identical input + detector output => identical id."""
    raw = f"{input_id}|{detector_id}|{rule_id or ''}|{start}|{end}".encode()
    return "f_" + hashlib.sha256(raw).hexdigest()[:16]


class DetectorError(BaseModel):
    detector_id: str
    error_type: str
    message: str
    required: bool = True


class RiskAssessment(BaseModel):
    """Transparent aggregation of findings. ``score`` is an ordinal ranking aid only."""

    level: Severity
    score: float = Field(ge=0.0, le=1.0)
    score_note: str = "Ordinal ranking score; NOT a calibrated probability."
    contributing_finding_ids: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    categories: list[Category] = Field(default_factory=list)
    effective_severities: dict[str, Severity] = Field(default_factory=dict)


class PolicyDecision(BaseModel):
    """Recommendation only. The application must enforce it; it grants no permissions."""

    action: Action
    reason_codes: list[str] = Field(default_factory=list)
    policy_id: str
    policy_version: str
    policy_hash: str
    profile: str
    review_required: bool = False
    indeterminate: bool = False
    sanitize_plan: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)


class Coverage(BaseModel):
    chars_total: int
    chars_scanned: int
    truncated: bool = False
    views: list[str] = Field(default_factory=list)
    classifier_chunks: int = 0


class ScanResult(BaseModel):
    schema_version: str = SCHEMA_VERSION
    input_id: str
    engine_version: str
    scanned_at: dt.datetime = Field(default_factory=utcnow)
    findings: list[Finding] = Field(default_factory=list)
    risk: RiskAssessment
    decision: PolicyDecision
    coverage: Coverage
    errors: list[DetectorError] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    duration_ms: float = 0.0
    detector_timings_ms: dict[str, float] = Field(default_factory=dict)
    versions: dict[str, str] = Field(default_factory=dict)


class DetectorManifest(BaseModel):
    id: str
    version: str
    name: str
    description: str
    capabilities: list[str] = Field(default_factory=list)
    categories: list[Category] = Field(default_factory=list)
    supported_contexts: list[str] = Field(default_factory=list)
    dependencies: list[str] = Field(default_factory=list)
    required: bool = True
    config_schema: dict[str, Any] = Field(default_factory=dict)
    languages: list[str] = Field(default_factory=lambda: ["en"])


class AuditEvent(BaseModel):
    timestamp: dt.datetime = Field(default_factory=utcnow)
    actor: str
    action: str
    config_version: str | None = None
    object_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

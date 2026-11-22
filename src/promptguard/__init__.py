"""PromptGuard: transparent, privacy-first prompt-injection detection and evaluation.

PromptGuard produces *risk signals and policy recommendations*. It does not and cannot
guarantee that prompt injection is prevented; see docs/limitations.md.
"""

from promptguard._version import __version__
from promptguard.core.engine import Scanner, ScannerConfig, scan
from promptguard.core.schema import (
    Action,
    Category,
    Finding,
    InputEnvelope,
    PolicyDecision,
    ScanResult,
    Severity,
    SourceType,
    TrustLevel,
)

__all__ = [
    "Action",
    "Category",
    "Finding",
    "InputEnvelope",
    "PolicyDecision",
    "ScanResult",
    "Scanner",
    "ScannerConfig",
    "Severity",
    "SourceType",
    "TrustLevel",
    "__version__",
    "scan",
]

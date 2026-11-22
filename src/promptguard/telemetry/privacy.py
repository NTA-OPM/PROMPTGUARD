"""Content-safe structured logging and in-process metrics.

Raw input text, evidence snippets and explanations are NEVER written by this module.
Correlation uses an HMAC of the input with a per-process random salt (override with
``PROMPTGUARD_LOG_SALT`` for cross-process correlation); short inputs are therefore not
trivially reversible by dictionary attack without the salt.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import threading
from collections import Counter
from typing import Any

from promptguard.core.schema import ScanResult

_LOG = logging.getLogger("promptguard.scan")
_PROCESS_SALT = os.environ.get("PROMPTGUARD_LOG_SALT", "").encode() or secrets.token_bytes(16)


def correlation_hash(text: str, salt: bytes | None = None) -> str:
    return hmac.new(
        salt or _PROCESS_SALT, text.encode("utf-8", "surrogatepass"), hashlib.sha256
    ).hexdigest()[:16]


def safe_log_record(
    result: ScanResult, *, text: str | None = None, salt: bytes | None = None
) -> dict[str, Any]:
    """Metadata-only record: category/severity/decision/timing, no content."""
    rec: dict[str, Any] = {
        "event": "promptguard.scan",
        "input_id": result.input_id,
        "action": result.decision.action.value,
        "profile": result.decision.profile,
        "risk_level": result.risk.level.value,
        "categories": sorted({f.category.value for f in result.findings}),
        "finding_count": len(result.findings),
        "max_severity": max(
            (f.severity for f in result.findings), default=None, key=lambda s: s.rank if s else -1
        ),
        "reason_codes": result.decision.reason_codes,
        "indeterminate": result.decision.indeterminate,
        "truncated": result.coverage.truncated,
        "chars": result.coverage.chars_total,
        "duration_ms": result.duration_ms,
        "engine_version": result.engine_version,
        "policy": f"{result.decision.policy_id}@{result.decision.policy_version}",
    }
    if rec["max_severity"] is not None:
        rec["max_severity"] = rec["max_severity"].value
    if text is not None:
        rec["input_hmac"] = correlation_hash(text, salt)
    return rec


def logging_hook(result: ScanResult) -> None:
    """Scanner hook that emits one content-free JSON log line per scan."""
    _LOG.info(json.dumps(safe_log_record(result), sort_keys=True))


class Metrics:
    """Tiny dependency-free counter set with Prometheus text exposition."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._c: Counter[tuple[str, tuple[tuple[str, str], ...]]] = Counter()
        self._sum_ms = 0.0
        self._n = 0

    def inc(self, name: str, **labels: str) -> None:
        with self._lock:
            self._c[(name, tuple(sorted(labels.items())))] += 1

    def observe_scan(self, result: ScanResult) -> None:
        self.inc(
            "promptguard_scans_total",
            action=result.decision.action.value,
            profile=result.decision.profile,
        )
        for cat in {f.category.value for f in result.findings}:
            self.inc("promptguard_findings_total", category=cat)
        with self._lock:
            self._sum_ms += result.duration_ms
            self._n += 1

    def render(self) -> str:
        lines = [
            "# HELP promptguard_scans_total Scans by recommended action.",
            "# TYPE promptguard_scans_total counter",
        ]
        with self._lock:
            for (name, labels), v in sorted(self._c.items()):
                lab = ",".join(f'{k}="{_esc(val)}"' for k, val in labels)
                lines.append(f"{name}{{{lab}}} {v}" if lab else f"{name} {v}")
            lines += [
                "# TYPE promptguard_scan_duration_ms_sum counter",
                f"promptguard_scan_duration_ms_sum {self._sum_ms:.3f}",
                "# TYPE promptguard_scan_duration_ms_count counter",
                f"promptguard_scan_duration_ms_count {self._n}",
            ]
        return "\n".join(lines) + "\n"


def _esc(v: str) -> str:
    return v.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")

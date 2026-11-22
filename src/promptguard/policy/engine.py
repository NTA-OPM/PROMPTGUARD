"""Policy model, validation and evaluation.

Detection and policy are separate: detectors return findings; the policy maps an
aggregated risk assessment + context to a *recommendation*. A policy can never authorize
a tool action; the host application keeps its own authorization.
"""

from __future__ import annotations

import hashlib
import json
import re
from importlib import resources
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from promptguard.core.schema import (
    Action,
    Category,
    DetectorError,
    Finding,
    InputEnvelope,
    PolicyDecision,
    RiskAssessment,
    Severity,
)

REQUIRED_PROFILES = (
    "user-input",
    "retrieved-document",
    "tool-output",
    "agent-plan",
    "multimodal-transcript",
    "high-risk-action",
    "trusted-instruction",
)
_SEMVER = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
ADVISORY = (
    "Recommendation only. The application must enforce it and keep its own authorization checks."
)


class PolicyError(ValueError):
    """Raised for invalid or tampered policy files."""


_FAILURE_ACTION = {
    "fail_open": Action.ALLOW_WITH_MONITORING,
    "review": Action.REVIEW,
    "fail_closed": Action.BLOCK,
}


class CategoryOverride(BaseModel):
    model_config = ConfigDict(extra="forbid")
    category: Category
    min_severity: Severity
    action: Action


class ProfilePolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    description: str = ""
    risk_actions: dict[Severity, Action]
    failure_mode: str = "fail_open"
    truncation_action: Action = Action.ALLOW_WITH_MONITORING
    quoted_downgrade: bool = False
    sanitize_invisible: bool = True
    critical_on_action_intent: bool = False
    category_overrides: list[CategoryOverride] = Field(default_factory=list)

    @field_validator("failure_mode")
    @classmethod
    def _fm(cls, v: str) -> str:
        if v not in _FAILURE_ACTION:
            raise ValueError(f"failure_mode must be one of {sorted(_FAILURE_ACTION)}")
        return v

    @model_validator(mode="after")
    def _check(self) -> ProfilePolicy:
        missing = [s.value for s in Severity if s not in self.risk_actions]
        if missing:
            raise ValueError(f"risk_actions missing levels: {missing}")
        prev = Action.ALLOW
        for s in Severity:
            a = self.risk_actions[s]
            if a < prev:
                raise ValueError(
                    f"risk_actions must be non-decreasing; {s.value}={a.value} is weaker than a lower level"
                )
            prev = a
        if self.risk_actions[Severity.CRITICAL] < Action.REVIEW:
            raise ValueError(
                "critical risk must map to review or block (policy would weaken controls)"
            )
        if self.risk_actions[Severity.HIGH] < Action.ALLOW_WITH_MONITORING:
            raise ValueError("high risk must be at least monitored")
        return self

    @property
    def failure_action(self) -> Action:
        return _FAILURE_ACTION[self.failure_mode]


class Policy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    policy_id: str = Field(pattern=r"^[a-z0-9][a-z0-9_.-]{0,63}$")
    version: str
    description: str = ""
    checksum: str | None = None
    profiles: dict[str, ProfilePolicy]

    @field_validator("version")
    @classmethod
    def _v(cls, v: str) -> str:
        if not _SEMVER.match(v):
            raise ValueError("version must be semantic (e.g. 1.0.0)")
        return v

    @model_validator(mode="after")
    def _profiles(self) -> Policy:
        missing = [p for p in REQUIRED_PROFILES if p not in self.profiles]
        if missing:
            raise ValueError(f"policy missing required profiles: {missing}")
        return self

    def canonical_hash(self) -> str:
        body = self.model_dump(mode="json", exclude={"checksum"})
        return hashlib.sha256(
            json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    def profile(self, name: str) -> ProfilePolicy:
        try:
            return self.profiles[name]
        except KeyError as exc:
            raise PolicyError(f"unknown policy profile: {name!r}") from exc


def parse_policy(data: bytes | str) -> Policy:
    try:
        raw = yaml.safe_load(data)
        if not isinstance(raw, dict):
            raise PolicyError("policy file must contain a mapping")
        policy = Policy.model_validate(raw)
    except (yaml.YAMLError, ValidationError) as exc:
        raise PolicyError(f"invalid policy: {exc}") from exc
    if policy.checksum is not None and policy.checksum != policy.canonical_hash():
        raise PolicyError(
            "policy checksum mismatch: file was modified after hashing "
            f"(expected {policy.canonical_hash()})"
        )
    return policy


def load_policy(path: str | Path | None = None) -> Policy:
    if path is None:
        data = resources.files("promptguard.data.policies").joinpath("default.yaml").read_bytes()
        return parse_policy(data)
    return parse_policy(Path(path).read_bytes())


def evaluate_policy(
    policy: Policy,
    profile_name: str,
    assessment: RiskAssessment,
    findings: list[Finding],
    *,
    errors: list[DetectorError],
    truncated: bool,
    limitations: list[str],
    effective: dict[str, Severity],
) -> PolicyDecision:
    prof = policy.profile(profile_name)
    reasons: list[str] = []
    risk_findings = [f for f in findings if f.finding_id in assessment.contributing_finding_ids]

    if risk_findings:
        action = prof.risk_actions[assessment.level]
        reasons.append(f"RISK_LEVEL_{assessment.level.value.upper()}")
        reasons.extend(assessment.reasons)
    else:
        action = Action.ALLOW
    # per-category overrides can only escalate
    for ov in prof.category_overrides:
        for f in risk_findings:
            if (
                f.category is ov.category
                and effective.get(f.finding_id, f.severity) >= ov.min_severity
                and ov.action > action
            ):
                action = ov.action
                reasons.append(f"CATEGORY_OVERRIDE:{ov.category.value}")
    for cat in sorted({f.category.value for f in risk_findings}):
        reasons.append(f"CATEGORY:{cat}")

    # Artifact-only findings (invisible/bidi characters) -> documented minimal sanitisation instead
    # of review. Never applied when any other signal is present or the profile opts out.
    sanitize_plan: list[str] = []
    if (
        prof.sanitize_invisible
        and risk_findings
        and assessment.level <= Severity.MEDIUM
        and all(f.metadata.get("sanitizable") for f in risk_findings)
    ):
        action = Action.SANITIZE
        reasons.append("SANITIZABLE_ARTIFACTS_ONLY")
    if action is Action.SANITIZE:
        sanitize_plan = ["remove_invisible_and_control_characters"]

    if truncated:
        reasons.append("TRUNCATED_INPUT")
        if prof.truncation_action > action:
            action = prof.truncation_action
    indeterminate = False
    req_errors = [e for e in errors if e.required]
    if req_errors:
        indeterminate = True
        for e in req_errors:
            reasons.append(f"DETECTOR_ERROR:{e.detector_id}")
        reasons.append(f"FAILURE_MODE:{prof.failure_mode}")
        if prof.failure_action > action:
            action = prof.failure_action
    elif errors:
        reasons.extend(f"OPTIONAL_DETECTOR_ERROR:{e.detector_id}" for e in errors)

    if not reasons:
        reasons.append("NO_ACTIONABLE_FINDINGS")
    return PolicyDecision(
        action=action,
        reason_codes=list(dict.fromkeys(reasons)),
        policy_id=policy.policy_id,
        policy_version=policy.version,
        policy_hash=policy.canonical_hash(),
        profile=profile_name,
        review_required=action in (Action.REVIEW,),
        indeterminate=indeterminate,
        sanitize_plan=sanitize_plan,
        limitations=[*limitations, ADVISORY],
        finding_ids=[f.finding_id for f in risk_findings],
    )


def resolve_profile(policy: Policy, envelope: InputEnvelope) -> str:
    from promptguard.core.schema import DEFAULT_PROFILE_FOR_SOURCE

    name = envelope.context_profile or DEFAULT_PROFILE_FOR_SOURCE[envelope.source_type]
    policy.profile(name)  # validates existence
    return name


def policy_summary(policy: Policy) -> dict[str, Any]:
    return {
        "policy_id": policy.policy_id,
        "version": policy.version,
        "hash": policy.canonical_hash(),
        "profiles": sorted(policy.profiles),
    }

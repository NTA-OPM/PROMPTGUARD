# Policy guide

Detection and policy are separate. The policy maps an aggregated risk level, context and
failure state to a **recommendation**; the application enforces it. A policy can never grant a
tool permission.

```yaml
policy_id: my-policy
version: 1.0.0
checksum: <output of `promptguard policy hash my-policy.yaml`>   # optional tamper check
profiles:
  user-input:            # required: user-input, retrieved-document, tool-output, agent-plan,
    failure_mode: fail_open        # multimodal-transcript, high-risk-action, trusted-instruction
    quoted_downgrade: true
    sanitize_invisible: true
    truncation_action: allow_with_monitoring
    critical_on_action_intent: false
    risk_actions: {informational: allow_with_monitoring, low: allow_with_monitoring,
                   medium: review, high: review, critical: block}
    category_overrides:    # may only escalate, never weaken
      - {category: data_exfiltration, min_severity: medium, action: block}
```

Actions (increasing restriction): `allow` < `allow_with_monitoring` < `sanitize` < `review` < `block`.

## Validation rules (`promptguard policy validate`)
all required profiles present; thresholds non-decreasing with risk; `critical` ≥ `review`;
`high` ≥ monitor; unknown keys rejected; failure mode ∈ {`fail_open`, `review`, `fail_closed`};
semantic version; checksum (if present) must match the canonical hash.

## Failure modes
`fail_open → allow_with_monitoring`, `review → review`, `fail_closed → block`. Applied when a
**required** detector raises. The decision then carries `indeterminate: true` and
`DETECTOR_ERROR:<id>` reason codes. Optional detectors (e.g. the classifier) failing never makes a
decision indeterminate. Defaults: user-input and trusted-instruction fail open; third-party content
profiles require review; agent-plan and high-risk-action fail closed.

## Sanitize
`sanitize` means: remove invisible/control characters only (joiners/variation selectors kept next to
non-ASCII text so emoji and Indic/Persian text survive). It never deletes words. Used only when
*every* risk finding is such an artifact and the profile allows it.

## Profile selection
`context_profile` on the envelope, else derived from `source_type`
(`user_input→user-input`, `retrieved_content/third_party_document/unknown→retrieved-document`,
`tool_output→tool-output`, `agent_plan→agent-plan`, `ocr_transcript→multimodal-transcript`,
`trusted_instruction→trusted-instruction`). Pick `high-risk-action` explicitly for content that can
influence irreversible actions.

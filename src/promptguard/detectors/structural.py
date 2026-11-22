"""Structural, Unicode and discussion-context detectors."""

from __future__ import annotations

import re
import unicodedata

from promptguard.core.schema import Category, Finding, Severity
from promptguard.detectors.base import Detector, ScanContext
from promptguard.normalization.pipeline import (
    _JOINERS,
    BIDI_CONTROLS,
    CONFUSABLES,
    html_hidden_spans,
    is_invisible,
    is_tag_char,
)

# ---------------------------------------------------------------------------- structural

_ROLE_LABEL = re.compile(
    r"^[ \t>]*(?:#{1,6}[ \t]*)?(?:\*\*)?\[?(?P<role>system|developer|assistant|user|human|ai|admin)\]?(?:\*\*)?[ \t]*[:>\]]",
    re.I | re.M,
)
_CONTROL_TOKEN = re.compile(
    r"<\|(?:im_start|im_end|system|user|assistant|endoftext|eot_id|start_header_id|end_header_id|begin_of_text|[a-z_]{2,24})\|>"
    r"|\[/?INST\]|<<\s*/?\s*SYS\s*>>|</s>|<s>\s*\[INST"
    r"|(?:^|\n)#{2,}[ \t]*(?:instruction|system|response)[ \t]*:",
    re.I,
)
_XML_ROLE_TAG = re.compile(
    r"</?(?:system|instructions?|system_prompt|developer|assistant|admin|prompt|tool_call|function_call|tool_response|im_start)\b[^>\n]{0,60}>",
    re.I,
)
_JSON_ROLE = re.compile(r"""["']role["']\s*:\s*["'](?:system|developer)["']""", re.I)


class StructuralDetector(Detector):
    id = "structural"
    name = "Structural / trust-boundary detector"
    description = (
        "Fake role labels, chat-template control tokens, role-like markup, JSON message "
        "structures and hidden HTML content."
    )
    capabilities = ("structure", "html-hidden-content")
    categories = (
        Category.TRUST_BOUNDARY_MANIPULATION,
        Category.CONTEXT_INJECTION,
        Category.SYSTEM_IMPERSONATION,
    )

    def run(self, ctx: ScanContext) -> list[Finding]:
        out: list[Finding] = []
        text = ctx.text
        third = ctx.third_party

        for m in _ROLE_LABEL.finditer(text):
            role = m.group("role").lower()
            privileged = role in {"system", "developer", "admin"}
            if privileged:
                sev = Severity.HIGH if third else Severity.MEDIUM
            else:
                sev = Severity.MEDIUM if third else Severity.LOW
            out.append(
                self.make(
                    ctx,
                    category=Category.SYSTEM_IMPERSONATION
                    if privileged
                    else Category.TRUST_BOUNDARY_MANIPULATION,
                    severity=sev,
                    explanation=(
                        f"Line begins with a '{role}' role label. Role labels inside content can "
                        "blur the boundary between data and instructions."
                    ),
                    spans=[(m.start("role"), m.end("role"))],
                    rule_id="PG-ST-ROLE",
                    confidence=0.6 if privileged else 0.4,
                )
            )
            if len(out) >= 10:
                break

        for m in list(_CONTROL_TOKEN.finditer(text))[:5]:
            out.append(
                self.make(
                    ctx,
                    category=Category.TRUST_BOUNDARY_MANIPULATION,
                    severity=Severity.HIGH,
                    explanation="Chat-template control token or instruction-section marker found in content.",
                    spans=[(m.start(), m.end())],
                    rule_id="PG-ST-CTRL",
                    confidence=0.8,
                )
            )
        for m in list(_XML_ROLE_TAG.finditer(text))[:5]:
            out.append(
                self.make(
                    ctx,
                    category=Category.TRUST_BOUNDARY_MANIPULATION,
                    severity=Severity.HIGH if third else Severity.MEDIUM,
                    explanation="Markup that mimics a system/instruction/tool boundary.",
                    spans=[(m.start(), m.end())],
                    rule_id="PG-ST-TAG",
                    confidence=0.55,
                )
            )
        for m in list(_JSON_ROLE.finditer(text))[:3]:
            out.append(
                self.make(
                    ctx,
                    category=Category.TRUST_BOUNDARY_MANIPULATION,
                    severity=Severity.HIGH if third else Severity.MEDIUM,
                    explanation="Embedded chat-message structure assigning a privileged role.",
                    spans=[(m.start(), m.end())],
                    rule_id="PG-ST-JSON",
                    confidence=0.6,
                )
            )

        if ctx.envelope.content_type == "text/html":
            for s, e in html_hidden_spans(text)[:5]:
                if len(text[s:e].split()) >= 3:
                    out.append(
                        self.make(
                            ctx,
                            category=Category.CONTEXT_INJECTION,
                            severity=Severity.LOW,
                            explanation=(
                                "Text that is not visible to a human reader (comment or visually "
                                "hidden element) but is visible to a model."
                            ),
                            spans=[(s, e)],
                            rule_id="PG-ST-HIDDEN",
                            confidence=0.4,
                            metadata={"hidden": True},
                        )
                    )
        return out


# ---------------------------------------------------------------------------- unicode


def _runs(text: str, pred) -> list[tuple[int, int]]:  # type: ignore[no-untyped-def]
    runs: list[tuple[int, int]] = []
    i, n = 0, len(text)
    while i < n:
        if pred(text[i]):
            j = i
            while j < n and pred(text[j]):
                j += 1
            runs.append((i, j))
            i = j
        else:
            i += 1
    return runs


class UnicodeDetector(Detector):
    id = "unicode"
    name = "Unicode / encoding anomaly detector"
    description = (
        "Invisible and bidi control characters, Unicode tag smuggling, mixed-script "
        "homoglyphs, compatibility forms and combining-mark abuse."
    )
    capabilities = ("unicode", "obfuscation-signals")
    categories = (Category.OBFUSCATION_EVASION,)

    def run(self, ctx: ScanContext) -> list[Finding]:
        text = ctx.text
        out: list[Finding] = []
        reps = ctx.reps

        # --- tag characters (ASCII smuggling); skip emoji subdivision-flag sequences
        tag_runs = [
            (s, e)
            for s, e in _runs(text, is_tag_char)
            if not (s > 0 and text[s - 1] == "\U0001f3f4")
        ]
        if tag_runs:
            decoded = [
                "".join(chr(ord(c) - 0xE0000) for c in text[s:e] if 0xE0020 <= ord(c) <= 0xE007E)
                for s, e in tag_runs
            ]
            out.append(
                self.make(
                    ctx,
                    category=Category.OBFUSCATION_EVASION,
                    severity=Severity.HIGH,
                    explanation=(
                        "Invisible Unicode tag characters encode hidden ASCII text "
                        f"({sum(len(d) for d in decoded)} hidden characters)."
                    ),
                    spans=tag_runs[:5],
                    rule_id="PG-UN-TAGS",
                    confidence=0.85,
                    normalized_snippets=[d for d in decoded[:5]],
                )
            )

        # --- other invisible characters
        suspicious: list[tuple[int, int]] = []
        inside_word = 0
        for s, e in _runs(text, lambda c: is_invisible(c) and not is_tag_char(c)):
            if s == 0 and text[0] == "﻿":
                s += 1
                if s >= e:
                    continue
            chunk = text[s:e]
            prev = text[s - 1] if s > 0 else ""
            nxt = text[e] if e < len(text) else ""
            legit_joiner = all(c in _JOINERS or 0xFE00 <= ord(c) <= 0xFE0F for c in chunk) and not (
                prev.isascii() and prev.isalnum()
            )
            if legit_joiner:
                continue
            suspicious.append((s, e))
            if prev.isascii() and prev.isalpha() and nxt.isascii() and nxt.isalpha():
                inside_word += 1
        total_invis = sum(e - s for s, e in suspicious)
        if suspicious:
            sev = Severity.MEDIUM if (inside_word or total_invis >= 3) else Severity.LOW
            out.append(
                self.make(
                    ctx,
                    category=Category.OBFUSCATION_EVASION,
                    severity=sev,
                    explanation=(
                        f"{total_invis} invisible or control character(s) in {len(suspicious)} place(s)"
                        + (f"; {inside_word} split ASCII words" if inside_word else "")
                        + ". They can hide or split instruction keywords."
                    ),
                    spans=suspicious[:5],
                    rule_id="PG-UN-INVIS",
                    confidence=0.6,
                    metadata={
                        "count": total_invis,
                        "inside_word": inside_word,
                        "sanitizable": True,
                    },
                )
            )

        # --- bidi override / isolate controls
        bidi = _runs(text, lambda c: c in BIDI_CONTROLS)
        if bidi:
            out.append(
                self.make(
                    ctx,
                    category=Category.OBFUSCATION_EVASION,
                    severity=Severity.MEDIUM,
                    explanation="Bidirectional override/isolate controls can make displayed text differ from its logical order.",
                    spans=bidi[:5],
                    rule_id="PG-UN-BIDI",
                    confidence=0.65,
                    metadata={"sanitizable": True},
                )
            )

        # --- mixed-script homoglyphs
        mixed: list[tuple[int, int]] = []
        folded_snips: list[str | None] = []
        for m in re.finditer(r"[^\W\d_]{3,}", text):
            tok = m.group()
            has_ascii = any(c.isascii() and c.isalpha() for c in tok)
            conf_chars = [c for c in tok if c in CONFUSABLES]
            if has_ascii and conf_chars:
                mixed.append((m.start(), m.end()))
                folded_snips.append("".join(CONFUSABLES.get(c, c) for c in tok))
        if mixed:
            out.append(
                self.make(
                    ctx,
                    category=Category.OBFUSCATION_EVASION,
                    severity=Severity.MEDIUM,
                    explanation=(
                        f"{len(mixed)} word(s) mix Latin letters with look-alike Cyrillic/Greek letters "
                        "(homoglyph substitution)."
                    ),
                    spans=mixed[:5],
                    rule_id="PG-UN-HOMOGLYPH",
                    confidence=0.65,
                    normalized_snippets=list(folded_snips[:5]),
                )
            )

        # --- compatibility forms (fullwidth / math alphanumerics that fold to ASCII letters)
        compat = [
            i
            for i, ch in enumerate(text)
            if not ch.isascii()
            and unicodedata.category(ch).startswith("L")
            and len(n := unicodedata.normalize("NFKC", ch)) == 1
            and n.isascii()
            and n.isalpha()
        ]
        if len(compat) >= 4:
            out.append(
                self.make(
                    ctx,
                    category=Category.OBFUSCATION_EVASION,
                    severity=Severity.LOW,
                    explanation=f"{len(compat)} letters are Unicode compatibility forms (fullwidth/mathematical) that fold to ASCII.",
                    spans=[(compat[0], compat[0] + 1)],
                    rule_id="PG-UN-COMPAT",
                    confidence=0.5,
                )
            )

        # --- combining-mark abuse
        zalgo = _runs(text, lambda c: unicodedata.category(c) == "Mn")
        zalgo = [(s, e) for s, e in zalgo if e - s >= 4 and (s == 0 or text[s - 1].isascii())]
        if zalgo:
            out.append(
                self.make(
                    ctx,
                    category=Category.OBFUSCATION_EVASION,
                    severity=Severity.LOW,
                    explanation="Excessive stacked combining marks on ASCII text.",
                    spans=zalgo[:3],
                    rule_id="PG-UN-COMBINING",
                    confidence=0.4,
                )
            )

        # --- encoded payloads present (informational; decoded content is also rule-scanned)
        enc = [v for v in reps.views if v.name.startswith(("b64", "pct"))]
        if enc:
            out.append(
                self.make(
                    ctx,
                    category=Category.OBFUSCATION_EVASION,
                    severity=Severity.LOW,
                    explanation=f"{len(enc)} encoded text segment(s) were decoded for analysis (analysis only, never executed).",
                    spans=[v.fixed_span for v in enc[:3] if v.fixed_span],
                    rule_id="PG-UN-ENCODED",
                    confidence=0.4,
                )
            )
        return out


# ---------------------------------------------------------------------------- discussion

_TOPIC = re.compile(
    r"\b(?:prompt[- ]injections?|jailbreak(?:s|ing)?|indirect injections?|adversarial prompts?|red[- ]team(?:ing)?|llm security|owasp)\b",
    re.I,
)
_DISCUSSION = re.compile(
    r"\b(?:attacks?|attackers?|vulnerabilit\w+|detect\w*|defen[cs]e\w*|mitigat\w+|examples?|research|paper|"
    r"prevent\w*|protect\w*|explain\w*|what is|how (?:do|does|can|to)|classif\w+|benchmark\w*|dataset|study)\b",
    re.I,
)


class DiscussionDetector(Detector):
    """Informational only: marks text that *talks about* prompt injection.

    Deliberately **not** used to suppress other findings (an attacker can add such words).
    It exists for analyst triage and for measuring false-positive pressure.
    """

    id = "discussion"
    name = "Security-discussion context marker"
    description = (
        "Flags educational/meta discussion of prompt injection; never suppresses findings."
    )
    required = False
    categories = (Category.BENIGN_SECURITY_DISCUSSION,)

    def run(self, ctx: ScanContext) -> list[Finding]:
        t = _TOPIC.search(ctx.text)
        if not t or not _DISCUSSION.search(ctx.text):
            return []
        return [
            self.make(
                ctx,
                category=Category.BENIGN_SECURITY_DISCUSSION,
                severity=Severity.INFORMATIONAL,
                explanation=(
                    "Text appears to discuss prompt-injection/jailbreak topics. This is a context "
                    "marker only and does not lower the risk of other findings."
                ),
                spans=[(t.start(), t.end())],
                rule_id="PG-DS-001",
                confidence=0.5,
            )
        ]

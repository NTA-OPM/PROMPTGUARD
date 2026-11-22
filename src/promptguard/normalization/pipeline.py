"""Representation / normalization pipeline.

The original text is never modified. We derive additional *views* for analysis; every
view keeps a mapping back to original offsets so evidence spans stay valid.

Views
-----
normalized   NFKC (per code point), invisible/control characters removed, mixed-script
             homoglyphs folded to Latin, spaces collapsed.
invis_space  Like ``normalized`` but invisible characters become spaces (catches
             zero-width characters used as word separators).
relaxed      ``normalized`` with intra-word separators (``_ - .``) and letter-spacing
             (``i g n o r e``) collapsed.
leet         ``relaxed`` with digit/symbol leetspeak folded inside words.
tags         Unicode "tag" characters (U+E0020..E007E) decoded to ASCII.
b64/pct      Bounded decodes of base64 / percent-encoded substrings (depth-limited).
html         Tags blanked out (length preserving), comment bodies and selected
             attributes kept. Never executes or renders anything.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
import urllib.parse
from collections.abc import Iterator
from dataclasses import dataclass, field

NORMALIZATION_VERSION = "1.0.0"

# --- character classes -----------------------------------------------------------------

_INVISIBLE_EXPLICIT = frozenset("­͏؜ᅟᅠ឴឵᠋᠌᠍᠎​‌‍‎‏‪‫‬‭‮⁠⁡⁢⁣⁤⁦⁧⁨⁩⁪⁫⁬⁭⁮⁯ㅤ﻿ﾠ")
BIDI_CONTROLS = frozenset("‪‫‬‭‮⁦⁧⁨⁩")  # embedding/override/isolate (Trojan-Source class)
_JOINERS = frozenset("‌‍")

CONFUSABLES: dict[str, str] = {
    # Cyrillic lower
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i",
    "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h", "ԛ": "q", "ԝ": "w", "ѵ": "v", "ӏ": "l",
    # Cyrillic upper
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P",
    "С": "C", "Т": "T", "Х": "X", "І": "I", "Ј": "J", "Ѕ": "S",
    # Greek
    "ο": "o", "α": "a", "ν": "v", "ρ": "p", "ι": "i", "κ": "k", "υ": "u", "τ": "t",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M",
    "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
}  # fmt: skip

_LEET = str.maketrans(
    {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i"}
)

_TAG_LO, _TAG_HI = 0xE0020, 0xE007E
_VS_SUPP_LO, _VS_SUPP_HI = 0xE0100, 0xE01EF


def is_tag_char(ch: str) -> bool:
    return 0xE0000 <= ord(ch) <= 0xE007F


def is_invisible(ch: str) -> bool:
    cp = ord(ch)
    if ch in _INVISIBLE_EXPLICIT or 0xE0000 <= cp <= 0xE007F or _VS_SUPP_LO <= cp <= _VS_SUPP_HI:
        return True
    if 0xFE00 <= cp <= 0xFE0F:  # variation selectors
        return True
    cat = unicodedata.category(ch)
    if cat == "Cc":
        return ch not in "\t\n\r"
    return cat == "Cf"


def is_script_letter(ch: str, script: str) -> bool:
    if not ch.isalpha():
        return False
    try:
        return unicodedata.name(ch).startswith(script)
    except ValueError:
        return False


# --- views -----------------------------------------------------------------------------


@dataclass(frozen=True)
class View:
    name: str
    text: str
    offsets: tuple[int, ...] | None = None  # original index of each char in ``text``
    fixed_span: tuple[int, int] | None = None  # whole-view evidence span (decoded views)
    note: str = ""

    def to_original(self, start: int, end: int) -> tuple[int, int]:
        if self.fixed_span is not None:
            return self.fixed_span
        assert self.offsets is not None
        if not self.offsets:
            return (0, 0)
        s = self.offsets[min(start, len(self.offsets) - 1)]
        e = self.offsets[min(max(end - 1, start), len(self.offsets) - 1)] + 1
        return (s, max(e, s))


def _identity(text: str, name: str, note: str = "") -> View:
    return View(name, text, tuple(range(len(text))), note=note)


def _sub_view(
    src: View, keep: list[int], new_chars: dict[int, str] | None, name: str, note: str
) -> View:
    """Build a view from ``src`` keeping indices ``keep`` (optionally replacing chars)."""
    assert src.offsets is not None
    chars: list[str] = []
    offs: list[int] = []
    for i in keep:
        chars.append(new_chars[i] if new_chars and i in new_chars else src.text[i])
        offs.append(src.offsets[i])
    return View(name, "".join(chars), tuple(offs), note=note)


@dataclass
class Representations:
    original: str
    views: list[View] = field(default_factory=list)
    stats: dict[str, int] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def by_name(self, name: str) -> View | None:
        return next((v for v in self.views if v.name == name), None)


def build_normalized(
    original: str, *, invisible_as_space: bool = False, collapse_ws: bool = True
) -> tuple[View, dict[str, int]]:
    chars: list[str] = []
    offs: list[int] = []
    stats = {"invisible": 0, "confusable_folded": 0, "compat_changed": 0, "combining_dropped": 0}
    last_space = False
    for i, ch in enumerate(original):
        if is_invisible(ch):
            stats["invisible"] += 1
            if invisible_as_space and not last_space and chars:
                chars.append(" ")
                offs.append(i)
                last_space = True
            continue
        cat = unicodedata.category(ch)
        if cat in ("Zs", "Zl", "Zp") or ch in "\t\x0b\x0c":
            if last_space and collapse_ws:
                continue
            chars.append(" ")
            offs.append(i)
            last_space = True
            continue
        if cat == "Mn" and chars and chars[-1].isascii() and chars[-1].isalpha():
            stats["combining_dropped"] += 1
            continue
        n = unicodedata.normalize("NFKC", ch)
        if n != ch:
            stats["compat_changed"] += 1
        for c in n:
            chars.append(c)
            offs.append(i)
        last_space = False
    text = "".join(chars)
    offsets = tuple(offs)
    # Fold confusables only inside tokens that also contain ASCII letters (mixed-script),
    # so genuine Cyrillic/Greek prose is left untouched.
    out = list(text)
    for m in re.finditer(r"[^\W\d_]+", text):
        tok = m.group()
        if any(c in CONFUSABLES for c in tok) and any(c.isascii() and c.isalpha() for c in tok):
            for j in range(m.start(), m.end()):
                if out[j] in CONFUSABLES:
                    out[j] = CONFUSABLES[out[j]]
                    stats["confusable_folded"] += 1
    name = "invis_space" if invisible_as_space else "normalized"
    return View(
        name, "".join(out), offsets, note="NFKC + invisible removal + homoglyph fold"
    ), stats


_SEP_BETWEEN_LETTERS = re.compile(r"(?<=[^\W\d_])[_\-.*|+~^](?=[^\W\d_])")
# single letters joined by a separator ("f.o.r.g.e.t"): delete the separators, keep word gaps
_SEP_LETTER_RUN = re.compile(r"(?<![^\W_])(?:[^\W\d_][._\-*|+~^]){3,}[^\W\d_](?![^\W_])")
_LETTER_SPACED = re.compile(r"(?<![^\W_])(?:[^\W\d_][ ]){3,}[^\W\d_](?![^\W_])")


def build_relaxed(norm: View) -> View | None:
    """``norm`` must be built with ``collapse_ws=False`` so word gaps stay distinguishable."""
    text = norm.text
    drop: set[int] = set()
    for m in _SEP_LETTER_RUN.finditer(text):
        for k in range(m.start(), m.end()):
            if not text[k].isalpha():
                drop.add(k)
    chars = list(text)
    for m in _SEP_BETWEEN_LETTERS.finditer(text):
        if m.start() not in drop:
            chars[m.start()] = " "
    swapped = "".join(chars)
    # collapse letter-spaced words ("i g n o r e") by deleting the single spaces
    for m in _LETTER_SPACED.finditer(swapped):
        for k in range(m.start(), m.end()):
            if swapped[k] == " ":
                drop.add(k)
    if swapped == text and not drop:
        return None
    keep: list[int] = []
    prev_space = False
    for i, ch in enumerate(swapped):
        if i in drop:
            continue
        if ch == " ":
            if prev_space:
                continue
            prev_space = True
        else:
            prev_space = False
        keep.append(i)
    view = View(
        "relaxed", swapped, norm.offsets, note="intra-word separators / letter spacing collapsed"
    )
    return _sub_view(view, keep, None, "relaxed", view.note)


_LEET_TOKEN = re.compile(r"[A-Za-z0-9@$!]{4,}")


def build_leet(relaxed: View) -> View | None:
    text = relaxed.text
    out = list(text)
    changed = False
    for m in _LEET_TOKEN.finditer(text):
        tok = m.group()
        letters = sum(c.isalpha() for c in tok)
        subs = sum(c in "013457@$!" for c in tok)
        if letters >= 2 and subs >= 1 and not tok.isdigit():
            folded = tok.translate(_LEET)
            for k, c in enumerate(folded):
                out[m.start() + k] = c
            changed = changed or folded != tok
    if not changed:
        return None
    return View("leet", "".join(out), relaxed.offsets, note="leetspeak folded inside words")


def build_tag_view(original: str) -> View | None:
    """Decode a run of Unicode tag characters ("ASCII smuggling") into visible ASCII."""
    out: list[str] = []
    first = last = -1
    for i, ch in enumerate(original):
        cp = ord(ch)
        if _TAG_LO <= cp <= _TAG_HI:
            out.append(chr(cp - 0xE0000))
            first = i if first < 0 else first
            last = i
    if not out:
        return None
    return View(
        "tags",
        "".join(out),
        None,
        fixed_span=(first, last + 1),
        note="Unicode tag characters decoded",
    )


_B64_RE = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{20,}={0,2}(?![A-Za-z0-9+/=_-])")
_PCT_RE = re.compile(r"(?:%[0-9A-Fa-f]{2}[A-Za-z0-9._~ -]{0,3}){6,}")


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    return sum(c.isprintable() or c in "\n\t" for c in s) / len(s)


def _try_b64(token: str) -> str | None:
    t = token.replace("-", "+").replace("_", "/")
    t += "=" * (-len(t) % 4)
    try:
        raw = base64.b64decode(t, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(raw) < 8:
        return None
    try:
        s = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if _printable_ratio(s) < 0.95:
        return None
    if sum(c.isalpha() or c.isspace() for c in s) / len(s) < 0.6:
        return None
    return s


def build_decoded_views(
    original: str, *, max_depth: int = 2, max_candidates: int = 16, max_bytes: int = 200_000
) -> Iterator[View]:
    """Yield bounded decoded views. Decoded text is analysed only, never executed."""
    budget = [max_bytes, max_candidates]

    def walk(text: str, span: tuple[int, int] | None, depth: int, label: str) -> Iterator[View]:
        if depth > max_depth:
            return
        for m in _B64_RE.finditer(text):
            if budget[0] <= 0 or budget[1] <= 0:
                return
            decoded = _try_b64(m.group())
            if decoded is None:
                continue
            budget[0] -= len(decoded)
            budget[1] -= 1
            sp = span or (m.start(), m.end())
            name = f"b64:{label}{depth}"
            yield View(name, decoded, None, fixed_span=sp, note=f"base64 decoded (depth {depth})")
            yield from walk(decoded, sp, depth + 1, label)
        for m in _PCT_RE.finditer(text):
            if budget[0] <= 0 or budget[1] <= 0:
                return
            decoded = urllib.parse.unquote(m.group())
            if decoded == m.group() or _printable_ratio(decoded) < 0.95:
                continue
            budget[0] -= len(decoded)
            budget[1] -= 1
            sp = span or (m.start(), m.end())
            yield View(f"pct:{label}{depth}", decoded, None, fixed_span=sp, note="percent-decoded")

    yield from walk(original, None, 1, "")


# --- HTML (offset-preserving, non-executing) -------------------------------------------

_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)
_TAG_RE = re.compile(r"<[^>]*>", re.S)
_BLOCK_RE = re.compile(r"<(script|style|template)\b[^>]*>.*?</\1\s*>", re.S | re.I)
_ATTR_RE = re.compile(
    r"""\b(alt|title|aria-label|placeholder|content|value)\s*=\s*("([^"]*)"|'([^']*)')""", re.I
)
_ENTITY_RE = re.compile(r"&#?\w{1,10};")
_HIDDEN_STYLE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0(?:\.0+)?\b"
    r"|color\s*:\s*(?:#fff(?:fff)?|white)\b|text-indent\s*:\s*-\d{3,}|height\s*:\s*0|width\s*:\s*0",
    re.I,
)
_ELEMENT_RE = re.compile(
    r"<(?P<tag>[a-zA-Z][\w:-]*)(?P<attrs>[^>]*)>(?P<body>.*?)</(?P=tag)\s*>", re.S
)


def build_html_view(original: str) -> View:
    """Length-preserving text view of HTML: tags blanked, comments and some attrs kept."""
    buf = list(original)

    def blank(s: int, e: int) -> None:
        for k in range(s, e):
            if buf[k] != "\n":
                buf[k] = " "

    for m in _BLOCK_RE.finditer(original):
        blank(m.start(), m.end())
    comment_spans = [
        (m.start(), m.end(), m.start(1), m.end(1)) for m in _COMMENT_RE.finditer(original)
    ]
    for s, e, cs, ce in comment_spans:
        blank(s, cs)
        blank(ce, e)
    in_comment = [(s, e) for s, e, _, _ in comment_spans]
    for m in _TAG_RE.finditer(original):
        if any(s <= m.start() < e for s, e in in_comment):
            continue
        keep: list[tuple[int, int]] = []
        for a in _ATTR_RE.finditer(m.group()):
            g = 3 if a.group(3) is not None else 4
            keep.append((m.start() + a.start(g), m.start() + a.end(g)))
        saved = {k: buf[k] for s, e in keep for k in range(s, e)}
        blank(m.start(), m.end())
        for k, c in saved.items():
            buf[k] = c
        # separate kept attribute values from neighbours
    for m in _ENTITY_RE.finditer(original):
        blank(m.start(), m.end())
    return View(
        "html",
        "".join(buf),
        tuple(range(len(buf))),
        note="HTML tags blanked; text, comments, alt/title kept",
    )


def html_hidden_spans(original: str) -> list[tuple[int, int]]:
    """Spans (in original coordinates) of elements styled/marked as visually hidden."""
    spans: list[tuple[int, int]] = []
    for m in _ELEMENT_RE.finditer(original):
        attrs = m.group("attrs")
        if (
            _HIDDEN_STYLE.search(attrs)
            or re.search(r"\bhidden\b|aria-hidden\s*=\s*[\"']?true", attrs, re.I)
        ) and m.group("body").strip():
            spans.append((m.start("body"), m.end("body")))
    for m in _COMMENT_RE.finditer(original):
        if m.group(1).strip():
            spans.append((m.start(1), m.end(1)))
    return spans


# --- quoted content ---------------------------------------------------------------------

_QUOTE_PAIRS = [
    re.compile(r"```.*?```", re.S),
    re.compile(r"`[^`\n]{4,}`"),
    re.compile(r'"[^"\n]{6,}"'),
    re.compile(r"“[^”\n]{6,}”"),
    re.compile(r"‘[^’\n]{6,}’"),
    re.compile(r"«[^»\n]{6,}»"),
    re.compile(r"^[ \t]*>[^\n]*", re.M),
]


def quoted_spans(original: str) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    for rx in _QUOTE_PAIRS:
        out.extend((m.start(), m.end()) for m in rx.finditer(original))
    return out


def span_inside(span: tuple[int, int], containers: list[tuple[int, int]]) -> bool:
    return any(s <= span[0] and span[1] <= e for s, e in containers)


def span_overlaps(span: tuple[int, int], containers: list[tuple[int, int]]) -> bool:
    return any(span[0] < e and s < span[1] for s, e in containers)


# --- top level --------------------------------------------------------------------------


def build_representations(
    original: str, *, content_type: str = "text/plain", max_decode_depth: int = 2
) -> Representations:
    rep = Representations(original=original)
    norm, stats = build_normalized(original)
    rep.stats.update(stats)
    rep.views.append(norm)
    if stats["invisible"]:
        sp, _ = build_normalized(original, invisible_as_space=True)
        if sp.text != norm.text:
            rep.views.append(sp)
    raw_norm, _ = build_normalized(original, collapse_ws=False)
    relaxed = build_relaxed(raw_norm)
    if relaxed is not None:
        rep.views.append(relaxed)
    leet = build_leet(relaxed or norm)
    if leet is not None:
        rep.views.append(leet)
    tags = build_tag_view(original)
    if tags is not None:
        rep.views.append(tags)
    rep.views.extend(build_decoded_views(original, max_depth=max_decode_depth))
    if content_type == "text/html":
        html = build_html_view(original)
        hn, _ = build_normalized(html.text)
        rep.views.append(View("html", hn.text, hn.offsets, note=html.note))
    rep.notes.append(f"normalization_pipeline={NORMALIZATION_VERSION}")
    return rep


def sanitize_text(original: str) -> tuple[str, list[str]]:
    """Documented, minimal sanitisation: remove invisible/control characters only.

    Joiners and variation selectors are kept unless they sit directly after an ASCII
    alphanumeric (where they have no legitimate role), so emoji and Indic/Persian text
    survive. It deliberately does **not** delete instruction-like words: removing
    semantics would silently alter meaning. Returns (text, applied_transformations).
    """
    out: list[str] = []
    for ch in original:
        if is_invisible(ch):
            keep_candidate = ch in _JOINERS or 0xFE00 <= ord(ch) <= 0xFE0F
            prev = out[-1] if out else ""
            if not (keep_candidate and prev and not (prev.isascii() and prev.isalnum())):
                continue
        out.append(ch)
    applied = ["remove_invisible_and_control_characters"] if len(out) != len(original) else []
    return "".join(out), applied

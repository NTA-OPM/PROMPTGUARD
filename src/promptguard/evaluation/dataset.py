"""Dataset manifests, loading with integrity checks, and leakage detection."""

from __future__ import annotations

import hashlib
import json
import random
import re
import unicodedata
from collections import Counter, defaultdict
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from promptguard.core.schema import SourceType


class DatasetError(ValueError):
    pass


class Example(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    text: str
    label: Literal["attack", "benign"]
    category: str  # attack: taxonomy category; benign: benign sub-type
    source_type: SourceType = SourceType.USER_INPUT
    language: str = "en"
    family: str  # attack template / near-duplicate family; splits never share a family
    split: Literal["dev", "test"]
    content_type: str = "text/plain"
    notes: str = ""


class FileEntry(BaseModel):
    path: str
    sha256: str


class DatasetManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    dataset_id: str
    version: str
    title: str
    license: str
    provenance: str
    collection_date: str
    intended_use: str
    schema_version: str = "1"
    files: list[FileEntry]
    splits: dict[str, str] = Field(default_factory=dict)
    locked_splits: list[str] = Field(default_factory=list)
    languages: list[str] = Field(default_factory=list)
    labels: list[str] = Field(default_factory=lambda: ["attack", "benign"])
    limitations: list[str] = Field(default_factory=list)
    contains_third_party_data: bool = False


class Dataset(BaseModel):
    manifest: DatasetManifest
    examples: list[Example]

    def split(self, name: str | None) -> list[Example]:
        return (
            self.examples
            if name in (None, "all")
            else [e for e in self.examples if e.split == name]
        )

    @property
    def sha256(self) -> str:
        h = hashlib.sha256()
        for f in sorted(self.manifest.files, key=lambda x: x.path):
            h.update(f.sha256.encode())
        return h.hexdigest()


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_dataset(directory: str | Path, *, verify: bool = True) -> Dataset:
    d = Path(directory)
    mpath = d / "manifest.json"
    if not mpath.is_file():
        raise DatasetError(f"manifest.json not found in {d}")
    try:
        manifest = DatasetManifest.model_validate_json(mpath.read_text(encoding="utf-8"))
    except ValidationError as exc:
        raise DatasetError(f"invalid manifest: {exc}") from exc
    examples: list[Example] = []
    for entry in manifest.files:
        p = (d / entry.path).resolve()
        if d.resolve() not in p.parents:
            raise DatasetError(f"manifest path escapes dataset directory: {entry.path}")
        if not p.is_file():
            raise DatasetError(f"missing dataset file: {entry.path}")
        if verify and file_sha256(p) != entry.sha256:
            raise DatasetError(f"sha256 mismatch for {entry.path}: dataset was modified")
        for ln, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                examples.append(Example.model_validate_json(line))
            except ValidationError as exc:
                raise DatasetError(f"{entry.path}:{ln}: {exc}") from exc
    ids = Counter(e.id for e in examples)
    dup_ids = [i for i, n in ids.items() if n > 1]
    if dup_ids:
        raise DatasetError(f"duplicate example ids: {dup_ids[:5]}")
    return Dataset(manifest=manifest, examples=examples)


# --------------------------------------------------------------------- leakage

_WS = re.compile(r"\s+")


def _canon(text: str) -> str:
    t = unicodedata.normalize("NFKC", text).casefold()
    t = "".join(c for c in t if c.isalnum() or c.isspace())
    return _WS.sub(" ", t).strip()


def _h(s: str) -> int:
    # stable across processes (builtin hash() is salted per process)
    return int.from_bytes(hashlib.blake2b(s.encode(), digest_size=8).digest(), "big")


def _shingles(text: str, k: int = 3) -> set[int]:
    w = _canon(text).split()
    if len(w) < k:
        return {_h(" ".join(w))}
    return {_h(" ".join(w[i : i + k])) for i in range(len(w) - k + 1)}


def jaccard(a: set[int], b: set[int]) -> float:
    return len(a & b) / len(a | b) if a and b else 0.0


def leakage_report(
    examples: list[Example], *, threshold: float = 0.8, seed: int = 0
) -> dict[str, object]:
    """Exact, near-duplicate (MinHash-LSH + exact Jaccard) and family leakage across splits."""
    issues: list[dict[str, object]] = []
    # family leakage
    fam_splits: dict[str, set[str]] = defaultdict(set)
    for e in examples:
        fam_splits[e.family].add(e.split)
    for fam, sp in fam_splits.items():
        if len(sp) > 1:
            issues.append({"type": "family_leakage", "family": fam, "splits": sorted(sp)})
    # exact duplicates
    by_canon: dict[str, list[Example]] = defaultdict(list)
    for e in examples:
        by_canon[_canon(e.text)].append(e)
    for group in by_canon.values():
        if len(group) > 1:
            cross = len({g.split for g in group}) > 1
            issues.append(
                {
                    "type": "exact_duplicate_cross_split" if cross else "exact_duplicate",
                    "ids": [g.id for g in group],
                }
            )
    # near duplicates via banded MinHash
    rng = random.Random(seed)  # noqa: S311
    n_perm, bands = 32, 8
    rows = n_perm // bands
    salts = [rng.getrandbits(61) for _ in range(n_perm)]
    sh = [_shingles(e.text) for e in examples]
    buckets: dict[tuple[int, tuple[int, ...]], list[int]] = defaultdict(list)
    for idx, s in enumerate(sh):
        sig = [min((x ^ sl) & ((1 << 61) - 1) for x in s) for sl in salts]
        for b in range(bands):
            buckets[(b, tuple(sig[b * rows : (b + 1) * rows]))].append(idx)
    seen: set[tuple[int, int]] = set()
    for members in buckets.values():
        if len(members) < 2 or len(members) > 50:
            continue
        for i in range(len(members)):
            for j in range(i + 1, len(members)):
                a, b = members[i], members[j]
                if (a, b) in seen or _canon(examples[a].text) == _canon(examples[b].text):
                    continue
                seen.add((a, b))
                sim = jaccard(sh[a], sh[b])
                if sim >= threshold:
                    cross = examples[a].split != examples[b].split
                    issues.append(
                        {
                            "type": "near_duplicate_cross_split" if cross else "near_duplicate",
                            "ids": [examples[a].id, examples[b].id],
                            "jaccard": round(sim, 3),
                        }
                    )
    blocking = [
        i for i in issues if str(i["type"]).endswith("cross_split") or i["type"] == "family_leakage"
    ]
    return {"issues": issues, "cross_split_leakage": len(blocking), "checked": len(examples)}


def dump_jsonl(examples: list[dict[str, object]], path: Path) -> str:
    """Write deterministic JSONL (ASCII-escaped so invisible characters are visible) and return sha256."""
    lines = [json.dumps(e, sort_keys=True, ensure_ascii=True) for e in examples]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return file_sha256(path)

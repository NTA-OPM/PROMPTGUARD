from __future__ import annotations

import time

import pytest

from promptguard import Scanner
from promptguard.detectors.rules import RuleDetector, RulePackError, load_rule_pack


def test_pack_loads_and_ids_unique() -> None:
    pack, sha = load_rule_pack()
    assert len(sha) == 64 and len(pack.rules) >= 40
    assert len({r.id for r in pack.rules}) == len(pack.rules)


@pytest.mark.parametrize(
    "payload",
    [
        "ignore " * 20000,
        "a" * 200_000,
        "ignore the " + "previous " * 20000,
        "send " + "to " * 20000 + "http://",
        "i g n o r e " * 10000,
        "(" * 50000,
        "ignore" + " " * 100000 + "instructions",
        "<!--" * 20000,
        "![" + "a" * 50000,
        "You are " + "no " * 30000,
    ],
)
def test_no_catastrophic_backtracking(payload: str) -> None:
    sc = Scanner(detectors=[RuleDetector()])
    t = time.perf_counter()
    sc.scan(payload)
    assert time.perf_counter() - t < 5.0


def test_bad_pack_rejected(tmp_path) -> None:  # type: ignore[no-untyped-def]
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "pack_id: x\nversion: 1\nrules:\n  - id: PG-XX-001\n    category: instruction_override\n    severity: high\n    confidence: 0.5\n    explanation: x\n    pattern: '('\n"
    )
    with pytest.raises(RulePackError):
        RuleDetector(bad)
    bad.write_text("not: [valid")
    with pytest.raises(RulePackError):
        load_rule_pack(bad)


def test_unknown_fields_rejected(tmp_path) -> None:  # type: ignore[no-untyped-def]
    p = tmp_path / "p.yaml"
    p.write_text(
        "pack_id: x\nversion: '1'\nrules:\n  - id: PG-XX-001\n    category: instruction_override\n    severity: high\n    confidence: 0.5\n    explanation: x\n    pattern: a\n    code: 'import os'\n"
    )
    with pytest.raises(RulePackError):
        load_rule_pack(p)

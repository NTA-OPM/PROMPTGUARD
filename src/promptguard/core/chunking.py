"""Sliding-window chunking with explicit offsets (used by model adapters)."""

from __future__ import annotations


def chunk_spans(n: int, size: int, overlap: int) -> list[tuple[int, int]]:
    """Return (start, end) windows covering ``[0, n)`` with ``overlap`` chars shared."""
    if size <= 0:
        raise ValueError("size must be positive")
    if not 0 <= overlap < size:
        raise ValueError("overlap must satisfy 0 <= overlap < size")
    if n <= size:
        return [(0, n)]
    step = size - overlap
    spans: list[tuple[int, int]] = []
    start = 0
    while start < n:
        end = min(start + size, n)
        spans.append((start, end))
        if end == n:
            break
        start += step
    return spans

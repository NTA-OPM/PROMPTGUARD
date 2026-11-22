from __future__ import annotations

import socket
from pathlib import Path

import pytest

from promptguard import Scanner

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "datasets" / "baseline"


@pytest.fixture(scope="session")
def scanner() -> Scanner:
    return Scanner()


@pytest.fixture
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail the test if anything tries to open a network connection."""

    def boom(*a: object, **k: object) -> None:
        raise AssertionError("network access attempted by core scanner")

    monkeypatch.setattr(socket.socket, "connect", boom)
    monkeypatch.setattr(socket, "create_connection", boom)

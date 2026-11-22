"""FastAPI dependency for guarding request bodies (reference integration)."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import HTTPException, Request

from promptguard.core.engine import Scanner
from promptguard.core.schema import Action, ScanResult, SourceType


def guard_dependency(
    scanner: Scanner,
    *,
    field: str = "text",
    source_type: SourceType = SourceType.USER_INPUT,
    block_at: Action = Action.BLOCK,
) -> Callable[[Request], Awaitable[ScanResult]]:
    """Return a dependency that scans ``body[field]``.

    * action >= ``block_at``: responds 422 with a structured, content-free error;
    * otherwise the :class:`ScanResult` is returned so the handler can route ``review``
      decisions to a human or a stricter path. It never executes or forwards anything.
    """

    async def dependency(request: Request) -> ScanResult:
        try:
            body: Any = await request.json()
            text = body[field]
            if not isinstance(text, str):
                raise TypeError
        except (ValueError, KeyError, TypeError) as exc:
            raise HTTPException(422, f"body must be JSON with a string field {field!r}") from exc
        result = await scanner.ascan(text, source_type=source_type)
        if result.decision.action >= block_at:
            raise HTTPException(
                422,
                {
                    "code": "prompt_guard_blocked",
                    "action": result.decision.action.value,
                    "reason_codes": result.decision.reason_codes,
                    "input_id": result.input_id,
                },
            )
        return result

    return dependency

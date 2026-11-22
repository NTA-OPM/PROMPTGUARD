"""Guard a chat endpoint.  Run: uvicorn examples.fastapi_app:app   (needs promptguard-oss[api])"""

from typing import Annotated

from fastapi import Depends, FastAPI

from promptguard import Action, Scanner, ScanResult
from promptguard.sdk.fastapi import guard_dependency

scanner = Scanner()
app = FastAPI()
guard = guard_dependency(scanner, field="message")  # 422 on BLOCK


@app.post("/chat")
async def chat(result: Annotated[ScanResult, Depends(guard)]) -> dict[str, str]:
    if result.decision.action is Action.REVIEW:
        return {"status": "held_for_review", "input_id": result.input_id}
    # ... call your LLM here. Tool calls still need independent authorization. ...
    return {"status": "accepted", "input_id": result.input_id}

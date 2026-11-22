# Integration guides

PromptGuard is **one layer**. Wire it in alongside the controls that actually bound impact.

## 1. Direct user input
```python
from promptguard import Scanner, Action
sc = Scanner()
res = sc.scan(user_text, source_type="user_input")
if res.decision.action is Action.BLOCK: ...        # refuse with a safe message
elif res.decision.action is Action.REVIEW: ...     # confirm / route to stricter path
```

## 2. RAG: scan before assembling context
```python
from promptguard.sdk.guard import gate_chunks, wrap_untrusted
gate = gate_chunks(sc, retrieved_chunks, source_id="kb")
context = "\n\n".join(wrap_untrusted(t) for t in gate.safe_texts)
log_for_review(gate.review); drop(gate.blocked)
```
`wrap_untrusted` is **labelling, not isolation**.

## 3. Agents (most important)
Scan tool outputs (`source_type="tool_output"`) and plans (`"agent_plan"`; use `context_profile=
"high-risk-action"` for sensitive steps). Then enforce **outside the model**: allow-listed tools,
least-privilege credentials, argument validation, human approval for irreversible actions, egress
allow-lists, no auto-rendering of model-produced images/links. A PromptGuard `allow` never
authorises a tool call.

## 4. FastAPI
```python
from promptguard.sdk.fastapi import guard_dependency
guard = guard_dependency(scanner, field="text")        # 422 on block, returns ScanResult otherwise
@app.post("/chat")
async def chat(result: Annotated[ScanResult, Depends(guard)]): ...
```

## 5. CI
`promptguard evaluate --dataset <yours> --min-recall 0.9 --max-fpr 0.1` fails the build on
regression. Pin the dataset (sha256 in the manifest) and keep a locked holdout.

## 6. Service
Run the Docker/uvicorn service behind TLS with API keys; ask for `detail: standard` in production.

## 7. Other frameworks
LangChain/LlamaIndex adapters are planned as optional packages (P1). The SDK surface is
deliberately small so an adapter is a thin wrapper over `Scanner.scan`.

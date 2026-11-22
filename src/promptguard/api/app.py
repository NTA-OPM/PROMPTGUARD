"""FastAPI service. Stateless by default; request/response bodies are never logged.

Security posture
----------------
* strict schemas (``extra=forbid``), body-size cap enforced at the ASGI layer (also for
  chunked uploads), per-text and batch limits, structured errors that never echo input;
* optional API keys (``standard`` and ``analyst`` roles), constant-time comparison;
* in-process token-bucket rate limiting (per key or client address);
* no URL fetching, no dynamic rule/plugin loading from requests;
* secure response headers; CORS disabled unless explicitly configured.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from promptguard._version import __version__
from promptguard.core.aggregation import AggregationOptions, aggregate
from promptguard.core.engine import InputRejected, Scanner, ScannerConfig
from promptguard.core.schema import (
    Finding,
    InputEnvelope,
    ScanResult,
    SourceType,
    TrustLevel,
)
from promptguard.policy.engine import PolicyError, evaluate_policy, load_policy, policy_summary
from promptguard.telemetry.privacy import Metrics

_REQ_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_DATASET_ID = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")


# ----------------------------------------------------------------------------- settings
def _csv(name: str) -> tuple[str, ...]:
    return tuple(x.strip() for x in os.environ.get(name, "").split(",") if x.strip())


@dataclass
class ApiSettings:
    api_keys: tuple[str, ...] = ()
    analyst_keys: tuple[str, ...] = ()
    max_body_bytes: int = 1_000_000
    max_text_chars: int = 200_000
    max_batch_items: int = 100
    rate_limit_per_minute: int = 120  # 0 disables
    enable_docs: bool = False
    metrics_enabled: bool = True
    dataset_dir: Path | None = None
    max_eval_examples: int = 5000
    cors_origins: tuple[str, ...] = ()
    policy_path: Path | None = None
    analyst_default_detail: bool = False
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_env(cls) -> ApiSettings:
        e = os.environ
        return cls(
            api_keys=_csv("PROMPTGUARD_API_KEYS"),
            analyst_keys=_csv("PROMPTGUARD_ANALYST_KEYS"),
            max_body_bytes=int(e.get("PROMPTGUARD_MAX_BODY_BYTES", 1_000_000)),
            max_text_chars=int(e.get("PROMPTGUARD_MAX_TEXT_CHARS", 200_000)),
            max_batch_items=int(e.get("PROMPTGUARD_MAX_BATCH_ITEMS", 100)),
            rate_limit_per_minute=int(e.get("PROMPTGUARD_RATE_LIMIT_PER_MINUTE", 120)),
            enable_docs=e.get("PROMPTGUARD_ENABLE_DOCS", "").lower() in ("1", "true", "yes"),
            metrics_enabled=e.get("PROMPTGUARD_METRICS", "true").lower()
            not in ("0", "false", "no"),
            dataset_dir=Path(e["PROMPTGUARD_DATASET_DIR"])
            if e.get("PROMPTGUARD_DATASET_DIR")
            else None,
            cors_origins=_csv("PROMPTGUARD_CORS_ORIGINS"),
            policy_path=Path(e["PROMPTGUARD_POLICY"]) if e.get("PROMPTGUARD_POLICY") else None,
        )

    @property
    def auth_enabled(self) -> bool:
        return bool(self.api_keys or self.analyst_keys)


# ----------------------------------------------------------------------------- errors
class ApiError(Exception):
    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        details: Any = None,
        headers: dict[str, str] | None = None,
    ):
        self.status, self.code, self.message, self.details, self.headers = (
            status,
            code,
            message,
            details,
            headers or {},
        )


def _error_response(
    request_id: str,
    status: int,
    code: str,
    message: str,
    details: Any = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    body: dict[str, Any] = {"error": {"code": code, "message": message, "request_id": request_id}}
    if details is not None:
        body["error"]["details"] = details
    return JSONResponse(body, status_code=status, headers=headers)


class _BodyTooLarge(Exception):
    pass


class GuardrailMiddleware:
    """Request id, body-size limit (incl. chunked) and secure headers. Pure ASGI."""

    def __init__(self, app: ASGIApp, *, max_body_bytes: int, docs_paths: tuple[str, ...]) -> None:
        self.app, self.max_body, self.docs_paths = app, max_body_bytes, docs_paths

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope["headers"]}
        rid = headers.get("x-request-id", "")
        rid = rid if _REQ_ID.match(rid) else uuid.uuid4().hex
        scope.setdefault("state", {})["request_id"] = rid
        path = scope.get("path", "")
        started = False
        exceeded = False
        replaced = False

        async def send_wrapper(message: Message) -> None:
            nonlocal started, replaced
            if exceeded:
                # The app may have turned our abort into some other error (e.g. 400); the
                # client must see a clear 413 instead. Drop the app's response.
                if not replaced:
                    replaced = True
                    started = True
                    await self._send_413(scope, send_wrapper_inner, rid)
                return
            await send_wrapper_inner(message)

        async def send_wrapper_inner(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
                hdrs = list(message.get("headers", []))
                extra = {
                    "x-request-id": rid,
                    "x-content-type-options": "nosniff",
                    "cache-control": "no-store",
                    "referrer-policy": "no-referrer",
                    "x-frame-options": "DENY",
                }
                if not path.startswith(self.docs_paths):
                    extra["content-security-policy"] = "default-src 'none'; frame-ancestors 'none'"
                present = {k.decode().lower() for k, _ in hdrs}
                hdrs += [(k.encode(), v.encode()) for k, v in extra.items() if k not in present]
                message["headers"] = hdrs
            await send(message)

        cl = headers.get("content-length")
        if cl and cl.isdigit() and int(cl) > self.max_body:
            await self._reject(scope, receive, send_wrapper_inner, rid)
            return
        total = 0

        async def receive_wrapper() -> Message:
            nonlocal total, exceeded
            msg = await receive()
            if msg["type"] == "http.request":
                total += len(msg.get("body", b""))
                if total > self.max_body:
                    exceeded = True
                    raise _BodyTooLarge
            return msg

        try:
            await self.app(scope, receive_wrapper, send_wrapper)
        except _BodyTooLarge:
            if not started:
                await self._send_413(scope, send_wrapper_inner, rid)
            return
        if exceeded and not replaced and not started:
            await self._send_413(scope, send_wrapper_inner, rid)

    async def _send_413(self, scope: Scope, send: Send, rid: str) -> None:
        async def _no_receive() -> Message:
            return {"type": "http.disconnect"}

        await _error_response(
            rid, 413, "payload_too_large", f"request body exceeds {self.max_body} bytes"
        )(scope, _no_receive, send)

    async def _reject(self, scope: Scope, receive: Receive, send: Send, rid: str) -> None:
        await self._send_413(scope, send, rid)


# ----------------------------------------------------------------------------- rate limit
class RateLimiter:
    def __init__(self, per_minute: int) -> None:
        self.rate = per_minute / 60.0
        self.capacity = float(max(per_minute, 1))
        self._state: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    def check(self, ident: str) -> float | None:
        """Return None if allowed, else seconds to wait."""
        if self.rate <= 0:
            return None
        now = time.monotonic()
        with self._lock:
            tokens, last = self._state.get(ident, (self.capacity, now))
            tokens = min(self.capacity, tokens + (now - last) * self.rate)
            if tokens < 1.0:
                self._state[ident] = (tokens, now)
                return (1.0 - tokens) / self.rate
            self._state[ident] = (tokens - 1.0, now)
            if len(self._state) > 10_000:
                cutoff = now - 600
                self._state = {k: v for k, v in self._state.items() if v[1] > cutoff}
        return None


# ----------------------------------------------------------------------------- schemas
class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str
    source_type: SourceType = SourceType.USER_INPUT
    trust_level: TrustLevel | None = None
    context_profile: str | None = Field(default=None, max_length=64)
    language_hint: str | None = Field(default=None, max_length=16)
    source_id: str | None = Field(default=None, max_length=256)
    content_type: str = Field(default="text/plain", pattern=r"^text/(plain|html)$")
    metadata: dict[str, Any] = Field(default_factory=dict)
    input_id: str | None = Field(default=None, max_length=64)
    detail: Literal["standard", "analyst"] = "standard"

    def envelope(self) -> InputEnvelope:
        data = self.model_dump(exclude={"detail", "input_id"}, exclude_none=True)
        if self.input_id:
            data["input_id"] = self.input_id
        return InputEnvelope(**data)


class BatchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    items: list[ScanRequest] = Field(min_length=1)
    detail: Literal["standard", "analyst"] = "standard"


class PolicyEvalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    findings: list[Finding] = Field(max_length=200)
    source_type: SourceType = SourceType.USER_INPUT
    context_profile: str | None = Field(default=None, max_length=64)
    truncated: bool = False


class EvaluateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    dataset_id: str
    split: Literal["dev", "test", "all"] = "dev"
    positive_at: Literal["review", "block"] = "review"
    context_mode: Literal["labeled", "ignore"] = "labeled"


_GENERIC = {
    "instruction_override": "Content appears to try to override earlier instructions.",
    "system_impersonation": "Content appears to claim privileged authority.",
    "prompt_disclosure": "Content appears to seek disclosure of hidden instructions.",
    "tool_invocation_manipulation": "Content appears to steer tool or action use.",
    "data_exfiltration": "Content appears to steer data toward an external destination.",
    "trust_boundary_manipulation": "Content blurs the boundary between data and instructions.",
    "jailbreak_framing": "Content uses jailbreak-style framing.",
    "obfuscation_evasion": "Content uses encoding or character-level disguise.",
    "context_injection": "Instruction-like content embedded in data.",
    "multi_step_coercion": "Content coerces multi-step or concealed behaviour.",
    "benign_security_discussion": "Text discusses security topics (context only).",
    "ambiguous_low_confidence": "Ambiguous signal requiring review.",
}


def present(result: ScanResult, detail: str) -> dict[str, Any]:
    """Standard detail hides rule ids, explanations, snippets and metadata (less to probe)."""
    d = result.model_dump(mode="json")
    if detail == "analyst":
        return d
    for f in d["findings"]:
        f["rule_id"] = None
        f["explanation"] = _GENERIC.get(f["category"], "Signal detected.")
        f["metadata"] = {}
        f["normalization_notes"] = []
        for ev in f["evidence"]:
            ev["snippet"] = ""
            ev["normalized_snippet"] = None
    d["versions"] = {
        k: v for k, v in d["versions"].items() if k in ("engine", "policy", "policy_hash")
    }
    d["detector_timings_ms"] = {}
    d["risk"]["effective_severities"] = {}
    return d


# ----------------------------------------------------------------------------- app factory
def create_app(settings: ApiSettings | None = None, scanner: Scanner | None = None) -> FastAPI:
    st = settings or ApiSettings.from_env()
    scanner = scanner or Scanner(
        load_policy(st.policy_path), config=ScannerConfig(max_chars=st.max_text_chars)
    )
    metrics = Metrics()
    limiter = RateLimiter(st.rate_limit_per_minute)
    scanner.add_hook(metrics.observe_scan)
    dataset_cache: dict[str, Any] = {}

    app = FastAPI(
        title="PromptGuard API",
        version=__version__,
        description="Prompt-injection risk signals and policy recommendations. Not a guarantee of prevention.",
        docs_url="/docs" if st.enable_docs else None,
        redoc_url=None,
        openapi_url="/openapi.json",
    )
    app.add_middleware(GuardrailMiddleware, max_body_bytes=st.max_body_bytes, docs_paths=("/docs",))
    if st.cors_origins:
        from fastapi.middleware.cors import CORSMiddleware

        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(st.cors_origins),
            allow_methods=["GET", "POST"],
            allow_headers=["X-API-Key", "Authorization", "Content-Type", "X-Request-ID"],
        )

    def rid(request: Request) -> str:
        return str(getattr(request.state, "request_id", "unknown"))

    @app.exception_handler(ApiError)
    async def _api_error(request: Request, exc: ApiError) -> JSONResponse:
        return _error_response(
            rid(request), exc.status, exc.code, exc.message, exc.details, exc.headers
        )

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        # never echo the offending input back
        details = [
            {"loc": [str(x) for x in e["loc"]], "type": e["type"], "msg": e["msg"]}
            for e in exc.errors()
        ]
        return _error_response(
            rid(request), 422, "invalid_request", "request validation failed", details
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = {404: "not_found", 405: "method_not_allowed"}.get(exc.status_code, "http_error")
        return _error_response(
            rid(request),
            exc.status_code,
            code,
            str(exc.detail) if exc.status_code != 404 else "not found",
        )

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        return _error_response(
            rid(request),
            500,
            "internal_error",
            "internal error; see server logs with the request id",
        )

    # ---- auth + rate limit
    def _role(key: str | None) -> str | None:
        if key is None:
            return None
        for k in st.analyst_keys:
            if hmac.compare_digest(k.encode(), key.encode()):
                return "analyst"
        for k in st.api_keys:
            if hmac.compare_digest(k.encode(), key.encode()):
                return "standard"
        return None

    def _key_from(request: Request) -> str | None:
        k = request.headers.get("x-api-key")
        if k:
            return k
        a = request.headers.get("authorization", "")
        return a[7:].strip() if a.lower().startswith("bearer ") else None

    def principal(request: Request) -> str:
        key = _key_from(request)
        if st.auth_enabled:
            role = _role(key)
            if role is None:
                raise ApiError(
                    401,
                    "unauthorized",
                    "missing or invalid API key",
                    headers={"WWW-Authenticate": "Bearer"},
                )
        else:
            role = "analyst"  # open local-development mode (reported by /ready)
        ident = hashlib.sha256(
            (key or (request.client.host if request.client else "anon")).encode()
        ).hexdigest()[:16]
        wait = limiter.check(ident)
        if wait is not None:
            raise ApiError(
                429,
                "rate_limited",
                "rate limit exceeded",
                headers={"Retry-After": str(int(wait) + 1)},
            )
        request.state.role = role
        return role

    def need_analyst(role: str = Depends(principal)) -> str:
        if role != "analyst":
            raise ApiError(403, "forbidden", "analyst role required")
        return role

    def check_detail(detail: str, role: str) -> None:
        if detail == "analyst" and role != "analyst":
            raise ApiError(403, "forbidden", "analyst detail requires an analyst key")

    def check_len(text: str) -> None:
        if len(text) > st.max_text_chars:
            raise ApiError(413, "payload_too_large", f"text exceeds {st.max_text_chars} characters")

    # ---- routes
    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.get("/ready")
    async def ready() -> dict[str, Any]:
        return {
            "status": "ready",
            "version": __version__,
            "detectors": [
                {"id": d.id, "version": d.version, "required": d.required}
                for d in scanner.detectors
            ],
            "policy": policy_summary(scanner.policy),
            "auth": "enabled" if st.auth_enabled else "disabled (development mode)",
            "network_access_required": False,
        }

    @app.post("/api/v1/scan")
    async def scan_one(req: ScanRequest, role: str = Depends(principal)) -> dict[str, Any]:
        check_detail(req.detail, role)
        check_len(req.text)
        try:
            result = await asyncio.to_thread(scanner.scan, req.envelope())
        except (InputRejected, PolicyError) as exc:
            raise ApiError(422, "invalid_request", str(exc)) from exc
        return present(result, req.detail)

    @app.post("/api/v1/scan/batch")
    async def scan_batch(req: BatchRequest, role: str = Depends(principal)) -> dict[str, Any]:
        check_detail(req.detail, role)
        if len(req.items) > st.max_batch_items:
            raise ApiError(413, "payload_too_large", f"batch exceeds {st.max_batch_items} items")
        if sum(len(i.text) for i in req.items) > st.max_text_chars * 2:
            raise ApiError(413, "payload_too_large", "batch total text too large")
        for i in req.items:
            check_len(i.text)
        out: list[dict[str, Any]] = []
        for item in req.items:
            try:
                res = await asyncio.to_thread(scanner.scan, item.envelope())
                out.append(present(res, req.detail))
            except (InputRejected, PolicyError) as exc:
                raise ApiError(422, "invalid_request", str(exc)) from exc
        return {"results": out}

    @app.post("/api/v1/policy/evaluate")
    async def policy_evaluate(
        req: PolicyEvalRequest, _: str = Depends(principal)
    ) -> dict[str, Any]:
        env = InputEnvelope(
            text="", source_type=req.source_type, context_profile=req.context_profile
        )
        try:
            from promptguard.policy.engine import resolve_profile

            profile = resolve_profile(scanner.policy, env)
        except PolicyError as exc:
            raise ApiError(422, "invalid_request", str(exc)) from exc
        prof = scanner.policy.profile(profile)
        # supplied findings are untrusted data: flags that alter severity are recomputed, not trusted
        findings = [
            f.model_copy(
                update={"metadata": {k: v for k, v in f.metadata.items() if k == "sanitizable"}}
            )
            for f in req.findings
        ]
        assessment = aggregate(
            findings, AggregationOptions(prof.quoted_downgrade, prof.critical_on_action_intent)
        )
        decision = evaluate_policy(
            scanner.policy, profile, assessment, findings, errors=[], truncated=req.truncated,
            limitations=["Findings were supplied by the caller and not verified by this service."],
            effective=assessment.effective_severities,
        )  # fmt: skip
        return {
            "risk": assessment.model_dump(mode="json"),
            "decision": decision.model_dump(mode="json"),
        }

    @app.get("/api/v1/detectors")
    async def list_detectors(_: str = Depends(principal)) -> dict[str, Any]:
        return {"detectors": [m.model_dump(mode="json") for m in scanner.manifests()]}

    @app.get("/api/v1/policies")
    async def list_policies(_: str = Depends(principal)) -> dict[str, Any]:
        return {
            **policy_summary(scanner.policy),
            "profiles": {n: p.model_dump(mode="json") for n, p in scanner.policy.profiles.items()},
        }

    @app.post("/api/v1/evaluate")
    async def run_evaluation(
        req: EvaluateRequest, _: str = Depends(need_analyst)
    ) -> dict[str, Any]:
        from promptguard.evaluation.dataset import DatasetError, load_dataset
        from promptguard.evaluation.runner import evaluate

        if st.dataset_dir is None:
            raise ApiError(
                404, "not_found", "evaluation datasets are not configured on this server"
            )
        if not _DATASET_ID.match(req.dataset_id):
            raise ApiError(422, "invalid_request", "invalid dataset_id")
        path = (st.dataset_dir / req.dataset_id).resolve()
        if st.dataset_dir.resolve() not in path.parents or not path.is_dir():
            raise ApiError(404, "not_found", "dataset not found")
        try:
            ds = dataset_cache.get(req.dataset_id) or load_dataset(path)
            dataset_cache[req.dataset_id] = ds
            if len(ds.examples) > st.max_eval_examples:
                raise ApiError(413, "payload_too_large", "dataset exceeds server evaluation limit")
            return await asyncio.to_thread(
                evaluate,
                ds,
                scanner,
                split=req.split,
                positive_at=req.positive_at,
                context_mode=req.context_mode,
                include_texts=False,
            )
        except (DatasetError, ValueError) as exc:
            raise ApiError(422, "invalid_request", str(exc)) from exc

    if st.metrics_enabled:

        @app.get("/metrics", response_class=PlainTextResponse)
        async def metrics_endpoint(_: str = Depends(principal)) -> str:
            return metrics.render()

    return app


def app_factory() -> FastAPI:  # for `uvicorn --factory promptguard.api.app:app_factory`
    return create_app()
